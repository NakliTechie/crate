// SPDX-License-Identifier: AGPL-3.0-or-later
// Crate — the ESM / programmatic API other NakliTechie tools (Folio, Slate,
// Bahi, Mahalla, …) bind to.
//
// The surface is intentionally small: 9 methods that mirror what apps
// already do against File System Access (FSA) — list / read / write /
// remove / move / mkdir / stat / history / onChange. Apps choose at
// runtime: local FSA (default) or this Crate adapter; same code path works
// against both. Full reference: docs/esm-api.md.
//
// Lifecycle:
//   const crate = await Crate.open({
//     bucketConfig: { accountId, name, region },
//     credentials:  { accessKey, secretKey },
//     passphrase,
//   });
//   await crate.list("/");              // [{ path, name, isDir, size, mime, ts }]
//   await crate.write("/docs/foo.md", new Uint8Array([...]));
//   const bytes = await crate.read("/docs/foo.md");
//   await crate.remove("/docs/foo.md");
//   await crate.move("/a.md", "/b.md");
//   await crate.mkdir("/projects/");
//   const meta = await crate.stat("/docs/foo.md");
//   const events = await crate.history("/docs/foo.md");
//   const unsub = crate.onChange((evt) => { … });
//   crate.close();                      // zeroes the master key
//
// Bucket-level first-time setup:
//   Use `Crate.bootstrap({…})` instead of `Crate.open({…})`. Bootstrap
//   writes a fresh .crate/crate.json + an empty manifest; open() expects
//   both to already exist.
//
// All file operations are end-to-end encrypted in this browser. The bucket
// owner sees ciphertext + access patterns only. The daemon (crate-agent)
// interoperates via the same wire format.

import * as cryptoLib from "./crypto.js";
import * as bucket from "./bucket.js";
import * as cratejson from "./cratejson.js";
import {
  Manifest, MANIFEST_PATH,
  createEvent, updateEvent, deleteEvent, moveEvent, mkdirEvent,
} from "./manifest.js";

const OBJECTS_PREFIX = "objects/";

export class CrateError extends Error {
  constructor(message) { super(message); this.name = "CrateError"; }
}

export class Crate {
  constructor({ bucketBase, region, accessKey, secretKey, masterKey, manifest, salt, manifestETag, lastFlushedEventCount }) {
    this._bucketBase = bucketBase;
    this._region = region;
    this._accessKey = accessKey;
    this._secretKey = secretKey;
    this._masterKey = masterKey;
    this._manifest = manifest;
    this._salt = salt;
    // _manifestETag tracks the last-known R2 ETag of .crate/manifest.jsonl.enc.
    // Used for If-Match conditional PUTs (concurrent-write safety: two tabs
    // PUTting at the same time → second one gets 412 → re-GET, splice, retry).
    // null = no known ETag yet; PUTs go through unconditionally.
    this._manifestETag = manifestETag || null;
    // _lastFlushedEventCount is the count of events known to be in the
    // remote manifest (i.e. the high-water mark of flushed-to-bucket
    // state). Initialised to manifest.events.length because everything
    // we just loaded is by definition already flushed; the next append
    // is the first pending local event. CRITICAL: do not leave this
    // undefined — _flushManifest's 412 replay path would otherwise treat
    // the entire loaded manifest as "local events to replay" and clobber
    // remote updates on retry. See 2026-05 security audit, finding H3.
    this._lastFlushedEventCount = typeof lastFlushedEventCount === "number"
      ? lastFlushedEventCount
      : (manifest?.events?.length ?? 0);
    this._listeners = new Set();
    this._closed = false;
  }

  // --- factory: open existing bucket -------------------------------------

  static async open({ bucketConfig, credentials, passphrase } = {}) {
    if (!bucketConfig?.accountId || !bucketConfig?.name) {
      throw new CrateError("Crate.open: bucketConfig.accountId + name required");
    }
    if (!credentials?.accessKey || !credentials?.secretKey) {
      throw new CrateError("Crate.open: credentials.accessKey + secretKey required");
    }
    if (!passphrase) throw new CrateError("Crate.open: passphrase required");

    const bucketBase = bucket.endpoints.R2(
      bucketConfig.accountId.trim().toLowerCase(),
      bucketConfig.name.trim(),
    );
    const region = bucketConfig.region || "auto";

    const cjGet = await bucket.signedGet({
      url: bucketBase + cratejson.CRATE_PATH,
      region, accessKey: credentials.accessKey, secretKey: credentials.secretKey,
    });
    if (!cjGet.ok) {
      throw new CrateError(
        `open: GET .crate/crate.json failed (${cjGet.status} ${cjGet.code}: ${cjGet.message})`,
      );
    }
    const cj = cratejson.parse(cjGet.body);
    const salt = cj.saltBytes;
    const masterKey = await cryptoLib.deriveMasterKey(passphrase, salt);

    const manGet = await bucket.signedGet({
      url: bucketBase + MANIFEST_PATH,
      region, accessKey: credentials.accessKey, secretKey: credentials.secretKey,
    });
    let manifest;
    let manifestETag = null;
    if (manGet.ok) {
      manifest = await Manifest.loadFromBytes(manGet.body, masterKey);
      manifestETag = manGet.etag || null;
    } else if (manGet.status === 404) {
      manifest = new Manifest();
    } else {
      cryptoLib.zero(masterKey);
      throw new CrateError(
        `open: GET manifest failed (${manGet.status} ${manGet.code}: ${manGet.message})`,
      );
    }

    return new Crate({
      bucketBase, region,
      accessKey: credentials.accessKey, secretKey: credentials.secretKey,
      masterKey, manifest, salt, manifestETag,
    });
  }

  // --- factory: bootstrap a fresh Crate ----------------------------------

  static async bootstrap({ bucketConfig, credentials, passphrase, identity, createdBy } = {}) {
    if (!bucketConfig?.accountId || !bucketConfig?.name) {
      throw new CrateError("Crate.bootstrap: bucketConfig.accountId + name required");
    }
    if (!credentials?.accessKey || !credentials?.secretKey) {
      throw new CrateError("Crate.bootstrap: credentials required");
    }
    if (!passphrase) throw new CrateError("Crate.bootstrap: passphrase required");

    const bucketBase = bucket.endpoints.R2(
      bucketConfig.accountId.trim().toLowerCase(),
      bucketConfig.name.trim(),
    );
    const region = bucketConfig.region || "auto";

    const salt = cryptoLib.randomSalt();
    const masterKey = await cryptoLib.deriveMasterKey(passphrase, salt);

    const crateJsonBytes = cratejson.build({
      salt,
      identity,
      createdBy: createdBy || cratejson.shortBrowserFingerprint(),
    });
    const putCj = await bucket.signedPut({
      url: bucketBase + cratejson.CRATE_PATH,
      body: crateJsonBytes, contentType: "application/json",
      region, accessKey: credentials.accessKey, secretKey: credentials.secretKey,
    });
    if (!putCj.ok) {
      cryptoLib.zero(masterKey);
      throw new CrateError(
        `bootstrap: write .crate/crate.json failed (${putCj.status} ${putCj.code}: ${putCj.message})`,
      );
    }

    const manifest = new Manifest();
    const manBytes = await manifest.encryptToBytes(masterKey);
    const putMan = await bucket.signedPut({
      url: bucketBase + MANIFEST_PATH,
      body: manBytes, contentType: "application/octet-stream",
      region, accessKey: credentials.accessKey, secretKey: credentials.secretKey,
    });
    if (!putMan.ok) {
      cryptoLib.zero(masterKey);
      throw new CrateError(
        `bootstrap: write manifest failed (${putMan.status} ${putMan.code}: ${putMan.message})`,
      );
    }
    const manifestETag = putMan.etag || null;

    return new Crate({
      bucketBase, region,
      accessKey: credentials.accessKey, secretKey: credentials.secretKey,
      masterKey, manifest, salt, manifestETag,
    });
  }

  // --- ESM API (v1 surface; see docs/esm-api.md) -------------------------

  async list(path = "/") {
    this._guardOpen();
    if (!path.endsWith("/")) path = path + "/";
    const tree = this._manifest.materialise();
    const out = new Map();
    for (const [p, entry] of tree.entries()) {
      if (!p.startsWith(path)) continue;
      const rest = p.slice(path.length).replace(/^\//, "");
      if (rest.length === 0) continue;
      const slash = rest.indexOf("/");
      if (slash === -1) {
        out.set(rest, {
          path: p, name: rest, isDir: !!entry.isDir,
          size: entry.size ?? 0, mime: entry.mime || null, ts: entry.ts,
        });
      } else {
        const dirName = rest.slice(0, slash);
        if (!out.has(dirName)) {
          out.set(dirName, {
            path: path + dirName + "/",
            name: dirName, isDir: true, size: 0, mime: null, ts: null,
          });
        }
      }
    }
    return [...out.values()];
  }

  async read(path) {
    this._guardOpen();
    const entry = this._manifest.materialise().get(path);
    if (!entry || entry.isDir) throw new CrateError(`read: not a file: ${path}`);
    const got = await bucket.signedGet({
      url: this._bucketBase + OBJECTS_PREFIX + entry.uuid,
      region: this._region, accessKey: this._accessKey, secretKey: this._secretKey,
    });
    if (!got.ok) throw new CrateError(`read: GET object failed (${got.status})`);
    if (got.body.length < 12) throw new CrateError("read: ciphertext too short");
    const iv = got.body.subarray(0, 12);
    const ct = got.body.subarray(12);

    // Bind decryption to the manifest-signed content_iv. Without this
    // check, a bucket-only attacker can replay an older object body
    // for the same UUID: AES-GCM still authenticates (key + UUID-AAD
    // match), so the user receives stale plaintext silently. The
    // manifest's content_iv field carries the IV of the CURRENT
    // version inside the HMAC-signed event chain; verifying the
    // object's leading IV against it pins the decryption to the
    // current manifest event. See 2026-05 security audit, H1.
    if (entry.content_iv) {
      const expected = cryptoLib.fromBase64(entry.content_iv);
      if (!constantTimeBytesEqual(iv, expected)) {
        throw new CrateError("read: object IV does not match manifest content_iv (rollback or tamper)");
      }
    }

    const dataKey = await cryptoLib.unwrapDataKey(
      this._masterKey,
      cryptoLib.fromBase64(entry.data_key_iv),
      cryptoLib.fromBase64(entry.data_key_ct),
      entry.uuid,
    );
    const plain = await cryptoLib.decrypt(dataKey, iv, ct, new TextEncoder().encode(entry.uuid));
    cryptoLib.zero(dataKey);
    return plain;
  }

  async write(path, bytes, { mime } = {}) {
    this._guardOpen();
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    const existing = this._manifest.materialise().get(path);

    if (existing && !existing.isDir && existing.uuid) {
      const dataKey = await cryptoLib.unwrapDataKey(
        this._masterKey,
        cryptoLib.fromBase64(existing.data_key_iv),
        cryptoLib.fromBase64(existing.data_key_ct),
        existing.uuid,
      );
      const sealed = await cryptoLib.encrypt(dataKey, bytes, new TextEncoder().encode(existing.uuid));
      cryptoLib.zero(dataKey);
      const body = new Uint8Array(sealed.iv.length + sealed.ciphertext.length);
      body.set(sealed.iv, 0);
      body.set(sealed.ciphertext, sealed.iv.length);
      const put = await bucket.signedPut({
        url: this._bucketBase + OBJECTS_PREFIX + existing.uuid,
        body, contentType: "application/octet-stream",
        region: this._region, accessKey: this._accessKey, secretKey: this._secretKey,
      });
      if (!put.ok) throw new CrateError(`write: PUT failed (${put.status})`);
      await this._manifest.append(
        updateEvent({ uuid: existing.uuid, size: bytes.length, contentIv: sealed.iv }),
        this._masterKey,
      );
      await this._flushManifest();
      this._emit({ op: "update", path, size: bytes.length });
      return;
    }

    const uuid = cryptoLib.newULID();
    const dataKey = cryptoLib.randomDataKey();
    const wrapped = await cryptoLib.wrapDataKey(this._masterKey, dataKey, uuid);
    const sealed = await cryptoLib.encrypt(dataKey, bytes, new TextEncoder().encode(uuid));
    cryptoLib.zero(dataKey);
    const body = new Uint8Array(sealed.iv.length + sealed.ciphertext.length);
    body.set(sealed.iv, 0);
    body.set(sealed.ciphertext, sealed.iv.length);
    const put = await bucket.signedPut({
      url: this._bucketBase + OBJECTS_PREFIX + uuid,
      body, contentType: "application/octet-stream",
      region: this._region, accessKey: this._accessKey, secretKey: this._secretKey,
    });
    if (!put.ok) throw new CrateError(`write: PUT failed (${put.status})`);
    await this._manifest.append(
      createEvent({
        uuid, path, size: bytes.length, mime: mime || "application/octet-stream",
        dataKeyIv: wrapped.iv, dataKeyCt: wrapped.ciphertext, contentIv: sealed.iv,
      }),
      this._masterKey,
    );
    await this._flushManifest();
    this._emit({ op: "create", path, size: bytes.length });
  }

  async remove(path) {
    this._guardOpen();
    const entry = this._manifest.materialise().get(path);
    if (!entry) return;
    if (entry.isDir) throw new CrateError(`remove: refuse to remove a folder; delete contents first`);
    const del = await bucket.signedDelete({
      url: this._bucketBase + OBJECTS_PREFIX + entry.uuid,
      region: this._region, accessKey: this._accessKey, secretKey: this._secretKey,
    });
    if (!del.ok) throw new CrateError(`remove: DELETE failed (${del.status})`);
    await this._manifest.append(deleteEvent({ uuid: entry.uuid }), this._masterKey);
    await this._flushManifest();
    this._emit({ op: "delete", path });
  }

  async move(from, to) {
    this._guardOpen();
    const entry = this._manifest.materialise().get(from);
    if (!entry) throw new CrateError(`move: source not found: ${from}`);
    if (entry.isDir) throw new CrateError(`move: cannot move folders (v1.0)`);
    await this._manifest.append(moveEvent({ uuid: entry.uuid, newPath: to }), this._masterKey);
    await this._flushManifest();
    this._emit({ op: "move", from, to });
  }

  async mkdir(path) {
    this._guardOpen();
    if (!path.endsWith("/")) path = path + "/";
    await this._manifest.append(mkdirEvent({ path }), this._masterKey);
    await this._flushManifest();
    this._emit({ op: "mkdir", path });
  }

  async stat(path) {
    this._guardOpen();
    const entry = this._manifest.materialise().get(path);
    if (!entry) return null;
    return {
      path: entry.path,
      isDir: !!entry.isDir,
      size: entry.size ?? 0,
      mime: entry.mime ?? null,
      ts: entry.ts ?? null,
      uuid: entry.uuid ?? null,
    };
  }

  async history(path) {
    this._guardOpen();
    const current = this._manifest.materialise().get(path);
    const out = [];
    let trackedUuid = current?.uuid ?? null;
    for (const e of this._manifest.events) {
      const matches =
        (e.op === "mkdir" && e.path === path) ||
        (trackedUuid && e.uuid === trackedUuid) ||
        (e.op === "create" && e.path === path) ||
        (e.op === "move" && e.path === path);
      if (e.op === "create" && e.path === path && !trackedUuid) trackedUuid = e.uuid;
      if (matches) out.push({ op: e.op, ts: e.ts, path: e.path, size: e.size });
    }
    return out;
  }

  onChange(handler) {
    this._guardOpen();
    if (typeof handler !== "function") throw new CrateError("onChange: handler must be a function");
    this._listeners.add(handler);
    return () => this._listeners.delete(handler);
  }

  // close zeroes the master key and detaches creds. All methods throw afterwards.
  close() {
    if (this._closed) return;
    cryptoLib.zero(this._masterKey);
    this._masterKey = null;
    this._accessKey = null;
    this._secretKey = null;
    this._manifest = null;
    this._listeners.clear();
    this._closed = true;
  }

  // --- internals ---------------------------------------------------------

  _guardOpen() {
    if (this._closed) throw new CrateError("Crate is closed");
  }

  _emit(evt) {
    for (const h of this._listeners) {
      try { h(evt); } catch (e) { console.error("onChange handler threw", e); }
    }
  }

  // _flushManifest PUTs the in-memory manifest with If-Match against our
  // last-known ETag. On 412 (a peer wrote between our last GET and this
  // PUT), we:
  //   1. Re-GET the bucket's manifest
  //   2. Snapshot our pending local events (everything appended since
  //      our last successful flush — i.e. since this._manifestETag was
  //      set)
  //   3. Replace our in-memory manifest with the fresh remote one
  //   4. Re-append our pending events on top
  //   5. PUT again with the new ETag
  // Retries up to 3 times before giving up (callers see CrateError).
  async _flushManifest() {
    const maxRetries = 3;
    // Snapshot the events that exist NOW so we can compute "what we added
    // since the last successful flush" if a 412 forces a replay. We use
    // the manifest's current prev_sig anchor — every event after the
    // anchor is "ours to replay."
    let localEventsToReplay = this._manifest.events.slice(this._lastFlushedEventCount ?? 0);

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const bytes = await this._manifest.encryptToBytes(this._masterKey);
      const put = await bucket.signedPut({
        url: this._bucketBase + MANIFEST_PATH,
        body: bytes, contentType: "application/octet-stream",
        ifMatch: this._manifestETag,
        region: this._region, accessKey: this._accessKey, secretKey: this._secretKey,
      });
      if (put.ok) {
        this._manifestETag = put.etag || null;
        this._lastFlushedEventCount = this._manifest.events.length;
        return;
      }
      if (put.preconditionFailed && attempt < maxRetries) {
        // Re-fetch + replay. The fresh manifest replaces ours under the
        // mutex (we don't have one here — Crate isn't shared cross-thread,
        // but it IS the same reference SyncClient holds; mutate in place).
        const got = await bucket.signedGet({
          url: this._bucketBase + MANIFEST_PATH,
          region: this._region, accessKey: this._accessKey, secretKey: this._secretKey,
        });
        if (!got.ok) {
          throw new CrateError(`_flushManifest: re-GET after 412 failed (${got.status})`);
        }
        const fresh = await Manifest.loadFromBytes(got.body, this._masterKey);
        // Mutate in place so any shared references (SyncClient, FolderUI
        // session.manifest) see the same Manifest object.
        this._manifest.events = fresh.events;
        this._manifest._lastSig = fresh._lastSig;
        // Replay our pending events. Append() uses prev_sig from
        // _lastSig + recomputes sigs against the new chain.
        for (const e of localEventsToReplay) {
          const partial = { ...e };
          delete partial.v;
          delete partial.ts;
          delete partial.prev_sig;
          delete partial.sig;
          await this._manifest.append(partial, this._masterKey);
        }
        this._manifestETag = got.etag || null;
        // localEventsToReplay stays valid for the next retry (same content;
        // they'll just get re-appended with newer prev_sigs).
        continue;
      }
      throw new CrateError(`_flushManifest: PUT failed (${put.status})`);
    }
    throw new CrateError("_flushManifest: too many ETag-conflict retries");
  }
}

// constantTimeBytesEqual is a length-tolerant constant-time-ish byte
// comparison. JS doesn't expose subtle.timingSafeEqual on TypedArrays
// (it's Node-only); for browser builds we implement the standard
// length-check + XOR-fold pattern. The IVs we compare are 12 bytes so
// timing variance is negligible, but the discipline matters because we
// use this for verification of manifest-signed values.
function constantTimeBytesEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
