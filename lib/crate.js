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
import { sealVault, openVault, writeKeySlots, VaultError } from "./vault.js";
import * as offline from "./offline.js";
import * as anchor from "./anchor.js";
import { flushManifest as sharedFlushManifest } from "./manifest-flush.js";
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

  static async open({ bucketConfig, credentials, passphrase, recoveryEntropy = null } = {}) {
    if (!credentials?.accessKey || !credentials?.secretKey) {
      throw new CrateError("Crate.open: credentials.accessKey + secretKey required");
    }
    if (!passphrase && !recoveryEntropy) throw new CrateError("Crate.open: passphrase or recoveryEntropy required");

    // R2 (sig-v4) or the carrier Worker — resolveBase decides, and the
    // region string carries the transport choice to every signed call.
    let bucketBase;
    try { bucketBase = bucket.resolveBase(bucketConfig); }
    catch (e) { throw new CrateError(`Crate.open: ${e.message}`); }
    const region = bucketConfig.region || "auto";

    // Offline: when the network is down (not a 4xx/5xx — those mean the
    // bucket answered), open from the last copy this device saw.
    let isOffline = false;
    let cjGet = await bucket.signedGet({
      url: bucketBase + cratejson.CRATE_PATH,
      region, accessKey: credentials.accessKey, secretKey: credentials.secretKey,
    });
    let cached = null;
    if (!cjGet.ok && cjGet.networkError) {
      cached = await offline.recall(bucketBase);
      if (cached) {
        isOffline = true;
        cjGet = { ok: true, status: 200, etag: null, body: cached.crateJson };
      }
    }
    if (!cjGet.ok) {
      throw new CrateError(
        `open: GET .crate/crate.json failed (${cjGet.status} ${cjGet.code}: ${cjGet.message})`,
      );
    }
    const cj = cratejson.parse(cjGet.body);

    // Recover the content key ("master key") from whichever slot the
    // caller holds: the passphrase (v1.0 derives it, v1.1 unwraps it) or
    // the recovery phrase's entropy (v1.1 only). lib/vault.js owns this.
    let masterKey;
    try {
      masterKey = await openVault(cj, { passphrase, recoveryEntropy });
    } catch (e) {
      if (e instanceof VaultError) throw new CrateError(`open: ${e.message}`, { cause: e });
      throw e;
    }
    // `salt` is the passphrase slot's salt (v1.0: the one salt). The
    // creds file and the daemon hand-off carry it for the v1.0 path.
    const salt = cj.version === "1.1" ? cj.passphraseWrap.saltBytes : cj.saltBytes;
    const hasRecovery = cj.version === "1.1" && !!cj.recoveryWrap;

    const manGet = isOffline
      ? { ok: true, status: 200, etag: cached.manifestETag, body: cached.manifest }
      : await bucket.signedGet({
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

    // Validate the loaded manifest against the persisted rollback anchor.
    // First load on this device falls through TOFU (anchor is null → ok).
    // On subsequent loads, REJECT if the bucket has rolled back below the
    // anchor (truncation) or forked from a different chain at the anchor
    // point (fork). See lib/anchor.js + 2026-05 security audit, finding H2.
    const prior = await anchor.loadAnchor(bucketBase);
    const v = anchor.validate(manifest.events, prior);
    if (!v.ok) {
      cryptoLib.zero(masterKey);
      throw new anchor.ManifestRollbackError(v.reason, v.detail);
    }
    if (v.tofu) {
      console.log("[crate] anchoring to current manifest state (count=%d) — first load on this device",
        v.anchor.count);
    }
    await anchor.saveAnchor(bucketBase, v.anchor);

    const c = new Crate({
      bucketBase, region,
      accessKey: credentials.accessKey, secretKey: credentials.secretKey,
      masterKey, manifest, salt, manifestETag,
    });
    c._hasRecovery = hasRecovery;
    c._crateJson = cj;
    c._crateJsonETag = cjGet.etag || null;
    c._offline = isOffline;
    if (!isOffline) {
      void offline.remember(bucketBase, { crateJson: cjGet.body, manifest: manGet.ok ? manGet.body : null, manifestETag });
    }
    return c;
  }

  // --- factory: bootstrap a fresh Crate ----------------------------------

  static async bootstrap({ bucketConfig, credentials, passphrase, recoveryEntropy = null, identity, createdBy } = {}) {
    if (!credentials?.accessKey || !credentials?.secretKey) {
      throw new CrateError("Crate.bootstrap: credentials required");
    }
    if (!passphrase) throw new CrateError("Crate.bootstrap: passphrase required");

    let bucketBase;
    try { bucketBase = bucket.resolveBase(bucketConfig); }
    catch (e) { throw new CrateError(`Crate.bootstrap: ${e.message}`); }
    const region = bucketConfig.region || "auto";

    // v1.1 vault: a random content key wrapped under the passphrase and,
    // when the user kept a recovery phrase, under its entropy as well.
    let sealed;
    try {
      sealed = await sealVault({
        passphrase, recoveryEntropy, identity,
        createdBy: createdBy || cratejson.shortBrowserFingerprint(),
      });
    } catch (e) {
      if (e instanceof VaultError) throw new CrateError(`Crate.bootstrap: ${e.message}`, { cause: e });
      throw e;
    }
    const masterKey = sealed.contentKey;
    const salt = sealed.passphraseSalt;
    const crateJsonBytes = sealed.crateJsonBytes;
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

    // Save the initial (empty) rollback anchor. Subsequent loads anywhere
    // on this device will refuse a bucket that rolled back below this
    // baseline. See lib/anchor.js + 2026-05 security audit, finding H2.
    await anchor.saveAnchor(bucketBase, manifest.tail());

    const c = new Crate({
      bucketBase, region,
      accessKey: credentials.accessKey, secretKey: credentials.secretKey,
      masterKey, manifest, salt, manifestETag,
    });
    c._hasRecovery = !!recoveryEntropy;
    c._crateJson = cratejson.parse(crateJsonBytes);
    c._crateJsonETag = putCj.etag || null;
    c._offline = false;
    void offline.remember(bucketBase, { crateJson: crateJsonBytes, manifest: manBytes, manifestETag });
    return c;
  }

  // --- key-slot operations (v1.1 vaults; additive to the v1 surface) ------

  // _rewrite re-seals the content key with the given slots and writes the
  // new crate.json with If-Match on the copy this instance read, so two
  // devices changing credentials at once cannot silently clobber each
  // other. Files are untouched — only the wraps change.
  async _rewrite({ passphrase = null, recoveryEntropy = null } = {}) {
    this._guardOpen();
    let r;
    try {
      r = await writeKeySlots({
        bucketBase: this._bucketBase, region: this._region,
        accessKey: this._accessKey, secretKey: this._secretKey,
        crateJson: this._crateJson, crateJsonETag: this._crateJsonETag,
        masterKey: this._masterKey, passphrase, recoveryEntropy,
      });
    } catch (e) {
      if (e instanceof VaultError) throw new CrateError(e.message, { cause: e });
      throw e;
    }
    this._crateJson = r.crateJson;
    this._crateJsonETag = r.crateJsonETag;
    this._salt = r.crateJson.passphraseWrap.saltBytes;
    this._hasRecovery = !!r.crateJson.recoveryWrap;
    void offline.remember(this._bucketBase, { crateJson: r.bytes });
  }

  // setPassphrase re-wraps the content key under a new passphrase. The
  // recovery slot, if any, is carried over. Nothing is re-encrypted.
  async setPassphrase(newPassphrase) {
    if (typeof newPassphrase !== "string" || newPassphrase.length === 0) {
      throw new CrateError("setPassphrase: passphrase required");
    }
    await this._rewrite({ passphrase: newPassphrase });
  }

  // enableRecovery adds (or replaces) the recovery slot. A v1.0 vault is
  // migrated to v1.1 in the same write and needs the current passphrase
  // for its passphrase slot (see vault.js migrateV10 for the trade-off).
  async enableRecovery(recoveryEntropy, { passphrase = null } = {}) {
    if (!(recoveryEntropy instanceof Uint8Array) || recoveryEntropy.length !== 32) {
      throw new CrateError("enableRecovery: 32 bytes of entropy required");
    }
    if (this._crateJson?.version !== "1.1" && !passphrase) {
      throw new CrateError("enableRecovery: this folder is a v1.0 vault; pass { passphrase } to migrate it");
    }
    await this._rewrite({ recoveryEntropy, passphrase: this._crateJson?.version === "1.1" ? null : passphrase });
  }

  get hasRecovery() { return !!this._hasRecovery; }

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
    // openObject dispatches on entry.chunk_size (v1 blob vs v2 chunked)
    // and enforces the manifest-signed content_iv rollback anchor
    // (2026-05 audit H1) before decrypting either format.
    const dataKey = await cryptoLib.unwrapDataKey(
      this._masterKey,
      cryptoLib.fromBase64(entry.data_key_iv),
      cryptoLib.fromBase64(entry.data_key_ct),
      entry.uuid,
    );
    try {
      return await cryptoLib.openObject(dataKey, got.body, entry);
    } catch (e) {
      throw new CrateError(`read: ${e.message}`);
    } finally {
      cryptoLib.zero(dataKey);
    }
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
      const sealed = await cryptoLib.sealObject(dataKey, bytes, existing.uuid);
      cryptoLib.zero(dataKey);
      const put = await bucket.signedPut({
        url: this._bucketBase + OBJECTS_PREFIX + existing.uuid,
        body: sealed.body, contentType: "application/octet-stream",
        region: this._region, accessKey: this._accessKey, secretKey: this._secretKey,
      });
      if (!put.ok) throw new CrateError(`write: PUT failed (${put.status})`);
      await this._manifest.append(
        updateEvent({ uuid: existing.uuid, size: bytes.length, contentIv: sealed.contentIv, chunkSize: sealed.chunkSize }),
        this._masterKey,
      );
      await this._flushManifest();
      this._emit({ op: "update", path, size: bytes.length });
      return;
    }

    const uuid = cryptoLib.newULID();
    const dataKey = cryptoLib.randomDataKey();
    const wrapped = await cryptoLib.wrapDataKey(this._masterKey, dataKey, uuid);
    const sealed = await cryptoLib.sealObject(dataKey, bytes, uuid);
    cryptoLib.zero(dataKey);
    const put = await bucket.signedPut({
      url: this._bucketBase + OBJECTS_PREFIX + uuid,
      body: sealed.body, contentType: "application/octet-stream",
      region: this._region, accessKey: this._accessKey, secretKey: this._secretKey,
    });
    if (!put.ok) throw new CrateError(`write: PUT failed (${put.status})`);
    await this._manifest.append(
      createEvent({
        uuid, path, size: bytes.length, mime: mime || "application/octet-stream",
        dataKeyIv: wrapped.iv, dataKeyCt: wrapped.ciphertext,
        contentIv: sealed.contentIv, chunkSize: sealed.chunkSize,
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

  // _flushManifest delegates to the shared implementation in
  // lib/manifest-flush.js. We construct a small adapter so this class's
  // `_`-prefixed instance properties map onto the unprefixed shape the
  // shared function reads/writes. Read-only props are exposed as plain
  // values; manifestETag and lastFlushedEventCount need getter/setter
  // pairs so writes propagate back to this._*.
  //
  // History on the dedupe: this method and FolderUI.flushManifest were
  // near-duplicate copies for a long time. The duplication bit us when
  // the v1.0.1 H2 patch added the rollback-anchor checks here but not
  // in FolderUI's copy (caught + fixed days later). Single source of
  // truth in manifest-flush.js prevents that class of drift.
  async _flushManifest() {
    const self = this;
    const state = {
      manifest: self._manifest,
      masterKey: self._masterKey,
      bucketBase: self._bucketBase,
      region: self._region,
      accessKey: self._accessKey,
      secretKey: self._secretKey,
      get manifestETag() { return self._manifestETag; },
      set manifestETag(v) { self._manifestETag = v; },
      get lastFlushedEventCount() { return self._lastFlushedEventCount; },
      set lastFlushedEventCount(v) { self._lastFlushedEventCount = v; },
    };
    return sharedFlushManifest(state, {
      errorFactory: (m) => new CrateError(m),
    });
  }
}

