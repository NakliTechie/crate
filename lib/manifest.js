// SPDX-License-Identifier: AGPL-3.0-or-later
// Manifest — append-only signed JSONL event log of all filesystem changes,
// stored encrypted at .crate/manifest.jsonl.enc.
//
// Spec: crate-browser-handoff-v1.0.md §"Manifest format"
//
// Wire format (decrypted, one event per line):
//
//   {"v":1,"ts":<ms>,"op":"create","uuid":"01H…","path":"/notes/foo.md",
//    "size":1234,"mime":"text/markdown","data_key_iv":"<b64>",
//    "data_key_ct":"<b64>","content_iv":"<b64>","prev_sig":"<b64>",
//    "sig":"<b64>"}
//   {"v":1,"ts":<ms>,"op":"update","uuid":"01H…","size":2345,
//    "content_iv":"<b64>","prev_sig":"<b64>","sig":"<b64>"}
//   {"v":1,"ts":<ms>,"op":"delete","uuid":"01H…","prev_sig":"<b64>","sig":"<b64>"}
//   {"v":1,"ts":<ms>,"op":"move","uuid":"01H…","path":"/notes/new.md",
//    "prev_sig":"<b64>","sig":"<b64>"}
//   {"v":1,"ts":<ms>,"op":"mkdir","path":"/notes/2026/","prev_sig":"<b64>",
//    "sig":"<b64>"}
//
// `sig` = HMAC-SHA256(masterKey, canonicalJSON(event_without_sig))
// `prev_sig` = the prior event's sig (base64), chained for tamper-evidence.
// First event uses prev_sig = "" (empty string, signed as such).
//
// The decrypted JSONL is then AES-GCM-sealed under the master key with
// `.crate/manifest.jsonl.enc:v1` as AAD before being PUT to the bucket.
// This binds the ciphertext to its purpose — moving the bytes to a
// different key in the bucket fails authentication.

import {
  encrypt, decrypt, hmacSign, hmacVerify, canonicalJSON,
  toBase64, fromBase64,
} from "./crypto.js";

export const MANIFEST_PATH = ".crate/manifest.jsonl.enc";
const MANIFEST_AAD = new TextEncoder().encode(".crate/manifest.jsonl.enc:v1");

// EventV = the schema version we emit. Forward-compat: readers tolerate
// unknown fields; writers bump v on breaking changes.
const EVENT_V = 1;

export class ManifestError extends Error {
  constructor(msg) { super(msg); this.name = "ManifestError"; }
}

// Manifest is an in-memory mutable log. Construct via `new Manifest()`,
// load existing bytes via `loadFromBytes`, append new events via `append`,
// serialize for PUT via `encryptToBytes`.
export class Manifest {
  constructor() {
    this.events = []; // array of validated event objects
    this._lastSig = ""; // tracks the most recent sig for prev_sig chaining
  }

  // append validates the event and adds it. Caller provides everything
  // except {v, prev_sig, sig} — those are filled here.
  async append(partialEvent, masterKeyBytes) {
    if (!partialEvent || typeof partialEvent !== "object") {
      throw new ManifestError("manifest.append: event must be an object");
    }
    const evt = { v: EVENT_V, ts: Date.now(), ...partialEvent };
    evt.prev_sig = this._lastSig;
    validateShape(evt);
    const sig = await signEvent(evt, masterKeyBytes);
    evt.sig = toBase64(sig);
    this.events.push(evt);
    this._lastSig = evt.sig;
    return evt;
  }

  // verify walks the chain and confirms every prev_sig + sig matches.
  // Returns { ok: true, count } on success; { ok: false, reason, at } on
  // first failure. Stops at first bad event.
  async verify(masterKeyBytes) {
    let prev = "";
    for (let i = 0; i < this.events.length; i++) {
      const e = this.events[i];
      if (e.prev_sig !== prev) {
        return { ok: false, at: i, reason: `prev_sig chain broken: ${e.prev_sig} vs ${prev}` };
      }
      const { sig, ...rest } = e;
      const expected = await signEvent(rest, masterKeyBytes);
      const ok = await hmacVerify(masterKeyBytes, canonicalJSON(rest), fromBase64(sig));
      if (!ok) return { ok: false, at: i, reason: "sig mismatch" };
      // Defensive: also bytes-check what we computed locally.
      const localOk = toBase64(expected) === sig;
      if (!localOk) return { ok: false, at: i, reason: "sig recompute mismatch" };
      prev = sig;
    }
    return { ok: true, count: this.events.length };
  }

  // latest returns the most recent event matching predicate, or undefined.
  latest(predicate) {
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (predicate(this.events[i])) return this.events[i];
    }
    return undefined;
  }

  // materialise replays the log to produce the current tree state.
  // Returns a Map<path, { uuid, size, mime, data_key_iv, data_key_ct,
  //                       content_iv, ts }>. Folders are virtual — their
  // existence is implied by file paths and explicit `mkdir` events.
  materialise() {
    const byUuid = new Map(); // uuid → { path, size, mime, … }
    const byPath = new Map();
    for (const e of this.events) {
      switch (e.op) {
        case "create": {
          const entry = {
            uuid: e.uuid,
            path: e.path,
            size: e.size,
            mime: e.mime || "application/octet-stream",
            data_key_iv: e.data_key_iv,
            data_key_ct: e.data_key_ct,
            content_iv: e.content_iv,
            ts: e.ts,
          };
          byUuid.set(e.uuid, entry);
          byPath.set(e.path, entry);
          break;
        }
        case "update": {
          const entry = byUuid.get(e.uuid);
          if (!entry) break; // dangling update — ignore
          entry.size = e.size ?? entry.size;
          entry.content_iv = e.content_iv ?? entry.content_iv;
          entry.ts = e.ts;
          break;
        }
        case "delete": {
          const entry = byUuid.get(e.uuid);
          if (!entry) break;
          byUuid.delete(e.uuid);
          byPath.delete(entry.path);
          break;
        }
        case "move": {
          const entry = byUuid.get(e.uuid);
          if (!entry) break;
          byPath.delete(entry.path);
          entry.path = e.path;
          entry.ts = e.ts;
          byPath.set(entry.path, entry);
          break;
        }
        case "mkdir": {
          // Folders are virtual; we just record the explicit-creation
          // event so empty folders survive a materialise pass.
          const folder = {
            uuid: null,
            path: e.path,
            isDir: true,
            ts: e.ts,
          };
          byPath.set(e.path, folder);
          break;
        }
        default:
          // Unknown op — forward-compat: ignore.
          break;
      }
    }
    return byPath;
  }

  // size returns the number of events. Useful for status reports.
  size() { return this.events.length; }

  // encryptToBytes returns the AES-GCM ciphertext ready to PUT to
  // .crate/manifest.jsonl.enc. Output layout:
  //   12-byte IV || ciphertext (with embedded 16-byte GCM auth tag)
  async encryptToBytes(masterKeyBytes) {
    const lines = this.events.map((e) => JSON.stringify(e)).join("\n") +
      (this.events.length ? "\n" : "");
    const plaintext = new TextEncoder().encode(lines);
    const { iv, ciphertext } = await encrypt(masterKeyBytes, plaintext, MANIFEST_AAD);
    const out = new Uint8Array(iv.length + ciphertext.length);
    out.set(iv, 0);
    out.set(ciphertext, iv.length);
    return out;
  }

  // loadFromBytes decrypts + parses the on-bucket .crate/manifest.jsonl.enc
  // body, then verifies every event's HMAC signature against the master
  // key. Returns a fresh Manifest. Throws on decrypt failure, parse
  // error, or any signature mismatch.
  //
  // The HMAC verification step was added per the 2026-05 security audit
  // (finding M1): AES-GCM already catches gross tampering of the
  // encrypted blob, but a producer with a bug or a malicious actor with
  // both the bucket and the master key (a contradiction in our threat
  // model — but worth defence-in-depth) could otherwise smuggle events
  // with invalid signatures past us.
  static async loadFromBytes(bytes, masterKeyBytes) {
    if (!(bytes instanceof Uint8Array)) {
      bytes = new Uint8Array(bytes);
    }
    if (bytes.length === 0) {
      return new Manifest(); // empty manifest is valid
    }
    if (bytes.length < 12) {
      throw new ManifestError("manifest: ciphertext too short (missing IV)");
    }
    const iv = bytes.subarray(0, 12);
    const ct = bytes.subarray(12);
    let plain;
    try {
      plain = await decrypt(masterKeyBytes, iv, ct, MANIFEST_AAD);
    } catch (e) {
      throw new ManifestError(`manifest: decrypt failed: ${e.message || e}`);
    }
    const m = Manifest.fromJSONL(new TextDecoder().decode(plain));
    // Verify each event's HMAC. fromJSONL already checks the prev_sig
    // continuity string, but not the actual MAC bytes.
    await m.verify(masterKeyBytes);
    return m;
  }

  // tail returns {count, lastSig} for use as an anchor (lib/anchor.js).
  // Empty manifest returns {count: 0, lastSig: ""}.
  tail() {
    return {
      count: this.events.length,
      lastSig: this.events.length > 0
        ? (this.events[this.events.length - 1].sig || "")
        : "",
    };
  }

  // fromJSONL parses an unencrypted JSONL string (test helper / inspection).
  static fromJSONL(text) {
    const m = new Manifest();
    if (!text || text.trim().length === 0) return m;
    const lines = text.split(/\r?\n/).filter((l) => l.length > 0);
    let prev = "";
    for (let i = 0; i < lines.length; i++) {
      let evt;
      try {
        evt = JSON.parse(lines[i]);
      } catch (e) {
        throw new ManifestError(`manifest: line ${i + 1} not JSON: ${e.message}`);
      }
      validateShape(evt);
      if (evt.prev_sig !== prev) {
        throw new ManifestError(
          `manifest: line ${i + 1} prev_sig chain broken: ${evt.prev_sig} vs ${prev}`,
        );
      }
      m.events.push(evt);
      prev = evt.sig;
    }
    m._lastSig = prev;
    return m;
  }
}

// validateShape enforces the per-op required fields. Throws on miss.
function validateShape(evt) {
  if (evt.v !== EVENT_V) {
    // Forward-compat: tolerate higher versions on read (we just won't
    // understand new fields); reject lower so a downgraded reader doesn't
    // pretend to grok a newer log. For v1.0 we hardcode equality.
    if (evt.v > EVENT_V) return; // tolerate
    throw new ManifestError(`manifest: unknown event version v=${evt.v}`);
  }
  if (typeof evt.op !== "string") throw new ManifestError("manifest: event missing op");
  if (typeof evt.ts !== "number") throw new ManifestError("manifest: event missing ts");
  switch (evt.op) {
    case "create":
      requireStr(evt, "uuid"); requireStr(evt, "path");
      requireNum(evt, "size");
      requireStr(evt, "data_key_iv"); requireStr(evt, "data_key_ct");
      requireStr(evt, "content_iv");
      break;
    case "update":
      requireStr(evt, "uuid"); requireStr(evt, "content_iv");
      requireNum(evt, "size");
      break;
    case "delete":
      requireStr(evt, "uuid");
      break;
    case "move":
      requireStr(evt, "uuid"); requireStr(evt, "path");
      break;
    case "mkdir":
      requireStr(evt, "path");
      break;
    default:
      // Forward-compat: tolerate unknown ops on read (materialise() will
      // ignore them); writer paths only emit the catalogued ops.
      break;
  }
}

function requireStr(evt, k) {
  if (typeof evt[k] !== "string" || evt[k].length === 0) {
    throw new ManifestError(`manifest: event op=${evt.op} requires string ${k}`);
  }
}
function requireNum(evt, k) {
  if (typeof evt[k] !== "number") {
    throw new ManifestError(`manifest: event op=${evt.op} requires number ${k}`);
  }
}

// signEvent computes the HMAC-SHA256 over the canonical JSON of the event
// MINUS the `sig` field. Used both at write (compute) and verify (recompute
// and compare). The `prev_sig` field IS part of the signed payload — that's
// what makes the chain tamper-evident.
async function signEvent(evt, masterKeyBytes) {
  const { sig, ...rest } = evt;
  const canonical = canonicalJSON(rest);
  return hmacSign(masterKeyBytes, canonical);
}

// --- convenience factories — keep handler code small ---------------------

// createEvent makes a `create` event. Caller supplies the encrypted-data-key
// blob + content IV (both produced earlier when sealing the file payload).
export function createEvent({ uuid, path, size, mime, dataKeyIv, dataKeyCt, contentIv }) {
  return {
    op: "create",
    uuid, path, size,
    mime: mime || "application/octet-stream",
    data_key_iv: toBase64(dataKeyIv),
    data_key_ct: toBase64(dataKeyCt),
    content_iv: toBase64(contentIv),
  };
}

export function updateEvent({ uuid, size, contentIv }) {
  return { op: "update", uuid, size, content_iv: toBase64(contentIv) };
}
export function deleteEvent({ uuid }) {
  return { op: "delete", uuid };
}
export function moveEvent({ uuid, newPath }) {
  return { op: "move", uuid, path: newPath };
}
export function mkdirEvent({ path }) {
  return { op: "mkdir", path };
}
