// SPDX-License-Identifier: AGPL-3.0-or-later
// Writer + reader for .crate/crate.json — the bucket-level metadata blob
// the browser writes on first-time setup and every paired surface reads
// to align on the schema + key-wrap state.
//
// Two schemas exist (selected by `version`):
//
//   v1.0 (legacy — what crate v1.0.x shipped):
//     {
//       "v": 1,
//       "version": "1.0",
//       "salt": "<base64 16 bytes>",      // PBKDF2 salt — master key = PBKDF2(passphrase, salt)
//       "identity": { /* opaque */ },
//       "created_at": "<rfc3339>",
//       "created_by": "<short fingerprint>"
//     }
//
//   v1.1 (current — adds recovery credential):
//     {
//       "v": 1,
//       "version": "1.1",
//       "passphrase_wrap": {                // master/content key wrapped under passphrase-KEK
//         "kdf":  "PBKDF2-SHA256",
//         "iter": 600000,
//         "salt": "<base64 16 bytes>",
//         "iv":   "<base64 12 bytes>",
//         "ct":   "<base64 48 bytes — 32-byte key + 16-byte GCM tag>"
//       },
//       "recovery_wrap": {                  // OPTIONAL — present only when user enabled recovery
//         "kdf":  "PBKDF2-SHA256",
//         "iter": 600000,
//         "salt": "<base64 16 bytes>",      // independent salt from passphrase_wrap.salt
//         "iv":   "<base64 12 bytes>",
//         "ct":   "<base64 48 bytes; same content key, different KEK>"
//       },
//       "identity": { /* opaque */ },
//       "created_at": "<rfc3339>",
//       "created_by": "<short fingerprint>"
//     }
//
// `v: 1` is the WIRE FORMAT version (JSON-level). Adding optional fields
// keeps it at 1. The string `version` is the SEMANTIC schema version: v1.0
// readers reject v1.1 docs (top-level `salt` missing); v1.1 readers accept
// both.
//
// Daemon coordination: crate-agent must learn the v1.1 schema before any
// vault is migrated to it. Until that lands, browsers should only WRITE
// v1.0 docs (via `build()`); read-side v1.1 detection (via `parse()`) is
// safe to ship ahead of the daemon update.

import { toBase64, fromBase64, SALT_LEN } from "./crypto.js";

export const CRATE_PATH = ".crate/crate.json";

const WRAP_IV_LEN = 12;                // AES-GCM nonce
const WRAPPED_KEY_LEN = 32 + 16;       // 32-byte content key + 16-byte GCM tag
const PBKDF2_MIN_ITER = 100_000;       // accept anything ≥ this; current default is 600k

export class CrateJsonError extends Error {
  constructor(message) { super(message); this.name = "CrateJsonError"; }
}

// build returns the JSON bytes for a v1.0 crate.json — the legacy schema
// where master key = PBKDF2(passphrase, salt). Use `buildV11` for new
// vaults that store a wrapped content key + optional recovery slot.
export function build({ salt, identity, createdBy } = {}) {
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_LEN) {
    throw new CrateJsonError(`cratejson.build: salt must be ${SALT_LEN} bytes`);
  }
  const doc = {
    v: 1,
    version: "1.0",
    salt: toBase64(salt),
    created_at: new Date().toISOString(),
  };
  if (identity) doc.identity = identity;
  if (createdBy) doc.created_by = createdBy;
  return new TextEncoder().encode(JSON.stringify(doc, null, 2));
}

// buildV11 returns the JSON bytes for a v1.1 crate.json. `passphraseWrap`
// is required; `recoveryWrap` is optional (omit if the user hasn't enabled
// the recovery credential yet — e.g. opt-in migration of a v1.0 vault that
// only got the passphrase wrap on first conversion).
//
// Each wrap argument: { salt: Uint8Array(16), iv: Uint8Array(12),
//                       ciphertext: Uint8Array(48), iter?: number }.
// kdf is fixed at "PBKDF2-SHA256"; iter defaults to 600000.
export function buildV11({ passphraseWrap, recoveryWrap, identity, createdBy } = {}) {
  if (!passphraseWrap) {
    throw new CrateJsonError("cratejson.buildV11: passphraseWrap required");
  }
  const doc = {
    v: 1,
    version: "1.1",
    passphrase_wrap: wrapToJson(passphraseWrap, "passphrase_wrap"),
    created_at: new Date().toISOString(),
  };
  if (recoveryWrap) {
    doc.recovery_wrap = wrapToJson(recoveryWrap, "recovery_wrap");
  }
  if (identity) doc.identity = identity;
  if (createdBy) doc.created_by = createdBy;
  return new TextEncoder().encode(JSON.stringify(doc, null, 2));
}

function wrapToJson(w, name) {
  if (!(w.salt instanceof Uint8Array) || w.salt.length !== SALT_LEN) {
    throw new CrateJsonError(`cratejson.${name}: salt must be ${SALT_LEN} bytes`);
  }
  if (!(w.iv instanceof Uint8Array) || w.iv.length !== WRAP_IV_LEN) {
    throw new CrateJsonError(`cratejson.${name}: iv must be ${WRAP_IV_LEN} bytes`);
  }
  if (!(w.ciphertext instanceof Uint8Array) || w.ciphertext.length !== WRAPPED_KEY_LEN) {
    throw new CrateJsonError(`cratejson.${name}: ciphertext must be ${WRAPPED_KEY_LEN} bytes (32-byte key + 16-byte GCM tag)`);
  }
  return {
    kdf: "PBKDF2-SHA256",
    iter: w.iter || 600000,
    salt: toBase64(w.salt),
    iv: toBase64(w.iv),
    ct: toBase64(w.ciphertext),
  };
}

// parse validates + returns the parsed Doc. Recognizes BOTH v1.0 and v1.1
// schemas; on success the returned doc carries normalized fields so callers
// don't re-decode base64:
//
//   v1.0:  doc.version === "1.0"
//          doc.saltBytes (Uint8Array 16)
//
//   v1.1:  doc.version === "1.1"
//          doc.passphraseWrap = { kdf, iter, saltBytes, ivBytes, ctBytes }
//          doc.recoveryWrap   = { kdf, iter, saltBytes, ivBytes, ctBytes } | undefined
//
// Throws CrateJsonError on malformed input.
export function parse(bytes) {
  let text;
  if (typeof bytes === "string") {
    text = bytes;
  } else if (bytes instanceof Uint8Array) {
    text = new TextDecoder().decode(bytes);
  } else {
    throw new CrateJsonError("cratejson.parse: input must be string or Uint8Array");
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new CrateJsonError(`cratejson.parse: invalid JSON: ${e.message}`);
  }
  if (doc === null || typeof doc !== "object") {
    throw new CrateJsonError("cratejson.parse: top-level must be an object");
  }
  if (doc.v !== 1) {
    throw new CrateJsonError(`cratejson.parse: unsupported wire-format v=${doc.v} (expected 1)`);
  }

  // Schema detection: presence of passphrase_wrap → v1.1; otherwise v1.0.
  const isV11 = doc.passphrase_wrap && typeof doc.passphrase_wrap === "object";

  if (isV11) {
    if (doc.version && doc.version !== "1.1") {
      throw new CrateJsonError(`cratejson.parse: passphrase_wrap present but version="${doc.version}" (expected "1.1")`);
    }
    doc.version = "1.1";
    doc.passphraseWrap = decodeWrap(doc.passphrase_wrap, "passphrase_wrap");
    if (doc.recovery_wrap) {
      doc.recoveryWrap = decodeWrap(doc.recovery_wrap, "recovery_wrap");
    }
    return doc;
  }

  // v1.0 path
  if (typeof doc.salt !== "string" || doc.salt.length === 0) {
    throw new CrateJsonError("cratejson.parse: salt is missing or empty");
  }
  let saltBytes;
  try {
    saltBytes = fromBase64(doc.salt);
  } catch (e) {
    throw new CrateJsonError(`cratejson.parse: salt base64 decode failed: ${e.message}`);
  }
  if (saltBytes.length !== SALT_LEN) {
    throw new CrateJsonError(`cratejson.parse: salt length ${saltBytes.length}, expected ${SALT_LEN}`);
  }
  doc.saltBytes = saltBytes;
  doc.version = doc.version || "1.0";
  return doc;
}

function decodeWrap(raw, name) {
  if (raw === null || typeof raw !== "object") {
    throw new CrateJsonError(`cratejson.parse: ${name} must be an object`);
  }
  if (raw.kdf && raw.kdf !== "PBKDF2-SHA256") {
    throw new CrateJsonError(`cratejson.parse: ${name}.kdf="${raw.kdf}" not supported (expected PBKDF2-SHA256)`);
  }
  const iter = raw.iter;
  if (!Number.isInteger(iter) || iter < PBKDF2_MIN_ITER) {
    throw new CrateJsonError(`cratejson.parse: ${name}.iter=${iter} too low (minimum ${PBKDF2_MIN_ITER})`);
  }
  let saltBytes, ivBytes, ctBytes;
  try { saltBytes = fromBase64(raw.salt); }
  catch (e) { throw new CrateJsonError(`cratejson.parse: ${name}.salt decode failed: ${e.message}`); }
  if (saltBytes.length !== SALT_LEN) {
    throw new CrateJsonError(`cratejson.parse: ${name}.salt length ${saltBytes.length}, expected ${SALT_LEN}`);
  }
  try { ivBytes = fromBase64(raw.iv); }
  catch (e) { throw new CrateJsonError(`cratejson.parse: ${name}.iv decode failed: ${e.message}`); }
  if (ivBytes.length !== WRAP_IV_LEN) {
    throw new CrateJsonError(`cratejson.parse: ${name}.iv length ${ivBytes.length}, expected ${WRAP_IV_LEN}`);
  }
  try { ctBytes = fromBase64(raw.ct); }
  catch (e) { throw new CrateJsonError(`cratejson.parse: ${name}.ct decode failed: ${e.message}`); }
  if (ctBytes.length !== WRAPPED_KEY_LEN) {
    throw new CrateJsonError(`cratejson.parse: ${name}.ct length ${ctBytes.length}, expected ${WRAPPED_KEY_LEN}`);
  }
  return { kdf: "PBKDF2-SHA256", iter, saltBytes, ivBytes, ctBytes };
}

// shortBrowserFingerprint returns a stable-ish short string describing
// the browser + OS — purely informational, surfaced in `created_by`.
// NOT used for auth; never expand into a real fingerprint surface.
export function shortBrowserFingerprint() {
  const ua = (navigator.userAgent || "").slice(0, 200);
  const platform = navigator.platform || "unknown";
  return `crate-browser/${platform}/${ua.replace(/\s+/g, " ").slice(0, 80)}`;
}
