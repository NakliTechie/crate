// SPDX-License-Identifier: AGPL-3.0-or-later
// Writer + reader for .crate/crate.json — the bucket-level metadata blob
// the browser writes on first-time setup and every paired surface reads
// to align on the canonical salt + version.
//
// Wire format is LOCKED — must match what the daemon's
// crate-agent/internal/cratejson/cratejson.go already parses
// (deployed in crate-agent@62872b9):
//
//   {
//     "v": 1,
//     "version": "1.0",
//     "salt": "<base64 std; 16 bytes>",
//     "identity": { /* opaque to daemon at v1.0 */ },
//     "created_at": "<rfc3339>",
//     "created_by": "<browser-fingerprint>"
//   }
//
// `v` and `salt` are required; everything else is optional + forward-compat.

import { toBase64, fromBase64, SALT_LEN } from "./crypto.js";

// CRATE_PATH is the canonical key in the bucket.
export const CRATE_PATH = ".crate/crate.json";

// Doc shape — what's stored in the bucket.
export class CrateJsonError extends Error {
  constructor(message) { super(message); this.name = "CrateJsonError"; }
}

// build returns the JSON bytes ready to PUT to the bucket.
// `salt` MUST be 16 bytes; `createdBy` is a short fingerprint string
// (e.g. UA + device hint) for audit.
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

// parse validates + returns the parsed Doc. Throws CrateJsonError on
// malformed input.
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
    throw new CrateJsonError(`cratejson.parse: unsupported version v=${doc.v} (expected 1)`);
  }
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
  doc.saltBytes = saltBytes; // convenience: caller doesn't need to re-decode
  return doc;
}

// shortBrowserFingerprint returns a stable-ish short string describing
// the browser + OS — purely informational, surfaced in `created_by`.
// NOT used for auth; never expand into a real fingerprint surface.
export function shortBrowserFingerprint() {
  const ua = (navigator.userAgent || "").slice(0, 200);
  const platform = navigator.platform || "unknown";
  return `crate-browser/${platform}/${ua.replace(/\s+/g, " ").slice(0, 80)}`;
}
