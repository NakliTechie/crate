// SPDX-License-Identifier: AGPL-3.0-or-later
// Crate credentials file format — v1.
//
// A `.crate-creds` file bundles the four bucket-identifying / accessing
// strings (account ID, bucket name, access key, secret key) into a
// single artifact encrypted under the user's passphrase. The user
// downloads this at first-time setup; on every subsequent unlock they
// pick the file + type the passphrase. Two clicks instead of five.
//
// The file is purely a CLIENT artifact — never stored on the bucket.
// Same encryption primitives as the master-key derivation
// (PBKDF2-SHA256 / 600k iter / AES-256-GCM), independent salt per file.
// Threat model in docs/encryption-model.md.
//
// Wire shape (the file you download is exactly this JSON, no wrapper):
//
//   {
//     "v":     1,
//     "type":  "crate-creds",
//     "hint":  "<bucket-name>",                  // plaintext, for UI display only
//     "kdf":   { "algo": "PBKDF2-SHA256", "iter": 600000 },
//     "salt":  "<base64 16 bytes>",              // independent of bucket salt
//     "iv":    "<base64 12 bytes>",
//     "ct":    "<base64 AES-256-GCM(plaintext-creds)>"
//   }
//
// The encrypted plaintext is canonical JSON of:
//
//   {
//     "v":          1,
//     "provider":   "r2",                          // future: "b2","hetzner","aws-s3"
//     "bucket":     { "name", "accountId", "region" },
//     "credentials":{ "accessKey", "secretKey" }
//   }

import * as cryptoLib from "./crypto.js";

export const FILE_VERSION = 1;
export const FILE_TYPE = "crate-creds";

export class CredsFileError extends Error {
  constructor(message) { super(message); this.name = "CredsFileError"; }
}

// pack returns a Uint8Array of UTF-8-encoded JSON for the file format
// above. The wrapped plaintext is canonicalised so byte-equal inputs
// produce identical ciphertexts when given the same passphrase + salt.
//
// `creds` shape:
//   { provider, bucket: { name, accountId, region }, credentials: { accessKey, secretKey } }
export async function pack(creds, passphrase) {
  if (!creds?.bucket?.name) throw new CredsFileError("pack: creds.bucket.name required");
  if (!creds?.bucket?.accountId) throw new CredsFileError("pack: creds.bucket.accountId required");
  if (!creds?.credentials?.accessKey) throw new CredsFileError("pack: creds.credentials.accessKey required");
  if (!creds?.credentials?.secretKey) throw new CredsFileError("pack: creds.credentials.secretKey required");
  if (!passphrase) throw new CredsFileError("pack: passphrase required");

  const inner = {
    v: FILE_VERSION,
    provider: creds.provider || "r2",
    bucket: {
      name: creds.bucket.name,
      accountId: creds.bucket.accountId,
      region: creds.bucket.region || "auto",
    },
    credentials: {
      accessKey: creds.credentials.accessKey,
      secretKey: creds.credentials.secretKey,
    },
  };
  const innerBytes = new TextEncoder().encode(cryptoLib.canonicalJSON(inner));

  const salt = cryptoLib.randomSalt();
  const fileKey = await cryptoLib.deriveMasterKey(passphrase, salt);
  try {
    // No AAD here — the encrypted blob is the entire payload; there's
    // nothing meaningful to bind. The hint field is plaintext metadata
    // that helps the UI label the file but isn't security-critical.
    const sealed = await cryptoLib.encrypt(fileKey, innerBytes, undefined);
    const envelope = {
      v: FILE_VERSION,
      type: FILE_TYPE,
      hint: creds.bucket.name,
      kdf: { algo: "PBKDF2-SHA256", iter: 600000 },
      salt: cryptoLib.toBase64(salt),
      iv: cryptoLib.toBase64(sealed.iv),
      ct: cryptoLib.toBase64(sealed.ciphertext),
    };
    return new TextEncoder().encode(JSON.stringify(envelope, null, 2) + "\n");
  } finally {
    cryptoLib.zero(fileKey);
  }
}

// unpack takes file bytes (Uint8Array, ArrayBuffer, or string) + the
// passphrase, validates the envelope, decrypts the inner creds, and
// returns the same shape pack() accepts. Throws CredsFileError on:
//   - malformed JSON
//   - wrong file type / version
//   - wrong passphrase (AES-GCM auth tag mismatch)
//   - corrupt ciphertext (auth tag mismatch)
export async function unpack(input, passphrase) {
  if (!passphrase) throw new CredsFileError("unpack: passphrase required");

  let text;
  if (typeof input === "string") text = input;
  else if (input instanceof ArrayBuffer) text = new TextDecoder().decode(input);
  else if (input instanceof Uint8Array) text = new TextDecoder().decode(input);
  else throw new CredsFileError("unpack: input must be string, ArrayBuffer, or Uint8Array");

  let envelope;
  try { envelope = JSON.parse(text.trim()); }
  catch (e) { throw new CredsFileError("unpack: not valid JSON"); }

  if (envelope?.type !== FILE_TYPE) {
    throw new CredsFileError(`unpack: not a Crate credentials file (type=${envelope?.type ?? "?"})`);
  }
  if (envelope.v !== FILE_VERSION) {
    throw new CredsFileError(`unpack: unsupported file version ${envelope.v} (this build reads v${FILE_VERSION})`);
  }
  for (const k of ["salt", "iv", "ct"]) {
    if (typeof envelope[k] !== "string") {
      throw new CredsFileError(`unpack: missing field ${k}`);
    }
  }

  const salt = cryptoLib.fromBase64(envelope.salt);
  const iv = cryptoLib.fromBase64(envelope.iv);
  const ct = cryptoLib.fromBase64(envelope.ct);

  const fileKey = await cryptoLib.deriveMasterKey(passphrase, salt);
  try {
    let plaintextBytes;
    try {
      plaintextBytes = await cryptoLib.decrypt(fileKey, iv, ct, undefined);
    } catch (e) {
      // AES-GCM auth-tag failure means wrong passphrase OR tampered file.
      throw new CredsFileError("Wrong passphrase, or the credentials file is corrupt.");
    }
    let inner;
    try {
      inner = JSON.parse(new TextDecoder().decode(plaintextBytes));
    } catch (e) {
      throw new CredsFileError("unpack: decrypted payload is not valid JSON");
    }
    // Shape-check the inner; forward-compat tolerant on extra fields.
    if (inner?.v !== FILE_VERSION) {
      throw new CredsFileError(`unpack: unsupported inner version ${inner?.v}`);
    }
    if (!inner?.bucket?.name || !inner?.bucket?.accountId) {
      throw new CredsFileError("unpack: inner missing bucket.{name,accountId}");
    }
    if (!inner?.credentials?.accessKey || !inner?.credentials?.secretKey) {
      throw new CredsFileError("unpack: inner missing credentials");
    }
    return {
      provider: inner.provider || "r2",
      bucket: {
        name: inner.bucket.name,
        accountId: inner.bucket.accountId,
        region: inner.bucket.region || "auto",
      },
      credentials: {
        accessKey: inner.credentials.accessKey,
        secretKey: inner.credentials.secretKey,
      },
    };
  } finally {
    cryptoLib.zero(fileKey);
  }
}

// peekHint reads only the plaintext `hint` field (bucket name) without
// touching the passphrase. Useful for showing "Welcome back to <hint>"
// on the unlock screen before the user types the passphrase.
// Returns null on malformed input.
export function peekHint(input) {
  let text;
  try {
    if (typeof input === "string") text = input;
    else text = new TextDecoder().decode(input);
    const envelope = JSON.parse(text.trim());
    if (envelope?.type !== FILE_TYPE) return null;
    return typeof envelope.hint === "string" ? envelope.hint : null;
  } catch {
    return null;
  }
}

// suggestedFilename returns the conventional download filename for a
// creds file: "<bucket-name>.crate-creds". Sanitises the bucket name
// just in case (bucket names are already DNS-1123 so it's safe).
export function suggestedFilename(bucketName) {
  const safe = String(bucketName || "crate").replace(/[^a-z0-9_.-]/gi, "_");
  return `${safe}.crate-creds`;
}
