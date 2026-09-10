// SPDX-License-Identifier: AGPL-3.0-or-later
// AES-256-GCM + PBKDF2 + HMAC-SHA256 over SubtleCrypto. All primitives
// match the daemon's wire format so the two surfaces interoperate
// byte-for-byte. Full design rationale in docs/encryption-model.md.
//
// Design choices:
//   - PBKDF2 iterations: 600,000 (OWASP 2023 recommendation).
//   - Master key:    deriveBits → extractable Uint8Array. Explicit
//                    zeroing on close(). We need the raw bytes for
//                    HMAC-SHA256 signing of manifest events.
//   - Payload AEAD:  AES-256-GCM. Per-file random 12-byte IV.
//   - Key wrapping:  AES-256-GCM (NOT AES-KW). Fewer primitives; fresh
//                    nonce per wrap is fine for our volumes; SubtleCrypto's
//                    wrapKey adds complexity we don't need (we treat
//                    data keys as raw bytes throughout).
//   - Manifest sig:  HMAC-SHA256(masterKey, canonical_event_json). Each
//                    event carries prev_sig — tamper-evident chain.

const PBKDF2_ITERATIONS = 600_000;
const MASTER_KEY_LEN = 32; // 256 bits
const DATA_KEY_LEN = 32;
const IV_LEN = 12;          // AES-GCM nonce
export const SALT_LEN = 16; // .crate/crate.json salt

// --- base64 helpers (URL-safe + standard tolerated symmetrically) ---------

export function toBase64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function fromBase64(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- random helpers --------------------------------------------------------

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}
export function randomSalt() { return randomBytes(SALT_LEN); }
export function randomIV() { return randomBytes(IV_LEN); }
export function randomDataKey() { return randomBytes(DATA_KEY_LEN); }

// zero overwrites a typed-array buffer. Use after a key/passphrase is no
// longer needed. (Cannot wipe a JS string — references to the original
// literal may persist anywhere; for strings the best mitigation is to
// drop the reference and let GC reuse the buffer.)
export function zero(buf) {
  if (!buf) return;
  if (ArrayBuffer.isView(buf)) {
    new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).fill(0);
  } else if (buf instanceof ArrayBuffer) {
    new Uint8Array(buf).fill(0);
  }
}

// --- PBKDF2 master-key derivation -----------------------------------------

// deriveMasterKey returns 32 raw bytes derived via PBKDF2-SHA256 with the
// spec-mandated parameters. Match the daemon's internal/kdf/kdf.go exactly
// (Iterations=600_000, KeyLen=32). Caller is responsible for zeroing the
// returned bytes when done.
export async function deriveMasterKey(passphrase, salt) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("crypto.deriveMasterKey: passphrase is empty");
  }
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_LEN) {
    throw new Error(`crypto.deriveMasterKey: salt must be ${SALT_LEN} bytes`);
  }
  const passKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    passKey,
    MASTER_KEY_LEN * 8,
  );
  return new Uint8Array(bits);
}

// --- KEK derivation + key wrapping (v1.1 schema) --------------------------
//
// In v1.1, the master key is no longer derived directly from the passphrase
// — it's a random "content key" stored encrypted under one or more
// key-encryption-keys (KEKs):
//   - passphrase-KEK = PBKDF2(UTF-8(passphrase), passphrase_wrap.salt)
//   - recovery-KEK   = PBKDF2(bip39_entropy,     recovery_wrap.salt)
// The same content key is wrapped under each KEK separately and stored in
// .crate/crate.json. Any one KEK can unwrap it; rotating the passphrase
// re-wraps the (unchanged) content key under a fresh passphrase-KEK
// without re-encrypting any file. See docs/encryption-model.md.

const KEK_LEN = 32;            // 256-bit AES key
const WRAPPED_KEY_LEN = MASTER_KEY_LEN + 16; // 32-byte key + 16-byte GCM tag

// deriveKEK runs PBKDF2-SHA256 over arbitrary input bytes and returns 32
// raw bytes. `secret` is a Uint8Array; the caller decides whether to feed
// UTF-8(passphrase) or BIP-39 entropy. `iter` defaults to the v1.0/v1.1
// standard 600k so wrap cost matches master-derivation cost.
export async function deriveKEK(secret, salt, iter = PBKDF2_ITERATIONS) {
  if (!(secret instanceof Uint8Array) || secret.length === 0) {
    throw new Error("crypto.deriveKEK: secret must be a non-empty Uint8Array");
  }
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_LEN) {
    throw new Error(`crypto.deriveKEK: salt must be ${SALT_LEN} bytes`);
  }
  const baseKey = await crypto.subtle.importKey(
    "raw", secret, { name: "PBKDF2" }, false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    baseKey, KEK_LEN * 8,
  );
  return new Uint8Array(bits);
}

// derivePassphraseKEK derives the v1.1 passphrase-KEK from a passphrase
// string + salt. Bytes-for-bytes equivalent to deriveMasterKey for the
// same inputs — kept distinct so call sites read at the right semantic
// level ("derive a KEK" vs "derive the master key").
export async function derivePassphraseKEK(passphrase, salt, iter = PBKDF2_ITERATIONS) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("crypto.derivePassphraseKEK: passphrase is empty");
  }
  return deriveKEK(new TextEncoder().encode(passphrase), salt, iter);
}

// deriveRecoveryKEK derives the v1.1 recovery-KEK from the 32 bytes of
// entropy the BIP-39 phrase encodes (see lib/recovery.js).
export async function deriveRecoveryKEK(entropy, salt, iter = PBKDF2_ITERATIONS) {
  if (!(entropy instanceof Uint8Array) || entropy.length !== 32) {
    throw new Error("crypto.deriveRecoveryKEK: entropy must be 32 bytes");
  }
  return deriveKEK(entropy, salt, iter);
}

// wrapKey seals a 32-byte content key under a KEK using AES-256-GCM with
// a fresh 12-byte IV. Returns { iv, ciphertext } — ciphertext = 32-byte
// wrapped key + 16-byte GCM tag (48 bytes total).
//
// No AAD: the wrap is self-contained — the bytes that come out are
// authenticated by the KEK alone. Matches the .crate/crate.json storage
// shape (each wrap slot is independently decryptable iff you have its KEK).
export async function wrapKey(kekBytes, keyBytes) {
  if (!(kekBytes instanceof Uint8Array) || kekBytes.length !== KEK_LEN) {
    throw new Error(`crypto.wrapKey: KEK must be ${KEK_LEN} bytes`);
  }
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== MASTER_KEY_LEN) {
    throw new Error(`crypto.wrapKey: key must be ${MASTER_KEY_LEN} bytes`);
  }
  return encrypt(kekBytes, keyBytes);
}

// unwrapKey is the inverse of wrapKey. Throws on AES-GCM auth failure
// (wrong KEK, tampered ciphertext, wrong IV). Returns 32 raw bytes —
// the recovered content/master key.
export async function unwrapKey(kekBytes, iv, ciphertext) {
  if (!(kekBytes instanceof Uint8Array) || kekBytes.length !== KEK_LEN) {
    throw new Error(`crypto.unwrapKey: KEK must be ${KEK_LEN} bytes`);
  }
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== WRAPPED_KEY_LEN) {
    throw new Error(`crypto.unwrapKey: ciphertext must be ${WRAPPED_KEY_LEN} bytes (32-byte key + 16-byte GCM tag)`);
  }
  const plaintext = await decrypt(kekBytes, iv, ciphertext);
  if (plaintext.length !== MASTER_KEY_LEN) {
    throw new Error(`crypto.unwrapKey: decrypted key wrong length ${plaintext.length}`);
  }
  return plaintext;
}

// --- AES-256-GCM payload encryption ---------------------------------------

async function importAesGcm(keyBytes, usages = ["encrypt", "decrypt"]) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 32) {
    throw new Error("crypto: AES-GCM key must be 32 bytes");
  }
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, usages);
}

// encrypt seals plaintext under key with a fresh random 12-byte IV.
// Returns { iv, ciphertext } as Uint8Arrays. aad MAY be Uint8Array | undefined
// (caller binds the path / object UUID as AAD to prevent ciphertext-shuffle).
export async function encrypt(keyBytes, plaintext, aad) {
  const k = await importAesGcm(keyBytes);
  const iv = randomIV();
  const params = { name: "AES-GCM", iv };
  if (aad) params.additionalData = aad;
  const ct = await crypto.subtle.encrypt(
    params,
    k,
    plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext),
  );
  return { iv, ciphertext: new Uint8Array(ct) };
}

// decrypt unseals ciphertext produced by encrypt(). Throws on auth-tag
// mismatch (wrong key, tampered ciphertext, wrong aad, wrong iv).
export async function decrypt(keyBytes, iv, ciphertext, aad) {
  const k = await importAesGcm(keyBytes);
  const params = { name: "AES-GCM", iv };
  if (aad) params.additionalData = aad;
  const pt = await crypto.subtle.decrypt(
    params,
    k,
    ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext),
  );
  return new Uint8Array(pt);
}

// --- per-file data-key wrapping (AES-GCM under master key) ----------------

// wrapDataKey returns { iv, ciphertext } of the data-key sealed under
// masterKey. fileUuid is bound as AAD.
export async function wrapDataKey(masterKeyBytes, dataKey, fileUuid) {
  const aad = fileUuid ? new TextEncoder().encode(fileUuid) : undefined;
  return encrypt(masterKeyBytes, dataKey, aad);
}

// unwrapDataKey is the inverse — same fileUuid AAD required.
export async function unwrapDataKey(masterKeyBytes, iv, ciphertext, fileUuid) {
  const aad = fileUuid ? new TextEncoder().encode(fileUuid) : undefined;
  return decrypt(masterKeyBytes, iv, ciphertext, aad);
}

// --- object payload: chunked AES-GCM (v2) + single-blob (v1) ---------------
//
// v1 object body (legacy, still readable):
//     IV(12) || AES-GCM(dataKey, plaintext, AAD = uuid)
//
// v2 object body (chunked — every write since this landed):
//     chunk_0 || chunk_1 || … || chunk_{n-1}
//     chunk_i = IV_i(12) || AES-GCM(dataKey, plaintext_i, AAD_i)
//     AAD_i   = utf8("<uuid>:<base64(IV_0)>:<i>:<n>")
//
// A file is v2 iff its manifest entry carries `chunk_size`; that field
// is inside the HMAC-signed event, so the format discriminator cannot be
// forged from the bucket. n = ceil(size / chunk_size), min 1 — an empty
// file is one authenticated empty chunk, so "no chunks" is never valid
// and truncation to nothing is detectable.
//
// Why every field in the AAD is load-bearing:
//   uuid      — cross-file splice (chunk from another file) fails.
//   IV_0      — cross-VERSION splice fails. IV_0 is random per write and
//               is the manifest-signed content_iv, so a chunk from an
//               older version of the same file at the same index is
//               bound to a different IV_0 and will not authenticate.
//               Same-uuid same-index reuse across versions is exactly
//               the attack single-blob AAD=uuid did not need to defend.
//   i         — reorder fails.
//   n         — truncation / extension fails even before the length
//               check, and a chunk sealed under a different total is
//               rejected.
// Chunk 0's own IV *is* IV_0 — it authenticates itself under its own
// nonce as AAD, which is well-defined and keeps `content_iv` meaning
// "the object's leading 12 bytes" for both formats, so the rollback
// anchor (2026-05 audit H1) reads identically for v1 and v2.
//
// Cross-surface contract: crate-agent must implement the same framing
// byte-for-byte. Chunk plaintext size is carried in the manifest, never
// assumed, so the two surfaces may pick different defaults.

export const CHUNK_SIZE = 8 * 1024 * 1024; // plaintext bytes per chunk
const GCM_TAG_LEN = 16;
const CHUNK_OVERHEAD = IV_LEN + GCM_TAG_LEN;

// chunkCount is ceil(size / chunkSize), minimum 1.
export function chunkCount(size, chunkSize) {
  if (!Number.isInteger(size) || size < 0) throw new Error("crypto: size must be a non-negative integer");
  if (!Number.isInteger(chunkSize) || chunkSize <= 0) throw new Error("crypto: chunkSize must be a positive integer");
  return Math.max(1, Math.ceil(size / chunkSize));
}

// chunkAAD is the canonical per-chunk AAD. Kept as plain ASCII so the
// daemon can reproduce it without a binary encoding spec.
export function chunkAAD(uuid, contentIv, index, total) {
  return new TextEncoder().encode(`${uuid}:${toBase64(contentIv)}:${index}:${total}`);
}

// sealObject encrypts plaintext into a v2 object body. Returns
// { contentIv, body, chunkSize }; contentIv is chunk 0's IV and must be
// recorded in the manifest as content_iv alongside chunkSize.
export async function sealObject(dataKey, plaintext, uuid, chunkSize = CHUNK_SIZE) {
  if (typeof uuid !== "string" || uuid.length === 0) throw new Error("crypto: sealObject requires uuid");
  const pt = plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext);
  const total = chunkCount(pt.length, chunkSize);
  const k = await importAesGcm(dataKey, ["encrypt"]);
  const contentIv = randomIV();
  const body = new Uint8Array(pt.length + total * CHUNK_OVERHEAD);
  let off = 0;
  for (let i = 0; i < total; i++) {
    const iv = i === 0 ? contentIv : randomIV();
    const slice = pt.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, pt.length));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: chunkAAD(uuid, contentIv, i, total) },
      k, slice,
    ));
    body.set(iv, off); off += IV_LEN;
    body.set(ct, off); off += ct.length;
  }
  return { contentIv, body, chunkSize };
}

// openObject decrypts an object body using its manifest entry, dispatching
// on `entry.chunk_size` (v2) vs absent (v1). Enforces, before any
// decryption, that the body's leading IV equals the manifest-signed
// content_iv (rollback anchor) and — for v2 — that the body length is
// exactly what `size` + `chunk_size` predict. Throws on any mismatch.
// The caller owns dataKey and zeroes it.
export async function openObject(dataKey, body, entry) {
  if (!(body instanceof Uint8Array)) body = new Uint8Array(body);
  if (body.length < IV_LEN) throw new Error("crypto: ciphertext too short (missing IV)");
  const uuid = entry.uuid;
  if (typeof uuid !== "string" || uuid.length === 0) throw new Error("crypto: openObject requires entry.uuid");
  const leadingIv = body.subarray(0, IV_LEN);

  if (entry.chunk_size == null) {
    // v1: single blob. content_iv is optional only because pre-audit
    // manifests may lack it; when present it is mandatory to match.
    if (entry.content_iv) {
      if (!constantTimeBytesEqual(leadingIv, fromBase64(entry.content_iv))) {
        throw new Error("crypto: object IV does not match manifest content_iv (rollback or tamper)");
      }
    }
    return decrypt(dataKey, leadingIv, body.subarray(IV_LEN), new TextEncoder().encode(uuid));
  }

  // v2: chunked. Every field below comes from the signed manifest.
  const chunkSize = entry.chunk_size;
  const size = entry.size;
  if (!Number.isInteger(chunkSize) || chunkSize <= 0) throw new Error("crypto: manifest chunk_size invalid");
  if (!Number.isInteger(size) || size < 0) throw new Error("crypto: manifest size invalid");
  if (typeof entry.content_iv !== "string") throw new Error("crypto: chunked entry missing content_iv");
  const contentIv = fromBase64(entry.content_iv);
  if (!constantTimeBytesEqual(leadingIv, contentIv)) {
    throw new Error("crypto: object IV does not match manifest content_iv (rollback or tamper)");
  }
  const total = chunkCount(size, chunkSize);
  if (body.length !== size + total * CHUNK_OVERHEAD) {
    throw new Error(`crypto: object length ${body.length} does not match manifest (size ${size}, ${total} chunks)`);
  }

  const k = await importAesGcm(dataKey, ["decrypt"]);
  const out = new Uint8Array(size);
  let off = 0, ptOff = 0;
  for (let i = 0; i < total; i++) {
    const ptLen = Math.min(chunkSize, size - ptOff);
    const iv = body.subarray(off, off + IV_LEN); off += IV_LEN;
    const ct = body.subarray(off, off + ptLen + GCM_TAG_LEN); off += ptLen + GCM_TAG_LEN;
    let pt;
    try {
      pt = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: chunkAAD(uuid, contentIv, i, total) },
        k, ct,
      ));
    } catch {
      throw new Error(`crypto: chunk ${i} of ${total} failed authentication`);
    }
    if (pt.length !== ptLen) throw new Error(`crypto: chunk ${i} decrypted to ${pt.length} bytes, expected ${ptLen}`);
    out.set(pt, ptOff); ptOff += ptLen;
  }
  return out;
}

// constantTimeBytesEqual is a length-tolerant constant-time-ish byte
// comparison. subtle.timingSafeEqual is Node-only; for browsers we use
// the standard length-check + XOR-fold pattern. Exported so every site
// that pins a fetched IV to a manifest-signed value shares one copy.
export function constantTimeBytesEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- HMAC-SHA256 (manifest signing) ---------------------------------------

// hmacSign returns HMAC-SHA256(masterKey, message) as a Uint8Array.
export async function hmacSign(masterKeyBytes, message) {
  const k = await crypto.subtle.importKey(
    "raw",
    masterKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const msg = typeof message === "string"
    ? new TextEncoder().encode(message)
    : (message instanceof Uint8Array ? message : new Uint8Array(message));
  const sig = await crypto.subtle.sign("HMAC", k, msg);
  return new Uint8Array(sig);
}

// hmacVerify validates a tag against (masterKey, message). Constant-time
// comparison via SubtleCrypto.verify.
export async function hmacVerify(masterKeyBytes, message, tag) {
  const k = await crypto.subtle.importKey(
    "raw",
    masterKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const msg = typeof message === "string"
    ? new TextEncoder().encode(message)
    : (message instanceof Uint8Array ? message : new Uint8Array(message));
  return crypto.subtle.verify(
    "HMAC",
    k,
    tag instanceof Uint8Array ? tag : new Uint8Array(tag),
    msg,
  );
}

// --- ULID helper (for file uuids in the manifest) -------------------------

const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// newULID returns a 26-char Crockford-base32 ULID — 48-bit timestamp +
// 80-bit randomness. Same shape as Go's oklog/ulid + the daemon's puller +
// the cf-worker's bucket-proxy.
export function newULID() {
  const ts = Date.now();
  const bytes = new Uint8Array(16);
  bytes[0] = Math.floor(ts / 0x010000000000) & 0xff;
  bytes[1] = Math.floor(ts / 0x000100000000) & 0xff;
  bytes[2] = Math.floor(ts / 0x000001000000) & 0xff;
  bytes[3] = Math.floor(ts / 0x000000010000) & 0xff;
  bytes[4] = Math.floor(ts / 0x000000000100) & 0xff;
  bytes[5] = ts & 0xff;
  crypto.getRandomValues(bytes.subarray(6));
  let s = "", acc = 0, accBits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    accBits += 8;
    while (accBits >= 5) {
      accBits -= 5;
      s += ULID_ALPHABET[(acc >> accBits) & 0x1f];
    }
  }
  if (accBits > 0) s += ULID_ALPHABET[(acc << (5 - accBits)) & 0x1f];
  return s.slice(0, 26);
}

// --- canonical JSON for deterministic signing ------------------------------

// canonicalJSON produces a deterministic UTF-8 byte string for an object,
// suitable as the input to HMAC. Sorts keys lexicographically at every
// level so a verifier can reconstruct the same bytes without ambiguity.
// Subset of JCS / RFC 8785 — enough for our flat manifest events.
export function canonicalJSON(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJSON).join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k]));
  return "{" + parts.join(",") + "}";
}

// --- SHA-256 hex (convenience for content addresses / etag verification) --

export async function sha256Hex(data) {
  const bytes = typeof data === "string"
    ? new TextEncoder().encode(data)
    : (data instanceof Uint8Array ? data : new Uint8Array(data));
  const h = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(h);
  let s = "";
  for (let i = 0; i < arr.length; i++) s += arr[i].toString(16).padStart(2, "0");
  return s;
}
