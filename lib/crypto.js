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
