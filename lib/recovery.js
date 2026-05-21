// SPDX-License-Identifier: AGPL-3.0-or-later
// BIP-39 recovery-phrase encode/decode — 24 words = 256 bits entropy +
// 8 bits checksum = 264 bits = 24 × 11.
//
// Spec: crate-browser-handoff-v1.0.md §"Encryption details":
//   "Recovery phrase: 24 words from BIP-39 English wordlist, encodes 264
//    bits (256 entropy + 8 checksum)"
//
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039.mediawiki
//
// What "recovery" means for Crate (clarifying scope — different from a
// Bitcoin seed phrase):
//   - The phrase is shown ONCE during onboarding for the user to write down.
//   - The phrase encodes the same 256 bits as the salt + a derived key from
//     it (NOT the master key directly — the master key is PBKDF2-derived
//     from passphrase + salt at every session). Loss of the passphrase
//     means the phrase plus your bucket can re-create access via a
//     deterministic re-derivation path documented in §"Recovery flow"
//     (M3.x — UI lands later).
//
// What this file provides at M3:
//   - `entropyToMnemonic(entropy)` — 32 bytes → 24-word phrase
//   - `mnemonicToEntropy(phrase)`  — 24-word phrase → 32 bytes (validates
//                                    checksum; throws on tamper)
//   - `generateMnemonic()`         — fresh 32 random bytes → 24-word phrase

import { BIP39_WORDS } from "./wordlist.js";

// SHA-256 via SubtleCrypto. Keep here (not in crypto.js) so this module
// is self-contained and importable from tests that don't pull in the
// rest of the cryptographic surface.
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

// generateMnemonic returns a fresh 24-word BIP-39 mnemonic.
export async function generateMnemonic() {
  const entropy = crypto.getRandomValues(new Uint8Array(32));
  return entropyToMnemonic(entropy);
}

// entropyToMnemonic converts 32 bytes of entropy into a 24-word phrase.
// Algorithm (BIP-39 §"Generating the mnemonic"):
//   1. Append the first ENT/32 bits of SHA-256(entropy) as checksum.
//   2. Split the combined (ENT + checksum) bits into 11-bit groups.
//   3. Each 11-bit group indexes the wordlist.
// For ENT=256: checksum=8 bits, 24 groups of 11 bits = 264 bits total.
export async function entropyToMnemonic(entropy) {
  if (!(entropy instanceof Uint8Array) || entropy.length !== 32) {
    throw new Error("recovery.entropyToMnemonic: entropy must be 32 bytes");
  }
  const hash = await sha256(entropy);
  const checksumBits = 8;                                // ENT(256)/32
  const checksum = hash[0];                              // first 8 bits of SHA-256
  const bits = new Uint8Array(33);
  bits.set(entropy);
  bits[32] = checksum;
  return bitsToWords(bits, 24, 11);
}

// mnemonicToEntropy converts a 24-word phrase back to the original 32 bytes,
// verifying the BIP-39 checksum. Throws on any malformed input (wrong word
// count, unknown word, checksum mismatch, etc.) — callers should treat any
// throw as "phrase is wrong; ask the user to re-enter."
//
// Whitespace-tolerant; words are normalised to lowercase before lookup.
export async function mnemonicToEntropy(phrase) {
  const words = normalizeMnemonic(phrase);
  if (words.length !== 24) {
    throw new Error(`recovery: mnemonic must be 24 words; got ${words.length}`);
  }
  const indices = new Uint16Array(24);
  for (let i = 0; i < 24; i++) {
    const idx = BIP39_WORDS.indexOf(words[i]);
    if (idx < 0) {
      throw new Error(`recovery: unknown word "${words[i]}" at position ${i + 1}`);
    }
    indices[i] = idx;
  }
  // Reconstruct the 264-bit stream from 24 × 11-bit words.
  const bits = wordsToBits(indices, 11);
  const entropy = bits.slice(0, 32);
  const claimedChecksum = bits[32];
  const hash = await sha256(entropy);
  const expectedChecksum = hash[0];
  if (claimedChecksum !== expectedChecksum) {
    throw new Error("recovery: checksum mismatch — phrase is invalid or mistyped");
  }
  return entropy;
}

// normalizeMnemonic splits on whitespace, lowercases, trims punctuation.
// Returns the array of cleaned words. The original phrase may use hyphens
// (Crate's UI convention) — we treat hyphens as separators.
export function normalizeMnemonic(phrase) {
  if (typeof phrase !== "string") throw new Error("recovery: phrase must be a string");
  return phrase
    .toLowerCase()
    .replace(/[‐-―−_]/g, "-") // normalize unicode dashes to ASCII
    .split(/[\s\-,]+/)
    .map((w) => w.trim())
    .filter((w) => w.length > 0);
}

// --- internal bit-packing helpers -----------------------------------------

// bitsToWords packs `bits` (Uint8Array, big-endian) into `count` groups of
// `groupBits` bits each, returning an array of phrase words via the BIP-39
// wordlist.
function bitsToWords(bits, count, groupBits) {
  const out = [];
  let acc = 0;
  let accBits = 0;
  let outIdx = 0;
  for (const b of bits) {
    acc = (acc << 8) | b;
    accBits += 8;
    while (accBits >= groupBits && outIdx < count) {
      accBits -= groupBits;
      const index = (acc >> accBits) & ((1 << groupBits) - 1);
      out.push(BIP39_WORDS[index]);
      outIdx++;
    }
  }
  return out;
}

// wordsToBits is the inverse — given an array of integer indices (each
// `groupBits` wide), pack them back into a Uint8Array of 8-bit bytes.
// Returns a Uint8Array of length = ceil(count * groupBits / 8).
function wordsToBits(indices, groupBits) {
  const totalBits = indices.length * groupBits;
  const out = new Uint8Array(Math.ceil(totalBits / 8));
  let acc = 0;
  let accBits = 0;
  let outIdx = 0;
  for (let i = 0; i < indices.length; i++) {
    acc = (acc << groupBits) | indices[i];
    accBits += groupBits;
    while (accBits >= 8 && outIdx < out.length) {
      accBits -= 8;
      out[outIdx++] = (acc >> accBits) & 0xff;
    }
  }
  // Any remaining tail bits get left-aligned in the last byte (matches
  // BIP-39 which always pads to a byte boundary anyway — for 256+8 we
  // land exactly on 33 bytes).
  return out;
}

// --- round-trip self-test for the smoke gate -------------------------------

// roundTripCheck is exported so the smoke harness + tests can confirm the
// BIP-39 implementation is reversible without exposing test fixtures.
// Returns { ok: true } on success or { ok: false, reason } on any failure.
export async function roundTripCheck() {
  try {
    const phrase = await generateMnemonic();
    const words = phrase.length === 24 ? phrase : normalizeMnemonic(phrase.join ? phrase.join(" ") : phrase);
    const joined = (Array.isArray(phrase) ? phrase : words).join(" ");
    const entropy = await mnemonicToEntropy(joined);
    const phrase2 = await entropyToMnemonic(entropy);
    const w1 = Array.isArray(phrase) ? phrase : normalizeMnemonic(phrase);
    const w2 = Array.isArray(phrase2) ? phrase2 : normalizeMnemonic(phrase2);
    if (w1.length !== 24 || w2.length !== 24) {
      return { ok: false, reason: `bad length: ${w1.length} vs ${w2.length}` };
    }
    for (let i = 0; i < 24; i++) {
      if (w1[i] !== w2[i]) return { ok: false, reason: `word ${i} mismatch: ${w1[i]} vs ${w2[i]}` };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: String(e) };
  }
}
