// SPDX-License-Identifier: AGPL-3.0-or-later
// The v1.1 key slots of .crate/crate.json, in one place.
//
//   content key  — 32 random bytes; every file's data key is wrapped
//                  under it and the manifest is signed with it. It is what
//                  the rest of the code calls `masterKey`.
//   passphrase_wrap — the content key sealed under
//                  PBKDF2(passphrase, salt). Always present.
//   recovery_wrap   — the content key sealed under PBKDF2(entropy, salt),
//                  where `entropy` is the 32 bytes a 24-word BIP-39 phrase
//                  encodes (lib/recovery.js). Present when the user kept
//                  a recovery phrase; addable later (enableRecovery).
//
// Either slot alone recovers the content key, so a lost passphrase is
// survivable when the phrase was written down — and setting a new
// passphrase is a re-wrap, not a re-encrypt (docs/encryption-model.md).
//
//   sealVault({ passphrase, recoveryEntropy? })
//     → { contentKey, crateJsonBytes, passphraseSalt }
//   openVault(doc, { passphrase } | { recoveryEntropy })
//     → contentKey        (throws VaultError on the wrong credential)
//   v1.0 docs open through openVault too (content key = PBKDF2 master key).

import * as cryptoLib from "./crypto.js";
import * as cratejson from "./cratejson.js";
import * as bucket from "./bucket.js";

export class VaultError extends Error {
  constructor(message, { wrongCredential = false } = {}) {
    super(message);
    this.name = "VaultError";
    this.wrongCredential = wrongCredential;
  }
}

// wrapUnder derives a KEK from `secretBytes` with a fresh salt and seals
// the content key under it. Returns the slot shape cratejson.buildV11 takes.
async function wrapUnder(secretBytes, contentKey) {
  const salt = cryptoLib.randomSalt();
  const kek = await cryptoLib.deriveKEK(secretBytes, salt);
  try {
    const { iv, ciphertext } = await cryptoLib.wrapKey(kek, contentKey);
    return { salt, iv, ciphertext };
  } finally {
    cryptoLib.zero(kek);
  }
}

// sealVault mints a fresh content key and the crate.json bytes that
// carry it. The caller owns `contentKey` (zero it on failure paths).
export async function sealVault({ passphrase, recoveryEntropy = null, identity, createdBy } = {}) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new VaultError("sealVault: passphrase required");
  }
  if (recoveryEntropy !== null && (!(recoveryEntropy instanceof Uint8Array) || recoveryEntropy.length !== 32)) {
    throw new VaultError("sealVault: recoveryEntropy must be 32 bytes when given");
  }
  const contentKey = cryptoLib.randomBytes(32);
  const passphraseWrap = await wrapUnder(new TextEncoder().encode(passphrase), contentKey);
  const recoveryWrap = recoveryEntropy ? await wrapUnder(recoveryEntropy, contentKey) : undefined;
  const crateJsonBytes = cratejson.buildV11({ passphraseWrap, recoveryWrap, identity, createdBy });
  return { contentKey, crateJsonBytes, passphraseSalt: passphraseWrap.salt };
}

// openVault recovers the content key from a parsed crate.json with either
// credential. A wrong credential throws VaultError{wrongCredential:true};
// anything else (no recovery slot on this vault, malformed doc) throws a
// plain VaultError.
export async function openVault(doc, { passphrase = null, recoveryEntropy = null } = {}) {
  if (!doc || typeof doc !== "object") throw new VaultError("openVault: doc required");
  if (doc.version !== "1.1") {
    // v1.0: the master key *is* PBKDF2(passphrase, salt). No recovery slot.
    if (!passphrase) throw new VaultError("openVault: this folder has no recovery phrase (v1.0 vault)");
    return cryptoLib.deriveMasterKey(passphrase, doc.saltBytes);
  }
  let slot, secret, what;
  if (passphrase) {
    slot = doc.passphraseWrap; secret = new TextEncoder().encode(passphrase); what = "passphrase";
  } else if (recoveryEntropy) {
    if (!doc.recoveryWrap) throw new VaultError("openVault: this folder has no recovery phrase");
    slot = doc.recoveryWrap; secret = recoveryEntropy; what = "recovery phrase";
  } else {
    throw new VaultError("openVault: passphrase or recoveryEntropy required");
  }
  const kek = await cryptoLib.deriveKEK(secret, slot.saltBytes, slot.iter);
  try {
    return await cryptoLib.unwrapKey(kek, slot.ivBytes, slot.ctBytes);
  } catch (e) {
    throw new VaultError(`openVault: wrong ${what} (${what.replace(" ", "_")} unwrap failed)`, { wrongCredential: true });
  } finally {
    cryptoLib.zero(kek);
  }
}

// rewrapVault re-seals an already-open v1.1 content key under new
// credentials — the primitive behind "set a new passphrase" and "enable
// recovery". Pass the slots to (re)write; an omitted slot is carried over
// from `doc` unchanged. Returns new crate.json bytes. A v1.0 vault is not
// re-wrapped here: its "content key" is PBKDF2 of the old passphrase, so
// migrating it means minting a fresh key (see enableRecovery, T1 phase 6).
export async function rewrapVault(doc, contentKey, { passphrase = null, recoveryEntropy = null, identity, createdBy } = {}) {
  if (!(contentKey instanceof Uint8Array) || contentKey.length !== 32) {
    throw new VaultError("rewrapVault: contentKey must be 32 bytes");
  }
  if (!doc || doc.version !== "1.1") throw new VaultError("rewrapVault: only v1.1 vaults can be re-wrapped");
  const carry = (w) => (w ? { salt: w.saltBytes, iv: w.ivBytes, ciphertext: w.ctBytes, iter: w.iter } : undefined);
  const passphraseWrap = passphrase
    ? await wrapUnder(new TextEncoder().encode(passphrase), contentKey)
    : carry(doc.passphraseWrap);
  const recoveryWrap = recoveryEntropy
    ? await wrapUnder(recoveryEntropy, contentKey)
    : carry(doc.recoveryWrap);
  return cratejson.buildV11({
    passphraseWrap, recoveryWrap,
    identity: identity ?? doc.identity,
    createdBy: createdBy ?? doc.created_by,
  });
}

// migrateV10 turns a v1.0 doc into v1.1 bytes without changing the key:
// the PBKDF2-derived master key becomes the content key, wrapped under
// the (same) passphrase and, when given, the recovery entropy. Nothing
// in the bucket is re-encrypted and an already-paired daemon keeps its
// key. The trade: a later passphrase change on this folder does not
// revoke someone who holds the old passphrase *and* the old crate.json
// (they can still derive the key); a full re-key is a separate, heavier
// operation. Recorded in docs/encryption-model.md.
export async function migrateV10(doc, masterKey, { passphrase, recoveryEntropy = null, createdBy } = {}) {
  if (!doc || doc.version === "1.1") throw new VaultError("migrateV10: not a v1.0 vault");
  if (typeof passphrase !== "string" || passphrase.length === 0) throw new VaultError("migrateV10: passphrase required");
  if (!(masterKey instanceof Uint8Array) || masterKey.length !== 32) throw new VaultError("migrateV10: masterKey must be 32 bytes");
  const passphraseWrap = await wrapUnder(new TextEncoder().encode(passphrase), masterKey);
  const recoveryWrap = recoveryEntropy ? await wrapUnder(recoveryEntropy, masterKey) : undefined;
  return cratejson.buildV11({ passphraseWrap, recoveryWrap, identity: doc.identity, createdBy: createdBy ?? doc.created_by });
}

// writeKeySlots re-seals the open content key with the requested slots and
// writes .crate/crate.json with If-Match on the copy last read, so two
// devices changing credentials at once cannot silently clobber each
// other. Returns { crateJson, crateJsonETag } for the caller to adopt.
// A v1.0 vault needs `passphrase` (the current one) to become v1.1.
export async function writeKeySlots({
  bucketBase, region, accessKey, secretKey,
  crateJson, crateJsonETag = null, masterKey,
  passphrase = null, recoveryEntropy = null, createdBy,
} = {}) {
  if (!crateJson) throw new VaultError("writeKeySlots: crateJson required");
  const bytes = crateJson.version === "1.1"
    ? await rewrapVault(crateJson, masterKey, { passphrase, recoveryEntropy, createdBy })
    : await migrateV10(crateJson, masterKey, { passphrase, recoveryEntropy, createdBy });
  const put = await bucket.signedPut({
    url: bucketBase + cratejson.CRATE_PATH,
    body: bytes, contentType: "application/json",
    ifMatch: crateJsonETag || undefined,
    region, accessKey, secretKey,
  });
  if (!put.ok) {
    throw new VaultError(put.status === 412
      ? "the folder's key file changed on another device — reopen the folder and try again"
      : `write .crate/crate.json failed (${put.status} ${put.code}: ${put.message})`);
  }
  return { crateJson: cratejson.parse(bytes), crateJsonETag: put.etag || null };
}
