// SPDX-License-Identifier: AGPL-3.0-or-later
// Full re-key of a folder: a fresh content key, every file's data key
// unwrapped with the old key and re-wrapped under the new one, the whole
// manifest re-signed under it with a trailing `rekey` event (generation
// + 1), and crate.json rewritten with a passphrase slot under the new
// key. Ciphertext objects are untouched. The recovery slot cannot be
// carried (its entropy is not held), so callers offer a new phrase.
//
// Order: manifest first (If-Match), then crate.json (If-Match). If the
// second write fails the old manifest is written back, so the bucket
// never holds a manifest and a key file that disagree. Other devices
// see the re-signed chain as a fork at their anchor; lib/anchor.js
// accepts it because the generation went up (they still need the
// passphrase to unwrap the new key — a bucket-only attacker cannot).
//
// Shared by Crate.rekey() and the folder's Backup → Re-key folder.

import * as cryptoLib from "./crypto.js";
import * as bucket from "./bucket.js";
import * as anchor from "./anchor.js";
import * as offline from "./offline.js";
import { writeKeySlots } from "./vault.js";
import { Manifest, MANIFEST_PATH, rekeyEvent } from "./manifest.js";

export async function rekeyFolder({
  bucketBase, region, accessKey, secretKey,
  masterKey, manifest, manifestETag = null, crateJson, crateJsonETag = null, passphrase,
} = {}) {
  if (typeof passphrase !== "string" || passphrase.length === 0) throw new Error("rekey: passphrase required");
  if (!(masterKey instanceof Uint8Array) || !manifest) throw new Error("rekey: open session required");
  const oldKey = masterKey;
  const newKey = cryptoLib.randomBytes(32);
  const next = new Manifest();
  for (const e of manifest.events) {
    const { v, prev_sig, sig, ...partial } = e;
    if (partial.op === "create" && partial.data_key_ct && partial.data_key_iv) {
      const dk = await cryptoLib.unwrapDataKey(oldKey, cryptoLib.fromBase64(partial.data_key_iv), cryptoLib.fromBase64(partial.data_key_ct), partial.uuid);
      try {
        const w = await cryptoLib.wrapDataKey(newKey, dk, partial.uuid);
        partial.data_key_iv = cryptoLib.toBase64(w.iv);
        partial.data_key_ct = cryptoLib.toBase64(w.ciphertext);
      } finally {
        cryptoLib.zero(dk);
      }
    }
    await next.append(partial, newKey);
  }
  await next.append(rekeyEvent({ generation: manifest.generation() + 1 }), newKey);

  const creds = { region, accessKey, secretKey };
  const oldManifestBytes = await manifest.encryptToBytes(oldKey);
  const newManifestBytes = await next.encryptToBytes(newKey);
  const putMan = await bucket.signedPut({
    url: bucketBase + MANIFEST_PATH, body: newManifestBytes, contentType: "application/octet-stream",
    ifMatch: manifestETag || undefined, ...creds,
  });
  if (!putMan.ok) {
    cryptoLib.zero(newKey);
    throw new Error(putMan.status === 412
      ? "the folder changed on another device — reopen and try again"
      : `rekey: write manifest failed (${putMan.status} ${putMan.code}: ${putMan.message})`);
  }
  let sealed;
  try {
    sealed = await writeKeySlots({
      bucketBase, ...creds, crateJson, crateJsonETag, masterKey: newKey,
      passphrase, recoveryEntropy: null, dropRecovery: true,
    });
  } catch (e) {
    const undo = await bucket.signedPut({
      url: bucketBase + MANIFEST_PATH, body: oldManifestBytes, contentType: "application/octet-stream",
      ifMatch: putMan.etag || undefined, ...creds,
    });
    cryptoLib.zero(newKey);
    throw new Error(`rekey: key file write failed (${e.message}); ${undo.ok ? "manifest restored" : "MANIFEST NOT RESTORED — reopen with the old passphrase and retry"}`, { cause: e });
  }
  await anchor.saveAnchor(bucketBase, next.tail());
  void offline.remember(bucketBase, { crateJson: sealed.bytes, manifest: newManifestBytes, manifestETag: putMan.etag || null });
  cryptoLib.zero(oldKey);
  return {
    masterKey: newKey, manifest: next, manifestETag: putMan.etag || null,
    crateJson: sealed.crateJson, crateJsonETag: sealed.crateJsonETag,
  };
}
