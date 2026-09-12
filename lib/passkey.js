// SPDX-License-Identifier: AGPL-3.0-or-later
// Passkey unlock — device-local.
//
// A passkey created with the WebAuthn PRF extension yields, on every
// successful assertion, a 32-byte secret that is a function of the
// credential and a salt we choose. We derive a KEK from that secret and
// seal ONE record for the folder on this device:
//   { creds (connection details), masterKey (the content key) }
// The record lives in IndexedDB; the bucket's crate.json is untouched, so
// there is no new slot to keep in sync across devices — a passkey opens
// the folder on the device it was enrolled on (or wherever the platform
// syncs both the passkey and this origin's storage, which is nowhere
// today). Losing the device loses the shortcut, never the folder.
//
// What a passkey unlock does NOT hand the session: the passphrase. So
// Backup actions that need it (credentials file, change passphrase,
// re-key) ask for it; a re-key or passphrase change made in a passkey
// session re-seals the record with the new key.
//
//   enrol(session, label)              → creates the passkey, seals the record
//   listEnrolled()                     → [{ id, label, bucketBase }]
//   unlock()                           → { creds, masterKey, bucketBase, label } via the platform prompt
//   reseal(session)                    → after re-key / passphrase change
//   forget(bucketBase)

import * as cryptoLib from "./crypto.js";
import * as idb from "./idb.js";

const STORE = "prefs";
const LIST_KEY = "passkey:folders";
const REC_PREFIX = "passkey:";
const AAD = new TextEncoder().encode("crate-passkey-record");

export function available() {
  return typeof PublicKeyCredential !== "undefined" && !!navigator.credentials?.create && window.isSecureContext;
}

function b64u(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function unb64u(s) { const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : ""; return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad), (c) => c.charCodeAt(0)); }

async function recKey(bucketBase) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(bucketBase)));
  return REC_PREFIX + Array.from(h.subarray(0, 12), (b) => b.toString(16).padStart(2, "0")).join("");
}

// kekFromPrf: HKDF-SHA256 over the PRF output with the record's salt.
async function kekFromPrf(prfBytes, salt) {
  const k = await crypto.subtle.importKey("raw", prfBytes, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("crate-passkey-kek-v1") }, k, 256);
  return new Uint8Array(bits);
}

// assert runs a WebAuthn assertion with PRF evaluation for `salt`.
// Returns { credentialId, prf } or throws. `ids` limits the prompt.
async function assert(salt, ids = null) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = {
    challenge, rpId: location.hostname, userVerification: "required", timeout: 60_000,
    extensions: { prf: { eval: { first: salt } } },
  };
  if (ids && ids.length) publicKey.allowCredentials = ids.map((id) => ({ type: "public-key", id: unb64u(id) }));
  const cred = await navigator.credentials.get({ publicKey });
  const ext = cred.getClientExtensionResults?.() || {};
  const prf = ext.prf?.results?.first;
  if (!prf) throw new Error("This passkey provider doesn't support the PRF extension, so it can't hold a key.");
  return { credentialId: b64u(cred.rawId), prf: new Uint8Array(prf) };
}

// enrol creates a passkey for this folder on this device and seals the
// record under its PRF secret. `label` is what the landing shows.
export async function enrol(session, label) {
  if (!available()) throw new Error("Passkeys aren't available in this browser.");
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const created = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "Crate", id: location.hostname },
      user: { id: userId, name: label, displayName: label },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      timeout: 60_000,
      extensions: { prf: {} },
    },
  });
  const enabled = created.getClientExtensionResults?.()?.prf?.enabled;
  if (enabled === false) throw new Error("This passkey provider doesn't support the PRF extension, so it can't hold a key.");
  const credentialId = b64u(created.rawId);
  // PRF output is only guaranteed on assertion: assert once now to seal.
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const { prf } = await assert(salt, [credentialId]);
  await sealRecord(session, { credentialId, salt, prf, label });
  cryptoLib.zero(prf);
  return { credentialId };
}

async function sealRecord(session, { credentialId, salt, prf, label }) {
  const kek = await kekFromPrf(prf, salt);
  try {
    const payload = new TextEncoder().encode(JSON.stringify({
      v: 1,
      creds: {
        provider: session.region === "carrier" ? "carrier" : "r2",
        bucket: { name: session.bucket?.name, accountId: session.bucket?.accountId, region: session.bucket?.region || session.region, url: session.bucket?.url },
        credentials: { accessKey: session.accessKey, secretKey: session.secretKey },
      },
      masterKey: b64u(session.masterKey),
    }));
    const { iv, ciphertext } = await cryptoLib.encrypt(kek, payload, AAD);
    await idb.set(STORE, await recKey(session.bucketBase), { v: 1, credentialId, salt, iv, ct: ciphertext, label, bucketBase: session.bucketBase, ts: Date.now() });
    const list = (await idb.get(STORE, LIST_KEY)) || [];
    const next = list.filter((f) => f.bucketBase !== session.bucketBase);
    next.push({ bucketBase: session.bucketBase, label, id: credentialId });
    await idb.set(STORE, LIST_KEY, next);
  } finally {
    cryptoLib.zero(kek);
  }
}

export async function listEnrolled() {
  try { return (await idb.get(STORE, LIST_KEY)) || []; } catch { return []; }
}

export async function forget(bucketBase) {
  try {
    await idb.del(STORE, await recKey(bucketBase));
    const list = (await idb.get(STORE, LIST_KEY)) || [];
    await idb.set(STORE, LIST_KEY, list.filter((f) => f.bucketBase !== bucketBase));
  } catch {}
}

// unlock prompts for any enrolled passkey and opens its record.
export async function unlock() {
  const list = await listEnrolled();
  if (list.length === 0) throw new Error("No passkey is set up for a folder on this device.");
  // One assertion, any enrolled credential; the salt must match the
  // record, so with several folders we ask per folder in turn only if
  // the first prompt's credential is not the one we guessed. Common case:
  // one folder — one prompt.
  const first = list[0];
  const rec = await idb.get(STORE, await recKey(first.bucketBase));
  if (!rec) throw new Error("The passkey record for this folder is missing; set it up again from Backup.");
  const { credentialId, prf } = await assert(rec.salt, list.map((f) => f.id));
  const chosen = list.find((f) => f.id === credentialId) || first;
  const record = chosen.bucketBase === first.bucketBase ? rec : await idb.get(STORE, await recKey(chosen.bucketBase));
  if (!record) throw new Error("The passkey record for this folder is missing; set it up again from Backup.");
  let prfForRecord = prf;
  if (record !== rec) {
    // A different folder's passkey answered; its salt differs — assert again with it.
    cryptoLib.zero(prf);
    ({ prf: prfForRecord } = await assert(record.salt, [record.credentialId]));
  }
  const kek = await kekFromPrf(prfForRecord, record.salt);
  cryptoLib.zero(prfForRecord);
  try {
    const pt = await cryptoLib.decrypt(kek, record.iv, record.ct, AAD);
    const obj = JSON.parse(new TextDecoder().decode(pt));
    return { creds: obj.creds, masterKey: unb64u(obj.masterKey), bucketBase: record.bucketBase, label: record.label };
  } catch (e) {
    throw new Error("This passkey no longer opens the folder (the key changed, or the record is damaged). Unlock with your passphrase and set the passkey up again.", { cause: e });
  } finally {
    cryptoLib.zero(kek);
  }
}

// reseal re-encrypts the record with the session's current key without a
// new prompt — used after a re-key. Needs a fresh assertion for the PRF,
// so it does prompt once.
export async function reseal(session) {
  const rec = await idb.get(STORE, await recKey(session.bucketBase));
  if (!rec) return false;
  const { prf } = await assert(rec.salt, [rec.credentialId]);
  await sealRecord(session, { credentialId: rec.credentialId, salt: rec.salt, prf, label: rec.label });
  cryptoLib.zero(prf);
  return true;
}

export async function isEnrolled(bucketBase) {
  try { return !!(await idb.get(STORE, await recKey(bucketBase))); } catch { return false; }
}
