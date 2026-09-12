// SPDX-License-Identifier: AGPL-3.0-or-later
// Per-file share links.
//
//   https://crate.naklios.dev/#share=<base64url(JSON)>
//
// The fragment never leaves the browser (it is not sent in HTTP requests).
// It carries everything a recipient needs to read ONE file and nothing
// that reaches any other file:
//   - a presigned GET URL for objects/{uuid} (sig-v4 query auth on R2/S3,
//     or the carrier's ?share=1&exp&sig) that stops working at `exp`;
//   - the file's own data key (unwrapped by the owner's tab), the
//     manifest-signed content IV, chunk size, uuid — what openObject needs.
//
// What a link is NOT: it is not a grant on the folder, it cannot be
// upgraded, and it does not expose the master key. What it IS: anyone who
// has it can read that file until `exp` (7 days at most), and the data
// key stays known to them for good, so a *changed* file's new bytes are
// also readable through a fresh URL — revoke by rotating the bucket
// token / carrier secret, or Delete forever. Links sit in browser history
// like any URL. All of this is said on the share dialog.

import * as cryptoLib from "./crypto.js";
import * as bucket from "./bucket.js";
import { presignUrl } from "./sigv4.js";

export const SHARE_TTL = Object.freeze([
  { label: "1 hour", seconds: 3600 },
  { label: "1 day", seconds: 86400 },
  { label: "7 days", seconds: 7 * 86400 },
]);
const OBJECTS_PREFIX = "objects/";

function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64url(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// objectShareUrl presigns a GET on objects/{uuid} for `seconds`.
export async function objectShareUrl({ bucketBase, region, accessKey, secretKey, uuid, seconds }) {
  const url = bucketBase + OBJECTS_PREFIX + uuid;
  const exp = Date.now() + seconds * 1000;
  if (bucket.isCarrier(region)) {
    const u = new URL(url);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secretKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const canonical = ["SHARE", u.pathname, String(exp)].join("\n");
    const sig = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical))), (b) => b.toString(16).padStart(2, "0")).join("");
    u.searchParams.set("share", "1");
    u.searchParams.set("exp", String(exp));
    u.searchParams.set("sig", sig);
    return { url: u.toString(), exp };
  }
  return { url: await presignUrl({ method: "GET", url, region, accessKey, secretKey, expiresSeconds: seconds }), exp };
}

// mintShare builds the link for one manifest entry. `session` is the
// folder session (bucketBase, region, keys, masterKey); `entry` is the
// materialised manifest entry; `origin` is where the recipient page lives.
export async function mintShare({ session, entry, name, seconds, origin }) {
  if (!entry?.uuid) throw new Error("share: entry has no uuid");
  const dataKey = await cryptoLib.unwrapDataKey(
    session.masterKey,
    cryptoLib.fromBase64(entry.data_key_iv),
    cryptoLib.fromBase64(entry.data_key_ct),
    entry.uuid,
  );
  try {
    const { url, exp } = await objectShareUrl({
      bucketBase: session.bucketBase, region: session.region,
      accessKey: session.accessKey, secretKey: session.secretKey,
      uuid: entry.uuid, seconds,
    });
    const payload = {
      v: 1,
      n: name,
      m: entry.mime || "application/octet-stream",
      s: entry.size ?? 0,
      u: entry.uuid,
      k: b64url(dataKey),
      iv: entry.content_iv,
      cs: entry.chunk_size ?? null,
      c: entry.compression || null,
      ss: entry.stored_size ?? null,
      exp,
      url,
    };
    const frag = b64url(new TextEncoder().encode(JSON.stringify(payload)));
    return { link: `${origin}/#share=${frag}`, exp };
  } finally {
    cryptoLib.zero(dataKey);
  }
}

// parseShare decodes a fragment payload; throws on anything malformed.
export function parseShare(fragment) {
  const m = String(fragment || "").match(/^#?share=([A-Za-z0-9_-]+)$/);
  if (!m) throw new Error("share: not a share link");
  let p;
  try { p = JSON.parse(new TextDecoder().decode(unb64url(m[1]))); } catch { throw new Error("share: link is damaged"); }
  if (p?.v !== 1 || typeof p.url !== "string" || typeof p.k !== "string" || typeof p.u !== "string" || typeof p.iv !== "string") {
    throw new Error("share: link is damaged");
  }
  return {
    name: String(p.n || "file"), mime: String(p.m || "application/octet-stream"), size: Number(p.s) || 0,
    uuid: p.u, key: unb64url(p.k), contentIv: p.iv, chunkSize: p.cs ?? undefined, compression: p.c || undefined, storedSize: p.ss ?? undefined, exp: Number(p.exp) || 0, url: p.url,
  };
}

// fetchShared downloads and decrypts the shared file. Returns plaintext.
export async function fetchShared(share, { signal } = {}) {
  if (share.exp && Date.now() > share.exp) throw new Error("This link has expired.");
  let res;
  try {
    res = await fetch(share.url, { method: "GET", signal, mode: "cors" });
  } catch (e) {
    if (e?.name === "AbortError") throw e;
    throw new Error("Couldn't reach the storage this file lives in.");
  }
  if (res.status === 403 || res.status === 401) throw new Error("This link has expired or was revoked.");
  if (res.status === 404) throw new Error("This file is no longer there.");
  if (!res.ok) throw new Error(`Storage answered ${res.status}.`);
  const body = new Uint8Array(await res.arrayBuffer());
  try {
    return await cryptoLib.openObject(share.key, body, { uuid: share.uuid, content_iv: share.contentIv, chunk_size: share.chunkSize, size: share.size, compression: share.compression, stored_size: share.storedSize });
  } catch (e) {
    throw new Error("The file's data doesn't match this link (it may have been replaced).");
  } finally {
    cryptoLib.zero(share.key);
  }
}
