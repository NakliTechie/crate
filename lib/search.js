// SPDX-License-Identifier: AGPL-3.0-or-later
// Search inside files: a per-device inverted index over text-like files.
//
// Built on demand in the tab (fetch + decrypt each text file ≤ TEXT_CAP,
// tokenise, map term → uuids), then stored in IndexedDB *encrypted under
// the folder's content key* — the bucket never sees it and the disk holds
// ciphertext. Incremental: a rebuild only reads files whose (uuid, ts)
// changed and drops uuids no longer in the tree. Cross-device merging is
// deliberately avoided: every device builds its own.
//
//   const idx = await loadIndex(session)          // null when none yet
//   const idx = await buildIndex(session, { onProgress })
//   const hits = queryIndex(idx, "invoice 2026")  // [{ uuid, path, snippet }]

import * as cryptoLib from "./crypto.js";
import * as idb from "./idb.js";
import { readObject } from "./read.js";

const STORE = "prefs";                 // small, keyed by "search:" + bucketBase
const KEY_PREFIX = "search:";
const TEXT_CAP = 2 * 1024 * 1024;      // per file
const TEXT_EXT = new Set(["txt","md","markdown","json","xml","yaml","yml","csv","tsv","log","ini","conf","toml","html","htm","css","js","jsx","ts","tsx","py","go","rs","rb","java","c","h","cpp","hpp","sql","sh","swift","kt","php","lua","r","tex","rst","org"]);

export function isTextEntry(path, entry) {
  const mime = (entry?.mime || "").toLowerCase();
  if (mime.startsWith("text/")) return true;
  if (/json|xml|yaml|javascript|x-sh/.test(mime)) return true;
  const ext = path.toLowerCase().split(".").pop();
  return TEXT_EXT.has(ext);
}

// candidates lists the text files in the tree (path, entry).
export function candidates(manifest) {
  const out = [];
  for (const [path, entry] of manifest.materialise().entries()) {
    if (entry.isDir || !entry.uuid) continue;
    if (!isTextEntry(path, entry)) continue;
    if ((entry.size || 0) > TEXT_CAP) continue;
    out.push({ path, entry });
  }
  return out;
}

// tokenise: lowercase words of 2+ letters/digits, unicode-aware; the
// first 200 KB of text is more than enough to find a document by.
export function tokenise(text) {
  const seen = new Set();
  const re = /[\p{L}\p{N}][\p{L}\p{N}_'-]{1,}/gu;
  let m;
  const slice = text.length > 200_000 ? text.slice(0, 200_000) : text;
  while ((m = re.exec(slice)) !== null) seen.add(m[0].toLowerCase());
  return seen;
}

function emptyIndex() {
  return { v: 1, built: 0, files: {}, terms: {} }; // files: uuid → {path, ts, head}; terms: term → [uuid]
}

async function storageKey(bucketBase) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(bucketBase)));
  return KEY_PREFIX + Array.from(h.subarray(0, 12), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function loadIndex(session) {
  try {
    const rec = await idb.get(STORE, await storageKey(session.bucketBase));
    if (!rec || !(rec.ct instanceof Uint8Array) || !(rec.iv instanceof Uint8Array)) return null;
    const pt = await cryptoLib.decrypt(session.masterKey, rec.iv, rec.ct, new TextEncoder().encode("crate-search-index"));
    const idx = JSON.parse(new TextDecoder().decode(pt));
    return idx?.v === 1 ? idx : null;
  } catch {
    return null; // wrong key (folder re-keyed) or absent → rebuild when asked
  }
}

async function saveIndex(session, idx) {
  const pt = new TextEncoder().encode(JSON.stringify(idx));
  const { iv, ciphertext } = await cryptoLib.encrypt(session.masterKey, pt, new TextEncoder().encode("crate-search-index"));
  await idb.set(STORE, await storageKey(session.bucketBase), { iv, ct: ciphertext, ts: Date.now() });
}

export async function clearIndex(session) {
  try { await idb.del(STORE, await storageKey(session.bucketBase)); } catch {}
}

// buildIndex (re)builds incrementally. onProgress({ done, total, path }).
export async function buildIndex(session, { onProgress, signal, previous = null } = {}) {
  const idx = previous && previous.v === 1 ? previous : emptyIndex();
  const wanted = candidates(session.manifest);
  const wantedUuids = new Set(wanted.map((c) => c.entry.uuid));

  // Drop files that left the tree, and their term postings.
  for (const uuid of Object.keys(idx.files)) {
    if (!wantedUuids.has(uuid)) delete idx.files[uuid];
  }
  const todo = wanted.filter(({ path, entry }) => {
    const f = idx.files[entry.uuid];
    return !f || f.ts !== entry.ts || f.path !== path;
  });
  // Rebuild postings from scratch for changed files: remove their uuid
  // from every term first (cheap enough at these sizes).
  const changed = new Set(todo.map((c) => c.entry.uuid));
  for (const [term, list] of Object.entries(idx.terms)) {
    const kept = list.filter((u) => wantedUuids.has(u) && !changed.has(u));
    if (kept.length) idx.terms[term] = kept; else delete idx.terms[term];
  }

  let done = 0;
  for (const { path, entry } of todo) {
    if (signal?.aborted) throw new DOMException("Indexing cancelled", "AbortError");
    let text = "";
    try {
      const bytes = await readObject(session, entry);
      text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    } catch (e) {
      console.warn("search: skip", path, e?.message || e);
      done += 1; continue;
    }
    for (const term of tokenise(text)) {
      (idx.terms[term] ||= []).push(entry.uuid);
    }
    idx.files[entry.uuid] = { path, ts: entry.ts, head: text.slice(0, 160).replace(/\s+/g, " ") };
    done += 1;
    if (onProgress) onProgress({ done, total: todo.length, path });
    await new Promise((r) => setTimeout(r, 0)); // let the UI breathe
  }
  idx.built = Date.now();
  await saveIndex(session, idx);
  return idx;
}

// queryIndex: every word must match (prefix match on terms), ranked by
// how many terms each file matched fully; returns [{uuid, path, snippet}].
export function queryIndex(idx, query) {
  if (!idx) return [];
  const words = [...tokenise(query)];
  if (words.length === 0) return [];
  const termKeys = Object.keys(idx.terms);
  let candidatesSet = null;
  const score = new Map();
  for (const w of words) {
    const hits = new Set();
    for (const t of termKeys) {
      if (t === w || t.startsWith(w)) for (const u of idx.terms[t]) { hits.add(u); score.set(u, (score.get(u) || 0) + (t === w ? 2 : 1)); }
    }
    candidatesSet = candidatesSet ? new Set([...candidatesSet].filter((u) => hits.has(u))) : hits;
    if (candidatesSet.size === 0) return [];
  }
  return [...candidatesSet]
    .filter((u) => idx.files[u])
    .sort((a, b) => (score.get(b) || 0) - (score.get(a) || 0))
    .map((u) => ({ uuid: u, path: idx.files[u].path, snippet: idx.files[u].head }));
}

// stale: is the index behind the tree (new/changed text files)?
export function staleCount(idx, manifest) {
  if (!idx) return candidates(manifest).length;
  return candidates(manifest).filter(({ path, entry }) => {
    const f = idx.files[entry.uuid];
    return !f || f.ts !== entry.ts || f.path !== path;
  }).length;
}
