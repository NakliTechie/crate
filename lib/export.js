// SPDX-License-Identifier: AGPL-3.0-or-later
// Crate folder export — tiered zip download.
//
// Three tiers, chosen automatically by total plaintext size + browser
// capability:
//
// - memory: total <= MEMORY_TIER_LIMIT_BYTES. We decrypt every file, build
//           a zip in memory via client-zip, blob-URL it, and click an <a
//           download>. Works on every browser including iOS Safari.
//
// - stream: total > MEMORY_TIER_LIMIT_BYTES AND showSaveFilePicker is
//           available (Chrome / Edge / Brave / Opera on desktop). We pipe
//           client-zip's streaming Response.body directly into the file
//           the user picks — O(1) memory per file regardless of folder
//           size. The user's bucket can be hundreds of GB and we never
//           hold more than the current file in memory.
//
// - too-large: total > MEMORY_TIER_LIMIT_BYTES AND showSaveFilePicker is
//              missing (Firefox, Safari, mobile). UI shows the
//              crate-agent install prompt — the daemon is the right tool
//              for backups at this size anyway.
//
// `source` shape (matches both folder.js's session and Crate's private
// state, so the same module serves the in-app folder UI and any ESM
// consumer):
//   {
//     manifest:   Manifest instance with materialise() -> Map<path, entry>
//     masterKey:  CryptoKey (AES-GCM, length 256)
//     bucketBase: string ending with '/'
//     region, accessKey, secretKey: bucket sigv4 creds
//   }

import { downloadZip } from "./vendor/client-zip/index.js";
import * as cryptoLib from "./crypto.js";
import * as bucket from "./bucket.js";

const OBJECTS_PREFIX = "objects/";
const MEMORY_TIER_LIMIT_BYTES = 500 * 1024 * 1024; // 500 MB

// planExport walks the manifest once to gather file paths + sizes + total.
// Decides the tier from total + browser capability. Returns synchronously
// usable summary the UI shows the user before they commit.
export function planExport(source, opts = {}) {
  const limit = opts.memoryLimitBytes ?? MEMORY_TIER_LIMIT_BYTES;
  const tree = source.manifest.materialise();
  const files = [];
  let totalBytes = 0;
  for (const [path, entry] of tree.entries()) {
    if (entry.isDir) continue;
    if (!entry.uuid) continue; // shouldn't happen, but skip orphans
    const size = typeof entry.size === "number" ? entry.size : 0;
    files.push({
      path,
      size,
      modified: entry.ts || null,
      uuid: entry.uuid,
      mime: entry.mime || "application/octet-stream",
      data_key_iv: entry.data_key_iv,
      data_key_ct: entry.data_key_ct,
      content_iv: entry.content_iv,
    });
    totalBytes += size;
  }
  // Stable order: alphabetical by path. Makes diffs across exports
  // meaningful and the resulting zip's entry order predictable.
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const hasFsa = typeof window !== "undefined" && typeof window.showSaveFilePicker === "function";
  let tier;
  if (files.length === 0) {
    tier = "empty";
  } else if (totalBytes <= limit) {
    tier = "memory";
  } else if (hasFsa) {
    tier = "stream";
  } else {
    tier = "too-large";
  }
  return {
    tier,
    fileCount: files.length,
    totalBytes,
    files,
    hasFsa,
    memoryLimitBytes: limit,
  };
}

// Internal: decrypt a single object from the bucket. Mirrors what
// folder.js's handleDownload and Crate.read do. Returns Uint8Array of the
// plaintext bytes.
async function readOne(source, fileMeta) {
  const objUrl = source.bucketBase + OBJECTS_PREFIX + fileMeta.uuid;
  const got = await bucket.signedGet({
    url: objUrl,
    region: source.region,
    accessKey: source.accessKey,
    secretKey: source.secretKey,
  });
  if (!got.ok) throw new Error(`export: GET ${fileMeta.uuid} failed (${got.status} ${got.message ?? ""})`);
  if (got.body.length < 12) throw new Error(`export: ciphertext too short for ${fileMeta.uuid}`);
  const iv = got.body.subarray(0, 12);
  const ct = got.body.subarray(12);
  // Pin to the manifest-signed content_iv so a replayed/rolled-back object
  // body is rejected instead of silently written into the backup as stale
  // plaintext — matches crate.js read() + folder.js download/preview
  // (2026-05 audit H1). planExport already carries content_iv on fileMeta.
  if (fileMeta.content_iv) {
    const expected = cryptoLib.fromBase64(fileMeta.content_iv);
    if (!constantTimeIvEqual(iv, expected)) {
      throw new Error(`export: object IV does not match manifest content_iv for ${fileMeta.uuid} (rollback or tamper)`);
    }
  }
  const dataKey = await cryptoLib.unwrapDataKey(
    source.masterKey,
    cryptoLib.fromBase64(fileMeta.data_key_iv),
    cryptoLib.fromBase64(fileMeta.data_key_ct),
    fileMeta.uuid,
  );
  try {
    return await cryptoLib.decrypt(dataKey, iv, ct, new TextEncoder().encode(fileMeta.uuid));
  } finally {
    cryptoLib.zero(dataKey);
  }
}

// runExport executes the export per the plan. `onProgress` is called as
// each file is processed: { phase: 'file', path, bytesDone, totalBytes,
// fileIndex, fileCount }. The signal aborts mid-stream.
export async function runExport(source, plan, opts = {}) {
  const { onProgress, signal } = opts;
  if (plan.tier === "too-large") {
    throw new Error("plan.tier === 'too-large'; runExport refuses to run");
  }
  if (plan.tier === "empty") {
    throw new Error("plan.tier === 'empty'; nothing to export");
  }

  const today = new Date().toISOString().slice(0, 10);
  const suggestedName = `crate-backup-${today}.zip`;

  // Tier 'stream' opens the save picker FIRST so the user picks the
  // destination before we start decrypting bytes. If they cancel here,
  // no work is wasted.
  let writableStream = null;
  if (plan.tier === "stream") {
    const handle = await window.showSaveFilePicker({
      suggestedName,
      types: [{ description: "Zip archive", accept: { "application/zip": [".zip"] } }],
    });
    writableStream = await handle.createWritable();
  }

  // Build an async iterable of {name, input, lastModified} entries for
  // client-zip. We yield one file at a time, decrypting as we go, so the
  // 'stream' tier keeps peak memory at one file regardless of total
  // folder size.
  let bytesDone = 0;
  let fileIndex = 0;
  const totalBytes = plan.totalBytes;
  const fileCount = plan.fileCount;
  const fileList = plan.files;

  async function* iterEntries() {
    for (const meta of fileList) {
      if (signal?.aborted) throw new DOMException("Export aborted", "AbortError");
      const buf = await readOne(source, meta);
      const name = meta.path.replace(/^\/+/, "");
      const lastModified = meta.modified ? new Date(meta.modified) : new Date();
      yield { name, input: buf, lastModified };
      bytesDone += buf.byteLength;
      fileIndex += 1;
      if (onProgress) onProgress({ phase: "file", path: meta.path, bytesDone, totalBytes, fileIndex, fileCount });
    }
  }

  const response = downloadZip(iterEntries());

  if (plan.tier === "stream") {
    try {
      await response.body.pipeTo(writableStream, { signal });
    } catch (e) {
      // pipeTo throws on signal; clean up the writable so the partial
      // file doesn't sit half-written on disk.
      try { await writableStream.abort(e); } catch {}
      throw e;
    }
    if (onProgress) onProgress({ phase: "done", bytesDone, totalBytes, fileIndex, fileCount });
    return { tier: plan.tier, savedAs: suggestedName };
  }

  // tier === 'memory': materialise the zip into a blob + click an <a>.
  const blob = await response.blob();
  if (signal?.aborted) throw new DOMException("Export aborted", "AbortError");
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = suggestedName;
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }
  if (onProgress) onProgress({ phase: "done", bytesDone, totalBytes, fileIndex, fileCount });
  return { tier: plan.tier, downloadedName: suggestedName, bytes: blob.size };
}

// constantTimeIvEqual — length-tolerant constant-time-ish byte compare,
// used to pin a fetched object's leading IV to the manifest-signed
// content_iv. Mirrors the equivalents in crate.js + folder.js (no shared
// export exists yet; kept local so this module stays self-contained).
function constantTimeIvEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
