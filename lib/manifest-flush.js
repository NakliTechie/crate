// SPDX-License-Identifier: AGPL-3.0-or-later
// Shared manifest-flush logic.
//
// Two surfaces flush the manifest back to the bucket:
//   - Crate._flushManifest (the ESM API surface; lib/crate.js)
//   - FolderUI.flushManifest (the wizard's folder UI; lib/folder.js)
//
// Both need to: re-encrypt the in-memory Manifest under the master key,
// PUT it back to .crate/manifest.jsonl.enc with If-Match against the
// last-known ETag, retry-with-replay on 412 (a peer wrote between our
// last GET and this PUT), validate the re-fetched manifest against the
// rollback anchor before trusting it, and advance the anchor on success.
//
// Until this module landed, they were near-duplicate copies that drifted
// (folder.js was missing the anchor advance + the 412 anchor check until
// v1.0.1's follow-up patch). Single source of truth here so future
// security or behaviour changes can't quietly diverge.
//
// State object shape (mutated in place — readers must see the updates):
//
//   {
//     manifest,                // Manifest instance (mutated in place on 412 replay)
//     masterKey,               // Uint8Array
//     bucketBase,              // string — bucket base URL with trailing slash
//     region, accessKey, secretKey,  // strings — for sigv4
//     manifestETag,            // string | null  ← READ + WRITTEN
//     lastFlushedEventCount,   // number          ← READ + WRITTEN
//   }
//
// The Crate class wraps its `_`-prefixed instance properties in a small
// getter/setter adapter so manifestETag / lastFlushedEventCount writes
// propagate back to this._manifestETag / this._lastFlushedEventCount.
// The FolderUI's `session` object already matches the unprefixed shape
// natively — no adapter needed.

import * as bucket from "./bucket.js";
import { Manifest, MANIFEST_PATH } from "./manifest.js";
import * as anchor from "./anchor.js";

const DEFAULT_MAX_RETRIES = 3;

// flushManifest — push the in-memory manifest to the bucket.
//
// opts:
//   maxRetries    — number of 412-conflict re-attempts (default 3)
//   errorFactory  — (message: string) => Error, used for non-anchor failures.
//                   Callers pass `(m) => new CrateError(m)` or similar so
//                   their type stays the throw type.
//
// Throws:
//   ManifestRollbackError if the 412 re-fetch yields a manifest that
//     fails anchor validation (truncation or fork).
//   errorFactory(message) on PUT failure / network error / retry exhaustion.
export async function flushManifest(state, opts = {}) {
  const maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES;
  const errorFactory = opts.errorFactory ?? ((m) => new Error(m));

  // Snapshot pending events at the start. On a 412 retry, the local
  // manifest is replaced by the fresh remote one — we replay these
  // appended-locally events on top of the new chain.
  let localEventsToReplay = state.manifest.events.slice(
    state.lastFlushedEventCount ?? 0,
  );

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const bytes = await state.manifest.encryptToBytes(state.masterKey);
    const put = await bucket.signedPut({
      url: state.bucketBase + MANIFEST_PATH,
      body: bytes,
      contentType: "application/octet-stream",
      ifMatch: state.manifestETag,
      region: state.region,
      accessKey: state.accessKey,
      secretKey: state.secretKey,
    });
    if (put.ok) {
      state.manifestETag = put.etag || null;
      state.lastFlushedEventCount = state.manifest.events.length;
      // Advance the rollback anchor — we just successfully extended the
      // remote chain. Any future loader on this device must extend at
      // least this far. Storage failure is non-fatal (next flush retries;
      // worst case the next load re-TOFUs at the current tail).
      try {
        await anchor.saveAnchor(state.bucketBase, state.manifest.tail());
      } catch (_e) { /* anchor storage best-effort */ }
      return;
    }
    if (put.preconditionFailed && attempt < maxRetries) {
      // Re-fetch and replay. The fresh manifest replaces ours under the
      // shared reference — both Crate's _manifest and any FolderUI
      // session.manifest are the same Manifest object, so the in-place
      // mutation below is observed by every reader.
      const got = await bucket.signedGet({
        url: state.bucketBase + MANIFEST_PATH,
        region: state.region,
        accessKey: state.accessKey,
        secretKey: state.secretKey,
      });
      if (!got.ok) {
        throw errorFactory(`flushManifest: re-GET after 412 failed (${got.status})`);
      }
      const fresh = await Manifest.loadFromBytes(got.body, state.masterKey);

      // Validate the re-fetched manifest against the rollback anchor
      // BEFORE trusting it. A bucket-only attacker who races a PUT to
      // induce our 412 could serve an older valid manifest in the
      // re-GET — AES-GCM and the prev_sig chain both pass on a valid
      // prefix, so this is the layer that catches the swap. See the
      // 2026-05 security audit, finding H2.
      const prior = await anchor.loadAnchor(state.bucketBase);
      const v = anchor.validate(fresh.events, prior);
      if (!v.ok) {
        throw new anchor.ManifestRollbackError(v.reason, v.detail);
      }

      // Mutate the manifest in place so any shared references see it.
      state.manifest.events = fresh.events;
      state.manifest._lastSig = fresh._lastSig;

      // Replay pending events. Manifest.append() recomputes prev_sig + sig
      // against the new chain — we strip the stale crypto fields first.
      for (const e of localEventsToReplay) {
        const partial = { ...e };
        delete partial.v;
        delete partial.ts;
        delete partial.prev_sig;
        delete partial.sig;
        await state.manifest.append(partial, state.masterKey);
      }
      state.manifestETag = got.etag || null;
      // localEventsToReplay stays valid for the next iteration — same
      // content; they'll re-append with newer prev_sigs against
      // whatever the next 412 hands us.
      continue;
    }
    throw errorFactory(`flushManifest: PUT failed (${put.status})`);
  }
  throw errorFactory("flushManifest: too many ETag-conflict retries");
}
