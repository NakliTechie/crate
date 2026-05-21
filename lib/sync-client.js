// SPDX-License-Identifier: AGPL-3.0-or-later
// Sync — keeps multiple tabs of the same origin AND multiple devices
// against the same bucket roughly in sync.
//
// Two channels:
//   - BroadcastChannel `crate-sync:{bucketID}` — same-origin cross-tab.
//     Each Crate mutation broadcasts a {type, op, path}; listening tabs
//     refetch the manifest + materialise + fire onChange events on their
//     local Crate instance.
//   - Periodic poll of .crate/manifest.jsonl.enc — cross-device.
//     Default 15s tick. If the manifest's encrypted bytes differ from
//     the last-known, fetch + decrypt + replace + diff against last
//     materialise → fire onChange events for affected paths.
//
// Concurrent-write safety: ETag-conditional PUT with replay-on-412 on
// the write path keeps two tabs from clobbering each other's manifest
// writes. See lib/crate.js::_flushManifest.

import * as bucket from "./bucket.js";
import { Manifest, MANIFEST_PATH } from "./manifest.js";

export const DEFAULT_POLL_INTERVAL_MS = 15_000;

export class SyncClient {
  /**
   * @param {Crate} crate              — open Crate instance
   * @param {object} [opts]
   * @param {number} [opts.pollIntervalMs] — default 15000
   * @param {string} [opts.channelName]    — default `crate-sync:${bucketBase}`
   * @param {object} [opts.logger]         — defaults to console
   */
  constructor(crate, opts = {}) {
    if (!crate) throw new Error("SyncClient: crate required");
    this._crate = crate;
    this._pollIntervalMs = opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const id = crate._bucketBase || "default";
    this._channelName = opts.channelName ?? `crate-sync:${id}`;
    this._logger = opts.logger ?? console;
    this._channel = null;
    this._pollTimer = null;
    this._stopped = false;
    this._lastBytes = null;
    this._lastTree = null;
    this._unsubLocal = crate.onChange((evt) => this._onLocalChange(evt));
  }

  start() {
    if (this._stopped) throw new Error("SyncClient: cannot restart after stop()");
    if (typeof BroadcastChannel === "function") {
      try {
        this._channel = new BroadcastChannel(this._channelName);
        this._channel.onmessage = (e) => this._onRemoteBroadcast(e.data);
      } catch (e) {
        this._logger.warn?.("SyncClient: BroadcastChannel unavailable", e);
      }
    }
    this._lastTree = this._crate._manifest.materialise();
    void this._tick();
    this._schedule();
  }

  stop() {
    this._stopped = true;
    if (this._pollTimer) {
      clearTimeout(this._pollTimer);
      this._pollTimer = null;
    }
    if (this._channel) {
      try { this._channel.close(); } catch {}
      this._channel = null;
    }
    if (this._unsubLocal) {
      this._unsubLocal();
      this._unsubLocal = null;
    }
  }

  // --- internals --------------------------------------------------------

  _schedule() {
    if (this._stopped) return;
    this._pollTimer = setTimeout(() => {
      void this._tick().finally(() => this._schedule());
    }, this._pollIntervalMs);
  }

  async _tick() {
    if (this._stopped) return;
    try {
      await this._pollManifest();
    } catch (e) {
      this._logger.warn?.("SyncClient: poll failed", e);
    }
  }

  async _pollManifest() {
    const r = await bucket.signedGet({
      url: this._crate._bucketBase + MANIFEST_PATH,
      region: this._crate._region,
      accessKey: this._crate._accessKey,
      secretKey: this._crate._secretKey,
    });
    if (!r.ok) return;
    if (this._lastBytes && bytesEqual(this._lastBytes, r.body)) return;

    const fresh = await Manifest.loadFromBytes(r.body, this._crate._masterKey);
    const newTree = fresh.materialise();

    // Mutate the Crate's manifest IN PLACE so every reference (session,
    // folder UI, refresh runner) sees the new state. The write path
    // flushes after every mutation under ETag-conditional PUT, so we
    // know nothing local is unflushed here either.
    this._crate._manifest.events = fresh.events;
    this._crate._manifest._lastSig = fresh._lastSig;

    // Record the new ETag + flushed-count on the SAME object the
    // FolderUI's flushManifest reads. The facade in entrypoint.js
    // points _crate at the session itself, so updating
    // `_crate.manifestETag` here propagates back to the session.
    if ("manifestETag" in this._crate) {
      this._crate.manifestETag = r.etag || null;
    }
    if ("lastFlushedEventCount" in this._crate) {
      this._crate.lastFlushedEventCount = fresh.events.length;
    }

    const oldTree = this._lastTree ?? new Map();
    for (const evt of diffTrees(oldTree, newTree)) {
      this._crate._emit({ ...evt, source: "remote" });
    }
    this._lastBytes = r.body;
    this._lastTree = newTree;
  }

  _onLocalChange(evt) {
    if (this._stopped || !this._channel) return;
    try {
      this._channel.postMessage({
        type: "local-mutation",
        ts: Date.now(),
        op: evt.op,
        path: evt.path ?? evt.to ?? evt.from,
      });
    } catch (e) {
      this._logger.warn?.("SyncClient: broadcast failed", e);
    }
  }

  _onRemoteBroadcast(msg) {
    if (this._stopped) return;
    if (!msg || msg.type !== "local-mutation") return;
    setTimeout(() => { void this._tick(); }, 200);
  }
}

// --- helpers --------------------------------------------------------------

function bytesEqual(a, b) {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// diffTrees compares two materialised maps and returns onChange-shaped events.
// Returned event shapes mirror what Crate.write/remove/move/mkdir emit, so
// the listener doesn't need to distinguish source.
//
//   create: path appears in new but not old
//   update: path in both with different uuid or size
//   delete: path in old but not new
//
// (Moves are detected as a {delete old, create new} pair; v1 doesn't
// try to coalesce.)
function diffTrees(oldTree, newTree) {
  const events = [];
  for (const [path, entry] of newTree) {
    const prev = oldTree.get(path);
    if (!prev) {
      events.push({ op: "create", path, size: entry.size ?? 0 });
    } else if (prev.uuid !== entry.uuid || prev.size !== entry.size) {
      events.push({ op: "update", path, size: entry.size ?? 0 });
    }
  }
  for (const [path] of oldTree) {
    if (!newTree.has(path)) {
      events.push({ op: "delete", path });
    }
  }
  return events;
}
