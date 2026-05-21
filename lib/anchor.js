// SPDX-License-Identifier: AGPL-3.0-or-later
// Manifest rollback / truncation anchor — closes the 2026-05 audit's H2
// finding on the browser side.
//
// Threat model: a bucket-only attacker (anyone with write access to the R2
// bucket, but NOT the passphrase or master key) can replay an older
// .crate/manifest.jsonl.enc. AES-GCM authenticates with the unchanged
// master key, and the prev_sig chain over the older prefix is still valid
// — so without external state, the browser silently accepts a rolled-back
// view of the folder. Newer files vanish; deleted files reappear.
//
// Defence: persist a "tail anchor" {count, lastSig} locally. Every load
// of the manifest checks that the loaded manifest extends (or matches) the
// anchor. Append-only is enforced — anchor.count only ever grows.
//
//   no anchor              → TOFU: anchor whatever the bucket serves
//   loaded.count <  anchor → REJECT: truncation
//   loaded.count >= anchor → check events[anchor.count-1].sig matches
//                            anchor.lastSig. Mismatch → REJECT: fork.
//                            Match → accept + advance anchor.
//
// Storage: IndexedDB primary (per-device, survives across tabs +
// reloads); sessionStorage fallback (tab-scoped) when IndexedDB is
// unavailable (private browsing, storage blocked). The two stores hold
// the same shape — first-load TOFU re-anchors on either.
//
// Anchor key: SHA-256(bucketBase) as 16-byte-prefix hex. Same hash on
// browser + daemon would let the two share an anchor; we don't share
// across surfaces today (the daemon has its own state.db row), but the
// keying scheme is identical so a future cross-surface anchor protocol
// can collapse the two.

import * as idb from "./idb.js";

const STORE = "anchors";
const SESSION_PREFIX = "crate:anchor:";

// computeAnchorKey returns a stable per-bucket key. Uses SHA-256(bucketBase)
// truncated to 16 bytes (32 hex chars) — long enough to avoid collision in a
// device's bucket set, short enough to read at a glance.
export async function computeAnchorKey(bucketBase) {
  if (!bucketBase || typeof bucketBase !== "string") {
    throw new Error("anchor: bucketBase required");
  }
  const bytes = new TextEncoder().encode(bucketBase);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = [...new Uint8Array(digest).slice(0, 16)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hex;
}

// loadAnchor returns the persisted anchor for bucketBase, or null if absent.
// Tries IndexedDB first, falls back to sessionStorage. Any storage error
// resolves to null (treated as "no anchor" so first-load TOFU kicks in
// rather than failing the open call).
export async function loadAnchor(bucketBase) {
  const key = await computeAnchorKey(bucketBase);
  // IndexedDB primary.
  try {
    const v = await idb.get(STORE, key);
    if (v && typeof v.count === "number" && typeof v.lastSig === "string") {
      return { count: v.count, lastSig: v.lastSig, source: "idb" };
    }
  } catch (_e) {
    // Fall through to sessionStorage.
  }
  // sessionStorage fallback (tab-scoped).
  try {
    const raw = sessionStorage.getItem(SESSION_PREFIX + key);
    if (raw) {
      const v = JSON.parse(raw);
      if (v && typeof v.count === "number" && typeof v.lastSig === "string") {
        return { count: v.count, lastSig: v.lastSig, source: "session" };
      }
    }
  } catch (_e) {
    // No storage available at all.
  }
  return null;
}

// saveAnchor persists the anchor for bucketBase. Writes to both stores so
// that a tab that started with IndexedDB working but later loses it (rare)
// still has the sessionStorage copy. Either store failing is non-fatal —
// the next anchor write retries; the worst case is a re-TOFU on next load.
export async function saveAnchor(bucketBase, anchor) {
  if (!anchor || typeof anchor.count !== "number" || typeof anchor.lastSig !== "string") {
    throw new Error("anchor: anchor must be {count, lastSig}");
  }
  const key = await computeAnchorKey(bucketBase);
  const payload = { count: anchor.count, lastSig: anchor.lastSig, ts: Date.now() };
  // IndexedDB primary.
  try {
    await idb.set(STORE, key, payload);
  } catch (_e) {
    // Continue to sessionStorage even if IDB failed.
  }
  // sessionStorage fallback (also written, so a fresh tab seeing IDB
  // succeed has a session-scoped copy as belt-and-braces).
  try {
    sessionStorage.setItem(SESSION_PREFIX + key, JSON.stringify(payload));
  } catch (_e) {
    // Both failed — accept; next call retries.
  }
}

// clearAnchor removes the anchor for bucketBase. Called from Lock /
// reset paths so a re-onboarded bucket on the same device gets a fresh
// TOFU rather than a stale anchor from a prior session.
export async function clearAnchor(bucketBase) {
  const key = await computeAnchorKey(bucketBase);
  try { await idb.del(STORE, key); } catch (_e) {}
  try { sessionStorage.removeItem(SESSION_PREFIX + key); } catch (_e) {}
}

// validate checks a loaded manifest against the saved anchor.
//
// Returns:
//   { ok: true, anchor: {count, lastSig}, tofu: true }   — no prior anchor; caller should save the returned anchor
//   { ok: true, anchor: {count, lastSig}, tofu: false }  — extends or matches prior anchor
//   { ok: false, reason: "truncation" | "fork", anchor, loaded } — REJECT
//
// `loadedEvents` is the manifest's events array (in load order). `prior`
// is what loadAnchor returned (null for first load).
export function validate(loadedEvents, prior) {
  const loaded = {
    count: loadedEvents.length,
    lastSig: loadedEvents.length > 0
      ? (loadedEvents[loadedEvents.length - 1].sig || "")
      : "",
  };
  if (!prior) {
    return { ok: true, anchor: loaded, tofu: true };
  }
  if (loaded.count < prior.count) {
    return {
      ok: false,
      reason: "truncation",
      detail: `loaded count ${loaded.count} < anchor count ${prior.count}`,
      anchor: prior,
      loaded,
    };
  }
  // loaded.count >= prior.count — the event at prior.count-1 must still
  // have the same sig the anchor recorded. (If prior.count === 0, the
  // anchor was empty — any first event is a valid extension.)
  if (prior.count > 0) {
    const anchorEvent = loadedEvents[prior.count - 1];
    const anchorSig = anchorEvent?.sig || "";
    if (anchorSig !== prior.lastSig) {
      return {
        ok: false,
        reason: "fork",
        detail: `event[${prior.count - 1}].sig differs from anchor.lastSig`,
        anchor: prior,
        loaded,
      };
    }
  }
  return { ok: true, anchor: loaded, tofu: false };
}

// ManifestRollbackError is thrown when validation rejects. Caller code
// catches by name (not instanceof — module-boundary fragility) so we
// expose a stable name string.
export class ManifestRollbackError extends Error {
  constructor(reason, detail) {
    super(`manifest rollback detected (${reason}): ${detail}`);
    this.name = "ManifestRollbackError";
    this.reason = reason; // "truncation" | "fork"
    this.detail = detail;
  }
}
