// SPDX-License-Identifier: AGPL-3.0-or-later
// Wizard + folder-UI entrypoint. Lives in its own file (rather than inline
// in index.html) because the CSP — `script-src 'self'` — blocks inline
// scripts. Loaded via <script src="./lib/entrypoint.js" type="module">.
//
// Two top-level views:
//   - #wizard-root  (onboarding wizard; first-run, unlock, or pair-device)
//   - #folder-root  (folder UI; mounted after the wizard's Done stage
//                    completes first-time setup OR after the user unlocks
//                    an existing folder from the Welcome screen)
//
// The wizard hides itself when first-time setup completes and reveals the
// folder UI. Reverse switch (back to wizard) on "Start over."
//
// `bucket` is exposed for the devtools smoke recipe documented at
// docs/README.md — lets users verify the same primitives work against
// Hetzner / B2 / AWS S3 without touching wizard code.

import { Crate } from "./crate.js";
import { createWizard, SESSION_CREDS_KEY } from "./onboarding.js";
import * as credsfile from "./credsfile.js";
import * as bucket from "./bucket.js";
import * as cryptoLib from "./crypto.js";
import * as cratejsonMod from "./cratejson.js";
import * as manifestMod from "./manifest.js";
import { FolderUI } from "./folder.js";
import { SyncClient } from "./sync-client.js";
import { createShell } from "./shell.js";
import * as recoveryMod from "./recovery.js";
import * as vaultMod from "./vault.js";
import { parseShare, fetchShared } from "./share.js";
import * as offline from "./offline.js";
import { icon } from "./icons.js";

const wizardRoot = document.getElementById("wizard-root");
const wizardColumn = document.getElementById("wizard-column");
const folderRoot = document.getElementById("folder-root");
const liveRegion = document.getElementById("live-region");

// The shell (topbar + sidebar) is always on screen; locked while the
// wizard runs, live once a session opens. See lib/shell.js.
const shell = createShell({ root: document.getElementById("app") });

const wizard = createWizard({
  root: wizardRoot,
  liveRegion,
  onComplete: (snapshot) => {
    console.info("onboarding complete", snapshot);
  },
});
shell.onHelp((btn) => wizard.openHelp({ returnFocus: btn }));

// openCrateFolder transitions from wizard → folder UI. The wizard's Done
// stage calls this when first-time setup succeeds; the session handle
// carries the in-memory master key + bucket creds + manifest.
window.openCrateFolder = function openCrateFolder(session) {
  if (!session || !folderRoot) {
    console.error("openCrateFolder: missing session or #folder-root", { session, folderRoot });
    return;
  }
  if (wizardColumn) wizardColumn.style.display = "none";
  folderRoot.style.display = "";
  shell.setLocked(false);

  // Wire SyncClient + FolderUI together. The session handle is shared:
  //   FolderUI mutates session.manifest (the canonical in-memory Manifest)
  //   SyncClient mutates the SAME Manifest's events array in place when
  //   it pulls remote changes
  //   Both call back through the facade's _emit so the UI re-renders.
  const crateFacade = makeCrateFacadeFromSession(session);
  const ui = FolderUI.mount(folderRoot, session, {
    shell,
    onChange: (evt) => crateFacade._emit(evt),
    onLock: () => lockCrateFolder(session, sync, crateFacade),
    // After a passphrase change the refresh-resume stash must be sealed
    // under the new one, or the next reload asks for a passphrase that
    // no longer opens anything.
    onPassphraseChange: async (newPassphrase) => {
      const creds = {
        provider: session.region === "carrier" ? "carrier" : "r2",
        bucket: { name: session.bucket?.name, accountId: session.bucket?.accountId, region: session.bucket?.region, url: session.bucket?.url },
        credentials: { accessKey: session.accessKey, secretKey: session.secretKey },
      };
      const bytes = await credsfile.pack(creds, newPassphrase);
      sessionStorage.setItem(SESSION_CREDS_KEY, new TextDecoder().decode(bytes));
    },
  });
  crateFacade._attachUI(ui);
  const sync = new SyncClient(crateFacade);
  sync.start();
  window.__CRATE_SYNC__ = sync;
};

// lockCrateFolder tears down the session and returns to the wizard.
// Zeroes the master key, clears bucket creds + passphrase from session
// memory, drops the sessionStorage encrypted blob, stops the sync
// client. After this, the only way back into the folder is to re-unlock
// (credentials file + passphrase, or the 5-input fallback).
function lockCrateFolder(session, sync, facade) {
  // Stop background work first so nothing fires after we zero the key.
  try { if (sync && typeof sync.stop === "function") sync.stop(); } catch (e) { console.warn("sync stop", e); }
  try { if (facade && typeof facade.close === "function") facade.close(); } catch (e) { console.warn("facade close", e); }

  // Zero the master key bytes (defence in depth — even if a stray
  // reference survives, the buffer is now full of zeros).
  if (session?.masterKey instanceof Uint8Array) {
    try { cryptoLib.zero(session.masterKey); } catch {}
  }

  // Drop everything secret from the session object.
  if (session) {
    session.passphrase = null;
    session.accessKey = null;
    session.secretKey = null;
    session.masterKey = null;
    session.manifest = null;
    session.salt = null;
  }

  // Clear the in-tab refresh-resume blob so a reload doesn't auto-
  // route back to the unlock screen with the file pre-loaded, and the
  // last-seen copy of the folder kept for offline opens.
  try { sessionStorage.removeItem(SESSION_CREDS_KEY); } catch {}
  if (session?.bucketBase) void offline.forget(session.bucketBase);

  // Hide the folder UI; show the wizard column again; dim the shell.
  if (folderRoot) folderRoot.style.display = "none";
  if (wizardColumn) wizardColumn.style.display = "";
  shell.setLocked(true);

  // Reset wizard state + route to Welcome.
  try { wizard.reset(); } catch (e) { console.warn("wizard reset", e); }

  // Best-effort: drop the sync handle from the devtools surface.
  try { delete window.__CRATE_SESSION__; } catch {}
  try { delete window.__CRATE_SYNC__; } catch {}
}

// makeCrateFacadeFromSession exposes the session as a Crate-shaped object
// so SyncClient can read _bucketBase/_region/_masterKey/_manifest and fire
// onChange events. The wizard's first-time-setup OR unlock-existing-folder
// paths produce a session handle (not a real Crate instance) — this facade
// adapts.
//
// _manifest reference is SHARED with session.manifest + FolderUI.session.manifest.
// SyncClient mutates the Manifest object's `events` field in place, so all
// three see the update simultaneously — no propagation needed.
function makeCrateFacadeFromSession(session) {
  const listeners = new Set();
  let attachedUI = null;
  // The facade uses GETTER/SETTER properties for manifestETag +
  // lastFlushedEventCount so SyncClient's writes propagate straight to
  // the session object the FolderUI reads. Without this indirection,
  // SyncClient would write to facade-local fields the FolderUI never sees.
  const facade = {
    _bucketBase: session.bucketBase,
    _region: session.region,
    _accessKey: session.accessKey,
    _secretKey: session.secretKey,
    // Key and manifest are read through the session on every access: a
    // re-key (Backup → Re-key folder) swaps both objects at once.
    get _masterKey() { return session.masterKey; },
    get _manifest() { return session.manifest; },
    get manifestETag() { return session.manifestETag; },
    set manifestETag(v) { session.manifestETag = v; },
    get lastFlushedEventCount() { return session.lastFlushedEventCount; },
    set lastFlushedEventCount(v) { session.lastFlushedEventCount = v; },
    _attachUI(ui) { attachedUI = ui; },
    _emit(evt) {
      for (const h of listeners) {
        try { h(evt); } catch (e) { console.error("onChange threw", e); }
      }
      if (attachedUI && typeof attachedUI.render === "function") attachedUI.render();
    },
    onChange(handler) {
      if (typeof handler !== "function") throw new Error("onChange: handler must be a function");
      listeners.add(handler);
      return () => listeners.delete(handler);
    },
    close() { listeners.clear(); },
  };
  return facade;
}

// __CRATE__ is the devtools surface — `Crate` is the public ESM API
// other apps import; the other namespaces are here for the devtools
// recipe in docs/README.md (cross-provider sigv4 sanity checks).
// --- shared-file view (#share=…) ----------------------------------------
// A recipient lands here with no folder, no account: the shell stays
// locked and the content column shows one card for one file. Nothing is
// fetched until they click; the link's key never leaves this tab.
function renderSharedFile(share) {
  const h = (tag, attrs = {}, kids = []) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) { if (v == null || v === false) continue; if (k === "class") n.className = v; else n.setAttribute(k, v); }
    for (const c of kids) if (c != null) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    return n;
  };
  const fmt = (b) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : b < 1073741824 ? `${(b / 1048576).toFixed(1)} MB` : `${(b / 1073741824).toFixed(2)} GB`);
  const expired = share.exp && Date.now() > share.exp;
  const until = share.exp ? new Date(share.exp).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "";
  const status = h("p", { class: "muted small", role: "status", "aria-live": "polite" }, [expired ? "This link has expired." : `Link works until ${until}.`]);
  const isText = /^text\//.test(share.mime) || /json|xml|yaml/.test(share.mime);
  const isImage = /^image\//.test(share.mime);
  const isPdf = share.mime === "application/pdf" || /\.pdf$/i.test(share.name);
  const isMedia = /^(audio|video)\//.test(share.mime);
  const dlBtn = h("button", { type: "button", class: "btn btn-primary btn-block btn-lg" }, [icon("download", { size: 16 }), ` Download ${share.name}`]);
  const pvBtn = (isText || isImage || isPdf || isMedia) ? h("button", { type: "button", class: "btn btn-secondary btn-block" }, [icon("eye", { size: 16 }), " Preview"]) : null;
  const previewHost = h("div", { class: "share-preview" });
  if (expired) { dlBtn.disabled = true; if (pvBtn) pvBtn.disabled = true; }
  let cached = null;
  const get = async () => {
    if (cached) return cached;
    dlBtn.disabled = true; if (pvBtn) pvBtn.disabled = true;
    status.textContent = "Fetching and decrypting…";
    try {
      cached = await fetchShared({ ...share, key: share.key.slice() });
      status.textContent = `Decrypted in this tab · ${fmt(cached.byteLength)}`;
      return cached;
    } catch (e) {
      status.textContent = e.message || String(e);
      throw e;
    } finally {
      dlBtn.disabled = false; if (pvBtn) pvBtn.disabled = false;
    }
  };
  dlBtn.addEventListener("click", async () => {
    let bytes; try { bytes = await get(); } catch { return; }
    const url = URL.createObjectURL(new Blob([bytes], { type: share.mime }));
    const a = h("a", { href: url, download: share.name }); document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  });
  if (pvBtn) pvBtn.addEventListener("click", async () => {
    let bytes; try { bytes = await get(); } catch { return; }
    previewHost.replaceChildren();
    if (isImage) {
      const url = URL.createObjectURL(new Blob([bytes], { type: share.mime }));
      previewHost.appendChild(h("img", { class: "preview-image", src: url, alt: share.name }));
    } else if (isPdf) {
      const url = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" }));
      previewHost.appendChild(h("iframe", { class: "preview-frame", src: url, title: share.name }));
    } else if (isMedia) {
      const url = URL.createObjectURL(new Blob([bytes], { type: share.mime }));
      const kind = share.mime.startsWith("video/") ? "video" : "audio";
      previewHost.appendChild(h(kind, { src: url, controls: "controls", class: kind === "video" ? "preview-video" : "preview-audio" }));
    } else {
      const text = new TextDecoder().decode(bytes.subarray(0, 512 * 1024));
      previewHost.appendChild(h("pre", { class: "code-block preview-text" }, [text + (bytes.byteLength > 512 * 1024 ? "\n…" : "")]));
    }
  });
  const card = h("section", { class: "landing share-card", "aria-labelledby": "share-title" }, [
    h("p", { class: "muted small" }, ["Someone shared a file from their Crate folder"]),
    h("h1", { id: "share-title", class: "landing-wordmark" }, [share.name]),
    h("p", { class: "landing-tagline" }, [`${fmt(share.size)} · ${share.mime}`]),
    h("div", { class: "landing-actions" }, [dlBtn, pvBtn]),
    status,
    previewHost,
    h("div", { class: "landing-links" }, [
      h("span", { class: "muted" }, ["Encrypted end to end — the storage it lives in sees only ciphertext; the key travelled in this link and is used in this tab only."]),
    ]),
    h("div", { class: "landing-links" }, [
      h("a", { href: "./" }, ["What is Crate?"]),
      h("a", { href: "guide/", target: "_blank", rel: "noopener noreferrer" }, ["Guide"]),
    ]),
  ]);
  wizardRoot.replaceChildren(card);
  document.getElementById("progress").style.display = "none";
  document.getElementById("wizard-nav").style.display = "none";
  wizardColumn.classList.add("is-landing");
  document.title = `${share.name} — shared via Crate`;
}

const shareFragment = location.hash.startsWith("#share=") ? location.hash : null;

window.__CRATE__ = {
  Crate, wizard, bucket,
  crypto: cryptoLib,
  cratejson: cratejsonMod,
  manifest: manifestMod,
  folder: { FolderUI },
  recovery: recoveryMod,
  vault: vaultMod,
  shell,
  share: { parseShare, fetchShared },
};
// Installable + offline shell. The worker only ever caches this origin's
// static files; bucket traffic never passes through it (see sw.js).
if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost")) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch((e) => console.warn("service worker", e));
  });
}

if (shareFragment) {
  try {
    renderSharedFile(parseShare(shareFragment));
  } catch (e) {
    console.error(e);
    wizard.init();
  }
} else {
  wizard.init();
}
