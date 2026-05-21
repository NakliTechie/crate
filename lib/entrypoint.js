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
import * as bucket from "./bucket.js";
import * as cryptoLib from "./crypto.js";
import * as cratejsonMod from "./cratejson.js";
import * as manifestMod from "./manifest.js";
import { FolderUI } from "./folder.js";
import { SyncClient } from "./sync-client.js";

const wizardRoot = document.getElementById("wizard-root");
const folderRoot = document.getElementById("folder-root");
const wizardChrome = [
  document.getElementById("progress"),
  document.getElementById("wizard-nav"),
];
const liveRegion = document.getElementById("live-region");

const wizard = createWizard({
  root: wizardRoot,
  liveRegion,
  onComplete: (snapshot) => {
    console.info("onboarding complete", snapshot);
  },
});

// openCrateFolder transitions from wizard → folder UI. The wizard's Done
// stage calls this when first-time setup succeeds; the session handle
// carries the in-memory master key + bucket creds + manifest.
window.openCrateFolder = function openCrateFolder(session) {
  if (!session || !folderRoot) {
    console.error("openCrateFolder: missing session or #folder-root", { session, folderRoot });
    return;
  }
  for (const node of wizardChrome) if (node) node.style.display = "none";
  if (wizardRoot) wizardRoot.style.display = "none";
  folderRoot.style.display = "";

  // Wire SyncClient + FolderUI together. The session handle is shared:
  //   FolderUI mutates session.manifest (the canonical in-memory Manifest)
  //   SyncClient mutates the SAME Manifest's events array in place when
  //   it pulls remote changes
  //   Both call back through the facade's _emit so the UI re-renders.
  const crateFacade = makeCrateFacadeFromSession(session);
  const ui = FolderUI.mount(folderRoot, session, {
    onChange: (evt) => crateFacade._emit(evt),
    onLock: () => lockCrateFolder(session, sync, crateFacade),
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
  // route back to the unlock screen with the file pre-loaded.
  try { sessionStorage.removeItem(SESSION_CREDS_KEY); } catch {}

  // Hide the folder UI; show the wizard chrome again.
  if (folderRoot) folderRoot.style.display = "none";
  for (const node of wizardChrome) if (node) node.style.display = "";
  if (wizardRoot) wizardRoot.style.display = "";

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
    _masterKey: session.masterKey,
    _manifest: session.manifest,
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
window.__CRATE__ = {
  Crate, wizard, bucket,
  crypto: cryptoLib,
  cratejson: cratejsonMod,
  manifest: manifestMod,
  folder: { FolderUI },
};
wizard.init();
