// SPDX-License-Identifier: AGPL-3.0-or-later
// Wizard + folder-UI entrypoint. Lives in its own file (rather than inline
// in index.html) because the CSP — `script-src 'self'` — blocks inline
// scripts. Loaded via <script src="./lib/entrypoint.js" type="module">.
//
// Two top-level views:
//   - #wizard-root  (M1/M2/M3 onboarding wizard; first-run + pair-device)
//   - #folder-root  (M4 folder UI; mounted after the wizard's Done stage
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
import { createWizard } from "./onboarding.js";
import * as bucket from "./bucket.js";
import * as cryptoLib from "./crypto.js";
import * as cratejsonMod from "./cratejson.js";
import * as manifestMod from "./manifest.js";
import * as recoveryMod from "./recovery.js";
import { FolderUI } from "./folder.js";

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
  FolderUI.mount(folderRoot, session);
};

// __CRATE__ is the dev/test surface — the M5 ESM API lock is `Crate` on
// the same object; downstream apps import that. The other namespaces stay
// for the devtools smoke recipe + tests.
window.__CRATE__ = {
  Crate, wizard, bucket,
  crypto: cryptoLib,
  cratejson: cratejsonMod,
  manifest: manifestMod,
  recovery: recoveryMod,
  folder: { FolderUI },
};
wizard.init();
