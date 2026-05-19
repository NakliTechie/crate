// SPDX-License-Identifier: AGPL-3.0-or-later
// Wizard entrypoint. Lives in its own file (rather than inline in
// index.html) because the CSP — `script-src 'self'` — blocks inline
// scripts. Loaded via <script src="./lib/entrypoint.js" type="module">.
//
// `bucket` is exposed for the devtools smoke recipe documented at
// docs/README.md — lets users verify the same primitives work
// against Hetzner / B2 / AWS S3 without touching wizard code.

import { Crate } from "./crate.js";
import { createWizard } from "./onboarding.js";
import * as bucket from "./bucket.js";

const root = document.getElementById("wizard-root");
const liveRegion = document.getElementById("live-region");

const wizard = createWizard({
  root,
  liveRegion,
  onComplete: (snapshot) => {
    // M2: snapshot still doesn't trigger real bucket bootstrap — that's
    // M3+ (encryption + manifest). At M2 the snapshot is informational;
    // the live bucket checks happen inside the wizard stages via
    // lib/bucket.js.
    console.info("onboarding complete", snapshot);
  },
});

window.__CRATE__ = { Crate, wizard, bucket };
wizard.init();
