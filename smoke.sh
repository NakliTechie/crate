#!/usr/bin/env bash
# Smoke test for crate (browser surface).
#
# M0 gates (always):
# - LICENSE present and is AGPL-3.0
# - index.html exists and is non-empty
# - Every first-party code file under lib/ carries an SPDX header
#   (vendored code under lib/vendor/ is exempt — it keeps upstream headers)
#
# M1 gates (added when M1 lands):
# - lib/onboarding.js exports createWizard
# - index.html carries a Content-Security-Policy meta tag
# - lib/wordlist.js carries the full 2048-word BIP-39 array
#
# M2 gates (added when M2 lands):
# - lib/sigv4.js exports signRequest
# - lib/bucket.js exports signedHead + corsPreflight + endpoints
#
# M3 gates (added when M3 lands):
# - lib/crypto.js exports deriveMasterKey + encrypt + decrypt + hmacSign
# - lib/manifest.js exports Manifest class + MANIFEST_PATH
# - lib/recovery.js exports generateMnemonic + mnemonicToEntropy
# - lib/cratejson.js exports build + parse + CRATE_PATH
# - lib/bucket.js exports signedPut + signedGet + signedDelete
#
# M4 gates (added when M4 lands):
# - lib/folder.js exports FolderUI class
# - index.html has a #folder-root mount point
#
# M5 gates (added when M5 lands):
# - lib/crate.js exports Crate.open + Crate.bootstrap
# - docs/esm-api.md mentions the 9-method surface
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -f LICENSE ]]; then
  echo "FAIL: LICENSE missing"; exit 1
fi
if ! grep -q "AFFERO GENERAL PUBLIC LICENSE" LICENSE; then
  echo "FAIL: LICENSE is not AGPL-3.0"; exit 1
fi

if [[ ! -s index.html ]]; then
  echo "FAIL: index.html missing or empty"; exit 1
fi

missing=0
while IFS= read -r f; do
  if ! head -3 "$f" | grep -q "SPDX-License-Identifier"; then
    echo "FAIL: $f missing SPDX header"
    missing=1
  fi
done < <(find lib -type f \( -name "*.js" -o -name "*.html" \) -not -path 'lib/vendor/*')

if (( missing )); then exit 1; fi

# --- M1 checks --------------------------------------------------------

if ! grep -q "createWizard" lib/onboarding.js; then
  echo "FAIL: lib/onboarding.js missing createWizard export"; exit 1
fi

if ! grep -q "Content-Security-Policy" index.html; then
  echo "FAIL: index.html missing Content-Security-Policy meta tag"; exit 1
fi

word_count=$(grep -c '^  "' lib/wordlist.js || true)
if [[ "$word_count" -ne 256 ]]; then
  echo "FAIL: lib/wordlist.js should have 256 lines of 8 words each (2048 BIP-39 words); found $word_count word lines"
  exit 1
fi

# --- M2 checks --------------------------------------------------------

if ! grep -qE "^export (async )?function signRequest" lib/sigv4.js; then
  echo "FAIL: lib/sigv4.js missing signRequest export"; exit 1
fi

for sym in signedHead corsPreflight endpoints unauthHead; do
  if ! grep -qE "^export (async )?function ${sym}\b|^export const ${sym}\b" lib/bucket.js; then
    echo "FAIL: lib/bucket.js missing $sym export"; exit 1
  fi
done

# --- M3 checks --------------------------------------------------------

for sym in deriveMasterKey encrypt decrypt hmacSign wrapDataKey unwrapDataKey randomSalt newULID canonicalJSON; do
  if ! grep -qE "^export (async )?function ${sym}\b" lib/crypto.js; then
    echo "FAIL: lib/crypto.js missing $sym export"; exit 1
  fi
done

if ! grep -qE "^export class Manifest\b" lib/manifest.js; then
  echo "FAIL: lib/manifest.js missing Manifest class export"; exit 1
fi
if ! grep -qE "^export const MANIFEST_PATH\b" lib/manifest.js; then
  echo "FAIL: lib/manifest.js missing MANIFEST_PATH export"; exit 1
fi
for sym in createEvent updateEvent deleteEvent moveEvent mkdirEvent; do
  if ! grep -qE "^export function ${sym}\b" lib/manifest.js; then
    echo "FAIL: lib/manifest.js missing $sym export"; exit 1
  fi
done

for sym in generateMnemonic mnemonicToEntropy entropyToMnemonic normalizeMnemonic; do
  if ! grep -qE "^export (async )?function ${sym}\b" lib/recovery.js; then
    echo "FAIL: lib/recovery.js missing $sym export"; exit 1
  fi
done

for sym in build parse shortBrowserFingerprint; do
  if ! grep -qE "^export function ${sym}\b" lib/cratejson.js; then
    echo "FAIL: lib/cratejson.js missing $sym export"; exit 1
  fi
done
if ! grep -qE "^export const CRATE_PATH\b" lib/cratejson.js; then
  echo "FAIL: lib/cratejson.js missing CRATE_PATH export"; exit 1
fi

for sym in signedPut signedGet signedDelete; do
  if ! grep -qE "^export (async )?function ${sym}\b" lib/bucket.js; then
    echo "FAIL: lib/bucket.js missing $sym export"; exit 1
  fi
done

# --- M4 checks --------------------------------------------------------

if ! grep -qE "^export class FolderUI\b" lib/folder.js; then
  echo "FAIL: lib/folder.js missing FolderUI class export"; exit 1
fi
if ! grep -q 'id="folder-root"' index.html; then
  echo "FAIL: index.html missing #folder-root mount point"; exit 1
fi

# --- M5 checks --------------------------------------------------------

if ! grep -qE "^export class Crate\b" lib/crate.js; then
  echo "FAIL: lib/crate.js missing Crate class export"; exit 1
fi
if ! grep -qE "static async open\b" lib/crate.js; then
  echo "FAIL: lib/crate.js missing Crate.open static method"; exit 1
fi
if ! grep -qE "static async bootstrap\b" lib/crate.js; then
  echo "FAIL: lib/crate.js missing Crate.bootstrap static method"; exit 1
fi

# All 9 ESM API methods present on the Crate prototype.
for method in list read write remove move mkdir stat history onChange; do
  if ! grep -qE "^\s+(async )?${method}\b" lib/crate.js; then
    echo "FAIL: lib/crate.js missing Crate.${method} method"; exit 1
  fi
done

if ! grep -q "ESM API" docs/esm-api.md; then
  echo "FAIL: docs/esm-api.md not updated for M5"; exit 1
fi

# --- M6 checks --------------------------------------------------------

if ! grep -qE "^export class SyncClient\b" lib/sync-client.js; then
  echo "FAIL: lib/sync-client.js missing SyncClient class export"; exit 1
fi
if ! grep -q "BroadcastChannel" lib/sync-client.js; then
  echo "FAIL: lib/sync-client.js missing BroadcastChannel wiring"; exit 1
fi

# --- M5.1: Unlock-existing-folder route --------------------------------

if ! grep -q "renderUnlock" lib/onboarding.js; then
  echo "FAIL: lib/onboarding.js missing renderUnlock — Unlock route not wired"; exit 1
fi

# --- M7 checks --------------------------------------------------------

for sym in encode renderTo; do
  if ! grep -qE "^export (async )?function ${sym}\b" lib/qr.js; then
    echo "FAIL: lib/qr.js missing $sym export"; exit 1
  fi
done

# M7.1 — confirm lib/qr.js is the real encoder, not the M7 placeholder.
if grep -q "M7.1 — pair via copy-paste for now" lib/qr.js; then
  echo "FAIL: lib/qr.js still has the M7 placeholder reason; M7.1 didn't land"; exit 1
fi
if ! grep -q "Reed-Solomon" lib/qr.js; then
  echo "FAIL: lib/qr.js doesn't look like a real QR encoder (no Reed-Solomon)"; exit 1
fi

if ! grep -q "handlePair" lib/folder.js; then
  echo "FAIL: lib/folder.js missing handlePair — M7 pairing UI not wired"; exit 1
fi
if ! grep -q "Pair an agent" lib/folder.js; then
  echo "FAIL: lib/folder.js missing 'Pair an agent' button"; exit 1
fi
if ! grep -q "renderPairModal" lib/folder.js; then
  echo "FAIL: lib/folder.js missing renderPairModal"; exit 1
fi

# --- M8.1: help modal (friend-gate self-serve instructions) ----------

if ! grep -q "openHelpModal" lib/onboarding.js; then
  echo "FAIL: lib/onboarding.js missing openHelpModal — M8.1 help modal not wired"; exit 1
fi
if ! grep -q "How this works" lib/onboarding.js; then
  echo "FAIL: lib/onboarding.js missing Welcome 'How this works' button"; exit 1
fi
if ! grep -q "help-card" index.html; then
  echo "FAIL: index.html missing .help-card styles"; exit 1
fi
if ! grep -q "Plan for backups" lib/onboarding.js; then
  echo "FAIL: help modal missing 'Plan for backups' step 8"; exit 1
fi

# --- Export feature (tiered backup download) -------------------------

for sym in planExport runExport formatBytes; do
  if ! grep -qE "^export (async )?function ${sym}\b" lib/export.js; then
    echo "FAIL: lib/export.js missing $sym export"; exit 1
  fi
done
if ! grep -q "client-zip" lib/export.js; then
  echo "FAIL: lib/export.js doesn't import client-zip"; exit 1
fi
if ! grep -q "showSaveFilePicker" lib/export.js; then
  echo "FAIL: lib/export.js missing FSA streaming path (showSaveFilePicker)"; exit 1
fi
if [[ ! -f lib/vendor/client-zip/index.js ]]; then
  echo "FAIL: lib/vendor/client-zip/index.js missing"; exit 1
fi
if [[ ! -f lib/vendor/client-zip/LICENSE ]]; then
  echo "FAIL: lib/vendor/client-zip/LICENSE missing"; exit 1
fi
if ! grep -q "client-zip" lib/vendor/LICENSES.md; then
  echo "FAIL: lib/vendor/LICENSES.md doesn't list client-zip"; exit 1
fi
if ! grep -q "handleExport" lib/folder.js; then
  echo "FAIL: lib/folder.js missing handleExport"; exit 1
fi
if ! grep -q "Export folder" lib/folder.js; then
  echo "FAIL: lib/folder.js missing 'Export folder' button"; exit 1
fi
if ! grep -q "renderExportModal" lib/folder.js; then
  echo "FAIL: lib/folder.js missing renderExportModal"; exit 1
fi
if [[ ! -f docs/backup.md ]]; then
  echo "FAIL: docs/backup.md missing — disaster-recovery runbook not landed"; exit 1
fi

echo "OK: crate v1"
