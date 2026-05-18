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

echo "OK: crate (M2 real R2 bucket connection — sig-v4 + bucket client + CSP + createWizard + BIP-39 wordlist + AGPL-3.0)"
