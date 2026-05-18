#!/usr/bin/env bash
# Smoke test for crate (browser surface), M0:
# - Assert LICENSE present and is AGPL-3.0
# - Assert index.html exists and is non-empty
# - Assert every code file under lib/ carries an SPDX header
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
done < <(find lib -type f \( -name "*.js" -o -name "*.html" \))

if (( missing )); then exit 1; fi

echo "OK: crate (M0 skeleton — LICENSE AGPL-3.0, index.html present, SPDX headers in lib/)"
