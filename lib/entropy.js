// SPDX-License-Identifier: AGPL-3.0-or-later
// Passphrase-strength estimator built on the vendored zxcvbn-ts. The
// library is loaded as UMD `<script>` tags in `index.html` and exposes
// globals on `window.zxcvbnts`; this module wraps the API and converts
// zxcvbn's guesses estimate into bits so the M1 onboarding wizard can
// gate Next at the spec's ≥70-bit floor.
//
// The wizard imports this lazily so the page can render before the
// 1.7 MB of dictionaries finishes parsing — see `estimate()`'s
// "not ready yet" fallback.

let _configured = false;
const READY = new Promise((resolve) => {
  // Poll on the next microtask + a few rAFs in case the UMD bundles are
  // still parsing. In practice they're done well before the user reaches
  // the Passphrase stage; this just guards the very-first-paint window.
  const tick = () => {
    if (window.zxcvbnts?.core && window.zxcvbnts["language-common"] && window.zxcvbnts["language-en"]) {
      const { zxcvbnOptions } = window.zxcvbnts.core;
      const common = window.zxcvbnts["language-common"];
      const en = window.zxcvbnts["language-en"];
      if (!_configured) {
        zxcvbnOptions.setOptions({
          translations: en.translations,
          graphs: common.adjacencyGraphs,
          dictionary: {
            ...common.dictionary,
            ...en.dictionary,
          },
        });
        _configured = true;
      }
      resolve(true);
      return;
    }
    requestAnimationFrame(tick);
  };
  tick();
});

export function isReady() {
  return _configured;
}

export function whenReady() {
  return READY;
}

// Heuristic floor for the meter when zxcvbn hasn't loaded yet — purely
// length × charset-class so the Next button is at least gated on
// something. Replaced by the zxcvbn result the moment it's ready.
function fallbackBits(s) {
  if (!s) return 0;
  let classes = 0;
  if (/[a-z]/.test(s)) classes += 26;
  if (/[A-Z]/.test(s)) classes += 26;
  if (/[0-9]/.test(s)) classes += 10;
  if (/[^a-zA-Z0-9]/.test(s)) classes += 33;
  return Math.floor(Math.log2(Math.max(1, classes)) * s.length);
}

const LABELS = ["very weak", "weak", "fair", "strong", "very strong"];

export function estimate(passphrase) {
  if (!passphrase) {
    return { bits: 0, score: 0, label: LABELS[0], ready: _configured };
  }
  if (!_configured) {
    const bits = fallbackBits(passphrase);
    const score = Math.min(4, Math.floor(bits / 22));
    return { bits, score, label: LABELS[score], ready: false };
  }
  const result = window.zxcvbnts.core.zxcvbn(passphrase);
  // guesses_log10 is zxcvbn's primary measure of attacker work in base 10;
  // convert to bits of entropy: bits = log10(guesses) × log2(10).
  const bits = Math.floor(result.guessesLog10 * 3.3219280948873626);
  const score = Math.max(0, Math.min(4, result.score));
  return { bits, score, label: LABELS[score], ready: true };
}
