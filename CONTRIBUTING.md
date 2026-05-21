# Contributing to Crate

## Licensing

Crate is **AGPL-3.0-or-later**. Every new code file gets an SPDX header:

- JavaScript / ES modules: `// SPDX-License-Identifier: AGPL-3.0-or-later`
- HTML: `<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->`

By contributing, you agree your contributions are licensed under AGPL-3.0-or-later.

## Dependencies

- **No proprietary deps.** Everything we ship has to be AGPL-3.0-or-later compatible.
- **No GPL-2.0-only deps.** GPL-2.0-or-later is fine; GPL-2.0-only is not (incompatible with AGPL-3.0).
- **Vendor, don't CDN.** Third-party code lives inline under [`lib/vendor/`](lib/vendor/) with the upstream LICENSE next to it and an entry in [`lib/vendor/LICENSES.md`](lib/vendor/LICENSES.md). Single-file ethos — we don't want runtime CDN dependencies.

## Style

- **Single static HTML.** `index.html` carries inline `<style>` and a single `<script type="module">` entrypoint. No build step.
- **DOM API for any node containing user data.** No `innerHTML` on user-supplied content. Use `document.createElement` + `textContent`.
- **CSP stays strict.** `default-src 'self'; script-src 'self'`. Adding `'unsafe-inline'` to `script-src` is a non-starter.
- **No telemetry, no analytics.** Crate's privacy claim depends on this. Zero exceptions.

## Testing

`./smoke.sh` runs structural checks. The real verification is walking the wizard against a real R2 bucket — there's no substitute for that gate.

When changing crypto: round-trip via [`lib/crypto.js`](lib/crypto.js) is the bare minimum; cross-surface byte-identity with [`crate-agent`](https://github.com/NakliTechie/crate-agent) is the actual contract.

## Security-relevant changes

Anything in [`lib/crypto.js`](lib/crypto.js), [`lib/manifest.js`](lib/manifest.js), or [`lib/bucket.js`](lib/bucket.js) deserves extra scrutiny. The threat model is documented in [`docs/encryption-model.md`](docs/encryption-model.md); changes here should update that doc in the same commit if behavior shifts.

For vulnerability reports, open a GitHub issue marked `security` or DM [@NakliTechie](https://github.com/NakliTechie).
