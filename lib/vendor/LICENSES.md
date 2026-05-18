# Vendored dependency licences

Each vendored library in `lib/vendor/` lists its source URL, version, and licence here. AGPL-3.0-or-later compatibility is required — see `CONTRIBUTING.md` for the policy.

| Library | Version | Source | Licence | Notes |
|---|---|---|---|---|
| [`zxcvbn-ts/core.umd.min.js`](zxcvbn-ts/core.umd.min.js) | 3.0.4 | [npm @zxcvbn-ts/core](https://www.npmjs.com/package/@zxcvbn-ts/core) | MIT (see [`zxcvbn-ts/LICENSE.txt`](zxcvbn-ts/LICENSE.txt)) | Realistic password-strength estimator. Powers `lib/entropy.js`. Exposes `window.zxcvbnts.core`. |
| [`zxcvbn-ts/language-common.umd.min.js`](zxcvbn-ts/language-common.umd.min.js) | 3.0.4 | [npm @zxcvbn-ts/language-common](https://www.npmjs.com/package/@zxcvbn-ts/language-common) | MIT | Cross-language data (passwords list, keyboard layouts, diceware). |
| [`zxcvbn-ts/language-en.umd.min.js`](zxcvbn-ts/language-en.umd.min.js) | 3.0.2 | [npm @zxcvbn-ts/language-en](https://www.npmjs.com/package/@zxcvbn-ts/language-en) | MIT | English-specific dictionaries: common words, first/last names, Wikipedia. |
| BIP-39 English wordlist (in `lib/wordlist.js`) | n/a | [bitcoin/bips bip-0039/english.txt](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt) | Public domain (BIP author dedication) | 2048 words. Used for recovery-phrase generation/confirmation and the 7-word generated passphrase. |

## Notes

- The three `zxcvbn-ts` UMD bundles total ~1.7 MB (language-en is ~1.2 MB of dictionaries). They load via `<script>` (not `<script type="module">`) and expose globals on `window.zxcvbnts`. `lib/entropy.js` calls `zxcvbnts.core.zxcvbn(...)` and is the only consumer.
- Considered swapping for the ESM `index.esm.js` bundle to keep the type-module idiom, but the per-package json shards (`commonWords.json.esm.js` etc.) make module resolution painful without a bundler. UMD wins on simplicity for v1.0.
- Slimming the language packs is a real lever if the cold-start size becomes a problem — switch to a custom build with only the password list (omit firstnames/lastnames/wikipedia) for ~80% size reduction with modest accuracy hit on detecting common-name passphrases.
