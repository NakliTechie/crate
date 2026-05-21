# Crate

A personal cloud folder. Files live in a bucket you own (Cloudflare R2 by default), encrypted before they leave your browser. Open a tab, the folder is there. BYOK, AES-256-GCM client-side, no NakliTechie accounts on the path.

Dropbox-shaped utility, NakliTechie-shaped substrate.

## Status

**v1.0 — live at [`crate.naklitechie.com`](https://crate.naklitechie.com).** Every milestone in the M0–M8 schedule is shipped:

| | What lands here |
|---|---|
| **M0** | Skeleton (single HTML + ESM modules; AGPL-3.0). |
| **M1** | Onboarding wizard — Welcome → Bucket → Credentials → CORS → Passphrase → Recovery → Done, plus the pair-device flow. |
| **M2** | Real Cloudflare R2 via AWS sig-v4 (`lib/sigv4.js`). Hetzner / B2 / AWS-S3 abstraction shipped at the same time; R2 verified end-to-end against a real bucket. |
| **M3** | AES-256-GCM payload encryption with per-file random data keys wrapped by a PBKDF2-derived master key (600 000 iterations; 16-byte salt in `.crate/crate.json`). Signed JSONL manifest at `.crate/manifest.jsonl.enc` with HMAC-SHA256 prev-sig chain (tamper-evident). Real BIP-39 24-word recovery phrase with checksum. |
| **M4** | Folder UI — tree view, drag-drop + file-picker upload, download, rename, delete, mkdir; mobile-responsive. |
| **M5** | ESM API lock — [`lib/crate.js`](lib/crate.js) exposes the 9-method surface (`list / read / write / remove / move / mkdir / stat / history / onChange`) documented in [`docs/esm-api.md`](docs/esm-api.md). Other NakliTechie tools bind against this. |
| **M5.1** | Unlock-existing-folder route at the Welcome stage — survives page refresh after onboarding. |
| **M6** | Sync binding — BroadcastChannel cross-tab + periodic manifest poll cross-device. Files added/edited/deleted in another tab or another paired device surface within ~15s (or ~200ms across same-origin tabs). |
| **M7** | Device pairing UI — mints a `CRATE-PAIR-…` token via `POST /v1/pairing/intent` against your transport, shows it with a copy button + expiry countdown + cancel. QR matrix display lands at M7.1. |
| **M8** | DNS cutover to `crate.naklitechie.com` (user-side task) + help modal + Chirag's friend-onboarding gate. This commit lands the polish; the DNS is the user's call. |

Wire format matches the [crate-agent daemon](https://github.com/NakliTechie/crate-agent) byte-for-byte — the two surfaces share a Crate folder transparently. Drop a file into `~/crate/` on your laptop, it surfaces in the browser tab; upload from the browser, it appears in `~/crate/`.

## Two surfaces

| Surface | Repo | When |
|---|---|---|
| Browser (this) | `NakliTechie/crate` | v1.0 at [`crate.naklitechie.com`](https://crate.naklitechie.com) |
| Native daemon | `NakliTechie/crate-agent` | v1.2+ (built — `crate-agent pair` + `crate-agent start` give bidirectional sync) |

Both build on the same Sync + Vault + Identity + Grant + History primitives (`NakliTechie/private-mesh`).

## Architecture

- **Browser**: end-to-end encryption in this tab. Bucket owner (Cloudflare, Hetzner, B2, AWS) sees ciphertext + access patterns only.
- **Daemon**: same encryption envelope; talks to the bucket through the Hub bucket-proxy (Hub holds R2 creds; daemon holds a sync-scope capability).
- **Hub** (`nakli-hub`): R2 proxy + macaroon-issuance. Sees ciphertext only.
- **Sync**: manifest at `.crate/manifest.jsonl.enc` is the source of truth. Every surface materialises it into a tree; mutations append signed events.

## Smoke

```sh
./smoke.sh
```

22 structural checks across M0–M7. Static analysis only — the real R2 manual gate (walk the wizard, upload a file, refresh, see file in tree) is the human verification gate the spec documents at each milestone.

## Quick start (against your own R2 bucket)

1. Create an R2 bucket in your Cloudflare account.
2. Create a scoped API token with read+write on that bucket.
3. Paste the CORS JSON from the wizard into the bucket's CORS settings.
4. Open `naklitechie.github.io/crate/` → "Set up a new folder" → walk the wizard.
5. Drop a file in. Refresh the tab. File's still there. Open the tab on your phone (same passphrase + creds via "Unlock an existing folder"). File's there too.

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
