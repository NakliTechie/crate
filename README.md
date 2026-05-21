# Crate

A personal cloud folder. Files live in a bucket you own (Cloudflare R2 by default), encrypted before they leave your browser. Open a tab, the folder is there. BYOK, AES-256-GCM client-side, no NakliTechie accounts on the path.

Dropbox-shaped utility, NakliTechie-shaped substrate.

## Status

**M5** — M3 (encryption + signed manifest) + M4 (folder UI) + M5 (ESM API lock) all land in this commit. AES-256-GCM payload encryption with per-file random data keys wrapped by a PBKDF2-derived master key (600 000 iterations, 16-byte salt stored in `.crate/crate.json`). Signed JSONL manifest at `.crate/manifest.jsonl.enc` with HMAC-SHA256 prev-sig chain (tamper-evident). Real BIP-39 24-word recovery phrase with checksum (importable into other tools). Folder UI mounts after the wizard's Done stage: tree view, drag-drop + file-picker upload, download, rename, delete, mkdir. The [`Crate`](lib/crate.js) ESM class exposes the locked 9-method surface (`list / read / write / remove / move / mkdir / stat / history / onChange`) documented in [`docs/esm-api.md`](docs/esm-api.md). Wire format matches the daemon (`crate-agent`) byte-for-byte — the two surfaces share a Crate folder transparently.

Remaining: M6 (multi-tab/device sync), M7 (device pairing UI — QR + intent POST), M8 (ship polish + DNS).

## Two surfaces

| Surface | Repo | When |
|---|---|---|
| Browser | `NakliTechie/crate` (this one) | v1.0 |
| Native daemon | `NakliTechie/crate-agent` | v1.2+ |

Both build on the same Sync + Vault + Identity + Grant + History primitives (`NakliTechie/private-mesh`).

## Smoke

```sh
./smoke.sh
```

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
