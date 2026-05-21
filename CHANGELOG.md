# Changelog

All notable changes to Crate. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [SemVer](https://semver.org/spec/v2.0.0.html); see the Versioning section in the README for what counts as breaking.

## [1.0.0] — 2026-05-21

First stable release. Frozen surfaces:

- Bucket wire format: `.crate/crate.json` + AES-256-GCM-encrypted JSONL manifest at `.crate/manifest.jsonl.enc` + AES-256-GCM-sealed objects at `objects/{uuid}`. PBKDF2-SHA256/600k iterations on the master key. HMAC-SHA256 prev_sig chain on every manifest event.
- ESM API: 9 methods on the `Crate` class — `list`, `read`, `write`, `remove`, `move`, `mkdir`, `stat`, `history`, `onChange`. Plus `Crate.open` / `Crate.bootstrap` / `crate.close`.
- CRATE-PAIR pairing protocol: token issuance via `POST /v1/pairing/intent`, redemption via `POST /v1/pairing/redeem`, cancellation via `POST /v1/pairing/intent/cancel`. Six error codes (`token_format`, `token_expired`, `token_not_found`, `token_already_redeemed`, `token_cancelled`, `protocol_version`).

### Added

- Onboarding wizard: bucket → credentials → CORS → passphrase → done. Cloudflare deep-links + step-by-step help modal for first-time R2 users.
- Folder UI: tree view, drag-drop + file-picker upload, download, rename, delete, mkdir, move. Mobile-responsive.
- Cross-tab sync via BroadcastChannel (~200 ms convergence on same origin).
- Cross-device sync via periodic manifest poll (~15 s).
- ETag-conditional PUT (`If-Match`) for concurrent-write safety. On 412 the writer re-fetches, splices its pending events on top, and retries up to 3×.
- Device-pairing UI: real QR matrix encoder for the `CRATE-PAIR-…` token.
- Tiered folder export: in-memory zip for ≤500 MB, File System Access streaming for larger folders on Chrome/Edge/Brave/Opera, daemon-install fallback for unsupported browsers.
- Per-file history modal showing every manifest event affecting a file.
- Search filter in the folder view (basename substring, case-insensitive).
- Header summary: file count + total size + encryption note.
- Hetzner / Backblaze B2 / AWS S3 endpoint support via the same sig-v4 client (algorithmically correct; R2 verified live).
- Cross-surface byte-identical interop with the [`crate-agent`](https://github.com/NakliTechie/crate-agent) Go daemon.
- Docs: encryption-model, ESM API reference, backup runbook.
- GitHub Actions: smoke checks run on every push to main + on every PR.

### Notes

- v1 has **one credential**: the passphrase. There is no recovery phrase, email-reset, or support backdoor. Redundancy comes from running the daemon + backing up the local mirror, mirroring the bucket with `rclone`, or R2 object versioning (see [`docs/backup.md`](docs/backup.md)).
- The pairing flow currently sends `identity_pubkey: "browser-stub"` in the intent payload. Authentication is enforced by the `X-Fabric-Grant` macaroon. Real per-browser Ed25519 identity binding lands with the nakliOS Identity integration.
