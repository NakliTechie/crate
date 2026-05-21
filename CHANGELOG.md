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
- Per-file preview modal: text + image files render inline (≤50 MB); other types fall back to Download.
- Per-file history modal: timestamped event log per path, read from the manifest already in memory.
- Folder header: file count + total size summary, recomputed on every render.
- Search input: filters the current tree view by basename substring (case-insensitive).
- Tiered folder export: in-memory zip for ≤500 MB, File System Access streaming for larger folders on Chrome/Edge/Brave/Opera, daemon-install fallback for unsupported browsers.
- Streaming-write download for large files: on browsers with `showSaveFilePicker` (Chrome/Edge/Brave/Opera), files ≥50 MB skip the in-memory Blob copy and write decrypted plaintext directly to a user-picked destination via `FileSystemWritableFileStream`. Memory peak drops from ~3× to ~2× file size on supported browsers; falls back transparently to the Blob path on others.
- Cross-tab sync via BroadcastChannel (~200 ms convergence on same origin).
- Cross-device sync via periodic manifest poll (~15 s).
- ETag-conditional PUT (`If-Match`) for concurrent-write safety. On 412 the writer re-fetches, splices its pending events on top, and retries up to 3×.
- Device-pairing UI: real QR matrix encoder for the `CRATE-PAIR-…` token.
- Hetzner / Backblaze B2 / AWS S3 endpoint support via the same sig-v4 client (algorithmically correct; R2 verified live).
- Cross-surface byte-identical interop with the [`crate-agent`](https://github.com/NakliTechie/crate-agent) Go daemon.
- Docs: encryption-model, ESM API reference, backup runbook (incl. bucket-credentials rotation).
- GitHub Actions: smoke checks run on every push to main + on every PR.

### Notes

- v1 has **one credential**: the passphrase. There is no recovery phrase, email-reset, or support backdoor. Redundancy comes from running the daemon + backing up the local mirror, mirroring the bucket with `rclone`, or R2 object versioning (see [`docs/backup.md`](docs/backup.md)).
- The pairing flow currently sends `identity_pubkey: "browser-stub"` in the intent payload. Authentication is enforced by the `X-Fabric-Grant` macaroon. Real per-browser Ed25519 identity binding lands with the nakliOS Identity integration.

### Considered for v1, explicitly out of scope

- **True streaming decrypt** (chunk-level, peak memory = chunk size). WebCrypto's AES-256-GCM requires the full ciphertext before yielding plaintext (auth tag at the end). True streaming needs chunked AEAD — a v2 wire format with per-segment tags and matching browser + daemon changes. v1 ships the FSA streaming-write path (above) which solves the desktop large-file case without breaking the wire format. Mobile large-file downloads remain memory-capped.
- **Camera-based QR scanning** for pairing tokens. QR display ships; the daemon is CLI with no camera, and OS-level QR-OCR (iOS Camera, Android Lens) already handles the human-OCR-the-screen case. No browser-side consumer means no scanner.
- **Trash / undelete UI.** `crate.remove()` issues a real DELETE; soft-delete needs a GC pass design that we don't have. Out of v1.
- **Public / shared file URLs.** v1's model is "passphrase = full access"; sharing requires per-file share keys orthogonal to the master key — new crypto design, v2.
- **Non-R2 provider end-to-end verification on real buckets.** Algorithmically supported; manual gate per provider account.

These are documented here so future contributors know the difference between "forgotten" and "explicitly deferred with a reason."
