# Changelog

All notable changes to Crate. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [SemVer](https://semver.org/spec/v2.0.0.html); see the Versioning section in the README for what counts as breaking.

## [Unreleased]

## [1.0.1] — 2026-05-21

### Security — second round (manifest rollback)

The architecturally-deferred finding from the 2026-05 audit has now landed. It required new code (anchor storage + per-call-site wiring), not a one-line patch; broken out from the v1.0.0 quick fixes so the changelog reflects the work.

- **H2 — manifest rollback / truncation detection** ([`<pending>`](https://github.com/NakliTechie/crate/commit/HEAD)). A bucket-only attacker can serve an older valid encrypted manifest — AES-GCM + the prev_sig chain both pass on the prefix, so the browser previously accepted it silently. Fix: per-bucket `{count, lastSig}` rollback anchor in **new `lib/anchor.js`**, persisted to IndexedDB (primary) with sessionStorage fallback for private-browsing / storage-blocked contexts. `Crate.open`, `Crate.bootstrap`, `Crate._flushManifest` (412-replay path), and `SyncClient._pollManifest` all validate against the anchor before accepting a manifest — **truncation** (loaded.count < anchor.count) and **fork** (chain diverges at the anchor point) both throw `ManifestRollbackError` and abort the load/poll. First-load is TOFU + `console.log`; subsequent loads enforce monotonic growth. New `Manifest.tail()` returns the `{count, lastSig}` pair for the writer-path anchor advance.

### Security — patches from the 2026-05 audit (from v1.0.0; recap)

OpenAI Codex (gpt-5.5) reviewed the crypto + sync paths under a defined threat model and turned up four High + one Medium + one Low finding. All quick fixes landed:

- **H1 — Object ciphertext rollback** ([`3699c86`](https://github.com/NakliTechie/crate/commit/3699c86)). `Crate.read`, `FolderUI.handleDownload`, `FolderUI.handlePreview` now verify the object body's leading IV against the manifest-signed `content_iv` (constant-time compare) before decrypting. Closes the "bucket attacker replays older valid ciphertext for the same UUID" path.
- **H3 — `Crate.open` lastFlushedEventCount init** ([`3699c86`](https://github.com/NakliTechie/crate/commit/3699c86)). Constructor now derives the initial high-water mark from `manifest.events.length` instead of leaving it undefined.
- **H4 — SyncClient erasing unflushed events** ([`3699c86`](https://github.com/NakliTechie/crate/commit/3699c86)). `_pollManifest` now skips the wholesale event-replace when local has unflushed events; the next `_flushManifest` 412 retry reconciles correctly.
- **M1 — Manifest signatures not verified on load** ([`3699c86`](https://github.com/NakliTechie/crate/commit/3699c86)). `Manifest.loadFromBytes` calls `verify(masterKey)` after parsing.

Full report: [`docs/security-review-2026-05-codex.md`](docs/security-review-2026-05-codex.md).

### Previously deferred — now landed in v1.0.1

H2 (manifest rollback / truncation) was deferred from v1.0.0 with the rationale that it needed real new code (persistent anchor storage). It landed in v1.0.1 above. No outstanding audit items.

### Added — encrypted credentials file

Two-factor unlock pattern: "thing you have" (a `.crate-creds` file) + "thing you know" (your passphrase). Replaces the previous 5-input unlock with a file picker + passphrase.

- **New module `lib/credsfile.js`** — `pack(creds, passphrase)` produces a JSON envelope `{v, type, hint, kdf, salt, iv, ct}`. Same primitives as the master key (PBKDF2-SHA256/600k iter + AES-256-GCM); independent salt per file. `unpack(bytes, passphrase)` validates + decrypts + returns the bucket + credentials. `peekHint(bytes)` reads only the plaintext hint field (the bucket name) without the passphrase — used by the Unlock UI to label "Welcome back to `<name>`" before the user types anything. `suggestedFilename(bucketName)` returns `"<bucket-name>.crate-creds"`.

- **Onboarding Done stage** gains a prominent "Download credentials file (recommended)" button with a hint card explaining what it does and why it's not auto-downloaded. File downloads as `<bucket-name>.crate-creds`.

- **Folder UI gets a `🔐 Credentials` button** in the utility toolbar so the same download is available any time the folder is open — covers users who skipped the Done-stage download or who came in via the manual 5-input unlock. Session memory now carries `passphrase` + `bucket.{name, accountId}` so the file can be rebuilt without re-prompting; same threat-model tier as the in-memory master key.

- **Unlock screen rewritten** with two modes:
  - **File mode (default)**: drag-drop / click-to-pick a `.crate-creds` file. Drop zone shows file-loaded state with the bucket-name hint pulled from the envelope. Passphrase input is disabled until a file is loaded; Enter key submits. Wrong passphrase shows a clear "Wrong passphrase, or the credentials file is corrupt" message. AES-GCM auth-tag failure is the discriminator.
  - **Manual mode**: original 5-input form preserved as fallback for users who don't have the file (lost it, on a new device, etc.).
  - Toggle between modes via inline links; no separate route or state.

- **Refresh-resilient session** — after a successful first-time setup OR a successful unlock, the encrypted creds blob is stashed in `sessionStorage` (NOT localStorage; tab-scoped). On page reload, the wizard detects the blob, routes straight to the Unlock screen with the file pre-loaded from session memory, and shows "Welcome back to `<bucket-name>`. Enter your passphrase to reopen it." The passphrase + master key still don't persist; the blob is useless without the passphrase. Cleared on explicit Start-over / reset.

### Threat-model notes

The credentials file doesn't weaken anything. Attacker with file only is back to PBKDF2/600k + AES-256-GCM brute force — same security floor as the bucket's master key derivation. Attacker with passphrase only has nothing more than they had before. The file makes carrying the four bucket strings a single artifact you can put in 1Password / USB drive / wherever you keep secrets. Threat-model details in `docs/encryption-model.md`.

### Notes for naklios integration

The same encrypted blob format that downloads as the file can be reused by the nakliOS Settings panel:
- "Set up a new folder" → opens crate.naklios.dev wizard
- "I have a Crate already" → file picker + passphrase + optional "Remember this folder on this device" checkbox
- Remember-on = store the encrypted blob in nakliOS-managed IndexedDB
- Boot flow becomes one-passphrase unlock; nakliOS broadcasts a `crate-session-ready` event after decrypting
- Apps that bind against the Crate ESM API attach to the shared session

Naklios implementation lives in the `nakli-dev` repo when ready; this build exposes the building blocks.

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
