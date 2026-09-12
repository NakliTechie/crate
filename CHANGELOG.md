# Changelog

All notable changes to Crate. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [SemVer](https://semver.org/spec/v2.0.0.html); see the Versioning section in the README for what counts as breaking.

## [Unreleased]

### Added — recovery phrase (T1, phases 3–4)

- **New folders are v1.1 vaults.** `Crate.bootstrap()` mints a random content key and writes `.crate/crate.json` with a `passphrase_wrap` and — when the user keeps a recovery phrase — a `recovery_wrap`; either slot recovers the key. `Crate.open()` takes `passphrase` or `recoveryEntropy`. v1.0 vaults open exactly as before; the daemon has parsed v1.1 since v1.2.0 (`internal/cratejson`). The wizard's first-time setup now goes through `Crate.bootstrap()` instead of its own copy.
- **Recovery stage** between passphrase and Done on both routes: 24 BIP-39 words (`lib/recovery.js`, 256 bits of entropy + checksum), type three back to continue, **Different words**, **Copy phrase**, or **Skip for now** (passphrase-only vault; enabling later is phase 6). The grid never elides a word — 2 columns on phones, 4 on desktop. Done's reminder and the save acknowledgement mention the phrase when it was kept.
- **Lost your passphrase? Use your recovery phrase.** On the unlock screen (manual details — the credentials file is sealed under the passphrase that was lost), choose **Recovery phrase**, paste the 24 words (checked as you type: word count, unknown word, checksum), and Crate opens the folder and asks for a **new passphrase** — the same five-words-or-your-own stage as setup. The new passphrase is written with `If-Match` on `crate.json` so two devices can't clobber each other; the recovery slot stays; nothing is re-encrypted.
- **Backup → Set up a recovery phrase / Change passphrase.** Existing folders get the phrase after the fact: 24 words in a dialog, three typed back, one conditional write of `crate.json`. A v1.0 folder is moved to v1.1 in that same write without changing its key — nothing is re-encrypted and a paired daemon keeps working — with the trade-off recorded in `docs/encryption-model.md` (an old passphrase plus an old copy of `crate.json` still derives the key; a full re-key is a later operation). Change passphrase validates strength as you type (20-bit refusal, 55-bit recommendation) and re-seals the refresh-resume stash under the new one.
- ESM API (additive): `Crate.open({ recoveryEntropy })`, `crate.setPassphrase(newPassphrase)`, `crate.enableRecovery(entropy)`, `crate.hasRecovery`.
- `lib/vault.js`: `sealVault` / `openVault` / `rewrapVault` — the one place that knows the key slots; unlock-via-phrase (phase 5) and enable-recovery (phase 6) build on it. Tests: `test/vault.test.mjs`, `test/crate-vault.test.mjs` (bootstrap + open by either credential against an in-memory bucket, wrong credential named, legacy v1.0 still opens).

### Added — install it, open it offline

- **Installable** (`manifest.webmanifest`, icons) and served by a service worker (`sw.js`) that caches this origin's static files network-first with a short timeout — a deploy still propagates on the next load, a dead network still opens the app. Bucket and carrier traffic never passes through it.
- **Offline open.** Every successful fetch of `crate.json` and the manifest is kept, sealed, in IndexedDB per bucket (`lib/offline.js`); with the network down, `Crate.open` falls back to it, the passphrase still unwraps the key, the manifest still verifies, and the folder lists as last seen with an "Offline" banner. Downloads and changes are refused until reconnect; the copy is dropped on Lock. Queued writes are not built (see `docs/prior-art.md`).
- Fixed: **Start over** after a failed or finished setup left the previous outcome in place, so a second setup in the same tab never ran.

### Added — PDF, audio and video previews

- Preview opens PDFs in the browser's own viewer (a frame over the decrypted blob), and plays audio and video with the native `<audio>` / `<video>` elements — whole-file decrypt in the tab, so the 50 MB preview cap applies; streaming decrypt over Range requests is a later step. Formats the browser can't play say so and point at Download. The shared-file page previews the same kinds. CSP gains `media-src 'self' blob:` and `frame-src blob:`.

### Added — share links

- **Share link** on any file: a URL that lets anyone who has it download that one file for 1 hour, 1 day or 7 days. The fragment (`#share=…`, never sent to a server) carries a presigned GET for the object — sig-v4 query auth on R2/S3/B2/Hetzner (`lib/sigv4.js::presignUrl`, pinned to the AWS reference vector), or the carrier's new `?share=1&exp&sig` route — plus the file's own data key, the manifest-signed IV and chunk size. The recipient page (the same `index.html`, locked shell, one card) fetches ciphertext with no credentials and decrypts in the tab: Download, and Preview for text and images. Nothing else in the folder is reachable; revoke early by rotating the carrier secret / R2 token, or Delete forever. A carrier deployed before this is detected via `/health` and told how to sync its fork. Tests: `test/share.test.mjs`, `test/sigv4-presign.test.mjs`.

### Added — Trash

- **Delete moves to Trash.** The object stays in your storage for 30 days; the **Trash** view (sidebar, with a count) lists deleted files with where they were and when, and offers **Restore** (back to the old path, or `name (restored).ext` if taken), **Delete forever**, and **Empty trash**. Expired items are purged by whichever browser opens the folder. Restore is a plain `create` with the same uuid, so the daemon and older readers see the same tree; removal is recorded by a new `purge` event that older readers ignore. A file deleted from the daemon side has its bytes removed at once — restoring it from the browser says so. `Crate.remove()` (ESM) still deletes immediately. Tests: `test/trash.test.mjs`.

### Added — multi-select

- Tick files (the icon cell becomes a checkbox on hover; shift-click selects a range; **Select all**; Escape clears) and act on the lot: **Download** (a zip through the export path, streamed to disk when the browser can), **Move to…** (a typed destination, existing folders listed, created if new; name clashes refused before anything moves), **Delete** (one confirmation naming the files). Folders stay single-action for now.

### Changed — no more browser prompts

- **New folder**, **Rename** and **Pair an agent** open an in-app dialog (`lib/dialog.js`: labelled fields, inline validation while you type, Enter confirms, Escape cancels, focus trapped and returned) instead of `window.prompt()`. The browser prompt ignored the theme, blocked the tab, and on a phone a mis-aimed tap froze the renderer during the 2026-09-10 walk.
- Names are checked as you type: empty, slashes, `.`/`..`, and — new — a name already present in the folder ("Something called “Photos” is already here"), closing the "mkdir conflict" confusion from the May behavioural audit. Pair asks for the transport URL and the Grant in one dialog.
- `smoke.sh` refuses a native `prompt()` the way it already refused `confirm()`.

## [1.1.0] — 2026-09-12

Minor, not major: the manifest gained an optional signed key, v1 objects stay readable, every new check fails closed, and the 9-method ESM API, the `.crate-creds` format and CRATE-PAIR are unchanged. New writes use the v2 object framing; crate-agent ≥ v1.2.0 reads and writes it byte-identically.

### Changed — the shell is the landing (file-manager-first redesign)

The page opens as a file manager, not as a setup wizard. A persistent shell — topbar (wordmark, search, actions) and sidebar (**All files · Recent · Photos · Devices · Backup**) — frames every state. Locked, the sidebar is dimmed and the content area holds one card: a headline, **Get started — about a minute**, and **Already set up? Open your folder**. The wizard's stages render in that same column; at Done the folder replaces the card and the sidebar lights up. Nobody leaves the frame they landed in.

- **Light theme by default**, dark under `prefers-color-scheme: dark`. One accent, working on the primary action, focus and the active view; warm neutral ramp elsewhere (`index.html` tokens). Direction: Calm.
- **Landing copy** drops the jargon at first sight: no bucket / R2 / Worker / API token / AGPL on the first screen. Prerequisites live at the top of the carrier stage, where they apply. **Set up with your own bucket** becomes the **Use a bucket you already have** link under the card. The **What is Crate?** explainer no longer auto-opens on first visit — **How it works** (card + topbar) opens it on demand.
- **Folder UI**: toolbar is **Upload** + **New folder**; search moves to the topbar; Refresh and Lock move to the `···` menu; **Pair an agent** lives in the **Devices** view; the credentials file and **Export everything** live in the **Backup** view, next to the passphrase reminder. Rows show Name · Modified · Size with a column header; row actions replace the metadata on hover (always visible on touch). File-type icons are inline SVG (`lib/icons.js`) instead of emoji.
- **Recent** (last 50 files by manifest timestamp, with the parent folder under each name) and **Photos** (every image, with a count in the sidebar) are derived from the manifest — no new events, no thumbnails (that would mean decrypting every image on open).
- Narrow screens: the sidebar becomes a scrollable row of view pills under the topbar; the locked state hides it and the search field so the card fills the screen. The three-row toolbar wrap at 375 px is gone with the toolbar.
- New modules `lib/shell.js` (topbar + sidebar wiring) and `lib/icons.js`; `FolderUI` gains `view`, `setView()`, `entriesForView()` and takes `opts.shell`; the wizard exposes `openHelp()`. `smoke.sh` checks the shell contract instead of the removed auto-open.
- `guide/index.html` follows: light palette (dark with the system), the landing and folder mock screens drawn as the shell, the toolbar/actions sections rewritten around the sidebar views and the `···` menu.
- Not changed: the wizard stages themselves, the wire format, the ESM API, `.crate-creds`, pairing.

### Added — one-click onboarding through a carrier Worker

- **Set up with one click** on the landing page: a new `carrier` route (`welcome → carrier → passphrase → done`) replaces the four manual stages (bucket, credentials, CORS, account ID) with Cloudflare's Deploy button pointed at [`crate-carrier`](https://github.com/NakliTechie/crate-carrier). The Deploy flow provisions the R2 bucket itself — verified: no API token is created or entered anywhere.
- `lib/bucket.js` gains a second transport selected by `region === "carrier"`: HMAC-signed requests to the user's Worker, `resolveBase()` for both providers, a `carrierProbe()` for the wizard, and automatic R2 multipart for bodies over 90 MiB (100 MiB is Cloudflare's per-request edge cap; measured working at 100 MiB in 7 parts). Every existing call site is unchanged — they already threaded `region`.
- `.crate-creds` carries `provider: "carrier"` with `bucket.url`; the same envelope, same passphrase wrap. `Crate.open` / `bootstrap`, unlock, the folder's creds re-emit and the NakliOS handoff all go through the provider.
- The Worker's own page links back to `crate.naklios.dev/#carrier=<its url>`, so the return trip needs no copying; the carrier secret is parked in `localStorage` for the duration of onboarding only (`docs/encryption-model.md` § Two carriers).
- CSP `connect-src` is now `'self' https:` — a carrier on your own domain is as reachable as one on `workers.dev`. Rationale in `docs/encryption-model.md` § What the page may talk to.
- ETags from any transport are normalised (`cleanEtag`): Cloudflare's edge rewrites the ETag on compressed responses to a weak `W/"…"`, which silently broke the manifest's `If-Match`.
- The original four-stage route remains as **Set up with your own bucket**.
- **Fixed before release:** `carrierProbe()` spread the Worker's health record (which carries its own `ok: true`) *after* its verdict, so a mismatched `CARRIER_SECRET` — and a Worker with no secret or no bucket — reported "secret matches" and setup failed at the first write instead of at Verify. Found on the phone-viewport walk; the verdict now wins, and `test/carrier-transport.test.mjs` pins all six probe outcomes.
- Status pills wrap on narrow screens instead of drawing their border through the second line.
- Tests: `test/carrier-transport.test.mjs`. Walked end to end against a Deploy-button-provisioned Worker: setup, two uploads, and an independent read-back with matching SHA-256s.

### Fixed — the five suggested words open the folder with spaces or dashes

Found on the live-site walk of the redesign: the passphrase stage shows five word chips and says "write them down", but the passphrase is stored dash-joined (`sphere-cancel-scan-blanket-interest`). Typing the words with spaces on unlock failed with `manifest: decrypt failed: OperationError`. Every unlock path (credentials file, manual details, refresh-resume) now tries the typed form, then spaces→dashes and dashes→spaces, and adopts the one that opens (`lib/passphrase.js`, `test/passphrase.test.mjs`). Only wrong-passphrase failures are retried; network and schema errors are not. The stage now says the passphrase is the five words joined with hyphens and shows the exact string to type under the chips (the desktop daemon's `pair` prompt takes only that form); a wrong passphrase reads as a sentence instead of an `OperationError`.

### Security — audit follow-through (May 2026, unreleased until now)

- **Manifest signatures fail closed.** `manifest.loadFromBytes` now verifies the HMAC chain it previously only computed; an invalid or broken chain refuses to load instead of materialising a tree. Held back in May for the cross-surface interop gate; the daemon has carried the same check since.
- **H1 propagated to export.** `export.js` verifies each fetched object's leading IV against the manifest-signed `content_iv` before decrypting (constant-time), as `Crate.read()` and the folder's download/preview already did — a replayed older object can no longer land stale plaintext in a backup zip.
- **H2 propagated to Refresh.** The folder's manual Refresh runs the rollback-anchor check (`loadAnchor → validate → saveAnchor`) before trusting a re-fetched manifest, matching `Crate.open`, the 412-replay and `SyncClient`.
- **Partial-upload orphans.** A batch upload that fails mid-way now flushes the events already appended, so objects that did reach the bucket are recorded rather than orphaned; the banner reports the partial count.

### Added — May 2026

- **Recovery-credential foundation (T1, phases 1–2).** `lib/recovery.js` restored, dual-wrap key derivation in `lib/crypto.js`, and the `.crate/crate.json` v1.1 schema (`passphrase_wrap` + `recovery_wrap`) parsed and written by `lib/cratejson.js`; `Crate.open` takes either branch. `Crate.bootstrap()` still writes v1.0 — the wizard stage and the unlock-via-recovery route are the open phases 3–8.
- **Send to NakliOS.** Opened by NakliOS in handoff mode (`?naklios-handoff=v1`, framed, origin allow-listed to `https://naklios.dev`), the Done stage offers a primary button that posts the encrypted `.crate-creds` envelope to the parent — strict ack provenance (origin + source + nonce), 15 s timeout, explicit click only. CSP `frame-ancestors` opened from `'none'` to `'self' https://naklios.dev` for exactly this.
- **Delete confirmation is an in-app modal** (`renderDeleteConfirmModal`), keyboard-reachable, instead of the browser's blocking popup; `smoke.sh` refuses a native `confirm()`.
- **Landing-first welcome and the "What is Crate?" explainer** (superseded by the shell redesign above, kept here for the record): the welcome stage stopped rendering as "step 1 of 6", and the three-point privacy promise was written once and shared with the explainer.

### Changed — chunked object framing (v2)

Files are now encrypted as independent AES-256-GCM chunks (8 MiB plaintext each) rather than one blob, so the per-chunk memory ceiling no longer scales with file size and each chunk can later be uploaded as its own R2 multipart part. `lib/crypto.js` gains `sealObject` / `openObject`, the only producer and consumer of an `objects/{uuid}` body; the four read sites (`Crate.read`, folder download, folder preview, export) and three write sites that each carried their own copy of the parse-and-verify logic now share them.

- **Per-chunk AAD is `uuid:base64(IV_0):index:total`.** Binding `IV_0` (the manifest-signed `content_iv`) closes the cross-version splice that per-chunk framing would otherwise open — a chunk from an older write of the same file at the same index no longer authenticates. Index and total close reorder and truncation; the body length is checked against the signed `size` before any decryption.
- **Manifest `create` / `update` events gain an optional `chunk_size`.** Its presence is the v1/v2 discriminator and it lives inside the HMAC-signed event, so the bucket cannot change a file's format. It is per-version: an `update` without it reverts the entry to v1, so an older single-blob writer stays correct. v1 events are emitted byte-identically (the key is omitted, not `null`).
- **v1 objects remain readable** through the same entry point; a file becomes v2 on its next write. No migration pass.
- Tests: `test/chunked-crypto.test.mjs` (round-trips at chunk boundaries, 14 tamper classes, v1 compatibility, AAD canonical form) and `test/manifest-chunked.test.mjs`. `docs/encryption-model.md` updated in the same change.
- **Cross-surface:** crate-agent v1.2.0+ seals and opens v2 objects byte-identically (`test/cross-surface-daemon.test.mjs` pins a daemon-sealed fixture); v1.3.x adds the carrier transport and `pair --carrier`. An older daemon fails closed on v2 objects rather than reading them wrong.

## [1.0.2] — 2026-05-22

### Security — extend H2 anchor coverage to the folder write path

The H2 manifest-rollback anchor checks added in v1.0.1 covered `Crate._flushManifest`, `Crate.open`, and `SyncClient._pollManifest`, but not the FolderUI's separate `flushManifest` copy — the wizard's folder UI writes through its own near-duplicate implementation, and that copy did not advance the anchor on success or validate the re-fetched manifest against the anchor on a 412 retry.

- **`FolderUI.flushManifest` now advances the rollback anchor on successful PUT** ([`4df3632`](https://github.com/NakliTechie/crate/commit/4df3632)). Calls `anchor.saveAnchor(bucketBase, manifest.tail())` after the PUT acks; best-effort try/catch matches `Crate._flushManifest`. Closes the cross-tab gap where a user writing via the folder UI in tab A would leave the saved anchor pinned at whatever count tab A read on open.
- **412-replay path now validates the re-fetched manifest** ([`4df3632`](https://github.com/NakliTechie/crate/commit/4df3632)). `anchor.loadAnchor` + `anchor.validate` on `fresh.events` before trusting the re-fetched manifest. A bucket-only attacker who races a PUT to induce the 412 could otherwise serve an older valid manifest in the re-GET — AES-GCM and the prev_sig chain both pass on a valid prefix, so this is the layer that catches the swap. Matches `Crate._flushManifest` and `SyncClient._pollManifest`.

### Refactored — single source of truth for flushManifest

Discovered during the H2-coverage patch: `Crate._flushManifest` and `FolderUI.flushManifest` had drifted for over a release cycle precisely because they were near-duplicates. The duplication has now been eliminated.

- **New `lib/manifest-flush.js` module** ([`8dbb6f0`](https://github.com/NakliTechie/crate/commit/8dbb6f0)) exports a single `flushManifest(state, opts)` function carrying the full flush + 412-replay + anchor logic. Both surfaces delegate:
  - `Crate._flushManifest` builds a small getter/setter adapter mapping its `_`-prefixed instance properties onto the unprefixed shape the shared function expects. Writes to `manifestETag` / `lastFlushedEventCount` propagate back to `this._manifestETag` / `this._lastFlushedEventCount`.
  - `FolderUI.flushManifest` passes `this.session` through directly — the session object already matches the unprefixed shape.
  - `errorFactory` injection lets each caller keep its own thrown type (`CrateError` for the ESM API; plain `Error` for the FolderUI banner).
- Net change: +180 / −155 across `crate.js` + `folder.js` + the new module. No behavioural change. `node --check` + `./smoke.sh` clean.

The class of drift that produced the H2-coverage gap can no longer recur — the anchor logic lives in one place.

### Notes

- Wire format is unchanged. v1.0.2 reads and writes byte-identical bucket state as v1.0.1; no migration required. v1.0.2 ↔ v1.0.x interop is fully preserved.
- `NakliOS`'s vendored copy under `vendor/crate/v1.0.1/` is being refreshed to v1.0.2 in a parallel commit. The v1.0.1 vendor copy already had the Crate-side H2 checks; only the FolderUI path was affected, and NakliOS uses the Crate ESM API directly (no FolderUI). The refresh is for the dedupe + smaller surface.

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

The same encrypted blob format that downloads as the file can be reused by the NakliOS Settings panel:
- "Set up a new folder" → opens crate.naklios.dev wizard
- "I have a Crate already" → file picker + passphrase + optional "Remember this folder on this device" checkbox
- Remember-on = store the encrypted blob in NakliOS-managed IndexedDB
- Boot flow becomes one-passphrase unlock; NakliOS broadcasts a `crate-session-ready` event after decrypting
- Apps that bind against the Crate ESM API attach to the shared session

NakliOS implementation lives in the `nakli-dev` repo when ready; this build exposes the building blocks.

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
- The pairing flow currently sends `identity_pubkey: "browser-stub"` in the intent payload. Authentication is enforced by the `X-Fabric-Grant` macaroon. Real per-browser Ed25519 identity binding lands with the NakliOS Identity integration.

### Considered for v1, explicitly out of scope

- **True streaming decrypt** (chunk-level, peak memory = chunk size). WebCrypto's AES-256-GCM requires the full ciphertext before yielding plaintext (auth tag at the end). True streaming needs chunked AEAD — a v2 wire format with per-segment tags and matching browser + daemon changes. v1 ships the FSA streaming-write path (above) which solves the desktop large-file case without breaking the wire format. Mobile large-file downloads remain memory-capped.
- **Camera-based QR scanning** for pairing tokens. QR display ships; the daemon is CLI with no camera, and OS-level QR-OCR (iOS Camera, Android Lens) already handles the human-OCR-the-screen case. No browser-side consumer means no scanner.
- **Trash / undelete UI.** `crate.remove()` issues a real DELETE; soft-delete needs a GC pass design that we don't have. Out of v1.
- **Public / shared file URLs.** v1's model is "passphrase = full access"; sharing requires per-file share keys orthogonal to the master key — new crypto design, v2.
- **Non-R2 provider end-to-end verification on real buckets.** Algorithmically supported; manual gate per provider account.

These are documented here so future contributors know the difference between "forgotten" and "explicitly deferred with a reason."
