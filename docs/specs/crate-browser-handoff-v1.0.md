# Crate Browser — Coding Agent Handoff v1.0

**Audience:** Coding agent (Claude Code) building Crate v1.0 browser surface
**Repo:** `NakliTechie/crate` (new repo, will be created at build start)
**Sibling references:** `NakliTechie/private-mesh` (primitives + SDKs), `NakliTechie/saanjha` (shared-list consumer tool, similar shape)
**Spec source of truth:** `crate-vision-and-roadmap-v1.0.md`
**Pairing protocol (cross-surface contract):** `crate-pairing-protocol-v1.0.md`

Read the vision doc first. Read the pairing protocol doc before implementing M7 — that's the binding spec for pairing-token issuance. This doc covers non-spec gaps for the browser v1.0 build only. The daemon (v1.2+) has its own handoff: `crate-daemon-handoff-v1.0.md`.

---

## Licence

**This repository is AGPL-3.0.**

- Every code file gets an SPDX header: `// SPDX-License-Identifier: AGPL-3.0-or-later`
- `LICENSE` file at repo root contains the full AGPL-3.0 text
- `README.md` includes a "Licence" section stating AGPL-3.0 and linking to LICENSE
- Specs and documentation files (`docs/*.md`) get a footer noting CC BY-SA 4.0
- **Do not introduce dependencies whose licences are incompatible with AGPL-3.0.** Apache-2.0, MIT, BSD, ISC, MPL-2.0 are all fine. GPL-2.0-only is incompatible. Proprietary or no-licence code is forbidden. Document every vendored dependency's licence in `lib/vendor/LICENSES.md`.

## Build target

Single HTML file at `index.html`, all JS as ES modules in `lib/`. No build step. No framework. No bundler. Loads in modern Chromium-based browsers (Chrome/Edge/Brave/Arc/Opera ≥ last 2 versions). Safari and Firefox: best-effort, not v1.0 gates.

## Browser floor

- ESM (`<script type="module">`)
- Web Crypto (`SubtleCrypto`) — AES-GCM, PBKDF2, HMAC-SHA256
- `fetch` with streams + `ReadableStream`
- IndexedDB (session state only — never user file content)
- Clipboard API (for copy buttons in onboarding)
- `BarcodeDetector` if available, fallback to manual paste

No FSA required in v1.0. No service worker. No WebRTC.

## Repository layout

```
crate/
  index.html               # single-page UI, onboarding + folder
  lib/
    crate.js               # exports Crate class (ESM API / programmatic surface)
    crypto.js              # AES-GCM + PBKDF2 + HMAC wrappers
    bucket.js              # S3-compatible HTTP client (sig-v4, no aws-sdk)
    manifest.js            # signed JSONL event log read/append/verify
    sync-client.js         # binds to Sync primitive from fabric-sdk-js
    onboarding.js          # wizard state machine
    qr.js                  # QR encode/decode (vendored, no CDN)
    recovery.js            # 24-word phrase encode/decode (BIP-39)
    wordlist.js            # BIP-39 English wordlist (vendored)
    vendor/
      LICENSES.md          # all vendored dep licences listed
  docs/
    README.md              # what Crate is, install, use
    encryption-model.md    # crypto details for security review
    esm-api.md             # contract docs for downstream tools
  LICENSE                  # AGPL-3.0
  CONTRIBUTING.md          # how to contribute (and the CLA position)
  smoke.sh                 # M0 placeholder, same convention as private-mesh
```

## Dependencies

**Allowed:**
- `fabric-sdk-js` from `NakliTechie/private-mesh` (Apache-2.0) — Sync, Identity, Vault, Grant, History clients
- Small vendored libraries placed in `lib/vendor/`, each with source URL + version + licence in a header comment:
  - QR encoder/decoder (~5kb, look for MIT-licensed options like `qr.js` or similar)
  - BIP-39 English wordlist as plain text data (public domain)
- Web Crypto API (built-in, no vendoring)

**Forbidden:**
- `aws-sdk` (build sig-v4 yourself, ~100 lines of HMAC-SHA256)
- Any cloud-provider SDK (we are S3-compatible, not provider-specific)
- Any CDN imports at runtime
- Any analytics, telemetry, or error-reporting service
- Any framework (React, Vue, Svelte, lit-html — vanilla JS only)
- Any GPL-2.0-only dependency (incompatible with AGPL-3.0)
- Any dependency lacking an explicit OSI-approved licence

## S3 sig-v4 implementation

Don't reach for a library. The auth header is ~100 lines of HMAC-SHA256. Test against:
- R2 (Cloudflare) — primary launch surface
- B2 (Backblaze) — secondary, validates the abstraction
- Hetzner Object Storage — tertiary
- AWS S3 — must work but not a launch surface

## Persistence rules

**In the bucket:**
- Ciphertext blobs at `objects/{uuid}`
- Manifest at `.crate/manifest.jsonl.enc` (encrypted, append-only)
- Bucket metadata at `.crate/crate.json` (salt, version, public Identity info)

**In IndexedDB:**
- Session cache only — decrypted manifest, working tree, in-flight upload state
- Clearable at any time, fully re-derivable from bucket

**In localStorage:**
- UI preferences only (theme, pane widths, last-used-device-name)
- Never bucket keys, passphrase, derived key, or recovery phrase

**In sessionStorage (opt-in only):**
- "Remember in this tab" stores bucket Access Key + Secret for the session
- Cleared on tab close
- Explicit user opt-in required, never default

**In memory only:**
- Master AES key (derived from passphrase via PBKDF2)
- Recovery phrase (only during recovery flow, cleared on stage exit)
- Held as non-extractable `CryptoKey` where SubtleCrypto allows

## Encryption details

- Master key = `PBKDF2-SHA256(passphrase, salt, 600_000 iterations, length=256)`
- Salt: 16 random bytes, stored in `.crate/crate.json`
- Recovery phrase: 24 words from BIP-39 English wordlist, encodes 264 bits (256 entropy + 8 checksum)
- Each file encrypted with a fresh random data key (32 bytes)
- Data key wrapped by master key using AES-KW or AES-GCM
- Per-file IV = 12 random bytes prepended to ciphertext
- AES-GCM auth tag handled by SubtleCrypto
- Manifest events signed with HMAC-SHA256 using master key

Bucket compromise leaks: file count, object sizes, access patterns. Reveals nothing about contents, filenames, or folder structure.

## Manifest format

JSONL, encrypted at the file level (`.crate/manifest.jsonl.enc`). Each line after decryption:

```json
{"v":1,"ts":1747572345000,"op":"create","uuid":"01H...","path":"/notes/foo.md","size":1234,"mime":"text/markdown","sig":"..."}
{"v":1,"ts":1747572400000,"op":"update","uuid":"01H...","size":2345,"sig":"..."}
{"v":1,"ts":1747572500000,"op":"delete","uuid":"01H...","sig":"..."}
{"v":1,"ts":1747572600000,"op":"move","uuid":"01H...","path":"/notes/foo-renamed.md","sig":"..."}
```

`sig` = HMAC-SHA256 of the event minus `sig` field, using master key. Manifest tampering is detectable.

Bind to `fabric-sdk-js` History primitive — don't reinvent.

## Onboarding wizard

The wizard is the product for the first 3 minutes. It must work flawlessly.

**State machine stages (new folder mode):**
1. Welcome — explain what's needed, two routes (New folder / Add device)
2. Bucket — create R2 bucket via deep link, paste name + Account ID, verify
3. Credentials — create scoped API token, paste Access Key + Secret, test auth
4. CORS — copy CORS JSON, paste into bucket settings, run preflight test
5. Passphrase — strength meter (target ≥70 bits entropy), confirm, optional generate
6. Recovery — display 24-word phrase, confirm 3 random positions
7. Done — folder ready, prompt to install daemon (deferred to v1.2)

**Pair-device stages (separate flow):**
1. Pair — accept QR scan or pairing code paste, enter passphrase, unlock
2. Done — folder appears, other devices notified

**Cross-cutting requirements:**
- Mobile-first responsive. The wizard must work on a phone screen — that's a primary usage moment.
- Each step has clear "you are here" indication (top progress bar)
- Deep-link buttons open Cloudflare dashboard pages in new tabs
- Copy buttons on every block the user must paste back into Cloudflare
- Bucket name pre-generated (e.g. `crate-{8 random alphanumerics}`), user can override
- Validation pills: Waiting → Checking → ✓ Found / ✗ Failed (with retry)
- "Back" always works, "Next" disabled until current step verified

**Reference mock:** `crate-onboarding-mock.html` in the outputs folder. Use its visual language and interaction patterns; implement against real Cloudflare APIs for v1.0.

## Folder UI (post-onboarding)

- File tree (left, collapsible on mobile)
- Preview pane (right, or full-screen on mobile)
- Top bar: path breadcrumbs, search, upload button, device indicator
- Right-click / long-press menu: rename, delete, move, download, "Open in [tool]"
- Drag-drop upload anywhere on tree
- Status bar (bottom): sync state, last activity, device count

## Design tokens + icons

Match NakliTechie portfolio style:

```css
--bg: #0a0a0a;
--surface: #141414;
--surface-2: #1c1c1c;
--border: #262626;
--border-strong: #3a3a3a;
--text: #e5e5e5;
--muted: #737373;
--muted-2: #525252;
--accent: #fafafa;
--ok: #4ade80;
--warn: #fbbf24;
--error: #f87171;
--link: #93c5fd;

font-family: system-ui, -apple-system, sans-serif;
font-mono: ui-monospace, 'SF Mono', Menlo, monospace;
```

Icons: inline SVG, Lucide-style stroke (vendor a small subset under MIT licence; document in `lib/vendor/LICENSES.md`).

## Mobile responsiveness

**Breakpoints:**
- `< 640px` — phone (single column, no sidebar, progress bar instead of step list, file tree fullscreen-toggleable, preview fullscreen)
- `640–960px` — tablet (collapsible sidebar)
- `> 960px` — desktop (sidebar + main, file tree + preview side by side)

**Touch targets:** minimum 44×44 px tap area for all interactive elements on phone.
**Avoid hover-only affordances.** Right-click menus must have a tap-and-hold or "more" button alternative.

## Keyboard

Reserved:
- `Cmd/Ctrl+K` — quick-open (path search)
- `Cmd/Ctrl+U` — upload
- `Cmd/Ctrl+,` — settings
- `/` — focus search
- `Esc` — close modal / cancel
- `Del` / `Backspace` — delete selected (with confirm)

Do not bind: `Cmd/Ctrl+S`, `Cmd/Ctrl+R`, `Cmd/Ctrl+W`.

## Empty + error states

Every empty state: one-line explanation + single CTA. No marketing copy.

- No bucket configured → "Connect a bucket to begin." → wizard
- Bucket empty → "Drop files here or tap Upload."
- Wrong passphrase → "Cannot decrypt manifest. Check passphrase." retry inline
- Network error → "Bucket unreachable. Retry?" with retry button
- CORS error → "Bucket is not configured to allow this origin." with copy-paste fix
- Manifest signature mismatch → "Manifest signature mismatch — bucket may have been tampered with. Refusing to continue." HARD STOP, no writes.
- Quota exceeded on R2 free tier → "Bucket is full. Upgrade R2 plan or delete files." with link

## CSP

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
connect-src 'self' https://*.r2.cloudflarestorage.com https://*.backblazeb2.com https://*.your-objectstorage.com https://*.amazonaws.com;
img-src 'self' blob: data:;
object-src 'none';
base-uri 'self';
form-action 'none';
frame-ancestors 'none';
```

User-supplied custom endpoints beyond known providers require manual CSP relaxation (out of scope for v1.0).

## A11y

- All controls reachable by Tab
- File tree implements ARIA tree pattern
- `:focus-visible` outline on all interactives
- Live region announces upload/download/sync state changes
- Colour contrast ≥ 4.5:1 for body text, ≥ 3:1 for large text and icons
- All buttons have accessible names (`aria-label` where icon-only)
- Form fields have associated labels

## Programmatic / ESM API

Exported from `lib/crate.js`. **This is a contract.** Folio, Slate, Bahi, Mahalla will bind to it. Do not break after v1.0 ships.

```js
import { Crate } from "/crate/lib/crate.js";

const c = await Crate.open({
  bucket: { endpoint, region, accessKey, secretKey, bucketName },
  identity,           // from fabric-sdk-js/identity
  passphrase,         // or pre-derived key
});

await c.list(path);
await c.read(path);
await c.write(path, blob);
await c.remove(path);
await c.move(from, to);
await c.mkdir(path);
await c.stat(path);
await c.history(path);
const unsub = c.onChange(handler);
```

Document this in `docs/esm-api.md` once locked.

## README scope

`README.md` covers: what it is (one paragraph), how to start onboarding, encryption model (one paragraph), keyboard shortcuts, how to consume from another tool (3-line ESM example), licensing (AGPL-3.0). Nothing about deployment, nothing about the broader fabric.

## Portfolio integration

- After v1.0 ships, add tile to `naklitechie.com` portfolio at v1.1 (managed bucket ready)
- v1.0 lives at `crate.naklitechie.com` but unlinked
- Internal tool integration starts before public listing: Folio first

## Hard rules — do NOT

- Do **not** persist BYOK secret to localStorage / IndexedDB / any disk store. sessionStorage with explicit opt-in is the maximum.
- Do **not** call any third-party origin other than the user's configured bucket. No analytics, no error reporting, no fonts, no CDN.
- Do **not** add accounts, login, or any NakliTechie-side identity. The user's Identity (keypair) is the only identity.
- Do **not** add a service worker in v1.0.
- Do **not** add "share via link" in v1.0. Grant-based sharing is v1.1.
- Do **not** add file preview / rendering. Hand off to other tools.
- Do **not** roll your own crypto. Use SubtleCrypto. Ask before reaching for libsodium.
- Do **not** bundle. Single HTML + ESM modules.
- Do **not** rename Sync, Vault, Identity, Grant, History primitive APIs. Bind to `fabric-sdk-js` as it stands.
- Do **not** show the recovery phrase or passphrase in any error message or log.
- Do **not** add "skip" buttons to the recovery phrase step.
- Do **not** introduce dependencies whose licences are incompatible with AGPL-3.0.

## Escalation — when to stop and ask Chirag

Stop and ask before proceeding if:

- Sync primitive's wire protocol has a browser-ism that would block the ESM API being usable from a non-browser caller.
- Manifest format choice (pure JSONL vs JSONL-with-merkle) turns out to need a hard decision at v1.0 not v1.3.
- A second bucket provider behaves so differently from R2 that the abstraction needs to change shape.
- CORS configuration on R2 turns out to be impossible without account-level setup the user can't do — would force a Worker proxy in v1.0.
- BIP-39 wordlist choice (English-only vs multilingual) needs a product decision before recovery phrase ships.
- A dependency you want to add has licence questions.

Don't stop for: naming internal functions, picking pane widths, choosing keyboard shortcuts for secondary actions, vendoring decisions for small libraries with clear MIT/Apache licences.

## Gate artifacts per milestone

**M0 — skeleton.** Repo created, LICENSE present (AGPL-3.0), README stub, smoke.sh, index.html that loads, lib/ skeleton with empty modules.
- Gate: `./smoke.sh` prints OK.

**M1 — onboarding shell.** Wizard state machine, all stages renderable, deep-link buttons, copy buttons. No real Cloudflare calls yet.
- Gate: Click through entire wizard with fake inputs; UI feels right; mobile responsive verified on a phone screen.

**M2 — real bucket connection.** S3 sig-v4 against R2, bucket-exists check, credentials test, CORS preflight.
- Gate: From freshly opened tab with R2 creds, all three checks pass against a real bucket.

**M3 — encryption + manifest.** AES-GCM round-trip, PBKDF2 key derivation, recovery phrase encode/decode, signed JSONL manifest.
- Gate: Upload a file, close tab, reopen, decrypt manifest, see file in tree, download and verify bytes match. Recovery phrase round-trip works.

**M4 — folder UI.** File tree, upload, download, delete, rename, mkdir, move. Mobile responsive.
- Gate: Full filesystem workflow from UI on a real R2 bucket, on desktop and on phone.

**M5 — ESM API.** Lock the agent-face surface, write minimal docs.
- Gate: A 10-line script in a separate `<script type="module">` can list, read, write, delete using the API.

**M6 — Sync binding.** Bind to fabric-sdk-js Sync; second tab/device sees changes within seconds.
- Gate: Two browser windows with same Identity + bucket; change in one appears in the other within 5 seconds.

**M7 — device pairing.** QR code encode/decode, pairing code paste, passphrase unlock, device-list management. Also: pairing-token issuance per Phase 1 of `crate-pairing-protocol-v1.0.md`.
- Gate: Phone scans QR from desktop, enters passphrase, sees the folder. Desktop shows the new device in its device list. Pairing-token issuance UI in Settings → Devices → Pair an agent works: generates a properly-formatted `CRATE-PAIR-` token per the protocol spec, POSTs the intent to the transport, displays token with expiry countdown and Cancel button. Verified against test vectors in `private-mesh/docs/test-vectors/crate-pairing/`.

**M8 — ship.** Polish, docs, help modal, error states, deploy to crate.naklitechie.com.
- Gate: Chirag smoke-tests against his own R2 bucket from M4 Pro and from a different machine; onboards a friend who has no Cloudflare account; both succeed.

After M8: v1.0 is shipped. v1.1 (managed bucket + Grant sharing) is a separate spec.

## What "done" looks like

A user can:
1. Visit `crate.naklitechie.com` on their phone
2. Follow the wizard, end up with a working folder in ~3 minutes
3. Drop files into the tab from their phone
4. Open the same URL on their laptop, scan a QR code from the phone, see the same files
5. Download decrypted bytes from either device
6. Have another NakliTechie tool (Folio, when integrated) read from the same folder via the ESM API
7. Generate a pairing token for a future daemon install (even though the daemon doesn't exist yet — the issuance UI is there, ready for v1.2)

No NakliTechie server is on the path. No account exists. No subscription is required. The user's bucket is the substrate, the user's Identity is the access control, the browser tab is the consumption surface, AGPL-3.0 is the licence that keeps it that way.


---

*This document is licensed CC BY-SA 4.0.*
