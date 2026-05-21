# Crate

A personal cloud folder. Files live in a bucket you own (Cloudflare R2 by default), encrypted before they leave your browser. Open a tab, the folder is there. BYOK, AES-256-GCM client-side, no NakliTechie accounts on the path.

Dropbox-shaped utility, NakliTechie-shaped substrate.

## Live

- **[`crate.naklios.dev`](https://crate.naklios.dev)** — canonical home, alongside the rest of [nakliOS](https://naklios.dev).
- **[`crate.naklitechie.com`](https://crate.naklitechie.com)** — personal-project surface.

Same app on both.

## What it is

- **Single static HTML file** + a few small ESM modules. No build step. Host it anywhere.
- **End-to-end encryption** in the browser tab: AES-256-GCM payloads with per-file random data keys, wrapped by a PBKDF2-derived master key (600 000 iterations, 16-byte random salt). Signed JSONL manifest with an HMAC-SHA256 prev-sig chain (tamper-evident). Full details: [`docs/encryption-model.md`](docs/encryption-model.md).
- **Bring your own bucket**. R2 by default; Hetzner / Backblaze B2 / AWS S3 work via the same sig-v4 client. We never see your bucket creds; you never need a NakliTechie account.
- **Two-click unlock.** First-time setup emits an encrypted `.crate-creds` file you download. Next time you open the folder — same device, new device, anywhere — drop the file + type your passphrase. The file is useless without the passphrase; both required to unlock.
- **Refresh-resilient sessions.** Reload the tab mid-session and you don't go back to square one; the encrypted creds blob lives in tab-scoped session memory, so the unlock prompt shortens to passphrase-only.
- **File-manager folder UI.** Tree view with file-type icons, in-place rename, drag-drop upload, click-to-preview for text + images, per-file history modal, full-folder search, total-size summary in the header. Bigger rows, hover-revealed actions, keyboard-navigable. Mobile-responsive.
- **Tiered export.** "Export folder" button downloads everything as a zip — small folders in-memory, large folders stream to disk via File System Access. Disaster-recovery runbook: [`docs/backup.md`](docs/backup.md).
- **Cross-device sync.** Open the same URL on your phone — same passphrase + creds file — same folder. Two tabs converge in ~200 ms; cross-device in ~15 s.
- **Optional native daemon** ([`crate-agent`](https://github.com/NakliTechie/crate-agent)) mirrors the bucket to a plaintext folder on macOS / Linux. Drop a file into `~/crate/` on your laptop, it surfaces in the browser tab.
- **AGPL-3.0-or-later.** The whole encryption layer is [`lib/crypto.js`](lib/crypto.js); every network call is in [`lib/bucket.js`](lib/bucket.js); the credentials-file format is [`lib/credsfile.js`](lib/credsfile.js). Read them.

## Quick start

1. Create an R2 bucket in your Cloudflare account (free tier: 10 GB storage + 1 M writes + 10 M reads / month).
2. Create a scoped API token with read+write on that bucket.
3. Paste the CORS JSON the wizard gives you into the bucket's CORS settings.
4. Open [`crate.naklios.dev`](https://crate.naklios.dev) → **Set up a new folder** → walk the wizard.
5. At Done, click **Download credentials file**. Store it where you keep secrets (1Password, password manager, USB drive).
6. Drop a file in. To open from another device: visit the same URL → **Unlock an existing folder** → drop the creds file + type your passphrase.

About 3 minutes start to finish. The Welcome page has a **How this works (read first)** button with step-by-step instructions.

## Unlocking

The credentials-file path is the default. There's a fallback for users who lost the file:

| You have | Inputs | Where |
|---|---|---|
| Credentials file + passphrase | 2 fields (drop file + type passphrase) | **Unlock an existing folder** → default mode |
| Just the passphrase + the 4 bucket strings | 5 fields | **Unlock an existing folder** → "No file? Enter the 5 details manually." |
| Nothing | — | Can't recover; v1 has no recovery credential. Make backups before you have data you can't afford to lose. |

If you skipped the Done-stage download, the folder UI's `🔐 Credentials` button emits the same file any time after unlock.

## Architecture

| Surface | Sees |
|---|---|
| Browser tab (this) | Plaintext (in your tab's memory only) ↔ ciphertext over the wire |
| Bucket owner (Cloudflare et al.) | Ciphertext + access patterns; never the plaintext or your passphrase |
| `crate-agent` daemon | Plaintext on your local disk; ciphertext over the wire to the bucket |
| `nakli-hub` (optional bucket-proxy) | Ciphertext only; never the plaintext |

The manifest at `.crate/manifest.jsonl.enc` is the source of truth for the folder shape. Every mutation appends a signed event; every surface materialises the manifest into a tree.

If you lose your passphrase AND your creds file AND your backups, your files are gone. Forever. We can't help you. That's the privacy guarantee cutting both ways. See [`docs/backup.md`](docs/backup.md) for the redundancy options.

## ESM API

Other apps (in nakliOS or elsewhere) bind against the 9-method surface in [`lib/crate.js`](lib/crate.js):

```js
import { Crate } from "https://crate.naklios.dev/lib/crate.js";

const c = await Crate.open({
  bucketConfig: { accountId: "…", name: "my-bucket", region: "auto" },
  credentials:  { accessKey: "…", secretKey: "…" },
  passphrase:   "…",
});
await c.write("/notes/today.md", new TextEncoder().encode("# today"));
const buf = await c.read("/notes/today.md");
for (const entry of await c.list("/")) console.log(entry.path);
c.close();
```

Full reference: [`docs/esm-api.md`](docs/esm-api.md).

## Repos

| | |
|---|---|
| Browser (this) | [`NakliTechie/crate`](https://github.com/NakliTechie/crate) |
| Native daemon | [`NakliTechie/crate-agent`](https://github.com/NakliTechie/crate-agent) |
| Transports + Hub | [`NakliTechie/private-mesh`](https://github.com/NakliTechie/private-mesh) |

## Smoke

```sh
./smoke.sh
```

Structural checks (also runs on every push + PR via GitHub Actions). The real verification gate is walking the wizard against your own R2 bucket on desktop + phone.

## Versioning

Crate is **v1**. Other naklios apps bind against this contract, so it's frozen:

- **The bucket wire format** (encryption envelope, `.crate/crate.json` schema, manifest JSONL shape) is frozen. Bytes written by v1 will be readable by every v1.x. A `v: 2` upgrade requires coordinated browser + daemon releases with a documented migration path.
- **The ESM API** in [`lib/crate.js`](lib/crate.js) is frozen at the 9 methods documented in [`docs/esm-api.md`](docs/esm-api.md). Additions bump the minor version (non-breaking). Removing or changing a method signature bumps the major.
- **The credentials-file format** (`lib/credsfile.js`) is frozen at v1. Same passphrase-encryption envelope as the master-key derivation.
- **The CRATE-PAIR pairing protocol** (token shape, redeem flow, error codes) is frozen against `nakli-hub` + `nakli-cf-worker` transports.

See [`CHANGELOG.md`](CHANGELOG.md) for the version history.

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
