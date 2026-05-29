# Crate

A personal cloud folder. Files live in a bucket you own (Cloudflare R2 by default), encrypted before they leave your browser. Open a tab, the folder is there — BYOK, AES-256-GCM client-side, no NakliTechie account on the path.

Dropbox-shaped utility, NakliTechie-shaped substrate.

## Live

- **[`crate.naklios.dev`](https://crate.naklios.dev)** — canonical home, alongside the rest of [nakliOS](https://naklios.dev).
- **[`crate.naklitechie.com`](https://crate.naklitechie.com)** — personal-project surface.

Same app on both.

## What it is

- **One static HTML file** + a few small ESM modules. No build step; host it anywhere.
- **End-to-end encrypted in the tab.** AES-256-GCM payloads with per-file data keys, wrapped by a PBKDF2 master key (600 000 iterations). Tamper-evident HMAC-SHA256 signed manifest. Details: [`docs/encryption-model.md`](docs/encryption-model.md).
- **Bring your own bucket.** R2 by default; Hetzner / Backblaze B2 / AWS S3 via the same sig-v4 client. We never see your creds.
- **Two-click unlock, refresh-resilient.** The downloaded `.crate-creds` file is useless without your passphrase — both required. Reload mid-session and the prompt shortens to passphrase-only.
- **File-manager folder UI.** Tree view, rename, drag-drop upload, text/image preview, per-file history, search, total-size. Keyboard-navigable, mobile-responsive.
- **Cross-device sync + tiered export.** Same URL on your phone → same folder (~15 s). "Export folder" zips everything (streams to disk for large folders). Backup runbook: [`docs/backup.md`](docs/backup.md).
- **Optional native daemon** ([`crate-agent`](https://github.com/NakliTechie/crate-agent)) mirrors the bucket to a plaintext `~/crate/` on macOS / Linux.
- **AGPL-3.0.** Encryption is [`lib/crypto.js`](lib/crypto.js); every network call is [`lib/bucket.js`](lib/bucket.js); the creds format is [`lib/credsfile.js`](lib/credsfile.js). Read them.

## Getting started

About 3 minutes, start to finish:

1. Create an **R2 bucket** in your Cloudflare account (free tier: 10 GB + 1 M writes + 10 M reads / month) and a **scoped API token** with read+write on it.
2. Open [`crate.naklios.dev`](https://crate.naklios.dev) → **Set up a new folder**. The wizard verifies the bucket, hands you the CORS JSON to paste, and walks you through a passphrase.
3. At **Done**, download the encrypted `.crate-creds` file and keep it where you store secrets ([Tijori](https://tijori.naklitechie.com), a password manager, a USB drive).
4. Drop a file in. To open elsewhere, visit the same URL → **Unlock an existing folder** → drop the creds file + type your passphrase.

First visit pops a **What is Crate?** explainer; reopen it any time from **New here? See how Crate works** on the start screen.

**Full illustrated walk-through** — every stage, the folder UI, backup, the security model: [`guide/`](guide/index.html), also live at [crate.naklios.dev/guide/](https://crate.naklios.dev/guide/).

## Unlocking

The credentials file is the default path; there's a fallback if you lost it:

| You have | How |
|---|---|
| Creds file + passphrase | Drop file + type passphrase (default) |
| Passphrase + the 4 bucket strings | "No file? Enter the 5 details manually." |
| Nothing | Can't recover — v1 has no recovery credential. Back up first. |

Skipped the download? The folder UI's `🔐 Credentials` button re-emits the file any time after unlock.

## Architecture

| Surface | Sees |
|---|---|
| Browser tab (this) | Plaintext in tab memory only ↔ ciphertext over the wire |
| Bucket owner (Cloudflare et al.) | Ciphertext + access patterns; never plaintext or passphrase |
| `crate-agent` daemon | Plaintext on your local disk; ciphertext to the bucket |
| `nakli-hub` (optional proxy) | Ciphertext only |

The manifest at `.crate/manifest.jsonl.enc` is the source of truth: every mutation appends a signed event; every surface materialises it into a tree.

Lose your passphrase **and** creds file **and** backups, and your files are gone. Forever — that's the privacy guarantee cutting both ways. Redundancy options: [`docs/backup.md`](docs/backup.md).

## ESM API

Other apps bind against the 9-method surface in [`lib/crate.js`](lib/crate.js):

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

Structural checks (also run on every push via GitHub Actions). The real gate is walking the wizard against your own R2 bucket on desktop + phone.

## Versioning

Crate is **v1** — frozen, because other naklios apps bind against it: the bucket wire format (encryption envelope, `.crate/crate.json` schema, manifest shape), the 9-method [`lib/crate.js`](lib/crate.js) ESM API, the `.crate-creds` format, and the CRATE-PAIR pairing protocol. Additive changes bump the minor; breaking ones bump the major. History: [`CHANGELOG.md`](CHANGELOG.md).

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
