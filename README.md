# Crate

A cloud folder only you can read. Files live in storage you own — a free Cloudflare account by default — and are encrypted on your device before they upload. No account with us, no server on the path, nothing to subscribe to.

Dropbox-shaped utility, NakliTechie-shaped substrate. **v1.2.0** — [CHANGELOG](CHANGELOG.md).

## Live

Same app on both: **[`crate.naklios.dev`](https://crate.naklios.dev)** (alongside [NakliOS](https://naklios.dev)) · **[`crate.naklitechie.com`](https://crate.naklitechie.com)**.

## Getting started

About a minute. You need a free [Cloudflare](https://dash.cloudflare.com/sign-up) account and a free [GitHub](https://github.com/signup) account.

1. Open [`crate.naklios.dev`](https://crate.naklios.dev) → **Get started**. Crate shows a secret it generated for you.
2. **Deploy to Cloudflare** copies the tiny [`crate-carrier`](https://github.com/NakliTechie/crate-carrier) Worker into your GitHub, creates an R2 bucket for it, and asks for `CARRIER_SECRET` — paste the secret. The build takes about a minute; reload its page to see the result.
3. **Visit → Continue to Crate**, then **Verify**, then **Next** for your passphrase: five random words joined with hyphens (`sphere-cancel-scan-blanket-interest`). Write that line down. Next comes a 24-word **recovery phrase** — write it on paper too (or skip and set it up later from **Backup**).
4. **Done** → download the `.crate-creds` file → **Open your folder**. Drop a file in.

**What you keep:** the `.crate-creds` file, the passphrase, and the 24-word **recovery phrase** on paper. File + passphrase open the folder anywhere (**Already set up? Open your folder**); either alone is useless. Lost the file? Enter the Worker URL and carrier secret by hand. Lost the passphrase? The recovery phrase opens the folder and lets you set a new one. Lost both? The files are gone — nobody can reset them.

Already run your own bucket and API token? **Use a bucket you already have** (under the card) is the four-step manual route — Cloudflare R2, Hetzner, Backblaze B2 or AWS S3 through the same sig-v4 client.

**Full illustrated walk-through:** [`guide/`](guide/index.html) · live at [crate.naklios.dev/guide/](https://crate.naklios.dev/guide/).

## What it is

- **A file manager from the first second.** Sidebar (All files · Recent · Photos · Devices · Backup), search, Upload + New folder; setup is a card inside the same frame. Rename, drag-drop, text/image preview, per-file history. Keyboard-navigable, phone-sized, light or dark with your system.
- **Encrypted in the tab.** AES-256-GCM in 8 MiB chunks with per-file data keys under a random content key, which your passphrase or your recovery phrase unwraps (PBKDF2, 600 000 iterations); an HMAC-SHA256 signed, rollback-anchored manifest that fails closed. [`docs/encryption-model.md`](docs/encryption-model.md).
- **Your storage.** The carrier Worker holds only an R2 binding and sees ciphertext; delete it and access ends. Or bring your own bucket — we never see your credentials.
- **Same folder everywhere.** Same URL on your phone (~15 s sync). **Backup → Export everything** zips the lot (streams to disk when large). [`docs/backup.md`](docs/backup.md).
- **Share a file.** A link that works for an hour, a day or a week; the recipient needs nothing. Deleted files wait 30 days in **Trash**; search looks inside text files; PDFs and media preview in place.
- **Two credentials, then some.** A 24-word recovery phrase for a lost passphrase; a passkey to open the folder on this device without typing it; re-key when you suspect a leak. Installable, and opens offline to the last-seen folder.
- **Optional desktop daemon** — [`crate-agent`](https://github.com/NakliTechie/crate-agent) (≥ 1.4.0 for this release) mirrors the folder to plaintext `~/crate/` on macOS / Linux. Pair it from **Devices**.
- **One static HTML file** plus small ESM modules, no build step. **AGPL-3.0.** Encryption is [`lib/crypto.js`](lib/crypto.js); every network call is [`lib/bucket.js`](lib/bucket.js); the creds format is [`lib/credsfile.js`](lib/credsfile.js). Read them.

## Unlocking

The credentials file is the default path; there's a fallback if you lost it:

| You have | How |
|---|---|
| Creds file + passphrase | Drop file + type passphrase (default) |
| Passphrase + your details (one-click: Worker URL + carrier secret; own bucket: the 4 bucket strings) | "No file? Enter the details manually." |
| Recovery phrase + your details | "Lost your passphrase? Use your recovery phrase." — then set a new passphrase |
| Nothing | Can't recover. Keep the phrase on paper; back up. |

Skipped the download? **Backup → Download credentials file** re-emits it any time.

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

Crate is **v1.x** — the v1 surface is frozen, because other naklios apps bind against it: the bucket wire format (encryption envelope, `.crate/crate.json` schema, manifest shape), the 9-method [`lib/crate.js`](lib/crate.js) ESM API, the `.crate-creds` format, and the CRATE-PAIR pairing protocol. Additive changes bump the minor; breaking ones bump the major. History: [`CHANGELOG.md`](CHANGELOG.md).

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
