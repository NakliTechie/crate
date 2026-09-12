# Crate

A personal cloud folder. Files live in a bucket you own (Cloudflare R2 by default), encrypted before they leave your browser. Open a tab, the folder is there — BYOK, AES-256-GCM client-side, no NakliTechie account on the path.

Dropbox-shaped utility, NakliTechie-shaped substrate.

## Live

- **[`crate.naklios.dev`](https://crate.naklios.dev)** — canonical home, alongside the rest of [NakliOS](https://naklios.dev).
- **[`crate.naklitechie.com`](https://crate.naklitechie.com)** — personal-project surface.

Same app on both.

## What it is

- **One static HTML file** + a few small ESM modules. No build step; host it anywhere.
- **End-to-end encrypted in the tab.** AES-256-GCM payloads with per-file data keys, wrapped by a PBKDF2 master key (600 000 iterations). Tamper-evident HMAC-SHA256 signed manifest. Details: [`docs/encryption-model.md`](docs/encryption-model.md).
- **Bring your own bucket.** R2 by default; Hetzner / Backblaze B2 / AWS S3 via the same sig-v4 client. We never see your creds.
- **Two-click unlock, refresh-resilient.** The downloaded `.crate-creds` file is useless without your passphrase — both required. Reload mid-session and the prompt shortens to passphrase-only.
- **File-manager UI, from the first second.** The page opens as a file manager — sidebar (All files · Recent · Photos · Devices · Backup), search, Upload — with setup as a card inside it. Rename, drag-drop upload, text/image preview, per-file history. Keyboard-navigable, mobile-responsive, light or dark with your system.
- **Cross-device sync + tiered export.** Same URL on your phone → same folder (~15 s). "Export folder" zips everything (streams to disk for large folders). Backup runbook: [`docs/backup.md`](docs/backup.md).
- **Optional native daemon** ([`crate-agent`](https://github.com/NakliTechie/crate-agent)) mirrors the bucket to a plaintext `~/crate/` on macOS / Linux.
- **AGPL-3.0.** Encryption is [`lib/crypto.js`](lib/crypto.js); every network call is [`lib/bucket.js`](lib/bucket.js); the creds format is [`lib/credsfile.js`](lib/credsfile.js). Read them.

## Getting started

About a minute, start to finish — **no API token, no CORS, no account ID**:

1. Open [`crate.naklios.dev`](https://crate.naklios.dev) → **Get started**. Crate shows a secret it generated for you.
2. Click **Deploy to Cloudflare**. Cloudflare copies the tiny [`crate-carrier`](https://github.com/NakliTechie/crate-carrier) Worker into your GitHub account, creates an R2 bucket for it, and asks for `CARRIER_SECRET` — paste the secret. (You'll need a free Cloudflare account and a free GitHub account; the first time, Cloudflare asks to connect the two.) The build takes about a minute — **its page does not update by itself; reload it** to see the result.
3. When it says deployed, click **Visit** → **Continue to Crate**. Back in Crate the Worker's address is filled in: click **Verify**, then **Next →** and pick a passphrase.
4. At **Done**, download the `.crate-creds` file and keep it with your passphrase — you need **both** to open the folder on another device ([Tijori](https://tijori.naklitechie.com), a password manager, a USB drive). Drop a file in. To open elsewhere: same URL → **Already set up? Open your folder** → the creds file + your passphrase.

**What you keep, forever:** two things — the `.crate-creds` file and your passphrase. Nothing else. The file holds your connection details, encrypted under the passphrase; the passphrase is the key to your files and cannot be reset by anyone. Lose the file and you can re-enter the details manually (Worker URL + the carrier secret, which you can rotate on the Worker). Lose the passphrase and the files are gone.

**Passphrase, in one line:** the wizard shows you five random words — write them down, tick the box, done. Prefer your own? Type it twice; the bar goes green at the recommended 55 bits ([zxcvbn](https://github.com/zxcvbn-ts/zxcvbn)'s estimate — five unrelated words, or twelve random mixed characters), and you may go lower after the page shows you how long one GPU would take to crack it. The word list is the public 2048-word BIP-39 English list, shipped inside the page; the strength comes from the random choice, not from the list being secret.

The Worker is yours, in your account, and holds only an R2 *binding* — it sees ciphertext and nothing else; delete it and access ends. Prefer manual setup with your own API token? **Use a bucket you already have** (under the card) is the original four-step route; its wizard walks through Cloudflare R2 (Hetzner, Backblaze and S3 work through the same fields if you know their endpoints).

**How it works** (on the card and in the top bar) opens a short explainer with the privacy promise and the three steps.

**Full illustrated walk-through** — every stage, the folder UI, backup, the security model: [`guide/`](guide/index.html), also live at [crate.naklios.dev/guide/](https://crate.naklios.dev/guide/).

## Unlocking

The credentials file is the default path; there's a fallback if you lost it:

| You have | How |
|---|---|
| Creds file + passphrase | Drop file + type passphrase (default) |
| Passphrase + your details (one-click: Worker URL + carrier secret; own bucket: the 4 bucket strings) | "No file? Enter the details manually." |
| Nothing | Can't recover — v1 has no recovery credential. Back up first. |

Skipped the download? **Backup → Download credentials file** re-emits it any time after unlock.

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
