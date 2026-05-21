# Crate

A personal cloud folder. Files live in a bucket you own (Cloudflare R2 by default), encrypted before they leave your browser. Open a tab, the folder is there. BYOK, AES-256-GCM client-side, no NakliTechie accounts on the path.

Dropbox-shaped utility, NakliTechie-shaped substrate.

## Live

- **[`crate.naklios.dev`](https://crate.naklios.dev)** — canonical home, alongside the rest of [nakliOS](https://naklios.dev).
- **[`crate.naklitechie.com`](https://crate.naklitechie.com)** — personal-project surface.

Same app on both.

## What it is

- **Single static HTML file** + a few small ESM modules. No build step. Host it anywhere.
- **End-to-end encryption** in the browser tab: AES-256-GCM payloads with per-file random data keys, wrapped by a PBKDF2-derived master key (600 000 iterations, 16-byte random salt). Signed JSONL manifest with an HMAC-SHA256 prev-sig chain (tamper-evident).
- **Bring your own bucket**. R2 by default; Hetzner / Backblaze B2 / AWS S3 work via the same sig-v4 client. We never see your bucket creds; you never need a NakliTechie account.
- **Cross-device sync**. Open the same URL on your phone — same passphrase + bucket creds — same folder. Two tabs converge in ~200ms; cross-device in ~15s.
- **Optional native daemon** ([`crate-agent`](https://github.com/NakliTechie/crate-agent)) mirrors the bucket to a local folder on macOS or Linux. Drop a file into `~/crate/` on your laptop, it surfaces in the browser tab.
- **AGPL-3.0-or-later**. The whole encryption layer is [`lib/crypto.js`](lib/crypto.js); every network call is in [`lib/bucket.js`](lib/bucket.js). Read them.

## Quick start

1. Create an R2 bucket in your Cloudflare account (free tier: 10 GB storage + 1 M writes + 10 M reads / month).
2. Create a scoped API token with read+write on that bucket.
3. Paste the CORS JSON the wizard gives you into the bucket's CORS settings.
4. Open [`crate.naklios.dev`](https://crate.naklios.dev) → "Set up a new folder" → walk the wizard.
5. Drop a file in. Refresh the tab. File's still there. Open the tab on your phone (same passphrase + creds via "Unlock an existing folder"). File's there too.

About 3 minutes start to finish. The Welcome page has a "How this works (read first)" button with step-by-step screenshots-quality instructions.

## Architecture

| Surface | Sees |
|---|---|
| Browser tab (this) | Plaintext (in your tab's memory only) ↔ ciphertext over the wire |
| Bucket owner (Cloudflare et al.) | Ciphertext + access patterns; never the plaintext or your passphrase |
| `crate-agent` daemon | Plaintext on your local disk; ciphertext over the wire to the bucket |
| `nakli-hub` (optional bucket-proxy) | Ciphertext only; never the plaintext |

The manifest at `.crate/manifest.jsonl.enc` is the source of truth for the folder shape. Every mutation appends a signed event; every surface materialises the manifest into a tree.

If you lose your passphrase, your files are gone. Forever. We can't help you. That's the privacy guarantee cutting both ways — write the passphrase down somewhere safe, and write the 24-word recovery phrase the wizard gives you down somewhere else.

## ESM API

Other apps (in nakliOS or elsewhere) bind against the 9-method surface in [`lib/crate.js`](lib/crate.js):

```js
import { Crate } from "https://crate.naklios.dev/lib/crate.js";

const c = await Crate.unlock({ bucket, accessKey, secretKey, passphrase });
await c.write("/notes/today.md", new TextEncoder().encode("# today"));
const buf = await c.read("/notes/today.md");
for await (const entry of c.list("/")) console.log(entry.path);
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

Structural checks. The real verification gate is walking the wizard against your own R2 bucket on desktop + phone.

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
