# Crate docs

Crate is a personal cloud folder. Files live in a bucket you own (Cloudflare R2 by default), encrypted client-side before they leave the browser. This directory holds the technical docs; the live app is at [`crate.naklios.dev`](https://crate.naklios.dev).

## In this directory

- [`encryption-model.md`](encryption-model.md) — full cryptographic design: key derivation, payload sealing, manifest signing, threat model. Read this if you're auditing or just curious.
- [`esm-api.md`](esm-api.md) — the 9-method `Crate` ESM API surface for embedding in other apps.
- [`backup.md`](backup.md) — disaster-recovery runbook. Four ways to keep a redundant copy + three disaster scenarios.

## Multi-provider support

Crate works against any S3-compatible bucket. The same primitives that drive the R2 wizard target Backblaze B2, Hetzner Object Storage, and AWS S3. Open devtools on the running app and call them directly:

```js
const b = window.__CRATE__.bucket;

// Hetzner Object Storage — datacenters: nbg1 (Nuremberg), fsn1 (Falkenstein), hel1 (Helsinki)
const r = await b.signedHead({
  url: b.endpoints.Hetzner("nbg1", "my-bucket"),
  region: "nbg1",
  accessKey: "…",
  secretKey: "…",
});
console.log(r); // { ok: true, status: 200 } if everything works
```

The wizard is R2-first because that's the launch surface. Non-R2 providers work the same way; the docs above (esm-api.md in particular) cover how to construct a `Crate` against a non-R2 bucket.

## Cross-surface interop

The wire format on the bucket is byte-identical to what the daemon [`crate-agent`](https://github.com/NakliTechie/crate-agent) reads and writes. Run the daemon on your laptop and the browser tab against the same bucket + passphrase, and they share the folder transparently — browser writes show up in the daemon's `~/crate/` within ~15s, and vice-versa.

## Repository layout

```
crate/
├── index.html              # the app — single HTML file
├── lib/
│   ├── crate.js            # ESM API surface (docs/esm-api.md)
│   ├── crypto.js           # PBKDF2 + AES-GCM (docs/encryption-model.md)
│   ├── manifest.js         # signed JSONL manifest
│   ├── bucket.js           # S3 sig-v4 client (every network call lives here)
│   ├── sigv4.js            # hand-rolled AWS Signature V4
│   ├── onboarding.js       # wizard
│   ├── folder.js           # folder UI
│   ├── export.js           # tiered backup export
│   ├── sync-client.js      # BroadcastChannel + manifest poll
│   ├── qr.js               # device-pair QR
│   └── vendor/             # third-party (zxcvbn-ts, client-zip, …)
└── docs/                   # you are here
```
