# Crate docs

Crate is a personal cloud folder built on the NakliTechie Private Mesh fabric. See the [browser handoff](specs/crate-browser-handoff-v1.0.md) for build conventions and per-milestone gates (lives here, with this surface). The product north star and the cross-surface pairing protocol live in the sibling `private-mesh` repo: [vision and roadmap](../../private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md), [pairing protocol](../../private-mesh/docs/specs/crate-pairing-protocol-v1.0.md).

## Milestones

| M | Theme |
|---|---|
| M0 | Skeleton (this commit) |
| M1 | Onboarding shell — wizard state machine, deep-link buttons, copy buttons |
| M2 | Real bucket connection — S3 sig-v4 against R2, CORS preflight, validation |
| M3 | Encryption + manifest — AES-GCM + PBKDF2 + signed JSONL |
| M4 | Folder UI — tree, upload, download, delete, rename, mkdir, mobile-responsive |
| M5 | ESM API — lock the agent-face surface (`docs/esm-api.md`) |
| M6 | Sync binding — second device sees changes within seconds |
| M7 | Device pairing — QR flow + passphrase unlock + pairing-token issuance |
| M8 | Ship — polish + deploy to `crate.naklitechie.com` |

## Sibling docs

- `encryption-model.md` — crypto details for security review (M3)
- `esm-api.md` — contract docs for downstream tools (M5)

## Manual M2 gate — verifying against a real R2 bucket

The wizard's Bucket / Credentials / CORS stages each make real HTTP calls. Per spec §"Gate artifacts" M2: *From freshly opened tab with R2 creds, all three checks pass against a real bucket.*

1. In Cloudflare, create an R2 bucket and a scoped API token (Object Read + Write).
2. Apply this CORS JSON to the bucket (the wizard's CORS stage copies it to your clipboard with the right origin baked in):

   ```json
   [{ "AllowedOrigins": ["http://localhost:8754"], "AllowedMethods": ["GET","PUT","POST","DELETE","HEAD"], "AllowedHeaders": ["*"], "ExposeHeaders": ["ETag"], "MaxAgeSeconds": 3600 }]
   ```

3. From `crate/`, run `python3 -m http.server 8754` and visit `http://localhost:8754/`.
4. Walk through Welcome → Bucket → Credentials → CORS → Done with real values. Each pill lands green.

Useful error paths:

- Wrong Account ID → Bucket pill `✗ Account ID not resolved` (DNS failure) or `✗ Bucket not found`.
- Right account + wrong bucket → Bucket pill `✗ Bucket not found at this Account ID`.
- Right bucket, wrong Secret → Credentials pill `✗ Authentication failed`.
- Right everything, CORS not yet applied → Credentials pill `✓ Credentials look valid — CORS still needs setup`; advancing to CORS and clicking preflight fails until you paste the JSON into Cloudflare.

## Hetzner abstraction smoke (devtools)

The same `lib/bucket.js` primitives target any S3-compatible provider. The wizard is R2-focused, but the abstraction is exposed on `window.__CRATE__.bucket` for cross-provider verification per spec §"S3 sig-v4 implementation" ("Hetzner Object Storage — tertiary, validates the abstraction"). Open devtools on the running page and run:

```js
const b = window.__CRATE__.bucket;
const r = await b.signedHead({
  url: b.endpoints.Hetzner("nbg1", "my-bucket"),
  region: "nbg1",
  accessKey: "...",
  secretKey: "...",
});
console.log(r); // { ok: true, status: 200, ... } if everything works
```

Datacenter values: `nbg1` (Nuremberg), `fsn1` (Falkenstein), `hel1` (Helsinki). Use the region that matches the bucket's location. Hetzner is stricter than R2 about `x-amz-content-sha256` semantics — the empty-body SHA-256 the signer ships works for both. If Hetzner returns 200 but R2 doesn't (or vice versa), the abstraction has drifted; fix `lib/sigv4.js` rather than papering over per-provider.
