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
