# Crate

A personal cloud folder. Files live in a bucket you own (Cloudflare R2 by default), encrypted before they leave your browser. Open a tab, the folder is there. BYOK, AES-256-GCM client-side, no NakliTechie accounts on the path.

Dropbox-shaped utility, NakliTechie-shaped substrate.

## Status

**M0** — skeleton. The build target is a single HTML file + ESM modules at `crate.naklitechie.com`. See `docs/README.md` for what each milestone delivers. The browser implementation contract lives at [`docs/specs/crate-browser-handoff-v1.0.md`](docs/specs/crate-browser-handoff-v1.0.md). The product roadmap and the cross-surface pairing protocol live in the sibling `private-mesh` repo: [`crate-vision-and-roadmap-v1.0.md`](../private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md) and [`crate-pairing-protocol-v1.0.md`](../private-mesh/docs/specs/crate-pairing-protocol-v1.0.md).

## Two surfaces

| Surface | Repo | When |
|---|---|---|
| Browser | `NakliTechie/crate` (this one) | v1.0 |
| Native daemon | `NakliTechie/crate-agent` | v1.2+ |

Both build on the same Sync + Vault + Identity + Grant + History primitives (`NakliTechie/private-mesh`).

## Smoke

```sh
./smoke.sh
```

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
