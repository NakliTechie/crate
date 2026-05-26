# Prior art and feature comparison

Crate wasn't modelled on anything in this doc. It exists because we
wanted a personal cloud folder we owned end-to-end and the existing
tools didn't fit — built from the problem, not from the prior art.
The mapping below is post-hoc: once Crate existed, it was worth
knowing where it lands in the broader design space, what the
neighbourhood already does that we don't, and what's worth shipping
to close those gaps. The comparisons help readers slot Crate into
categories they already understand. They're not a lineage claim.

The crypto model (per-file random data keys wrapped by a
passphrase-derived master), the folder-on-cloud posture, and the
bucket-as-source-of-truth design happen to land in the same
neighbourhood as Cryptomator's vault format — convergent, not
derivative. The piece that's genuinely unusual is the *delivery*:
open a URL, drop a credentials file, type a passphrase. No install,
no account, no native binary, no app store. The rest of this doc
maps where that combo lands, where the comparables still do things
we don't, and what we want to ship next.

## How to read the table

Crate's combo — **browser-only + BYOB S3 + E2EE + live folder via a
signed manifest** — is unusual. Most projects pick a different subset.
Six chosen because they cover the spectrum:

- **Crate** — this project
- **Cryptomator** — closest crypto model + folder semantics
- **Restic** — closest E2EE-manifest-on-S3 engineering
- **Kopia** — modern Restic-shape with a (local) web UI
- **JuiceFS** — FS-on-object-storage without E2EE; the "what Crate is not"
- **MEGA** — E2EE cloud with browser UI; the Dropbox-shape with E2EE

Five more (rclone crypt, Tahoe-LAFS, s3fs/Mountpoint, SeaweedFS, Storj
DCS) are covered as [cousins](#cousins) below.

## Access shape

| Feature | Crate | Cryptomator | Restic | Kopia | JuiceFS | MEGA |
|---|---|---|---|---|---|---|
| Install required | None (open URL) | Desktop + iOS/Android (paid web Hub) | CLI binary | CLI binary + local web UI | FUSE mount + metadata DB | Browser, desktop, mobile |
| Account required | No | No (Hub: yes, paid) | No | No | No | Yes (MEGA account) |
| BYOB (bring your own backend) | Yes — R2/S3/B2/Hetzner | Yes — any cloud folder or WebDAV | Yes — S3-compatible / SFTP / local | Yes — S3 / GCS / Azure / SFTP / local | Yes — any S3-compatible | No (MEGA's backend) |
| Self-hosted metadata required | No | No | No | No | **Yes** (Redis/MySQL/TiKV) | No |
| Mobile | Responsive PWA-shape | Native iOS + Android apps | None (server-shaped) | None | None | Native iOS + Android apps |
| Native daemon | [`crate-agent`](https://github.com/NakliTechie/crate-agent) for local mirror | Mounts as local drive (FUSE/Dokany) | CLI only | CLI + repository server | FUSE mount | Desktop sync client |
| ESM/SDK for embedding | Yes — [9-method API](esm-api.md) | None (CLI/GUI only) | Go API | Go API | None | REST API |

## Folder semantics

| Feature | Crate | Cryptomator | Restic | Kopia | JuiceFS | MEGA |
|---|---|---|---|---|---|---|
| POSIX-compliant | No (folder-shaped, not POSIX) | No (vault format, not POSIX) | No (snapshot-shaped) | No (snapshot-shaped) | **Yes** | No |
| Live folder (vs. snapshot) | Yes | Yes | No — snapshots | No — snapshots | Yes | Yes |
| Per-file history | Yes — manifest event log | Filesystem-level only | Yes — every snapshot | Yes — every snapshot | Filesystem-level only | Yes |
| Filename / path search | Yes (folder UI) | OS file manager | CLI find | Yes | OS tools | Yes |
| Full-text search | No | No | No | No | No (OS tools) | No |
| Preview (text + image) | Yes | No (opens in OS) | No | No | No (OS tools) | Yes (broad) |
| Drag-drop upload | Yes | Yes (OS drag) | No | No | Yes (OS drag) | Yes |
| Bulk export | Yes — zip / FSA stream | OS copy | restic restore | kopia restore | OS copy | Yes |
| Rename / move | Yes (atomic via manifest) | Yes (OS-level) | N/A (snapshots immutable) | N/A | Yes (POSIX) | Yes |
| Trash / undelete | No (history only) | OS trash | Snapshots are immutable history | Snapshots are immutable history | OS trash | Yes — rubbish bin |

## Encryption

| Feature | Crate | Cryptomator | Restic | Kopia | JuiceFS | MEGA |
|---|---|---|---|---|---|---|
| E2EE | **Yes** | **Yes** | **Yes** | **Yes** | Optional, server-side | **Yes** (with caveats — own protocol, multiple papers) |
| Cipher | AES-256-GCM | AES-GCM + AES-CTR (older) / AES-GCM (newer) | AES-256-CTR + Poly1305-AES | AES-256-GCM / ChaCha20-Poly1305 | AES-256-GCM | AES-128-CBC + RSA-2048 |
| KDF | PBKDF2-SHA256 600k iter | Scrypt | Scrypt | Scrypt / Argon2id | N/A | PBKDF2-SHA512 100k iter |
| Per-file random data keys | Yes | Yes | N/A (content-addressed blobs) | N/A | N/A | Yes |
| Filename encryption | **Yes** (inside encrypted manifest — bucket sees only UUIDs) | Yes (encrypted filenames in vault) | Yes (everything is content-addressed hashes) | Yes | No | Yes |
| Manifest signing / tamper-evidence | **Yes** — HMAC-SHA256 prev-sig chain | Vault has integrity check per file | Per-pack MAC | Per-blob MAC | No | Per-block MAC |
| Dedup (content-addressed) | No | No | **Yes** (rolling-hash chunks) | **Yes** (rolling-hash chunks) | Optional | No |
| Compression | No | No | **Yes** — zstd | **Yes** — zstd | Optional | No |
| Key rotation | No (v1) | Yes (desktop) | repository password change | Yes | N/A | Yes (re-encrypt) |

## Recovery & access

| Feature | Crate | Cryptomator | Restic | Kopia | JuiceFS | MEGA |
|---|---|---|---|---|---|---|
| Passphrase + creds-file unlock | Yes (2-click) | No (vault path + passphrase) | passphrase only | passphrase only | N/A | email + password |
| Recovery code / paper key | No (lost = lost) | **Yes** (paper recovery key in Hub) | No | No | N/A | **Yes** (master key export) |
| Hardware key (WebAuthn / Passkey) | No | YubiKey via desktop | No | No | N/A | TOTP 2FA only |
| Multi-factor / Shamir split | No | No | No | No | N/A | No |
| Account-reset path | None — by design | Hub: admin reset | None | None | N/A | Limited (account recovery, not encryption) |

## Sync & collaboration

| Feature | Crate | Cryptomator | Restic | Kopia | JuiceFS | MEGA |
|---|---|---|---|---|---|---|
| Cross-device sync | Yes — via bucket (manifest converges) | Via cloud-provider sync (Dropbox, etc.) | Via shared repository | Via shared repository | Via shared mount | Yes — native |
| Concurrent writers | ETag-conditional PUT, last-writer-wins | Vault-level (cloud sync arbitrates) | Repository lock | Repository lock | POSIX semantics | Server-side ordering |
| CRDT / proper merge | No | No | N/A | N/A | N/A | No |
| Share single file (public link) | No | No | No | No | No | **Yes** (link + key in fragment) |
| Shared folders (multi-user) | No | No | Shared repository (everyone has full passphrase) | Same | Yes — multi-tenant | **Yes** (per-folder key share) |

## Ops

| Feature | Crate | Cryptomator | Restic | Kopia | JuiceFS | MEGA |
|---|---|---|---|---|---|---|
| License | AGPL-3.0-or-later | GPL-3.0 (desktop), proprietary Hub | BSD-2-Clause | Apache-2.0 | Apache-2.0 (CE), commercial (enterprise) | Proprietary |
| Source size (rough) | Single HTML + ~10 small ESM modules | ~100k LOC across desktop/mobile/Hub | ~80k LOC Go | ~150k LOC Go | ~400k LOC Go + DB | Closed |
| Verifiable build | View source on a static HTML page | Reproducible-ish, multi-platform | Reproducible Go builds | Reproducible Go builds | Reproducible Go builds | No |
| Bundle size (browser-side) | ~ static HTML + ESM ~ few-hundred KB | N/A | N/A | N/A | N/A | ~ multi-MB web app |
| Spec / wire-format frozen | Yes — [v1 freeze](../README.md#versioning) | Vault format spec public | Repository format documented | Repository format documented | Format documented | Internal |

## Cousins

Not in the table because they sit at a different layer or pick a
significantly different subset — but worth knowing about.

**rclone crypt + rclone mount** — DIY E2EE overlay on any rclone
backend (50+ supported). Fundamentally CLI; the closest you get to a
"browser-only Crate-shape" with rclone is `rclone serve webdav` behind a
web file manager, which isn't really the same product. Useful as a
mirror tool (and we recommend it in [`backup.md`](backup.md)).

**Tahoe-LAFS** — capability-based E2EE distributed filesystem, dates to
2007. Ideologically the closest ancestor: bucket-doesn't-see-plaintext,
capabilities as the access primitive, signed mutable directories. Uses
its own storage protocol over its own grid, not S3. The browser UI
exists but is dated.

**s3fs-fuse / goofys / Mountpoint for Amazon S3** — FUSE wrappers that
mount an S3 bucket as a local drive. Plaintext on the wire, no
encryption. POSIX-shaped; useful when the bucket is yours and you want
shell tools to work. Different product entirely.

**SeaweedFS** — self-hosted distributed object/file store; closer to
MinIO + sync layer than to Crate. It would sit *underneath* a
Crate-like client (as the S3 backend), not next to it as a peer.

The architectural contrast is instructive. SeaweedFS's filer keeps
metadata in a real DB (MySQL / Postgres / Redis / Cassandra / LevelDB
/ ~15 others) because server-side encryption means the server holds
the keys and can query the index. Crate uses an encrypted append-only
JSONL manifest because we *can't* hold keys server-side — E2EE means
metadata must be downloadable-and-decryptable client-side. That
single constraint is why "just be a well-designed filer like
SeaweedFS" isn't a path open to us without giving up the wedge.

Worth borrowing from them even so:

- **TTL / lifecycle as the trash primitive.** Their "automatic entry
  TTL expiration" maps cleanly onto R2 / S3 / B2 / Hetzner bucket
  lifecycle rules. See *Trash / undelete* under [Coming soon](#coming-soon)
  for the impl note.
- **Active-Active Replication.** Our [backup runbook](backup.md)
  currently says "manual `rclone sync`". SeaweedFS does continuous
  cross-cluster replication with conflict handling. One-way
  continuous is a `cron` + `rclone bisync` runbook upgrade away;
  two-way is harder (our ETag-conditional model assumes one
  canonical bucket) but worth studying their conflict resolution if
  hot-failover between bucket providers becomes a real ask.
- **Cloud Drive cache semantics.** `crate-agent` currently does full
  bidirectional mirror; SeaweedFS's "Cloud Drive" pattern
  (cloud-primary, local hot cache, async write-back, evict cold
  blobs) is the design template for a future `crate-agent` smart-cache
  mode when vaults grow past laptop-disk-comfortable size.

**Storj DCS** — S3-compatible decentralised storage with optional
client-side encryption. If you swapped Crate's R2 default for Storj
DCS, it would Just Work. They're stacked, not competing.

## The wedge, restated

Reading the tables row-by-row, three groups of cells light up Crate's
unique territory:

1. **Access shape** — "Install required: None" + "Account required:
   No" + "Mobile: Responsive PWA-shape" + "BYOB". No other row in the
   table has all four. Cryptomator gets the closest, but you install
   an app. MEGA gets the closest browser UX, but you're on their
   backend with their account.
2. **Tamper-evident bucket protocol** — "Manifest signing: HMAC-SHA256
   prev-sig chain" + "Filename encryption inside encrypted manifest".
   Restic and Kopia have manifest signing but in a snapshot frame;
   Cryptomator has filename encryption but without a chained log; MEGA
   has neither.
3. **ESM SDK** — "ESM/SDK for embedding: Yes — 9-method API". Other
   naklios apps bind against this surface. None of the comparables
   exposes itself as an in-page module a sibling app can import.

That's the wedge to build on. Everything in the next section is about
keeping it sharp.

## Coming soon

The comparables ship features Crate doesn't, and many are squarely
worth shipping while keeping the browser-only + BYOB + E2EE invariants
intact. The list below is *what we'd like to ship*, not a roadmap —
priorities and ordering live in [`plan/pending.md`](../plan/pending.md).

### Recovery & access

- **Recovery credential.** A second key-wrap slot in `.crate/crate.json`
  so a recovery phrase (or a downloaded recovery file) can unlock the
  master key independently of the passphrase. Closes the "lost
  passphrase = lost forever" gap that Cryptomator (paper key) and MEGA
  (master key export) already cover. Schema bump documented in
  [encryption-model.md](encryption-model.md#no-recovery-credential).
- **WebAuthn / Passkey unlock.** Treat the passkey as a second
  key-wrap factor — passkey signs a challenge, signature derives a wrap
  key, master key unwraps. Hardware-key-grade unlock, no install. Goes
  beyond what Cryptomator's YubiKey support gives, because it works in
  a browser tab.
- **Shamir-split credentials file.** Optional 2-of-3 split of
  `.crate-creds` for users who want the file held by separate parties
  (laptop / phone / family-member). Same envelope, three shares.

### Folder semantics

- **Trash / undelete with retention.** A `delete` manifest event
  tags the `objects/{uuid}` blob with an expiry timestamp; a
  bucket-side lifecycle rule (R2 / S3 / B2 / Hetzner all support
  this natively) sweeps tagged objects after N days. A `restore`
  manifest event before expiry brings the file back; after expiry
  it's gone. No custom janitor needed — the bucket cleans itself
  even when no daemon is running. Lifecycle-as-trash-primitive is
  borrowed from [SeaweedFS](#cousins).
- **Full-text search.** Per-folder inverted index, encrypted and
  stored as `.crate/index.<uuid>.enc`. Indexing runs in a Web Worker
  on write. Search runs entirely in-browser; the bucket sees ciphertext.
  No comparable in the table has this — it would be a genuine
  differentiator, not just gap-closing.
- **PDF / video / audio preview.** PDFs via pdf.js; video/audio via
  `<video>`/`<audio>` with a streaming decrypt adapter (we already
  decrypt to `Blob`; need range-request support on the bucket reader).
- **Multi-select bulk ops.** Move, delete, download multiple files at
  once. Cosmetic but expected.
- **Tagging / metadata.** Optional per-file tags, lived inside the
  manifest event, queryable in the folder UI.

### Sharing & collaboration

- **Per-file share links.** `https://crate.naklios.dev/share#<uuid>:<key>`
  — the key fragment never hits the server (URL fragments aren't sent
  on HTTP), the link recipient hits the bucket directly via a scoped
  read-only signed URL we issue from the owner's tab. MEGA and Filen
  ship this pattern and it's the single biggest "why isn't this in
  Crate?" question. Requires the bucket to accept signed read URLs,
  which R2 / S3 / B2 / Hetzner all do.
- **Shared folders with separate trust circle.** Per-folder
  sub-namespace with its own key, wrapped under each member's master
  key. Lets a Crate owner share `/shared/family/` with a partner
  without giving up the whole vault.

### Storage

- **Content-addressed dedup.** Rolling-hash chunking with each chunk
  encrypted under a content-derived key (convergent encryption with the
  master key as the convergence secret, to avoid the well-known
  confirmation-of-file attack). Restic and Kopia have this; the
  payoff is much smaller buckets for users with image / video
  collections.
- **Compression.** Zstd before encryption. Cheap win; transparent.
- **Key rotation.** Passphrase change without re-encrypting every file:
  unwrap-and-rewrap all data keys under the new master, leave file
  ciphertexts alone. Manifest gets a `rekey` event recording the
  rotation timestamp; readers prefer the newest wrap. Cryptomator
  desktop has this; we should match.

### Platform reach

- **PWA install + offline cache.** Service worker caches the static
  HTML + ESM modules and last-known manifest; bucket reads degrade
  gracefully when offline. Reads stay E2EE in-browser; writes queue
  for next online tick.
- **WebDAV bridge.** A small Cloudflare Worker (or `crate-agent` mode)
  exposes a WebDAV endpoint that the OS can mount as a network drive.
  The bridge holds NO keys — it relays signed range-reads from the
  authenticated session in the user's browser tab via WebSocket. Makes
  Crate mountable by `Finder` / `Explorer` for users who want
  shell-tool access without giving up the no-install browser-only path.

## Updating this doc

When we ship something from "Coming soon", move it into the appropriate
section table with a one-line description. When a comparable ships a
feature that changes their column, update it — these projects evolve
and a stale comparison is worse than no comparison. Date the doc at the
top if the gap to the last review is more than ~3 months.

Last reviewed: 2026-05-26.
