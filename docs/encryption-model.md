# Crate encryption model

This is the design doc for everything cryptographic in Crate. It exists so you don't have to reverse-engineer `lib/crypto.js` and `lib/manifest.js` to convince yourself the privacy claim is real.

## The claim

> The bucket owner (Cloudflare, Backblaze, Hetzner, AWS — whoever you picked) sees ciphertext and access patterns only. Without your passphrase, the bucket's contents are unintelligible random bytes. Crate itself never sees your passphrase or your plaintext — the encryption happens in your browser tab before any HTTP request goes out.

## What the bucket holds

For a working Crate folder, your bucket has this structure:

```
your-bucket/
├── .crate/
│   ├── crate.json              # config (plaintext): salt, version, hints
│   └── manifest.jsonl.enc      # encrypted, signed, append-only event log
└── objects/
    ├── 01JFXKEY1FILE0…ULID     # one encrypted blob per file you've stored
    ├── 01JFXKEY1FILE0…ULID     # ULID is the object's UUID; the manifest maps
    └── …                       # paths -> UUIDs
```

`crate.json` is plaintext because it has to be — the salt has to be readable to derive the master key from your passphrase on the next unlock. Everything else is encrypted.

## Key hierarchy

There are three keys in play, derived in a chain:

```
passphrase  ──[ PBKDF2-SHA256(salt, 600 000 iter, 32 bytes) ]──>  master key
master key  ──[ AES-256-GCM wrap, per-file random data key  ]──>  data key (one per file)
data key    ──[ AES-256-GCM encrypt(plaintext, IV, AAD=UUID)]──>  ciphertext blob
```

### The master key

- **Algorithm**: PBKDF2-SHA256, 600 000 iterations, 32-byte output.
- **Salt**: 16 random bytes from `crypto.getRandomValues`, stored in `.crate/crate.json` at bucket-setup time and never changed.
- **Lives only in your browser tab's memory.** Never written to disk, never sent over the network, never put into IndexedDB or sessionStorage. `Crate.close()` zeros it via `crypto.subtle`'s internal handling (we deliberately don't keep our own copy).
- **600k iterations** matches the OWASP 2023 recommendation for PBKDF2-SHA256. About 1 second on a modern phone, 200 ms on a desktop — annoying enough to slow brute-force, fast enough you don't notice.

The master key never directly encrypts file content. It only wraps per-file data keys.

### Per-file data keys

- **Algorithm**: AES-256-GCM, fresh 32-byte random key per file from `crypto.getRandomValues`.
- **Lives only as long as one read or write operation.** Generated fresh on `write()`, used immediately, zeroed.
- **Wrapped under the master key** via AES-256-GCM with the file's UUID as additional-authenticated-data (AAD). The wrapped form (IV + ciphertext) lives in the manifest, not on the object itself.

Why per-file keys? So that if a single data key ever leaks (e.g., a debugger snapshot, a coredump), the blast radius is one file — not the whole vault.

The AAD-on-UUID binding is the row-swap defense: if an attacker swaps two `objects/{uuid}` blobs in the bucket, the unwrap step fails authentication because the AAD no longer matches the ciphertext's intended UUID.

### File ciphertext

- **Algorithm**: AES-256-GCM with the per-file data key.
- **Layout**: 12-byte IV ‖ ciphertext+tag.
- **AAD**: the file's UUID — same defense as the data-key wrap.

Each file gets a fresh IV per write. We never reuse an IV under the same key, even on `update()` — the data key is the same, but the IV changes.

## The signed manifest

`.crate/manifest.jsonl.enc` is the source of truth for the folder shape. It's an append-only JSONL stream of events:

```json
{"v":1,"ts":"2026-05-21T15:00:00Z","op":"create","path":"/notes/foo.md","uuid":"01JFX…","size":1234,"mime":"text/markdown","data_key_iv":"…","data_key_ct":"…","content_iv":"…","prev_sig":"","sig":"abc…"}
{"v":1,"ts":"2026-05-21T15:01:00Z","op":"update","path":"/notes/foo.md","uuid":"01JFX…","size":1255,"data_key_iv":"…","data_key_ct":"…","content_iv":"…","prev_sig":"abc…","sig":"def…"}
{"v":1,"ts":"2026-05-21T15:02:00Z","op":"delete","path":"/notes/foo.md","uuid":"01JFX…","prev_sig":"def…","sig":"ghi…"}
```

Five event kinds: `create`, `update`, `delete`, `move`, `mkdir`. Materialising the manifest means folding the event stream into a final `Map<path, entry>` — last write wins per path; `move` rewrites the path; `delete` removes; `mkdir` records empty folders.

### The prev_sig chain

Each event's `sig` is `HMAC-SHA256(master_key, canonical_json(event_without_sig))`. Each event's `prev_sig` field equals the previous event's `sig`. So:

- Tampering with any event invalidates that event's `sig` AND breaks the next event's `prev_sig` reference.
- Reordering events breaks the chain.
- Truncating the tail leaves the chain technically valid but visibly shorter — the daemon and browser both reject manifests whose tail goes backwards in time.

`Manifest.verify(master_key)` walks the chain and rejects on the first mismatch. The browser runs this on every load; the daemon runs it on every puller tick.

### Encrypted at rest

The whole manifest is then AES-256-GCM-encrypted under the master key (with its own fresh IV per write) before being PUT to the bucket as `.crate/manifest.jsonl.enc`. So the bucket sees neither the events themselves nor the signature chain — both are inside the AEAD seal.

This means even an attacker with bucket access can't see what files exist, only how many objects exist. The object count + size distribution is the access-pattern leak; there's no defense against that short of constant-rate dummy traffic, which isn't worth the cost for v1.0.

## Concurrent writes — ETag-conditional PUT

Two surfaces (browser tab + daemon, or two browser tabs) can race on manifest writes. Crate uses R2's `If-Match: <etag>` to make the PUT atomic:

1. Read the manifest, record its `ETag`.
2. Mutate locally (append events).
3. PUT with `If-Match: <last-known ETag>`.
4. If R2 returns 412 (precondition failed): another writer beat us. Re-GET, splice our local events on top of the fresh manifest, re-sign, retry. Up to 3 times.

The browser side is `_flushManifest()` in `lib/crate.js`; the daemon side is `putManifest()` in `internal/syncer/syncer.go`. Same algorithm, symmetric.

## No recovery credential

v1 has only one credential: your passphrase. There is no recovery phrase, no email-reset, no support backdoor. If you lose the passphrase, the bucket's contents are unrecoverable random bytes — by design.

That's the privacy guarantee cutting both ways. The cryptographic property that prevents Cloudflare from reading your files also prevents Crate (or anyone) from helping you recover them. Use a password manager. Write the passphrase on paper. Pick something memorable.

A future "Forgot passphrase? Use recovery phrase" flow would require a second credential bound to the same encryption — that's a v2 design decision (the schema would need an additional key-wrap slot in `.crate/crate.json`). v1 doesn't ship it.

## Credentials file (`.crate-creds`)

To open a Crate you need five things: bucket name, account ID, access key, secret key, passphrase. The first four are bucket-identifying / accessing strings; the fifth is your secret. Typing all five every time is hostile.

The credentials file bundles the first four into a single artifact encrypted under the fifth. The user downloads it at first-time setup; on every subsequent unlock they pick the file + type the passphrase. Two clicks instead of five.

The file is a CLIENT artifact — **never stored on the bucket**. Wire shape:

```json
{
  "v":     1,
  "type":  "crate-creds",
  "hint":  "<bucket-name>",
  "kdf":   { "algo": "PBKDF2-SHA256", "iter": 600000 },
  "salt":  "<base64 16 bytes — independent of bucket salt>",
  "iv":    "<base64 12 bytes>",
  "ct":    "<base64 AES-256-GCM(canonical-JSON inner)>"
}
```

Inner plaintext (the thing the file hides):

```json
{
  "v":          1,
  "provider":   "r2",
  "bucket":     { "name": "...", "accountId": "...", "region": "auto" },
  "credentials":{ "accessKey": "...", "secretKey": "..." }
}
```

The `hint` field is plaintext so the unlock UI can show "Welcome back to `<bucket-name>`" before the user types anything. It's not security-critical: anyone who can read the file already knows the bucket exists, and the bucket's identifying strings are inside the AEAD seal anyway.

### Threat model

The file doesn't weaken anything compared to typing the five strings directly:

| Attacker has | Result |
|---|---|
| File only | PBKDF2/600k + AES-256-GCM brute force barrier. 70-bit passphrase = practically infeasible. |
| Passphrase only | They'd need to re-derive the bucket creds from somewhere else (Cloudflare dashboard, e.g.). The file doesn't add risk; they already have the creds in their head. |
| Both | Reads the folder. By design — this is what "two factor for credentials" means. |
| File posted publicly | Pre-encrypted; same passphrase floor. The file IS designed to be passable (email, store in 1Password, etc.). |

Independent salt per file (not the bucket's salt) so two Crates encrypted under the same passphrase have unrelated ciphertext.

### Refresh-resilient session

The same encrypted blob is also written to `sessionStorage` after first-time setup or a successful unlock. On page refresh, the wizard detects the blob and routes the user to a streamlined "Welcome back to `<name>`. Enter passphrase to reopen." prompt. The blob is tab-scoped (dies on tab close, not on refresh) and useless without the passphrase. Cleared on Start-over.

### Implementation

Single module: [`lib/credsfile.js`](../lib/credsfile.js). Pure WebCrypto, no third-party code, no new vendor. The same `lib/crypto.js` primitives the master-key derivation uses.

## What we explicitly don't protect against

Threat model is precise. Some things are out of scope:

- **Compromise of your browser tab.** If a Chrome extension can read this tab's memory while you're unlocked, it can read your master key + every file you touch. We can't defend against this — same as 1Password, BitWarden, etc. Run a clean browser profile if this matters.
- **Compromise of your laptop's RAM while the daemon is running.** Same as above for `crate-agent`. Cold-boot attacks; root malware; anything with `ptrace` on a running process.
- **Side-channel timing on the bucket.** The number of objects + sizes leak (access pattern). For high-stakes ops, route through Tor and use a different IP per session.
- **Future cryptanalytic break of AES-256-GCM or PBKDF2-SHA256.** If either falls, so does everyone using them. Crate's format is versioned (`v:1` everywhere); migrating to `v:2` if needed is a defined path (re-encrypt-on-write).
- **Quantum computing on a usable timescale.** AES-256 retains 128 bits of security against Grover, which is still post-quantum-safe enough for most threat models. We'll revisit if NIST PQ standards stabilise.

## Reading the code

Three files do the heavy lifting:

- [`lib/crypto.js`](../lib/crypto.js) — every primitive: `deriveMasterKey`, `encrypt`, `decrypt`, `wrapDataKey`, `unwrapDataKey`, `hmacSign`. Pure WebCrypto; no third-party code in this file.
- [`lib/manifest.js`](../lib/manifest.js) — the `Manifest` class: `append`, `verify`, `materialise`, `encryptToBytes`, `loadFromBytes`. JSONL parsing + the prev_sig chain.
- [`lib/bucket.js`](../lib/bucket.js) — every network call. `signedGet`, `signedPut` (with `If-Match` for concurrent-write safety), `signedDelete`, `corsPreflight`, etc.

If you find a bug in any of these, open an issue — security-relevant findings get fast turnaround.
