# Crate (browser) — security review (Codex, 2026-05)

**Status as of 2026-05-21**: H1, H3, H4, M1 patched in [`3699c86`](https://github.com/NakliTechie/crate/commit/3699c86). H2 (manifest rollback / truncation detection) deferred to v1.x — requires persistent tail anchor across browser+daemon; design discussion needed. L1 (`.crate-creds` plaintext hint) is intentional and documented in `lib/credsfile.js`.

The body below is the raw audit output, unedited.

---

## Critical

(none found)

## High

### 1. Object ciphertext rollback for the same file UUID is accepted
- **File:** `lib/crate.js:223-231`, `lib/folder.js:572-584`, `lib/crypto.js:135-144`
- **What:** File reads authenticate object ciphertext only with `uuid` AAD and trust the IV embedded in the object body, while the manifest’s `content_iv` is not checked on read.
- **Why it matters:** A bucket-only attacker can replay an older ciphertext body for the same `objects/{uuid}`; AES-GCM still authenticates because the key and UUID AAD match, so the user receives stale plaintext without detection even if the manifest is current.
- **Fix:** Bind each content version to the manifest by verifying the object IV/hash/tag against signed manifest fields, or use immutable per-version object keys/content hashes and reject object bytes that do not match the signed manifest entry.

### 2. Manifest rollback/truncation via old valid ciphertext is not detected
- **File:** `lib/manifest.js:175-206`, `lib/crate.js:99-107`, `lib/folder.js:720-728`, `lib/sync-client.js:96-114`
- **What:** Any previously valid encrypted manifest can be served back and accepted as the current state.
- **Why it matters:** A bucket-only attacker can replay an older `.crate/manifest.jsonl.enc`, silently hiding newer creates, resurrecting deleted entries, or reverting metadata; AES-GCM and the `prev_sig` chain only prove the replayed prefix was once valid.
- **Fix:** Persist and verify a last-seen manifest tail `{count, sig}` per client and require newly loaded manifests to extend it; for stronger multi-device protection, anchor the current signed head outside the replayable bucket or use bucket/object-versioning semantics that clients verify.

### 3. Programmatic `Crate.open()` conflict replay can lose remote updates
- **File:** `lib/crate.js:52-67`, `lib/crate.js:99-121`, `lib/crate.js:399-445`
- **What:** `_lastFlushedEventCount` is never initialized for `Crate.open()`, so a 412 retry treats the entire old manifest plus the new local event as “local events to replay.”
- **Why it matters:** If two writers race, the losing writer can replay stale `create`/`update`/`move` events after the fresh remote manifest, causing materialisation to roll back another writer’s update while still producing a valid `prev_sig` chain.
- **Fix:** Initialize `_lastFlushedEventCount` to `manifest.events.length` on open/bootstrap and update it on every sync refresh, or track pending local events by a remembered base tail signature rather than by an unset counter.

### 4. Sync polling can erase unflushed UI upload events
- **File:** `lib/folder.js:468-475`, `lib/folder.js:512-520`, `lib/sync-client.js:106-114`
- **What:** `FolderUI.uploadOne()` appends manifest events before the batch `flushManifest()`, while `SyncClient._pollManifest()` can replace `manifest.events` in place during that unflushed window.
- **Why it matters:** A remote write or poll during a multi-file upload can silently drop local upload events, leaving uploaded ciphertext orphaned and absent from the manifest.
- **Fix:** Serialize sync refreshes and local mutations through one manifest queue, or have `SyncClient` skip/merge while the session has unflushed local events.

## Medium

### 1. Manifest signatures are not verified on load
- **File:** `lib/manifest.js:74-90`, `lib/manifest.js:206-232`
- **What:** `Manifest.loadFromBytes()` decrypts and parses JSONL but never calls `verify()`, and `fromJSONL()` checks only `prev_sig` string continuity, not each HMAC.
- **Why it matters:** Bucket-only tampering is still blocked by AES-GCM, but the advertised signed JSONL layer is not actually enforced after decryption and would not catch malformed same-key or implementation-bugged producers.
- **Fix:** Have `loadFromBytes()` verify every event HMAC after parsing and fail closed on any mismatch.

## Low / Informational

### 1. `.crate-creds` leaks the bucket hint in plaintext
- **File:** `lib/credsfile.js:80-87`, `lib/credsfile.js:102-138`
- **What:** The credentials file stores `hint` outside the encrypted payload.
- **Why it matters:** Someone who steals only the `.crate-creds` file can read the bucket name hint without the passphrase, though not the access key, secret key, account ID, or encrypted credentials.
- **Fix:** Treat this as intentional UI metadata or move the hint inside the encrypted payload if bucket-name disclosure is not acceptable.

## Confirmed-safe areas

- PBKDF2 uses SHA-256, 600,000 iterations, 16-byte salts, and 32-byte master keys in `lib/crypto.js:71-90`.
- AES-GCM IVs are generated with `crypto.getRandomValues()` and are 12 bytes in `lib/crypto.js:45-49` and `lib/crypto.js:102-115`.
- Credentials files use an independent random salt and AES-GCM encryption under the passphrase-derived key in `lib/credsfile.js:73-87`.
- HMAC verification uses `crypto.subtle.verify()` in `lib/crypto.js:167-183`.
- Manifest encryption uses explicit AAD for `.crate/manifest.jsonl.enc:v1` in `lib/manifest.js:175-206`.
- `signedPut()` preserves and signs `If-Match` for manifest conditional writes in `lib/bucket.js:242-268`.
- SigV4 signs concrete payload hashes, including empty-body SHA-256 for GET/HEAD/DELETE and SHA-256 of PUT bodies in `lib/sigv4.js:129-154`.
- Locking zeroes the `Uint8Array` master key, clears session secrets, removes the encrypted session creds blob, and deletes devtools session handles in `lib/entrypoint.js:77-111`.
- CSP has `script-src 'self'` with no `unsafe-inline` or `unsafe-eval`; `connect-src` is limited to self plus S3-compatible bucket hosts in `index.html:5-9`.