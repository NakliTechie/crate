# Crate ESM API

The `Crate` class in [`lib/crate.js`](../lib/crate.js) is the programmatic surface other NakliTechie tools (Folio, Slate, Bahi, Mahalla, VaultMind, Tijori, KanZen…) bind to. The 9-method surface below is the v1 contract — adding methods is a minor version bump; removing or changing them is a major bump.

The shape mirrors File System Access (FSA). Apps choose at runtime: local FSA (default) or this Crate adapter. Same code path; different backend.

## Lifecycle

```js
import { Crate } from "./lib/crate.js";

// Open an existing folder
const crate = await Crate.open({
  bucketConfig: { accountId: "62231b…", name: "my-crate", region: "auto" },
  credentials:  { accessKey: "ak…", secretKey: "sk…" },
  passphrase:   "correct horse battery staple seven",
});

// …use it…
await crate.list("/");
const bytes = await crate.read("/notes/foo.md");
await crate.write("/notes/foo.md", new TextEncoder().encode("hello"));
await crate.remove("/notes/foo.md");
await crate.move("/a.md", "/b.md");
await crate.mkdir("/projects/");
const meta = await crate.stat("/notes/foo.md");
const events = await crate.history("/notes/foo.md");
const unsub = crate.onChange((e) => console.log("changed:", e));

// Always close — zeroes the in-memory master key
crate.close();
```

For first-time bucket setup (writes `.crate/crate.json` + an empty
manifest) use `Crate.bootstrap({…})` with the same args as `open({…})`.
The onboarding wizard's Done stage uses this internally; downstream apps
will rarely call it directly.

## Methods — full reference

### `Crate.open({ bucketConfig, credentials, passphrase } | { bucketConfig, credentials, recoveryEntropy })`

Opens an existing Crate folder. Reads `.crate/crate.json` and recovers
the content key from the slot the caller holds: the passphrase (a v1.0
vault derives the key with PBKDF2-SHA256, 600 000 iterations; a v1.1
vault unwraps it), or — v1.1 only — `recoveryEntropy`, the 32 bytes a
24-word recovery phrase encodes (`lib/recovery.js::mnemonicToEntropy`).
Then reads + decrypts the manifest and returns a `Crate` ready for I/O.

**Throws** `CrateError` on:
- bucket missing or unreachable
- credentials reject (HTTP 403 from R2)
- `.crate/crate.json` absent (use `Crate.bootstrap` for first-time setup)
- wrong passphrase / wrong recovery phrase (the message names which)
- `recoveryEntropy` given for a vault with no recovery slot
- manifest decrypt or signature check fails (tampered ciphertext)

### `Crate.bootstrap({ bucketConfig, credentials, passphrase, recoveryEntropy?, identity?, createdBy? })`

Initialises a fresh Crate as a **v1.1 vault**: mints a random content
key, writes `.crate/crate.json` with a `passphrase_wrap` and — when
`recoveryEntropy` is given — a `recovery_wrap`, plus an empty
signed-JSONL manifest, then returns an open instance. If the bucket
already had a `.crate/crate.json`, calling `bootstrap` OVERWRITES it;
existing manifest events become unreadable. Use with care.

### `crate.setPassphrase(newPassphrase)` — v1.1

Re-wraps the content key under a new passphrase and writes
`.crate/crate.json` with `If-Match` on the copy this instance read. The
recovery slot, if any, is carried over; no object or manifest byte
changes. Throws `CrateError` mentioning "another device" on a 412.

### `crate.enableRecovery(recoveryEntropy, { passphrase? })` — v1.1

Adds or replaces the recovery slot (same conditional write). A v1.0
vault is migrated to v1.1 in the same write and needs the current
`passphrase` for its passphrase slot; the key is unchanged (see
[encryption-model.md](encryption-model.md#the-content-key-v11--and-the-master-key-v10)
for the trade-off). `crate.hasRecovery` reports the slot's presence.

### `crate.list(path = "/")` → `Array<Entry>`

Lists the immediate children of `path`. Returns
`[{ path, name, isDir, size, mime, ts }]`. Folders surface even if no
explicit `mkdir` event exists — they're implied by file paths.

### `crate.read(path)` → `Uint8Array`

Streams the encrypted object body, unwraps its data key with the master
key, decrypts the payload, and returns the plaintext bytes. Caller wraps
in a `Blob` or `TextDecoder` as appropriate.

### `crate.write(path, bytes, { mime? } = {})`

If `path` exists: re-encrypts under the SAME data key + a fresh IV,
PUTs the ciphertext, appends an `update` event to the manifest. If
`path` is new: generates a fresh data key, wraps under master, PUTs to
`objects/{uuid}`, appends a `create` event. Either way, the manifest is
re-encrypted + PUT to the bucket after the operation.

### `crate.remove(path)`

DELETEs the underlying `objects/{uuid}` and appends a `delete` event.
Idempotent: removing an already-absent path is a no-op. (The folder UI's
Delete is softer: it appends the event and keeps the object for 30 days
so the file can be restored from Trash — see encryption-model.md.)

### `crate.move(from, to)`

Pure manifest event — the object stays at the same `objects/{uuid}` URL.
Cheap, doesn't re-PUT the ciphertext.

### `crate.mkdir(path)`

Records an explicit `mkdir` event so empty folders survive a
re-materialisation. Folders are otherwise virtual (implied by file
paths).

### `crate.stat(path)` → `{ path, isDir, size, mime, ts, uuid } | null`

Returns the current metadata for `path`, or `null` if absent. The
returned object MUST be treated as read-only.

### `crate.history(path)` → `Array<{ op, ts, path, size }>`

Returns all manifest events affecting `path`, oldest first. Useful for
"who changed this and when" UIs. Includes the `create`, all `update`s,
any `move`s, and a final `delete` if present.

### `crate.onChange(handler)` → `unsubscribe()`

Subscribes to change notifications. The handler fires for **this instance's** mutations, for other tabs in the same origin (via BroadcastChannel), and for changes the manifest poller picks up from other devices (~15s polling cadence). Returns an `unsubscribe` function.

### `crate.close()`

Zeroes the master key, detaches the bucket credentials, clears the
listener list. After `close()`, every method throws `CrateError("Crate
is closed")`. Idempotent.

## Errors

All thrown errors are `CrateError` (which extends `Error`). The `name`
is `"CrateError"`; the `message` carries the operation + the upstream
HTTP status / decrypt error / etc.

## Cross-surface interop

The wire format (`.crate/crate.json`, encrypted-JSONL manifest, AES-GCM
object payloads, AES-GCM-wrapped data keys, PBKDF2-derived master key)
matches the daemon `crate-agent` byte-for-byte. The two surfaces share
the same Crate folder transparently; a file written from the browser
appears in the daemon's `~/crate/` within seconds (and vice-versa).

## Embedding example

```html
<!doctype html>
<script type="module">
  import { Crate } from "https://crate.naklios.dev/lib/crate.js";

  const crate = await Crate.open({
    bucketConfig: { accountId: "…", name: "…", region: "auto" },
    credentials:  { accessKey: "…", secretKey: "…" },
    passphrase:   "…",
  });

  await crate.write("/hello.txt", new TextEncoder().encode("hi"));
  const back = await crate.read("/hello.txt");
  console.log(new TextDecoder().decode(back));    // → "hi"
  await crate.remove("/hello.txt");

  crate.close();
</script>
```

Run from any origin the bucket's CORS allows (or, for a carrier folder, any origin in the Worker's `ALLOW_ORIGINS`).

## Versioning

The 9-method surface above is the v1 contract; v1.1 added `setPassphrase`, `enableRecovery`, `hasRecovery` and the `recoveryEntropy` open path (additive — minor bump). Adding a method bumps the minor version (no breaking change). Removing or changing a method signature bumps the major version and breaks downstream consumers.

The encryption format version is `v: 1` (carried in `.crate/crate.json` and every manifest event); `crate.json` additionally carries a schema `version` of `"1.0"` (salt + derived key) or `"1.1"` (wrapped content key, optional recovery slot), both readable by browser and daemon. A `v: 2` upgrade requires a migration path from v1 (read-old + write-new on next open) and coordinated browser+daemon releases. The daemon tolerates higher `v` on read (forward-compat) but only writes the version it was built for.
