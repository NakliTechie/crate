# Crate ESM API — locked at M5

The `Crate` class in `lib/crate.js` is the programmatic surface other
NakliTechie tools (Folio, Slate, Bahi, Mahalla, VaultMind, Tijori, KanZen…)
bind to. **This surface is frozen at M5; new methods require a major
version bump.**

The shape mirrors File System Access (FSA). Apps choose at runtime: local
FSA (default) or this Crate adapter. Same code path; different backend.

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

### `Crate.open({ bucketConfig, credentials, passphrase })`

Opens an existing Crate folder. Reads `.crate/crate.json` for the salt,
derives the master key via PBKDF2-SHA256 (600 000 iterations), reads +
decrypts the manifest, and returns a `Crate` instance ready for I/O.

**Throws** `CrateError` on:
- bucket missing or unreachable
- credentials reject (HTTP 403 from R2)
- `.crate/crate.json` absent (use `Crate.bootstrap` for first-time setup)
- manifest decrypt fails (wrong passphrase or tampered ciphertext)

### `Crate.bootstrap({ bucketConfig, credentials, passphrase, identity?, createdBy? })`

Initialises a fresh Crate. Writes `.crate/crate.json` (with a fresh
16-byte salt) and an empty signed-JSONL manifest, then returns an open
instance. If the bucket already had a `.crate/crate.json`, calling
`bootstrap` OVERWRITES it; existing manifest events become unreadable.
Use with care.

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
Idempotent: removing an already-absent path is a no-op.

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

Subscribes to change notifications fired by **this instance's**
mutations. Returns an `unsubscribe` function. Cross-tab and cross-device
fires at M6 (Sync binding).

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

## 10-line external-script gate

The M5 gate is "a 10-line script in a separate `<script type=module>`
can list, read, write, delete using the API." Concretely:

```html
<!doctype html>
<script type="module">
  import { Crate } from "./lib/crate.js";
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

Run from any same-origin page; needs the bucket's CORS to allow that
origin.

## Versioning

The 9-method surface above is the v1.0 contract. Adding a method bumps
the minor version (no breaking change). Removing or changing a method
signature bumps the major version and breaks downstream consumers — do
not do it lightly.

The encryption format version is `v: 1` (carried in `.crate/crate.json`
and every manifest event). A `v: 2` upgrade requires:
- a migration path from v1 (read-old + write-new on next open)
- a documented breaking-change RFC in `docs/specs/`

Both surfaces (browser + daemon) MUST update together; the daemon
tolerates higher `v` on read (for forward-compat) but only writes `v: 1`
until its own upgrade ships.
