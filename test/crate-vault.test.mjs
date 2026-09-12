// SPDX-License-Identifier: AGPL-3.0-or-later
// Crate.bootstrap writes a v1.1 vault; Crate.open recovers it with the
// passphrase OR the recovery phrase; a wrong credential is refused as
// such; a legacy v1.0 crate.json still opens. Runs against an in-memory
// bucket (fetch stub) — the transport is not under test here.

import assert from "node:assert/strict";
import { Crate, CrateError } from "../lib/crate.js";
import * as cratejson from "../lib/cratejson.js";
import * as cryptoLib from "../lib/crypto.js";
import { Manifest } from "../lib/manifest.js";
import { entropyToMnemonic, mnemonicToEntropy } from "../lib/recovery.js";

// --- in-memory bucket behind fetch ------------------------------------
const store = new Map(); // url → { body: Uint8Array, etag }
let n = 0;
globalThis.fetch = async (url, init = {}) => {
  const method = (init.method || "GET").toUpperCase();
  const key = String(url);
  if (method === "PUT") {
    const body = init.body instanceof Uint8Array ? init.body : new Uint8Array(init.body);
    const h = init.headers || {};
    const ifMatch = h["if-match"] || h["If-Match"] || (typeof h.get === "function" ? h.get("if-match") : null);
    if (ifMatch && store.get(key)?.etag !== ifMatch) return new Response("<Error><Code>PreconditionFailed</Code></Error>", { status: 412 });
    const etag = `"e${++n}"`;
    store.set(key, { body, etag });
    return new Response(null, { status: 200, headers: { etag } });
  }
  const hit = store.get(key);
  if (!hit) return new Response("<Error><Code>NoSuchKey</Code><Message>nope</Message></Error>", { status: 404, headers: { "content-type": "application/xml" } });
  if (method === "HEAD") return new Response(null, { status: 200, headers: { etag: hit.etag, "content-length": String(hit.body.length) } });
  return new Response(hit.body, { status: 200, headers: { etag: hit.etag } });
};

const bucketConfig = { provider: "r2", accountId: "0".repeat(32), name: "vault-test", region: "auto" };
const credentials = { accessKey: "AKIAEXAMPLEKEY000000", secretKey: "secretkeysecretkeysecretkey" };
const PASS = "sphere-cancel-scan-blanket-interest";
const entropy = cryptoLib.randomBytes(32);
const words = await entropyToMnemonic(entropy);

// bootstrap with a recovery phrase → v1.1 with both slots on the bucket
const c = await Crate.bootstrap({ bucketConfig, credentials, passphrase: PASS, recoveryEntropy: entropy });
assert.equal(c._hasRecovery, true);
const cjBytes = store.get(c._bucketBase + cratejson.CRATE_PATH).body;
const cj = cratejson.parse(cjBytes);
assert.equal(cj.version, "1.1");
assert.ok(cj.passphraseWrap && cj.recoveryWrap);
assert.equal(cj.salt, undefined, "v1.1 carries no top-level salt");
await c.write("/hello.txt", new TextEncoder().encode("hello"));
const key0 = Buffer.from(c._masterKey).toString("hex");
c.close();

// open with the passphrase
const byPass = await Crate.open({ bucketConfig, credentials, passphrase: PASS });
assert.equal(Buffer.from(byPass._masterKey).toString("hex"), key0);
assert.equal(new TextDecoder().decode(await byPass.read("/hello.txt")), "hello");
assert.equal(byPass._hasRecovery, true);
byPass.close();

// open with the recovery phrase — typed back as words, spaces, mixed case
const typed = words.map((w, i) => (i % 5 === 0 ? w.toUpperCase() : w)).join("  ");
const byPhrase = await Crate.open({ bucketConfig, credentials, recoveryEntropy: await mnemonicToEntropy(typed) });
assert.equal(Buffer.from(byPhrase._masterKey).toString("hex"), key0);
assert.equal(new TextDecoder().decode(await byPhrase.read("/hello.txt")), "hello");
byPhrase.close();

// wrong passphrase / wrong phrase → CrateError naming the credential
await assert.rejects(Crate.open({ bucketConfig, credentials, passphrase: "sphere-cancel-scan-blanket-wrong" }), (e) => e instanceof CrateError && /wrong passphrase/.test(e.message));
await assert.rejects(Crate.open({ bucketConfig, credentials, recoveryEntropy: cryptoLib.randomBytes(32) }), (e) => e instanceof CrateError && /wrong recovery phrase/.test(e.message));
await assert.rejects(Crate.open({ bucketConfig, credentials }), (e) => e instanceof CrateError && /passphrase or recoveryEntropy/.test(e.message));

// bootstrap without a phrase → passphrase-only v1.1; phrase unlock says so (not "wrong")
store.clear();
const c2 = await Crate.bootstrap({ bucketConfig, credentials, passphrase: PASS });
assert.equal(c2._hasRecovery, false);
const cj2 = cratejson.parse(store.get(c2._bucketBase + cratejson.CRATE_PATH).body);
assert.equal(cj2.version, "1.1");
assert.equal(cj2.recoveryWrap, undefined);
c2.close();
await assert.rejects(Crate.open({ bucketConfig, credentials, recoveryEntropy: entropy }), (e) => e instanceof CrateError && /no recovery phrase/.test(e.message));

// legacy v1.0 vault written by an older Crate still opens (master key = PBKDF2)
store.clear();
{
  const salt = cryptoLib.randomSalt();
  const mk = await cryptoLib.deriveMasterKey(PASS, salt);
  const base = c2._bucketBase;
  store.set(base + cratejson.CRATE_PATH, { body: cratejson.build({ salt }), etag: '"v10"' });
  const man = new Manifest();
  store.set(base + ".crate/manifest.jsonl.enc", { body: await man.encryptToBytes(mk), etag: '"m10"' });
  const legacy = await Crate.open({ bucketConfig, credentials, passphrase: PASS });
  assert.equal(Buffer.from(legacy._masterKey).toString("hex"), Buffer.from(mk).toString("hex"));
  assert.equal(legacy._hasRecovery, false);
  legacy.close();
  await assert.rejects(Crate.open({ bucketConfig, credentials, recoveryEntropy: entropy }), (e) => /no recovery phrase/.test(e.message));
}

console.log("OK: Crate.bootstrap writes v1.1; open by passphrase or recovery phrase; wrong credential named; v1.0 vaults still open");

// --- setPassphrase / enableRecovery: re-wrap, never re-encrypt ----------
store.clear();
{
  const a = await Crate.bootstrap({ bucketConfig, credentials, passphrase: PASS });
  await a.write("/keep.txt", new TextEncoder().encode("keep"));
  const objectsBefore = [...store.keys()].filter((k) => k.includes("/objects/")).map((k) => [k, store.get(k).etag]);
  assert.equal(a.hasRecovery, false);

  // add a recovery phrase after the fact
  await a.enableRecovery(entropy);
  assert.equal(a.hasRecovery, true);
  // change the passphrase; the phrase slot survives
  await a.setPassphrase("brand-new-words-here-now");
  a.close();

  const byNew = await Crate.open({ bucketConfig, credentials, passphrase: "brand-new-words-here-now" });
  assert.equal(new TextDecoder().decode(await byNew.read("/keep.txt")), "keep");
  assert.equal(byNew.hasRecovery, true);
  byNew.close();
  await assert.rejects(Crate.open({ bucketConfig, credentials, passphrase: PASS }), /wrong passphrase/);
  const byPhrase2 = await Crate.open({ bucketConfig, credentials, recoveryEntropy: entropy });
  assert.equal(new TextDecoder().decode(await byPhrase2.read("/keep.txt")), "keep");
  byPhrase2.close();

  // no object body was rewritten
  const objectsAfter = [...store.keys()].filter((k) => k.includes("/objects/")).map((k) => [k, store.get(k).etag]);
  assert.deepEqual(objectsAfter, objectsBefore);

  // a stale instance loses the If-Match race instead of clobbering
  const stale = await Crate.open({ bucketConfig, credentials, recoveryEntropy: entropy });
  const fresh = await Crate.open({ bucketConfig, credentials, recoveryEntropy: entropy });
  await fresh.setPassphrase("fresh-wins-this-race");
  await assert.rejects(stale.setPassphrase("stale-must-lose"), (e) => e instanceof CrateError && /another device/.test(e.message));
  stale.close(); fresh.close();
  const after = await Crate.open({ bucketConfig, credentials, passphrase: "fresh-wins-this-race" });
  after.close();
}
console.log("OK: setPassphrase / enableRecovery re-wrap the key slots; objects untouched; etag tracked");
