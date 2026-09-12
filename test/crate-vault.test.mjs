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
await assert.rejects(Crate.open({ bucketConfig, credentials }), (e) => e instanceof CrateError && /passphrase, recoveryEntropy or contentKey/.test(e.message));

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

// --- v1.0 vault → enableRecovery migrates to v1.1 without re-keying ----
store.clear();
{
  const salt = cryptoLib.randomSalt();
  const mk = await cryptoLib.deriveMasterKey(PASS, salt);
  const base = (await Crate.bootstrap({ bucketConfig, credentials, passphrase: "throwaway" }))._bucketBase; // just to learn the base
  store.clear();
  store.set(base + cratejson.CRATE_PATH, { body: cratejson.build({ salt }), etag: '"v10"' });
  const man = new Manifest();
  store.set(base + ".crate/manifest.jsonl.enc", { body: await man.encryptToBytes(mk), etag: '"m10"' });

  const legacy = await Crate.open({ bucketConfig, credentials, passphrase: PASS });
  await legacy.write("/old.txt", new TextEncoder().encode("old"));
  await assert.rejects(legacy.enableRecovery(entropy), /v1\.0 vault; pass \{ passphrase \}/);
  await legacy.enableRecovery(entropy, { passphrase: PASS });
  assert.equal(legacy.hasRecovery, true);
  const migrated = cratejson.parse(store.get(base + cratejson.CRATE_PATH).body);
  assert.equal(migrated.version, "1.1");
  // key unchanged: the same passphrase still opens, files readable, phrase opens too
  assert.equal(Buffer.from(legacy._masterKey).toString("hex"), Buffer.from(mk).toString("hex"));
  legacy.close();
  const again = await Crate.open({ bucketConfig, credentials, passphrase: PASS });
  assert.equal(Buffer.from(again._masterKey).toString("hex"), Buffer.from(mk).toString("hex"));
  assert.equal(new TextDecoder().decode(await again.read("/old.txt")), "old");
  again.close();
  const viaPhrase = await Crate.open({ bucketConfig, credentials, recoveryEntropy: entropy });
  assert.equal(new TextDecoder().decode(await viaPhrase.read("/old.txt")), "old");
  viaPhrase.close();
}
console.log("OK: v1.0 vault migrates to v1.1 on enableRecovery; key and files unchanged; phrase opens it");

// --- rekey: new content key, data keys re-wrapped, chain re-signed, anchor accepts via generation
store.clear();
{
  const { Manifest: M2 } = await import("../lib/manifest.js");
  const anchor = await import("../lib/anchor.js");
  const a = await Crate.bootstrap({ bucketConfig, credentials, passphrase: PASS, recoveryEntropy: entropy });
  await a.write("/one.txt", new TextEncoder().encode("one"));
  await a.write("/two.txt", new TextEncoder().encode("two"));
  const oldKeyHex = Buffer.from(a._masterKey).toString("hex");
  const objectsBefore = [...store.keys()].filter((k) => k.includes("/objects/")).map((k) => [k, store.get(k).etag]);
  const before = a._manifest.events.map((e) => e.sig);
  const priorAnchor = a._manifest.tail();
  assert.equal(priorAnchor.generation, 0);

  const r = await a.rekey({ passphrase: PASS });
  assert.equal(r.generation, 1);
  assert.notEqual(Buffer.from(a._masterKey).toString("hex"), oldKeyHex);
  assert.equal(a.hasRecovery, false, "recovery slot dropped — a new phrase must be set");
  assert.equal(new TextDecoder().decode(await a.read("/two.txt")), "two", "reads work on the live instance");
  // every event re-signed, one rekey event appended, objects untouched
  assert.equal(a._manifest.events.length, before.length + 1);
  assert.ok(a._manifest.events.slice(0, -1).every((e, i) => e.sig !== before[i]));
  assert.equal(a._manifest.events.at(-1).op, "rekey");
  assert.deepEqual([...store.keys()].filter((k) => k.includes("/objects/")).map((k) => [k, store.get(k).etag]), objectsBefore);
  a.close();

  // the old phrase no longer opens; the passphrase does, and the folder is intact
  await assert.rejects(Crate.open({ bucketConfig, credentials, recoveryEntropy: entropy }), /no recovery phrase/);
  const b = await Crate.open({ bucketConfig, credentials, passphrase: PASS });
  assert.equal(new TextDecoder().decode(await b.read("/one.txt")), "one");
  assert.equal(b._manifest.generation(), 1);
  const events = b._manifest.events.map((e) => ({ ...e }));
  const bKey = b._masterKey.slice();
  b.close();

  // a device anchored before the re-key sees a "fork" at the old sig but a higher generation → accepted
  const v = anchor.validate(events, { count: priorAnchor.count, lastSig: priorAnchor.lastSig, generation: 0 });
  assert.equal(v.ok, true); assert.equal(v.rekeyed, true); assert.equal(v.anchor.generation, 1);
  // a replay of the pre-re-key manifest (generation 0) against the post-re-key anchor is refused
  const old = new M2(); for (const e of events.slice(0, -1)) old.events.push({ ...e, sig: "old" + e.sig });
  const v2 = anchor.validate(old.events, { count: events.length, lastSig: events.at(-1).sig, generation: 1 });
  assert.equal(v2.ok, false);
  // a forged chain claiming generation 2 without the key still fails signature verification before the anchor is consulted
  const forged = events.map((e) => ({ ...e }));
  forged.push({ v: 1, ts: Date.now(), op: "rekey", generation: 2, prev_sig: forged.at(-1).sig, sig: "forged" });
  const m3 = new M2(); m3.events = forged;
  assert.equal((await m3.verify(bKey)).ok, false);
}
console.log("OK: rekey — fresh content key, data keys re-wrapped, chain re-signed with a generation the anchor accepts; replay refused");

// --- compression through the Crate API: write → read, update keeps working, share carries it
store.clear();
{
  const c = await Crate.bootstrap({ bucketConfig, credentials, passphrase: PASS });
  const big = new TextEncoder().encode("row,value\n".repeat(5000));
  await c.write("/data.csv", big, { mime: "text/csv" });
  const e = c._manifest.materialise().get("/data.csv");
  assert.equal(e.compression, "deflate-raw");
  assert.ok(e.stored_size < big.length / 5);
  assert.equal(e.size, big.length);
  const obj = store.get(c._bucketBase + "objects/" + e.uuid).body;
  assert.ok(obj.length < big.length / 4, "the bucket holds the deflated bytes");
  assert.equal(Buffer.from(await c.read("/data.csv")).toString(), Buffer.from(big).toString());
  // an update to incompressible content drops the flag for that version
  const noise = cryptoLib.randomBytes(3000);
  await c.write("/data.csv", noise, { mime: "text/csv" });
  const e2 = c._manifest.materialise().get("/data.csv");
  assert.equal(e2.compression, undefined);
  assert.equal(Buffer.from(await c.read("/data.csv")).toString("hex"), Buffer.from(noise).toString("hex"));
  c.close();
}
console.log("OK: compression — Crate.write deflates text, read inflates, per-version flag");
