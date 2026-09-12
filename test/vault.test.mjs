// SPDX-License-Identifier: AGPL-3.0-or-later
// v1.1 key slots: seal with a passphrase (+ optional recovery phrase),
// open with either, refuse the wrong one, re-wrap without changing the
// content key, still open v1.0. T1 phases 3-6 build on this.

import assert from "node:assert/strict";
import { sealVault, openVault, rewrapVault, VaultError } from "../lib/vault.js";
import * as cratejson from "../lib/cratejson.js";
import * as cryptoLib from "../lib/crypto.js";
import { entropyToMnemonic, mnemonicToEntropy } from "../lib/recovery.js";

const eq = (a, b) => assert.equal(Buffer.from(a).toString("hex"), Buffer.from(b).toString("hex"));
const PASS = "sphere-cancel-scan-blanket-interest";
const entropy = cryptoLib.randomBytes(32);
const words = await entropyToMnemonic(entropy);
assert.equal(words.length, 24);

// seal with both slots → v1.1 doc with both wraps, distinct salts
const sealed = await sealVault({ passphrase: PASS, recoveryEntropy: entropy, createdBy: "test" });
const doc = cratejson.parse(sealed.crateJsonBytes);
assert.equal(doc.version, "1.1");
assert.ok(doc.passphraseWrap && doc.recoveryWrap, "both slots present");
assert.notEqual(Buffer.from(doc.passphraseWrap.saltBytes).toString("hex"), Buffer.from(doc.recoveryWrap.saltBytes).toString("hex"));
eq(sealed.passphraseSalt, doc.passphraseWrap.saltBytes);

// either credential recovers the same content key
eq(await openVault(doc, { passphrase: PASS }), sealed.contentKey);
eq(await openVault(doc, { recoveryEntropy: await mnemonicToEntropy(words.join(" ")) }), sealed.contentKey);

// wrong credential → VaultError{wrongCredential:true}, not a generic throw
for (const bad of [{ passphrase: "sphere cancel scan blanket wrong" }, { recoveryEntropy: cryptoLib.randomBytes(32) }]) {
  await assert.rejects(openVault(doc, bad), (e) => e instanceof VaultError && e.wrongCredential === true);
}

// seal without recovery → no slot; opening by phrase is a plain VaultError (not "wrong")
const noRec = await sealVault({ passphrase: PASS });
const docNoRec = cratejson.parse(noRec.crateJsonBytes);
assert.equal(docNoRec.recoveryWrap, undefined);
await assert.rejects(openVault(docNoRec, { recoveryEntropy: entropy }), (e) => e instanceof VaultError && e.wrongCredential === false);

// rewrap: new passphrase, recovery slot carried over byte-for-byte; content key unchanged
const re = cratejson.parse(await rewrapVault(doc, sealed.contentKey, { passphrase: "new-pass-phrase-here" }));
eq(await openVault(re, { passphrase: "new-pass-phrase-here" }), sealed.contentKey);
await assert.rejects(openVault(re, { passphrase: PASS }), (e) => e.wrongCredential === true);
eq(re.recoveryWrap.ctBytes, doc.recoveryWrap.ctBytes);
eq(await openVault(re, { recoveryEntropy: entropy }), sealed.contentKey);

// rewrap: add a recovery slot to a vault that had none (the enableRecovery shape for v1.1)
const added = cratejson.parse(await rewrapVault(docNoRec, noRec.contentKey, { recoveryEntropy: entropy }));
eq(added.passphraseWrap.ctBytes, docNoRec.passphraseWrap.ctBytes);
eq(await openVault(added, { recoveryEntropy: entropy }), noRec.contentKey);

// v1.0 doc: openVault falls back to PBKDF2 master key; no recovery; rewrap refused
const salt = cryptoLib.randomSalt();
const v10 = cratejson.parse(cratejson.build({ salt }));
eq(await openVault(v10, { passphrase: PASS }), await cryptoLib.deriveMasterKey(PASS, salt));
await assert.rejects(openVault(v10, { recoveryEntropy: entropy }), (e) => e instanceof VaultError && !e.wrongCredential);
await assert.rejects(rewrapVault(v10, noRec.contentKey, { recoveryEntropy: entropy }), VaultError);

// input guards
await assert.rejects(sealVault({ passphrase: "" }), VaultError);
await assert.rejects(sealVault({ passphrase: PASS, recoveryEntropy: new Uint8Array(31) }), VaultError);

console.log("OK: vault v1.1 slots — passphrase or recovery phrase opens; wrong credential refused; re-wrap keeps the content key; v1.0 still opens");
