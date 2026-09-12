// SPDX-License-Identifier: AGPL-3.0-or-later
// Live-walk regression (2026-09-12): the five suggested words are stored
// dash-joined; typing them with spaces failed with "manifest: decrypt
// failed: OperationError". Both forms must be tried on unlock.

import assert from "node:assert/strict";
import { passphraseCandidates, isWrongPassphraseError } from "../lib/passphrase.js";

// spaces → the dashed form is tried second
assert.deepEqual(passphraseCandidates("sphere cancel scan blanket interest"),
  ["sphere cancel scan blanket interest", "sphere-cancel-scan-blanket-interest"]);
// dashes → the spaced form is tried second (own passphrase set with spaces)
assert.deepEqual(passphraseCandidates("sphere-cancel-scan-blanket-interest"),
  ["sphere-cancel-scan-blanket-interest", "sphere cancel scan blanket interest"]);
// neither separator → exactly one attempt
assert.deepEqual(passphraseCandidates("correcthorsebattery"), ["correcthorsebattery"]);
// stray whitespace around the words is tried away, typed form still first
assert.deepEqual(passphraseCandidates("  a b  "), ["  a b  ", "a-b", "a b"]);
// mixed separators normalise both ways
assert.deepEqual(passphraseCandidates("x-y z"), ["x-y z", "x-y-z", "x y z"]);
// empty input yields no candidates (callers refuse before this anyway)
assert.deepEqual(passphraseCandidates(""), []);
assert.deepEqual(passphraseCandidates(null), []);

// only passphrase-shaped failures are retried
assert.equal(isWrongPassphraseError(new Error("manifest: decrypt failed: OperationError")), true);
assert.equal(isWrongPassphraseError(new Error("Wrong passphrase, or the credentials file is corrupt.")), true);
assert.equal(isWrongPassphraseError(new Error("bucket: HEAD 404")), false);
assert.equal(isWrongPassphraseError(new TypeError("Failed to fetch")), false);
assert.equal(isWrongPassphraseError(null), false);

console.log("OK: passphrase forms — spaces and dashes both open the folder; network errors are not retried");
