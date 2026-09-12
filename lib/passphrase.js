// SPDX-License-Identifier: AGPL-3.0-or-later
// Passphrase input forms. The wizard's five suggested BIP-39 words are
// stored dash-joined ("sphere-cancel-scan-blanket-interest"); a person who
// wrote the words down types them with spaces. Both must open the folder,
// so every unlock path tries the forms below in order and adopts the one
// that works. Pure functions, no DOM — tested in test/passphrase.test.mjs.

// passphraseCandidates returns the forms of a typed passphrase worth
// trying, the typed one first: spaces→dashes, dashes→spaces, trimmed.
// Deduplicated; a passphrase with neither separator yields one entry.
export function passphraseCandidates(typed) {
  const t = String(typed ?? "");
  const out = [t];
  const trimmed = t.trim();
  if (/\s/.test(trimmed)) out.push(trimmed.split(/\s+/).join("-"));
  if (/-/.test(trimmed)) out.push(trimmed.split(/-+/).join(" "));
  if (trimmed !== t) out.push(trimmed);
  return [...new Set(out)].filter((c) => c.length > 0);
}

// isWrongPassphraseError: the failure shapes a wrong passphrase produces
// on open — the manifest's AES-GCM tag check (OperationError), or the
// creds file's own check. Anything else (network, 404, schema) is not a
// passphrase problem and must not be retried with a different one.
export function isWrongPassphraseError(e) {
  const m = String(e?.message ?? e ?? "");
  return /decrypt failed|OperationError|Wrong passphrase/i.test(m);
}
