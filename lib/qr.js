// SPDX-License-Identifier: AGPL-3.0-or-later
// QR encode for the device-pairing flow.
//
// M7 v1.0 ships ONLY the device-pairing UI (intent POST + countdown +
// cancel + copy-to-clipboard). The QR matrix renderer is deferred to
// M7.1 — vendoring a QR-Code library (Project Nayuki or kazuhikoarase)
// is its own audit + licence pass. Users can still pair in M7 via
// copy-paste: the phone receives the CRATE-PAIR token in clipboard
// or via OS share-sheet from the desktop tab.
//
// Until M7.1 lands, render() returns a placeholder block. Once the
// vendor lands, swap in the real matrix renderer behind the same API.

export function encode(_text, _opts) {
  return {
    available: false,
    reason: "QR rendering is M7.1 — pair via copy-paste for now",
  };
}

// renderTo() draws a QR code into `el`. When QR isn't available it
// inserts a small "scan-via-copy-paste-fallback" instruction block.
// Same signature both before and after M7.1 so consumers don't need
// to branch on availability.
export function renderTo(el, text, opts = {}) {
  while (el.firstChild) el.removeChild(el.firstChild);
  const placeholder = document.createElement("div");
  placeholder.className = "qr-placeholder muted small";
  placeholder.textContent = "QR display arrives at M7.1 — copy the token below and paste it on the other device.";
  el.appendChild(placeholder);
  // Suppress unused-var lints for the to-be-implemented signature.
  void text; void opts;
}
