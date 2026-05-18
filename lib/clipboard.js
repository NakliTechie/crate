// SPDX-License-Identifier: AGPL-3.0-or-later
// Clipboard helper. Modern path uses `navigator.clipboard.writeText`;
// the fallback covers older browsers and contexts where Clipboard API
// is blocked (e.g. iframe without permissions).
//
// Callers: onboarding CORS stage, recovery-phrase stage, pair-token stage.

export async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through to the textarea-selection fallback.
    }
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "absolute";
  ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(ta);
  return ok;
}
