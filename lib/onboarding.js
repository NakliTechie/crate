// SPDX-License-Identifier: AGPL-3.0-or-later
// Crate onboarding wizard. Hash-routed FSM that walks the user through
// the 6 new-folder stages (welcome → bucket → credentials → cors →
// passphrase → done) and the unlock-existing-folder stage.
//
// The entropy meter on the Passphrase stage is real (zxcvbn-ts via
// lib/entropy.js). The passphrase is memory-only — it NEVER touches
// IndexedDB or localStorage.

import { BIP39_WORDS, wordAt } from "./wordlist.js";
import { copyText } from "./clipboard.js";
import { estimate, whenReady } from "./entropy.js";
import * as idb from "./idb.js";
import * as bucket from "./bucket.js";
import * as cryptoLib from "./crypto.js";
import * as cratejson from "./cratejson.js";
import * as credsfile from "./credsfile.js";
import { icon } from "./icons.js";
import { passphraseCandidates, isWrongPassphraseError } from "./passphrase.js";
import { Manifest } from "./manifest.js";

// Key under which we stash the encrypted creds blob in sessionStorage
// for refresh-resilience. sessionStorage scope = current tab, cleared
// on close. Same crypto as the downloadable file; passphrase still
// required to decrypt.
export const SESSION_CREDS_KEY = "crate:session-creds-v1";

// Key recording that the first-visit "What is Crate?" explainer has been
// shown. localStorage (persists across tabs + reloads, unlike the
// sessionStorage creds blob) so the modal auto-opens exactly once, ever,
// per browser profile.

// --- Constants ---------------------------------------------------------

export const STAGES = Object.freeze([
  "welcome",
  "carrier", // one-click route: the user's own crate-carrier Worker (no API token, no CORS)
  "bucket",
  "credentials",
  "cors",
  "passphrase",
  "done",
  "unlock", // unlock an existing paired folder: read .crate/crate.json,
            // decrypt manifest, hand off to folder UI without going
            // through the new-folder wizard again.
]);

const NEW_FOLDER_STAGES = ["welcome", "bucket", "credentials", "cors", "passphrase", "done"];
const CARRIER_STAGES = ["welcome", "carrier", "passphrase", "done"];
const CARRIER_DEPLOY_URL = "https://deploy.workers.cloudflare.com/?url=https://github.com/NakliTechie/crate-carrier";

// The carrier secret has to survive a page load: the user generates it
// here, pastes it into Cloudflare's deploy form in another tab, and comes
// back via the Worker's "Continue to Crate" link — a fresh load of this
// origin. So it is parked in localStorage for the duration of onboarding
// only: written when generated, read on that return, deleted the moment
// setup finishes (or on Start over / a successful unlock), and ignored
// after an hour. It grants ciphertext-only access to the user's bucket.
const PENDING_CARRIER_KEY = "crate:carrier-pending-v1";
const PENDING_CARRIER_TTL_MS = 60 * 60 * 1000;
const pendingCarrier = {
  save(rec) { try { localStorage.setItem(PENDING_CARRIER_KEY, JSON.stringify({ ...rec, ts: Date.now() })); } catch {} },
  load() {
    try {
      const rec = JSON.parse(localStorage.getItem(PENDING_CARRIER_KEY) || "null");
      if (!rec?.secret || Date.now() - (rec.ts || 0) > PENDING_CARRIER_TTL_MS) { this.clear(); return null; }
      return rec;
    } catch { return null; }
  },
  clear() { try { localStorage.removeItem(PENDING_CARRIER_KEY); } catch {} },
};

// prerequisitesList — what a new user must already have, stated before
// they start rather than discovered at step 2. Both accounts are free.
const SIGNUP = Object.freeze({
  cloudflare: "https://dash.cloudflare.com/sign-up",
  github: "https://github.com/signup",
});
function extLink(href, text) {
  return el("a", { href, target: "_blank", rel: "noopener noreferrer" }, [text]);
}
function prerequisitesList() {
  return el("ul", { class: "prereqs" }, [
    el("li", {}, ["A free ", extLink(SIGNUP.cloudflare, "Cloudflare account"), " — your Worker and bucket live there. ", el("span", { class: "muted" }, ["No card needed for Crate's usage."])]),
    el("li", {}, ["A free ", extLink(SIGNUP.github, "GitHub account"), " — Cloudflare copies the carrier's code into it. ", el("span", { class: "muted" }, ["Connected to Cloudflare once, on first deploy."])]),
    el("li", {}, ["A passphrase you'll remember. ", el("span", { class: "muted" }, ["Nobody can recover it for you."])]),
  ]);
}

function randomCarrierSecret() {
  return Array.from(cryptoLib.randomBytes(32), (b) => b.toString(16).padStart(2, "0")).join("");
}
function hostOf(url) { try { return new URL(url).host; } catch { return String(url || ""); } }
function validCarrierUrl(url) {
  try { const u = new URL(url); return u.protocol === "https:" && !!u.host; } catch { return false; }
}
const UNLOCK_STAGES = ["welcome", "unlock"];

const DEEP_LINKS = {
  bucket: "https://dash.cloudflare.com/?to=/:account/r2/overview",
  tokens: "https://dash.cloudflare.com/?to=/:account/r2/api-tokens",
};

// --- NakliOS one-click handoff -----------------------------------------
// NakliOS embeds crate in a sandboxed iframe to receive the encrypted
// `.crate-creds` envelope over postMessage instead of a manual file
// download + re-import. The parent opens:
//   https://crate.naklios.dev/?naklios-handoff=v1&parentOrigin=<enc>&nonce=<enc>
// Handoff mode is entered ONLY when the params are present, actually
// framed, AND parentOrigin is in this strict allowlist. The receiver's
// contract is frozen as `crate:naklios-setup:v1` (sender) /
// `naklios:crate-setup:ack:v1` (ack); see plan/ for the message spec.
const HANDOFF_ORIGINS = ["https://naklios.dev"];
const HANDOFF_SETUP_TYPE = "crate:naklios-setup:v1";
const HANDOFF_ACK_TYPE = "naklios:crate-setup:ack:v1";
const HANDOFF_ACK_TIMEOUT_MS = 15000;
const HANDOFF_MAX_CREDS_CHARS = 256000;

// Ack `status` → user-facing message + whether it's a terminal success.
const HANDOFF_ACK_MESSAGES = {
  stored: { ok: true, message: "Sent to NakliOS — enter your passphrase there to unlock." },
  declined: { ok: false, message: "NakliOS declined the import." },
  "already-connected": { ok: false, message: "NakliOS already has a Crate connected." },
  rejected: { ok: false, message: "NakliOS could not accept the setup." },
  failed: { ok: false, message: "NakliOS could not accept the setup." },
  expired: { ok: false, message: "The handoff timed out — reopen it from NakliOS." },
};

// Passphrase strength, in bits by zxcvbn's estimate. The passphrase is the
// only thing between bucket ciphertext and plaintext, attacked offline at
// PBKDF2-600k speed (~16k guesses/s on one GPU). MIN_BITS is the recommended
// floor — five random words clear it, ~60,000 GPU-years. Below it the user
// may still proceed after an explicit acknowledgement, down to HARD_MIN_BITS,
// which exists only to refuse the trivial ("password", a birthday).
const MIN_BITS = 55;
const HARD_MIN_BITS = 20;
const SUGGESTED_WORDS = 5;

// crackTime renders "how long on one GPU" for a bit-strength, so a weak
// choice is a number the user can weigh rather than a label.
function crackTime(bits) {
  const secs = Math.pow(2, bits) / 16000;
  if (secs < 60) return "under a minute";
  if (secs < 3600) return `${Math.round(secs / 60)} minutes`;
  if (secs < 86400) return `${Math.round(secs / 3600)} hours`;
  if (secs < 86400 * 365) return `${Math.round(secs / 86400)} days`;
  const years = secs / (86400 * 365);
  if (years < 1000) return `${Math.round(years)} years`;
  if (years < 1e6) return `${Math.round(years / 1000)} thousand years`;
  if (years < 1e9) return `${Math.round(years / 1e6)} million years`;
  return "longer than the universe";
}

// --- Helpers -----------------------------------------------------------

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (v === true) node.setAttribute(k, "");
    else if (v === false || v == null) { /* skip */ }
    else node.setAttribute(k, v);
  }
  for (const child of [].concat(children)) {
    if (child == null) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function makeFragment(...children) {
  const frag = document.createDocumentFragment();
  for (const child of children) {
    if (child) frag.appendChild(child);
  }
  return frag;
}

function announce(liveRegion, message) {
  if (!liveRegion) return;
  liveRegion.textContent = "";
  // Force a tick so screen readers pick up identical-text re-announces.
  setTimeout(() => { liveRegion.textContent = message; }, 50);
}

function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

// Hyphen-joined 7-word passphrase from BIP-39. ~77 bits entropy.
// Uses the raw wordlist directly (no checksum needed; this is just a
// strong default passphrase the user can take or replace).
function generatePassphrase() {
  const out = [];
  const buf = new Uint32Array(SUGGESTED_WORDS);
  crypto.getRandomValues(buf);
  for (const v of buf) out.push(wordAt(v % BIP39_WORDS.length));
  return out.join("-");
}

// Random `crate-XXXXXXXX` bucket name suggestion.
function suggestBucketName() {
  const bytes = randomBytes(8);
  const alpha = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "crate-";
  for (const b of bytes) s += alpha[b % alpha.length];
  return s;
}

// CORS JSON the user pastes into Cloudflare. Origin is dynamic — uses
// `location.origin` so the snippet is correct for both local dev and
// crate.naklitechie.com without manual edits.
function corsJson(origin) {
  return JSON.stringify(
    [
      {
        AllowedOrigins: [origin],
        AllowedMethods: ["GET", "PUT", "POST", "DELETE", "HEAD"],
        AllowedHeaders: ["*"],
        ExposeHeaders: ["ETag"],
        MaxAgeSeconds: 3600,
      },
    ],
    null,
    2,
  );
}

// --- Reusable UI primitives -------------------------------------------

function makePill() {
  const pill = el("span", { class: "pill pill-idle", role: "status", "aria-live": "polite" });
  function setState(state, message) {
    pill.className = `pill pill-${state}`;
    pill.textContent = message;
  }
  function reset(message = "Waiting") { setState("idle", message); }
  reset();
  return {
    el: pill,
    reset,
    check(message = "Checking…") { setState("checking", message); },
    ok(message = "✓ Found") { setState("ok", message); },
    fail(message = "✗ Failed") { setState("fail", message); },
  };
}

function makeCopyButton(getText, label = "Copy") {
  const btn = el("button", { type: "button", class: "btn btn-secondary copy-btn" }, [label]);
  btn.addEventListener("click", async () => {
    const original = btn.textContent;
    const text = typeof getText === "function" ? getText() : getText;
    const ok = await copyText(text);
    btn.textContent = ok ? "✓ Copied" : "Copy failed";
    btn.classList.toggle("copy-ok", ok);
    btn.classList.toggle("copy-fail", !ok);
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove("copy-ok", "copy-fail");
    }, 1500);
  });
  return btn;
}

function makeDeepLinkButton(href, label) {
  return el("a", {
    href,
    target: "_blank",
    rel: "noopener noreferrer",
    class: "btn btn-secondary deep-link",
  }, [label]);
}

// Maps a status "tone" to a CSS design-token colour for inline status
// text (handoff send feedback). Unknown/empty → muted.
function toneColor(tone) {
  if (tone === "ok") return "var(--ok)";
  if (tone === "error") return "var(--error)";
  return "var(--muted)";
}

// The three-point privacy promise, rendered identically on the landing
// screen and inside the "What is Crate?" help modal so both tell the
// same story. Returns a <ul class="promise-list">.
function promiseList() {
  const item = (glyph, title, detail) =>
    el("li", { class: "promise-item" }, [
      el("span", { class: "promise-icon", "aria-hidden": "true" }, [icon(glyph, { size: 18 })]),
      el("span", { class: "promise-text" }, [
        el("strong", {}, [title]),
        el("span", {}, [detail]),
      ]),
    ]);
  return el("ul", { class: "promise-list" }, [
    item("lock", "Locked on your device", "Encrypted before upload. Your passphrase never leaves this device, so nobody else can read your files — not us, not your storage provider."),
    item("bucket", "Your storage", "A free Cloudflare account holds the files; Crate sets it up for you. Or bring a bucket you already have."),
    item("slash", "No middleman", "No Crate account, no server on the path, no telemetry. Your browser talks to your storage."),
  ]);
}

const WRONG_PASSPHRASE_MSG = "That passphrase didn't open the folder. Check the words and their order — the five suggested words are typed with dashes or spaces between them, either works.";

// --- Shape validation --------------------------------------------------
// Cheap, instant client-side checks. Cheaper to surface "you typed the
// wrong shape" before doing a network round-trip.

// R2 Account ID is a 32-char lowercase hex string.
function validAccountId(s) {
  return typeof s === "string" && /^[0-9a-f]{32}$/.test(s.trim());
}

// S3 bucket name rules (subset that R2 honours): 3–63 chars, lowercase,
// alphanumeric + hyphens, no leading/trailing hyphen, no double hyphen.
function validBucketName(s) {
  if (typeof s !== "string") return false;
  const t = s.trim();
  if (t.length < 3 || t.length > 63) return false;
  if (!/^[a-z0-9]/.test(t) || !/[a-z0-9]$/.test(t)) return false;
  if (/--/.test(t)) return false;
  return /^[a-z0-9-]+$/.test(t);
}

// Loose floors — only catch typos, not strength.
function validAccessKey(s) { return typeof s === "string" && s.trim().length >= 16; }
function validSecretKey(s) { return typeof s === "string" && s.trim().length >= 20; }

// R2 region is `auto`. Other providers vary; the wizard is R2-only.
const R2_REGION = "auto";

// AbortController dispenser — each stage's "verify" can swap to a fresh
// controller so navigating Back / re-entering the stage aborts the prior
// in-flight fetch. Stored on the wizard instance.
function makeAborter() {
  let current = null;
  return {
    fresh() {
      if (current) current.abort();
      current = new AbortController();
      return current.signal;
    },
    cancel() {
      if (current) { current.abort(); current = null; }
    },
  };
}

// --- Wizard factory ----------------------------------------------------

export function createWizard({ root, onComplete, liveRegion } = {}) {
  if (!root) throw new Error("createWizard: { root } is required");

  const state = {
    stage: "welcome",
    route: "new-folder", // "new-folder" | "unlock"
    data: {
      carrier: { url: "", secret: "", verified: false, existing: false },
      bucket: { name: suggestBucketName(), accountId: "", verified: false },
      credentials: { accessKey: "", secretKey: "", verified: false },
      cors: { preflighted: false },
      passphrase: { value: "", confirmed: false, mode: "suggested", suggested: "", saved: false, acceptWeak: false }, // memory-only
      unlock: {
        // Mode: "file" picks a .crate-creds file + passphrase (default).
        // Mode: "manual" falls back to the 5-input form.
        mode: "file",
        // File mode state — set when user picks a file or when we
        // auto-restore an in-tab session from sessionStorage.
        fileBytes: null, fileHint: null, fileFromSession: false,
        // Manual mode state — bucket + bucket-creds inputs.
        manualKind: "carrier", carrierUrl: "",
        bucketName: "", accountId: "",
        accessKey: "", secretKey: "",
        // Shared.
        passphrase: "",
        status: "idle", error: null,
      },
    },
    // NakliOS handoff mode. `null` unless crate was opened inside an
    // allowlisted NakliOS iframe with the handoff params (see
    // detectHandoff). When set: { parentOrigin, nonce }.
    handoff: null,
    // Done-stage "Send to NakliOS" progress: { status, message, tone }.
    handoffSend: { status: "idle", message: "", tone: "" },
    // Cleanup for the in-flight ack listener + timeout (non-serialised).
    _handoffCleanup: null,
  };

  // detectHandoff validates the URL params + framing + origin allowlist.
  // Returns { parentOrigin, nonce } only when ALL hold; else null (crate
  // renders as the normal standalone wizard). Never throws.
  function detectHandoff() {
    try {
      if (typeof window === "undefined" || window.parent === window) return null;
      const params = new URLSearchParams(location.search);
      if (params.get("naklios-handoff") !== "v1") return null;
      const parentOrigin = params.get("parentOrigin");
      const nonce = params.get("nonce");
      if (!parentOrigin || !nonce) return null;
      if (!HANDOFF_ORIGINS.includes(parentOrigin)) return null;
      return { parentOrigin, nonce };
    } catch {
      return null;
    }
  }
  state.handoff = detectHandoff();

  // The nav footer lives outside `root` so its listeners persist across
  // re-renders. The wizard owns its buttons via the wiring below.
  const navHost = document.getElementById("wizard-nav");
  const backBtn = navHost?.querySelector("[data-nav='back']");
  const nextBtn = navHost?.querySelector("[data-nav='next']");
  const progressHost = document.getElementById("progress");

  // Wizard-level aborter — every stage's verify/test/preflight call passes
  // `aborter.fresh()` so a click-twice or stage-change cancels the prior
  // in-flight request. `render()` calls `aborter.cancel()` on swap-out.
  const aborter = makeAborter();

  // Remembered Bucket-stage probe result. The Credentials stage uses this
  // to disambiguate "credentials fetch failed because bucket unreachable"
  // from "credentials fetch failed because CORS not set up yet" — if the
  // unauth probe succeeded earlier, a TypeError on the signed HEAD is
  // very likely CORS rather than a network outage.
  let lastBucketProbeReachable = false;

  function persistableSnapshot() {
    // Strip secrets before writing to IndexedDB.
    return {
      stage: state.stage,
      route: state.route,
      data: {
        // Nothing of the carrier stage is persisted: the secret lives in
        // pendingCarrier, and the Worker URL must come from the Worker's own
        // "Continue to Crate" link or an explicit paste — never from a
        // remembered value the user might submit without looking.
        bucket: { ...state.data.bucket },
        credentials: {
          // accessKey/secretKey are sensitive enough to omit from disk
          // even though they're not the master passphrase. They live
          // only in memory for the active session.
          verified: state.data.credentials.verified,
        },
        cors: { ...state.data.cors },
        // passphrase is memory-only — never written.
      },
    };
  }

  async function saveSession() {
    try {
      await idb.set("onboarding", "session", persistableSnapshot());
    } catch (e) {
      // IDB failures shouldn't break the wizard — surface in console only.
      console.warn("onboarding: failed to persist session", e);
    }
  }

  async function loadSession() {
    try {
      const saved = await idb.get("onboarding", "session");
      if (!saved) return;
      if (saved.data?.bucket) Object.assign(state.data.bucket, saved.data.bucket);
      if (saved.data?.credentials) {
        state.data.credentials.verified = !!saved.data.credentials.verified;
      }
      if (saved.data?.cors) Object.assign(state.data.cors, saved.data.cors);
      if (saved.route) state.route = saved.route;
    } catch (e) {
      console.warn("onboarding: failed to load session", e);
    }
  }

  function canAdvance(stage) {
    switch (stage) {
      case "welcome": return true;
      case "carrier": return state.data.carrier.verified;
      case "bucket": return state.data.bucket.verified;
      case "credentials": return state.data.credentials.verified;
      case "cors": return state.data.cors.preflighted;
      case "passphrase": return state.data.passphrase.confirmed;
      case "done": return false;
      default: return false;
    }
  }

  function stagesForRoute() {
    switch (state.route) {
      case "unlock":  return UNLOCK_STAGES;
      case "carrier": return CARRIER_STAGES;
      default:        return NEW_FOLDER_STAGES;
    }
  }

  function reachableStages() {
    const stages = stagesForRoute();
    const reached = [];
    for (const s of stages) {
      reached.push(s);
      if (!canAdvance(s) && s !== "welcome") break;
    }
    return reached;
  }

  function stageIndex() {
    const stages = stagesForRoute();
    const i = stages.indexOf(state.stage);
    return { stages, index: i === -1 ? 0 : i };
  }

  function go(stage) {
    if (!STAGES.includes(stage)) return;
    // Clamp forward jumps to the highest currently-reachable stage.
    const reached = reachableStages();
    let target = stage;
    if (!reached.includes(stage)) {
      target = reached[reached.length - 1];
    }
    state.stage = target;
    // Always render here. We update the hash for free browser-back +
    // shareable URLs, but the hashchange handler short-circuits when
    // state matches the hash (which it always does on a programmatic
    // `go()`), so render won't fire from hashchange. Without this
    // direct call, programmatic navigation took two clicks to repaint.
    if (location.hash !== `#${target}`) {
      location.hash = target;
    }
    render();
    saveSession();
  }

  function next() {
    const { stages, index } = stageIndex();
    const nextStage = stages[index + 1];
    if (nextStage) go(nextStage);
  }

  function back() {
    const { stages, index } = stageIndex();
    const prevStage = stages[index - 1];
    if (prevStage) go(prevStage);
  }

  function reset() {
    state.stage = "welcome";
    state.route = "new-folder";
    state.data.carrier = { url: "", secret: "", verified: false, existing: false };
    pendingCarrier.clear();
    state.data.bucket = { name: suggestBucketName(), accountId: "", verified: false };
    state.data.credentials = { accessKey: "", secretKey: "", verified: false };
    state.data.cors = { preflighted: false };
    state.data.passphrase = { value: "", confirmed: false, mode: "suggested", suggested: "", saved: false, acceptWeak: false };
    state.data.unlock = {
      mode: "file",
      fileBytes: null, fileHint: null, fileFromSession: false,
      bucketName: "", accountId: "",
      accessKey: "", secretKey: "",
      manualKind: "carrier", carrierUrl: "",
      passphrase: "",
      status: "idle", error: null,
    };
    if (root) root.removeAttribute("data-test-complete");
    idb.del("onboarding", "session").catch(() => {});
    // Clear any cached in-tab session blob; Start Over should not
    // silently route the next visitor back to a half-onboarded state.
    try { sessionStorage.removeItem(SESSION_CREDS_KEY); } catch {}
    go("welcome");
  }

  // --- Stage renderers -------------------------------------------------

  function renderWelcome() {
    // The landing is a card inside the locked shell (topbar + dimmed
    // sidebar frame it). One headline, one primary action, one way back
    // in. Everything about *how* — prerequisites, the one-click deploy,
    // the own-bucket route — lives one step later, where it applies.
    const startBtn = el("button", { type: "button", class: "btn btn-primary btn-block btn-lg" }, ["Get started — about a minute"]);
    startBtn.addEventListener("click", () => { state.route = "carrier"; go("carrier"); });
    const unlockBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Already set up? Open your folder"]);
    unlockBtn.addEventListener("click", () => { state.route = "unlock"; go("unlock"); });

    const helpLink = el("button", { type: "button", class: "btn-link", "aria-haspopup": "dialog" }, ["How it works"]);
    helpLink.addEventListener("click", () => openHelpModal({ returnFocus: helpLink }));
    const ownBucketLink = el("button", { type: "button", class: "btn-link" }, ["Use a bucket you already have"]);
    ownBucketLink.addEventListener("click", () => { state.route = "new-folder"; go("bucket"); });

    return makeFragment(
      el("section", { class: "landing", "aria-labelledby": "stage-title" }, [
        el("div", { class: "landing-hero" }, [
          el("h1", { id: "stage-title", class: "landing-wordmark" }, ["Your files, in a folder only you can read."]),
          el("p", { class: "landing-tagline" }, [
            "Crate is a cloud folder that lives in free storage you own. Files are locked on this device before they upload — no account with us, nothing to subscribe to.",
          ]),
        ]),
        el("div", { class: "landing-actions" }, [startBtn, unlockBtn]),
        promiseList(),
        el("div", { class: "landing-links" }, [
          helpLink,
          ownBucketLink,
          el("a", { href: "guide/", target: "_blank", rel: "noopener noreferrer" }, ["Guide"]),
          el("a", { href: "https://github.com/NakliTechie/crate", target: "_blank", rel: "noopener noreferrer" }, ["GitHub"]),
        ]),
      ]),
    );
  }

  // openSetupGuide opens the detailed modal walking the user through the
  // Cloudflare R2 setup steps. Reached from the "Full setup guide" button
  // inside the concise help modal (openHelpModal). Targets a first-time
  // visitor who has never seen Cloudflare R2.
  function openSetupGuide({ returnFocus = null } = {}) {
    const overlay = document.createElement("div");
    overlay.className = "help-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-labelledby", "setup-title");
    const card = document.createElement("div");
    card.className = "help-card";
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    const close = () => {
      document.removeEventListener("keydown", onKey);
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      try { if (returnFocus && typeof returnFocus.focus === "function") returnFocus.focus(); } catch {}
    };
    function onKey(e) { if (e.key === "Escape") close(); }
    document.addEventListener("keydown", onKey);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

    const closeBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Close"]);
    closeBtn.addEventListener("click", close);

    const setupTitle = el("h2", { id: "setup-title", tabindex: "-1" }, ["Setting up with your own bucket — what each step does"]);
    card.appendChild(setupTitle);
    card.appendChild(el("p", { class: "lead" }, [
      "Crate doesn't host anything. Your files live in a storage bucket you own at Cloudflare (or Hetzner, Backblaze, AWS). This browser tab encrypts them with your passphrase before they leave. Nobody — not us, not Cloudflare — can read them without your passphrase.",
    ]));

    const step = (n, title, kids) =>
      el("section", { class: "help-step" }, [
        el("div", { class: "help-step-num" }, [String(n)]),
        el("div", { class: "help-step-body" }, [
          el("h3", {}, [title]),
          ...kids,
        ]),
      ]);

    card.appendChild(step(1, "Get a Cloudflare account (60 seconds, free tier)", [
      el("p", {}, [
        "Sign up at ",
        el("a", { href: "https://dash.cloudflare.com/sign-up", target: "_blank", rel: "noopener noreferrer" }, ["dash.cloudflare.com/sign-up"]),
        ". Free tier is enough — R2 includes 10 GB of free storage + 1 million writes (Class A ops) + 10 million reads (Class B ops) per month. No credit card required for the free tier.",
      ]),
    ]));

    card.appendChild(step(2, "Find your Account ID", [
      el("p", {}, [
        "From the Cloudflare dashboard, open any of your zones (or just the R2 section). On the right sidebar you'll see ",
        el("strong", {}, ["Account ID"]),
        " — a 32-character hex string. Copy it; the wizard asks for it on the Bucket step.",
      ]),
      el("p", { class: "muted small" }, [
        "It looks like ",
        el("code", {}, ["62231b040ed00c96cdcf3a4541eab958"]),
        ".",
      ]),
    ]));

    card.appendChild(step(3, "Create an R2 bucket", [
      el("p", {}, [
        "Go to ",
        el("a", { href: "https://dash.cloudflare.com/?to=/:account/r2/overview", target: "_blank", rel: "noopener noreferrer" }, ["R2 Object Storage"]),
        " in the dashboard. Click ",
        el("strong", {}, ["Create bucket"]),
        ". Give it any name (Crate suggests ",
        el("code", {}, ["crate-XXXXXXXX"]),
        " by default — you can keep that or pick your own). Leave the location at ",
        el("em", {}, ["Automatic"]),
        ". Done — the bucket exists.",
      ]),
    ]));

    card.appendChild(step(4, "Create an API token scoped to that bucket", [
      el("p", {}, [
        "Open ",
        el("a", { href: "https://dash.cloudflare.com/?to=/:account/r2/api-tokens", target: "_blank", rel: "noopener noreferrer" }, ["R2 → Manage R2 API Tokens"]),
        ". Click ",
        el("strong", {}, ["Create API Token"]),
        ".",
      ]),
      el("ul", {}, [
        el("li", {}, ["Permission: ", el("strong", {}, ["Object Read & Write"]), "."]),
        el("li", {}, ["Specify bucket: pick the one you just made (don't leave it at All bucket — scope matters)."]),
        el("li", {}, ["TTL: leave blank (token doesn't expire) OR pick a long horizon."]),
      ]),
      el("p", {}, [
        "Cloudflare will show you the ",
        el("strong", {}, ["Access Key ID"]),
        " + ",
        el("strong", {}, ["Secret Access Key"]),
        " ONCE. Copy both somewhere — once you close that page, the secret is gone for good (you'd have to delete the token + create a new one). The wizard asks for both on the Credentials step.",
      ]),
    ]));

    card.appendChild(step(5, "CORS — let this browser tab talk to your bucket", [
      el("p", {}, [
        "Open your bucket → ",
        el("strong", {}, ["Settings"]),
        " tab → ",
        el("strong", {}, ["CORS Policy"]),
        " → Add. The wizard will give you the exact JSON to paste — you'll see a Copy button on the CORS step. Paste, save, click back to the wizard. (About 30 seconds.)",
      ]),
      el("p", {}, [
        "The JSON tells Cloudflare ",
        el("em", {}, ["which web origin is allowed to talk to your bucket from a browser"]),
        ". The wizard fills it with whatever URL you're on right now — so if you're at ",
        el("code", {}, [(typeof location !== "undefined" && location.origin) ? location.origin : "https://crate.naklitechie.com"]),
        ", it puts that origin in ",
        el("code", {}, ["AllowedOrigins"]),
        ". That's how the browser knows it's allowed to fetch from your bucket.",
      ]),
      el("p", {}, [
        el("strong", {}, ["This does not give us access to your files."]),
        " It only tells Cloudflare to send the right CORS headers back when this origin's JavaScript fetches your bucket. The files themselves are encrypted in your browser before they ever leave — with your passphrase, which we never see. The bucket itself is yours; the API token you created in step 4 is yours; the encryption key is derived from your passphrase, which lives only in your tab's memory.",
      ]),
      el("p", { class: "muted small" }, [
        "Don't trust us on this — read the code. ",
        el("a", { href: "https://github.com/NakliTechie/crate/blob/main/lib/crypto.js", target: "_blank", rel: "noopener noreferrer" }, ["lib/crypto.js"]),
        " is the entire encryption layer (PBKDF2 + AES-256-GCM); ",
        el("a", { href: "https://github.com/NakliTechie/crate/blob/main/lib/bucket.js", target: "_blank", rel: "noopener noreferrer" }, ["lib/bucket.js"]),
        " is every network call this app makes. There's no telemetry, no analytics, no backend. The whole app is one HTML file + a few small modules; you can host it yourself off any static server.",
      ]),
      el("p", { class: "muted small" }, [
        "Without CORS, the browser refuses to talk to the bucket. This is correct + secure; the bucket owner (you) opts in to which origins can hit it.",
      ]),
    ]));

    card.appendChild(step(6, "Pick a passphrase you'll remember", [
      el("p", {}, [
        "The wizard's Passphrase step uses ",
        el("a", { href: "https://github.com/dropbox/zxcvbn", target: "_blank", rel: "noopener noreferrer" }, ["zxcvbn"]),
        " to score it. Aim for 70 bits or more — a few unrelated words is fine, e.g. ",
        el("code", {}, ["correct-horse-battery-staple-seven"]),
        ". The Generate button gives you one if you can't think of one.",
      ]),
      el("p", {}, [
        el("strong", {}, ["If you lose this passphrase, your files are gone. Forever. We cannot help you."]),
        " There is no reset link, no support email, no recovery flow we can offer. Your files are encrypted with a key derived from this passphrase; without it, what's in the bucket is unreadable random bytes — to us, to Cloudflare, to anyone. That's the privacy guarantee; it cuts both ways.",
      ]),
      el("p", {}, [
        "Write the passphrase down. On paper. In ",
        el("a", { href: "https://tijori.naklitechie.com/", target: "_blank", rel: "noopener" }, ["Tijori"]),
        " (our own offline password manager) — or whatever password manager you use. Somewhere you'll still have access to in five years. There is no backup credential, no recovery phrase, no email-reset. The passphrase is the only credential.",
      ]),
    ]));

    card.appendChild(step(7, "Done — drop a file in", [
      el("p", {}, [
        "After the wizard's Done step you'll see the folder. Drag-drop or click Upload to encrypt and store a file. Refresh the page → choose ",
        el("strong", {}, ["Already set up? Open your folder"]),
        " → enter the bucket + API token + passphrase → the folder is back. Open this same URL on your phone, same flow, you'll see the same files (encrypted in transit; the bucket sees only ciphertext).",
      ]),
    ]));

    card.appendChild(step(8, "Plan for backups", [
      el("p", {}, [
        el("strong", {}, ["Your bucket is your only copy of the files by default."]),
        " If you lose access to the bucket (account closed, accidentally deleted, ransomware on your Cloudflare account), the files are gone unless you've made a copy somewhere else. The encryption that keeps Cloudflare from reading your files also means Cloudflare can't restore them for you.",
      ]),
      el("p", {}, ["Three options, pick whichever fits how you work:"]),
      el("ul", {}, [
        el("li", {}, [
          el("strong", {}, ["Run "]),
          el("a", { href: "https://github.com/NakliTechie/crate-agent", target: "_blank", rel: "noopener noreferrer" }, [el("strong", {}, ["crate-agent"])]),
          el("strong", {}, [" on a laptop"]),
          " — it mirrors the bucket to a plaintext folder on disk. Then point Time Machine / restic / rsync at that folder. Best option for ongoing backups.",
        ]),
        el("li", {}, [
          el("strong", {}, ["Mirror the bucket"]),
          " — ",
          el("code", {}, ["rclone sync"]),
          " between two buckets, or Cloudflare's R2 → R2 replication. The mirror stays ciphertext; restore = swap creds in the wizard.",
        ]),
        el("li", {}, [
          el("strong", {}, ["Export from the browser"]),
          " — the folder UI has an Export button. Small folders go as a zip; larger folders stream to a chosen folder on disk (Chrome / Edge / Brave). One-shot. Use the daemon for recurring backups.",
        ]),
      ]),
      el("p", { class: "muted small" }, [
        "Full runbook with disaster-recovery scenarios: ",
        el("a", { href: "docs/backup.md" }, ["docs/backup.md"]),
        ".",
      ]),
    ]));

    card.appendChild(el("hr", { class: "stage-divider" }));
    card.appendChild(el("p", { class: "muted small" }, [
      el("strong", {}, ["Want a desktop sync daemon? "]),
      "There's a Go binary, ",
      el("a", { href: "https://github.com/NakliTechie/crate-agent", target: "_blank", rel: "noopener noreferrer" }, ["crate-agent"]),
      ", that mirrors a folder on your laptop to/from the same bucket. macOS + Linux today; Windows v1.1. Click ",
      el("strong", {}, ["Pair an agent"]),
      " from inside the folder UI to wire it up.",
    ]));
    card.appendChild(el("p", { class: "muted small" }, [
      "Want the full illustrated walk-through (every stage, the folder UI, backup, the daemon, the security model)? Open the ",
      el("a", { href: "guide/", target: "_blank", rel: "noopener noreferrer" }, ["user guide ↗"]),
      ".",
    ]));

    card.appendChild(closeBtn);

    // Move focus into the dialog so keyboard + screen-reader users land
    // inside it rather than on the page behind.
    try { setupTitle.focus({ preventScroll: true }); } catch {}
  }

  // openHelpModal opens the concise "What is Crate?" explainer — what it
  // is, the privacy promise, and how it works in three steps. Reached from
  // "How it works" on the landing card and in the topbar (wizard.openHelp);
  // the detailed Cloudflare walk-through lives behind its "Full setup
  // guide" button (openSetupGuide).
  function openHelpModal({ returnFocus = null } = {}) {
    const overlay = document.createElement("div");
    overlay.className = "help-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-labelledby", "help-title");
    const card = document.createElement("div");
    card.className = "help-card";
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    const close = () => {
      document.removeEventListener("keydown", onKey);
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      try { if (returnFocus && typeof returnFocus.focus === "function") returnFocus.focus(); } catch {}
    };
    function onKey(e) { if (e.key === "Escape") close(); }
    document.addEventListener("keydown", onKey);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

    const helpTitle = el("h2", { id: "help-title", tabindex: "-1" }, ["What is Crate?"]);
    card.appendChild(helpTitle);
    card.appendChild(el("p", { class: "lead" }, [
      "Crate is a personal cloud folder you fully own. There's no NakliTechie account and no server in the middle — your files live in storage you rent directly (a free Cloudflare R2 bucket works fine), encrypted on your device before they ever upload.",
    ]));

    card.appendChild(promiseList());

    card.appendChild(el("hr", { class: "stage-divider" }));

    const step = (n, title, kids) =>
      el("section", { class: "help-step" }, [
        el("div", { class: "help-step-num" }, [String(n)]),
        el("div", { class: "help-step-body" }, [
          el("h3", {}, [title]),
          ...kids,
        ]),
      ]);

    card.appendChild(step(1, "Connect storage you own", [
      el("p", {}, [
        "One click deploys a tiny helper into your own free Cloudflare account and creates the bucket for you — about a minute, once. Prefer to point Crate at a bucket you already have (R2, Hetzner, Backblaze, AWS)? That path is there too.",
      ]),
    ]));
    card.appendChild(step(2, "Pick a passphrase", [
      el("p", {}, [
        "Your files are locked with a key derived from your passphrase, right here on your device. Nobody — not us, not your storage provider — can read them without it.",
      ]),
      el("p", { class: "muted small" }, [
        "Lose the passphrase and the files are gone for good; there's no reset link we can offer. Write it down somewhere safe.",
      ]),
    ]));
    card.appendChild(step(3, "Open it from anywhere", [
      el("p", {}, [
        "At the end of setup, download your .crate-creds file and keep your passphrase. On any other device: open this same link, choose “Already set up? Open your folder”, pick that file, enter your passphrase — and your folder is there. Your storage provider only ever sees encrypted bytes.",
      ]),
    ]));

    card.appendChild(el("hr", { class: "stage-divider" }));
    card.appendChild(el("p", { class: "muted small" }, [
      "Bringing a bucket you already have? The full setup guide walks through Cloudflare's dashboard step by step.",
    ]));

    const setupBtn = el("button", { type: "button", class: "btn btn-secondary" }, ["Full setup guide"]);
    setupBtn.addEventListener("click", () => { close(); openSetupGuide({ returnFocus }); });
    const gotItBtn = el("button", { type: "button", class: "btn btn-primary" }, ["Got it"]);
    gotItBtn.addEventListener("click", close);
    card.appendChild(el("div", { class: "row" }, [setupBtn, gotItBtn]));

    // Move focus into the dialog so keyboard + screen-reader users land
    // inside it rather than on the page behind.
    try { helpTitle.focus({ preventScroll: true }); } catch {}
  }

  // The one-click route. Everything the four manual stages did — bucket,
  // API token, CORS, account ID — is done by Cloudflare's Deploy button
  // reading crate-carrier's wrangler.jsonc. What the user does here:
  // copy the secret we generated, paste it into the deploy form, and come
  // back (the Worker's page links straight here with its URL).
  function renderCarrier() {
    const c = state.data.carrier;
    if (!c.secret) {
      const pending = pendingCarrier.load();
      if (pending) c.secret = pending.secret;
      else { c.secret = randomCarrierSecret(); pendingCarrier.save({ secret: c.secret }); }
    }
    const pill = makePill();
    if (c.verified) pill.ok("✓ Carrier verified");

    const secretInput = el("input", { id: "carrier-secret", type: "text", class: "input mono", readonly: "", value: c.secret, "aria-describedby": "carrier-secret-help" });
    secretInput.addEventListener("focus", () => secretInput.select());
    const copyBtn = makeCopyButton(() => c.secret, "Copy secret");

    const urlInput = el("input", { id: "carrier-url", type: "url", class: "input", autocomplete: "off", inputmode: "url",
      value: c.url, placeholder: "https://crate-carrier.you.workers.dev" });
    urlInput.addEventListener("input", () => {
      c.url = urlInput.value.trim(); c.verified = false; c.existing = false;
      pill.reset(); updateNav();
    });

    const verifyBtn = el("button", { type: "button", class: "btn btn-primary" }, ["Verify"]);
    const unlockHint = el("p", { class: "muted small", hidden: "" });
    verifyBtn.addEventListener("click", async () => {
      const url = c.url?.trim();
      if (!validCarrierUrl(url)) { pill.fail("✗ Paste the Worker's https:// URL"); c.verified = false; updateNav(); return; }
      verifyBtn.disabled = true; pill.check("Checking the Worker…");
      try {
        const r = await bucket.carrierProbe({ url, secretKey: c.secret, signal: aborter.fresh() });
        if (!r.ok) { pill.fail("✗ " + r.message); c.verified = false; }
        else if (r.existing) {
          // A crate.json already lives behind this carrier. Running setup
          // would overwrite it and orphan whatever is in the bucket.
          pill.fail("✗ This carrier already holds a Crate folder");
          c.verified = false; c.existing = true;
          unlockHint.hidden = false;
        } else { pill.ok("✓ Worker is up, secret matches, bucket is empty"); c.verified = true; c.existing = false; }
      } catch (e) {
        if (e?.name !== "AbortError") { pill.fail("✗ " + (e?.message ?? e)); c.verified = false; }
      } finally { verifyBtn.disabled = false; updateNav(); saveSession(); }
    });
    const unlockLink = el("button", { type: "button", class: "btn-link" }, ["Unlock it instead →"]);
    unlockLink.addEventListener("click", () => { state.route = "unlock"; go("unlock"); });
    unlockHint.appendChild(unlockLink);

    return makeFragment(
      el("section", { class: "stage stage-carrier" }, [
        el("h2", { id: "stage-title" }, ["Deploy your carrier"]),
        el("p", { class: "muted" }, [
          "One click gives you a tiny Worker in your own Cloudflare account, holding your own R2 bucket. No API token, no CORS, no account ID — Cloudflare sets all of it up. The Worker only ever sees encrypted bytes.",
        ]),
        el("details", { class: "prereqs-details" }, [
          el("summary", {}, ["You'll need (both free) — Cloudflare, GitHub, a passphrase"]),
          prerequisitesList(),
        ]),
        el("ol", { class: "steps" }, [
          el("li", {}, [
            el("div", { class: "field" }, [
              el("label", { for: "carrier-secret" }, ["1 · Copy this secret"]),
              el("div", { class: "row" }, [secretInput, copyBtn]),
              el("p", { id: "carrier-secret-help", class: "field-help muted" }, ["This is the connection secret between Crate and your storage — not your passphrase; you'll choose that after deploying. Generated for you, and it stays the same if you come back to this page. Paste it into Cloudflare's ", el("code", {}, ["CARRIER_SECRET"]), " field."]),
            ]),
          ]),
          el("li", {}, [
            el("p", {}, ["2 · Deploy — pick your GitHub account, paste the secret into ", el("code", {}, ["CARRIER_SECRET"]), ", leave the rest as suggested, click ", el("b", {}, ["Deploy"]), "."]),
            el("p", { class: "muted small" }, ["The build usually takes about a minute. ", el("b", {}, ["Cloudflare's build page does not update by itself"]), " — reload it after a minute to see the result."]),
            makeDeepLinkButton(CARRIER_DEPLOY_URL, "Deploy to Cloudflare ↗"),
          ]),
          el("li", {}, [
            el("p", {}, ["3 · When it says deployed, click ", el("b", {}, ["Visit"]), ", then ", el("b", {}, ["Continue to Crate"]), " — the Worker's address fills in below (or paste it). Click ", el("b", {}, ["Verify"]), ", then ", el("b", {}, ["Next →"]), " to choose your passphrase."]),
            el("div", { class: "field" }, [
              el("label", { for: "carrier-url" }, ["Worker URL"]),
              urlInput,
            ]),
            el("div", { class: "row" }, [verifyBtn, pill.el]),
            unlockHint,
          ]),
        ]),
      ]),
    );
  }

  function renderBucket() {
    const pill = makePill();
    const nameInput = el("input", {
      id: "bucket-name", type: "text", class: "input", autocomplete: "off",
      value: state.data.bucket.name, "aria-describedby": "bucket-name-help",
    });
    nameInput.addEventListener("input", () => {
      state.data.bucket.name = nameInput.value;
      state.data.bucket.verified = false;
      pill.reset();
      updateNav();
    });
    const accountInput = el("input", {
      id: "bucket-account", type: "text", class: "input", autocomplete: "off",
      value: state.data.bucket.accountId, placeholder: "32-character hex string",
    });
    accountInput.addEventListener("input", () => {
      state.data.bucket.accountId = accountInput.value;
      state.data.bucket.verified = false;
      pill.reset();
      updateNav();
    });
    const verifyBtn = el("button", { type: "button", class: "btn btn-primary" }, ["Verify"]);
    verifyBtn.addEventListener("click", () => {
      verifyBtn.disabled = true;
      const name = state.data.bucket.name?.trim();
      const accountId = state.data.bucket.accountId?.trim().toLowerCase();
      // Shape-check only. We can't probe the bucket at this stage:
      // R2 doesn't return CORS headers on unauthenticated responses
      // (CORS applies to authenticated data-plane requests), so the
      // browser blocks the response regardless of bucket CORS policy.
      // The real bucket-existence check is the signed HEAD at the
      // Credentials stage, which has both auth and (post-CORS-setup)
      // CORS headers. By design: shape check here, real verify later.
      if (!validAccountId(accountId)) {
        pill.fail("✗ Account ID must be 32 hex characters");
        state.data.bucket.verified = false;
      } else if (!validBucketName(name)) {
        pill.fail("✗ Bucket name invalid (3–63 chars; lowercase + digits + hyphens; no leading/trailing or double hyphen)");
        state.data.bucket.verified = false;
      } else {
        pill.ok("✓ Values look valid (real check at next stage)");
        state.data.bucket.verified = true;
        // Optimistic — kept so the Credentials-stage CORS-hint logic
        // still works. Reset on input change.
        lastBucketProbeReachable = true;
      }
      verifyBtn.disabled = false;
      updateNav();
      saveSession();
    });
    return makeFragment(
      el("section", { class: "stage stage-bucket" }, [
        el("h2", { id: "stage-title" }, ["Create your bucket"]),
        el("p", { class: "muted" }, ["Open Cloudflare's R2 dashboard in a new tab, create a bucket, then paste its name and your Cloudflare Account ID here."]),
        makeDeepLinkButton(DEEP_LINKS.bucket, "Open Cloudflare R2 ↗"),
        el("div", { class: "field" }, [
          el("label", { for: "bucket-name" }, ["Bucket name"]),
          nameInput,
          el("p", { id: "bucket-name-help", class: "field-help muted" }, ["Suggested above. Override if you used a different name."]),
        ]),
        el("div", { class: "field" }, [
          el("label", { for: "bucket-account" }, ["Cloudflare Account ID"]),
          accountInput,
          el("p", { class: "field-help muted" }, [
            "In the R2 (or account) dashboard, it's in the right-hand sidebar — a 32-character hex string.",
          ]),
        ]),
        el("div", { class: "row" }, [verifyBtn, pill.el]),
        el("p", { class: "muted small" }, ["Verify is a quick format check — the real existence + reachability test runs against R2 when you paste your credentials at the next step."]),
      ]),
    );
  }

  function renderCredentials() {
    const pill = makePill();
    const accessInput = el("input", {
      id: "access-key", type: "text", class: "input", autocomplete: "off",
      value: state.data.credentials.accessKey,
    });
    accessInput.addEventListener("input", () => {
      state.data.credentials.accessKey = accessInput.value;
      state.data.credentials.verified = false;
      pill.reset();
      updateNav();
    });
    const secretInput = el("input", {
      id: "secret-key", type: "password", class: "input", autocomplete: "new-password",
      value: state.data.credentials.secretKey,
    });
    secretInput.addEventListener("input", () => {
      state.data.credentials.secretKey = secretInput.value;
      state.data.credentials.verified = false;
      pill.reset();
      updateNav();
    });
    const testBtn = el("button", { type: "button", class: "btn btn-primary" }, ["Test credentials"]);
    testBtn.addEventListener("click", async () => {
      testBtn.disabled = true;
      const accessKey = state.data.credentials.accessKey?.trim();
      const secretKey = state.data.credentials.secretKey?.trim();
      if (!validAccessKey(accessKey)) {
        pill.fail("✗ Access Key looks too short — re-check what you pasted");
        state.data.credentials.verified = false;
        testBtn.disabled = false;
        updateNav();
        return;
      }
      if (!validSecretKey(secretKey)) {
        pill.fail("✗ Secret Key looks too short — re-check what you pasted");
        state.data.credentials.verified = false;
        testBtn.disabled = false;
        updateNav();
        return;
      }
      pill.check();
      const url = bucket.endpoints.R2(
        state.data.bucket.accountId.trim().toLowerCase(),
        state.data.bucket.name.trim(),
      );
      try {
        const r = await bucket.signedHead({
          url, region: R2_REGION, accessKey, secretKey, signal: aborter.fresh(),
        });
        if (r.ok) {
          pill.ok("✓ Credentials authenticated");
          state.data.credentials.verified = true;
        } else if (r.code === "CORS_OR_NETWORK" && lastBucketProbeReachable) {
          // Bucket was reachable in stage 2 (unauth probe got a real
          // 401/200/403), but the signed HEAD got blocked here. Highly
          // likely CORS hasn't been applied yet — the next stage fixes it.
          // Mark verified=true so the user can advance and complete CORS.
          pill.ok("✓ Credentials look valid — CORS still needs setup (next stage)");
          state.data.credentials.verified = true;
        } else if (r.status === 403 || /SignatureDoesNotMatch|InvalidAccessKeyId|AccessDenied/i.test(r.code ?? "")) {
          pill.fail("✗ Authentication failed — re-check Access Key + Secret");
          state.data.credentials.verified = false;
        } else if (r.status === 404) {
          pill.fail("✗ Bucket not found — re-check the Bucket stage");
          state.data.credentials.verified = false;
        } else if (r.code === "CORS_OR_NETWORK" || r.code === "NETWORK_ERROR") {
          pill.fail("✗ Bucket unreachable — check your network");
          state.data.credentials.verified = false;
        } else {
          pill.fail(`✗ ${r.message ?? `HTTP ${r.status}`}`);
          state.data.credentials.verified = false;
        }
      } catch (err) {
        if (bucket.isAbortError(err)) { testBtn.disabled = false; return; }
        pill.fail(`✗ ${err.message ?? "Unexpected error"}`);
        state.data.credentials.verified = false;
      }
      testBtn.disabled = false;
      updateNav();
      saveSession();
    });
    return makeFragment(
      el("section", { class: "stage stage-credentials" }, [
        el("h2", { id: "stage-title" }, ["Create an API token"]),
        el("p", { class: "muted" }, ["In Cloudflare's R2 dashboard, create a token scoped to your bucket with Object Read + Write permissions. Paste the Access Key ID and Secret Access Key here."]),
        makeDeepLinkButton(DEEP_LINKS.tokens, "Open R2 API Tokens ↗"),
        el("div", { class: "field" }, [
          el("label", { for: "access-key" }, ["Access Key ID"]),
          accessInput,
        ]),
        el("div", { class: "field" }, [
          el("label", { for: "secret-key" }, ["Secret Access Key"]),
          secretInput,
          el("p", { class: "field-help muted" }, ["Held in memory only for this session. Never written to disk."]),
        ]),
        el("div", { class: "hint-card" }, [
          el("div", { class: "hint-card-title", style: "color: var(--warn);" }, [
            "⚠ Copy the Secret Access Key now",
          ]),
          el("p", { class: "muted small", style: "margin: 0;" }, [
            "Cloudflare shows it only once. If you leave this page without it, you'll have to delete the token and create a new one.",
          ]),
        ]),
        el("div", { class: "row" }, [testBtn, pill.el]),
      ]),
    );
  }

  function renderCors() {
    const pill = makePill();
    const cors = corsJson(location.origin);
    const corsBlock = el("pre", { class: "code-block", tabindex: "0", "aria-label": "CORS configuration JSON" }, [
      el("code", { text: cors }),
    ]);
    const copyBtn = makeCopyButton(() => cors, "Copy CORS JSON");
    const preflightBtn = el("button", { type: "button", class: "btn btn-primary" }, ["Run preflight check"]);
    preflightBtn.addEventListener("click", async () => {
      preflightBtn.disabled = true;
      pill.check("Running preflight…");
      const url = bucket.endpoints.R2(
        state.data.bucket.accountId.trim().toLowerCase(),
        state.data.bucket.name.trim(),
      );
      // Browsers don't expose CORS preflight results to JS — we can't
      // manually fire an OPTIONS with `Access-Control-Request-*` headers
      // (those are CORS-protocol headers, stripped by fetch). The
      // correct check is to make a real signed request: if the browser
      // lets the response through, CORS is set correctly.
      try {
        const r = await bucket.signedHead({
          url,
          region: R2_REGION,
          accessKey: state.data.credentials.accessKey?.trim(),
          secretKey: state.data.credentials.secretKey?.trim(),
          signal: aborter.fresh(),
        });
        if (r.ok) {
          pill.ok("✓ Preflight succeeded — bucket accepts cross-origin requests");
          state.data.cors.preflighted = true;
        } else if (r.code === "CORS_OR_NETWORK" || r.code === "NETWORK_ERROR") {
          pill.fail("✗ CORS not configured (paste the JSON above into your bucket's CORS settings)");
          state.data.cors.preflighted = false;
        } else if (r.status === 403) {
          pill.fail("✗ Credentials lost auth — re-check the Credentials stage");
          state.data.cors.preflighted = false;
        } else {
          pill.fail(`✗ ${r.message ?? `HTTP ${r.status}`}`);
          state.data.cors.preflighted = false;
        }
      } catch (err) {
        if (bucket.isAbortError(err)) { preflightBtn.disabled = false; return; }
        pill.fail(`✗ ${err.message ?? "Preflight failed"}`);
        state.data.cors.preflighted = false;
      }
      preflightBtn.disabled = false;
      updateNav();
      saveSession();
    });
    // We know the user's bucket + account ID at this stage, so deep-link
    // straight to the bucket's CORS settings page rather than the
    // generic R2 dashboard. Saves a tedious manual navigation.
    const acctId = (state.data.bucket.accountId || "").trim().toLowerCase();
    const bucketName = (state.data.bucket.name || "").trim();
    const corsUrl = acctId && bucketName
      ? `https://dash.cloudflare.com/${acctId}/r2/default/buckets/${bucketName}/settings#cors-policy`
      : DEEP_LINKS.bucket;
    const dashBtn = makeDeepLinkButton(corsUrl, "Open this bucket's CORS settings ↗");
    return makeFragment(
      el("section", { class: "stage stage-cors" }, [
        el("h2", { id: "stage-title" }, ["Configure CORS"]),
        el("p", { class: "muted" }, [
          "Your browser needs your bucket to allow cross-origin requests from this page. Three quick steps:",
        ]),
        el("ol", { class: "stage-list" }, [
          el("li", {}, [
            "Click ",
            el("strong", {}, ["Copy CORS JSON"]),
            " below.",
          ]),
          el("li", {}, [
            "Click ",
            el("strong", {}, ["Open this bucket's CORS settings ↗"]),
            " — opens the right page in Cloudflare in a new tab. Scroll to the ",
            el("strong", {}, ["CORS Policy"]),
            " section, click ",
            el("strong", {}, ["Add CORS policy"]),
            " (or ",
            el("strong", {}, ["Edit"]),
            " if one exists), paste the JSON, click ",
            el("strong", {}, ["Save"]),
            ".",
          ]),
          el("li", {}, [
            "Come back to this tab and click ",
            el("strong", {}, ["Run preflight check"]),
            ". (CORS changes take ~30 seconds to propagate; if it fails, wait + retry.)",
          ]),
        ]),
        corsBlock,
        el("div", { class: "row" }, [copyBtn, dashBtn]),
        el("div", { class: "row" }, [preflightBtn, pill.el]),
      ]),
    );
  }

  // The passphrase stage opens with five generated words. Most people
  // should take them and write them down; the strength meter and the two
  // typed fields exist behind "choose my own" for people who want to.
  // The generated words clear the recommended floor by design; a typed
  // passphrase may go below it after an explicit acknowledgement.
  function renderPassphrase() {
    const pp = state.data.passphrase;
    if (pp.mode === "suggested") return renderSuggestedPassphrase();
    return renderOwnPassphrase();
  }

  function renderSuggestedPassphrase() {
    const pp = state.data.passphrase;
    if (!pp.suggested) pp.suggested = generatePassphrase();
    const words = pp.suggested.split(/[\s-]+/).filter(Boolean);
    const chips = el("div", { class: "words", role: "group", "aria-label": `Your passphrase, ${SUGGESTED_WORDS} words` },
      words.map((w, i) => el("span", { class: "word" }, [el("span", { class: "word-n", "aria-hidden": "true" }, [String(i + 1)]), w])));
    const copyBtn = makeCopyButton(() => pp.suggested, "Copy");
    const againBtn = el("button", { type: "button", class: "btn btn-secondary" }, ["Different words"]);
    againBtn.addEventListener("click", () => {
      pp.suggested = generatePassphrase(); pp.saved = false; pp.value = ""; pp.confirmed = false;
      render();
      announce(liveRegion, "New five-word passphrase shown.");
    });
    const box = el("input", { type: "checkbox", id: "pp-saved" });
    if (pp.saved) box.setAttribute("checked", "checked");
    box.addEventListener("change", () => {
      pp.saved = box.checked;
      pp.value = pp.saved ? pp.suggested : "";
      pp.confirmed = pp.saved;
      updateNav();
    });
    const ownLink = el("button", { type: "button", class: "btn-link" }, ["I'd rather choose my own passphrase"]);
    ownLink.addEventListener("click", () => { pp.mode = "own"; pp.value = ""; pp.confirmed = false; pp.saved = false; render(); });
    return makeFragment(
      el("section", { class: "stage stage-passphrase" }, [
        el("h2", { id: "stage-title" }, ["Your passphrase"]),
        el("p", { class: "muted" }, [
          "These five words unlock your folder. Write them down now — on paper, or in your password manager. Nobody can recover them for you, and Crate never stores them.",
        ]),
        chips,
        el("p", { class: "muted small" }, ["Typed out, it is ", el("code", {}, [pp.suggested]), " — dashes or spaces between the words, either opens the folder."]),
        el("div", { class: "row" }, [copyBtn, againBtn]),
        el("label", { class: "ack", for: "pp-saved" }, [box, el("span", {}, ["I've saved these five words somewhere I'll find them again."])]),
        el("p", { class: "muted small" }, [ownLink]),
        el("p", { class: "muted small" }, ["Why five random words: about 55 bits of strength — roughly 60,000 years for one GPU to exhaust — and words are far easier to write down correctly than symbols."]),
      ]),
    );
  }

  function renderOwnPassphrase() {
    const passInput = el("input", {
      id: "passphrase", type: "password", class: "input",
      autocomplete: "new-password", value: state.data.passphrase.value,
      "aria-describedby": "passphrase-meter-text",
    });
    const confirmInput = el("input", {
      id: "passphrase-confirm", type: "password", class: "input",
      autocomplete: "new-password",
    });
    const meterBar = el("div", { class: "meter-fill", "aria-hidden": "true" });
    const meter = el("div", { class: "meter", role: "presentation" }, [meterBar]);
    const meterText = el("p", { id: "passphrase-meter-text", class: "field-help muted", "aria-live": "polite" }, ["Strength: —"]);
    const matchText = el("p", { class: "field-help muted", "aria-live": "polite" }, [""]);
    // Below the recommended floor: show the cost in plain numbers and let
    // the user accept it. Above the hard floor only.
    const weakBox = el("input", { type: "checkbox", id: "pp-accept-weak" });
    const weakText = el("span", {});
    const weakCard = el("label", { class: "ack weak-ack", for: "pp-accept-weak", hidden: "" }, [weakBox, weakText]);
    weakBox.addEventListener("change", () => { state.data.passphrase.acceptWeak = weakBox.checked; refresh(); });
    const backLink = el("button", { type: "button", class: "btn-link" }, ["← Use the suggested five words instead"]);
    backLink.addEventListener("click", () => { const pp = state.data.passphrase; pp.mode = "suggested"; pp.value = ""; pp.confirmed = false; pp.saved = false; render(); });

    function refresh() {
      const value = passInput.value;
      state.data.passphrase.value = value;
      const r = estimate(value);
      meterBar.style.width = `${Math.min(100, (r.bits / 120) * 100)}%`;
      // Label by Crate's own bands, not zxcvbn's (which calls 38 bits "very strong").
      const band = r.bits >= MIN_BITS ? "strong" : r.bits >= HARD_MIN_BITS ? "usable — weaker than recommended" : "too weak";
      meterText.textContent = value ? `Strength: ${band} (${r.bits} bits${r.ready ? "" : " — estimating…"})` : "Strength: —";
      meterBar.className = `meter-fill ${r.bits >= MIN_BITS ? "meter-4" : r.bits >= HARD_MIN_BITS ? "meter-2" : "meter-0"}`;
      const matched = value && value === confirmInput.value;
      const pp = state.data.passphrase;
      const strong = r.bits >= MIN_BITS;
      const acceptable = r.bits >= HARD_MIN_BITS;
      const weakOffered = matched && r.ready && !strong && acceptable;
      weakCard.hidden = !weakOffered;
      if (weakOffered) {
        weakText.textContent = `This is weaker than recommended: about ${r.bits} bits, which one GPU could exhaust in ${crackTime(r.bits)} if it ever got hold of your bucket. I accept that and want to use it anyway.`;
        weakBox.checked = !!pp.acceptWeak;
      } else {
        pp.acceptWeak = false;
      }
      const ok = matched && (strong || (weakOffered && pp.acceptWeak));
      pp.confirmed = ok;
      if (!confirmInput.value) {
        matchText.textContent = "";
      } else if (!matched) {
        matchText.textContent = "✗ Doesn't match";
      } else if (strong) {
        matchText.textContent = "✓ Match — strong";
      } else if (acceptable) {
        matchText.textContent = "✓ Match — weaker than recommended (see below)";
      } else {
        matchText.textContent = `✓ Match — but too weak to accept (under ${HARD_MIN_BITS} bits)`;
      }
      updateNav();
    }
    passInput.addEventListener("input", refresh);
    confirmInput.addEventListener("input", refresh);

    // Kick the meter to warm up zxcvbn-ts in the background.
    whenReady().then(refresh).catch(() => {});

    return makeFragment(
      el("section", { class: "stage stage-passphrase" }, [
        el("h2", { id: "stage-title" }, ["Choose your own passphrase"]),
        el("p", { class: "muted" }, [
          "This unlocks your folder. Crate cannot reset or recover it, so save it somewhere you'll find it again. Enter it twice. The bar turns green at the recommended strength (",
          el("strong", {}, [`${MIN_BITS}`]),
          " bits); you can go below that if you accept the trade-off, which the page will spell out.",
        ]),
        el("div", { class: "hint-card" }, [
          el("div", { class: "hint-card-title" }, ["What clears the bar:"]),
          el("ul", {}, [
            el("li", {}, [
              el("strong", {}, ["Memorable: 5 unrelated common words."]),
              " e.g. ",
              el("code", {}, ["correct-horse-battery-staple-lamp"]),
              " (~55 bits). Two words plus a number and a symbol is ~30 — usable, but a GPU exhausts it in days.",
            ]),
            el("li", {}, [
              el("strong", {}, ["Compact: 12+ random characters mixing upper, lower, digits, symbols."]),
              " e.g. ",
              el("code", {}, ["7zL!q4Mn$ePr"]),
              " (~75 bits). Harder to type but shorter.",
            ]),
            el("li", {}, [
              el("strong", {}, ["What doesn't work:"]),
              " single dictionary words (any length), one word + common digits/punctuation (",
              el("code", {}, ["Password123!"]),
              " is ~20 bits in zxcvbn's model), birthdays, song lyrics, character names. The bar below tells you how it scores.",
            ]),
          ]),
        ]),
        el("div", { class: "field" }, [
          el("label", { for: "passphrase" }, ["Passphrase"]),
          passInput,
          meter,
          meterText,
        ]),
        el("div", { class: "field" }, [
          el("label", { for: "passphrase-confirm" }, ["Confirm passphrase"]),
          confirmInput,
          matchText,
        ]),
        weakCard,
        el("p", { class: "muted small" }, [backLink]),
        el("p", { class: "muted small" }, ["Held in memory only — never written to disk anywhere."]),
      ]),
    );
  }

  function renderDone() {
    if (root) root.setAttribute("data-test-complete", "true");

    // First-time setup runs ONCE — kicked off when the Done stage first
    // renders. Subsequent re-renders (e.g. after restartBtn click then back)
    // skip the work. Setup writes .crate/crate.json + an empty signed
    // manifest to the bucket, derives the master key, and stashes a session
    // handle on window.__CRATE_SESSION__ for the folder UI to consume.
    if (!state.firstTimeSetup) {
      state.firstTimeSetup = { status: "running", error: null, session: null };
      void runFirstTimeSetup().then((session) => {
        state.firstTimeSetup = { status: "done", error: null, session };
        if (typeof window !== "undefined") window.__CRATE_SESSION__ = session;
        if (onComplete) {
          try { onComplete({ ...persistableSnapshot(), firstTimeSetup: "done" }); }
          catch (e) { console.error(e); }
        }
        if (state.stage === "done") render();
      }).catch((err) => {
        console.error("first-time setup failed", err);
        state.firstTimeSetup = { status: "failed", error: err, session: null };
        if (state.stage === "done") render();
      });
    }

    const status = state.firstTimeSetup?.status ?? "running";
    const setupErr = state.firstTimeSetup?.error;

    let heading, lead, actions;
    if (status === "running") {
      heading = "Setting up your folder…";
      lead = "Deriving master key, writing bucket metadata, initialising manifest.";
      actions = [];
    } else if (status === "failed") {
      heading = "Setup didn't finish";
      lead = setupErr?.message ?? "Unknown error while writing to the bucket.";
      const retryBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, ["Retry setup"]);
      retryBtn.addEventListener("click", () => {
        state.firstTimeSetup = null;
        render();
      });
      const restartBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Start over"]);
      restartBtn.addEventListener("click", () => reset());
      actions = [retryBtn, restartBtn];
    } else {
      heading = "Your folder is ready";
      lead = state.route === "carrier"
        ? "Carrier verified. Passphrase set. Encrypted metadata written to your bucket through your Worker."
        : "Bucket connected. Credentials accepted. CORS configured. Passphrase set. Encrypted metadata written to the bucket.";

      // Affirmative-save gate. The user must confirm they've stored the
      // creds somewhere they can find them again BEFORE entering the
      // folder. Downloading the file alone isn't enough — plenty of
      // users download then never move it out of Downloads/. We want
      // an active "yes, I've put this in 1Password / Tijori / a USB
      // drive / handwritten note" affirmation. Persisted on
      // state.data.done so re-renders preserve it.
      state.data.done = state.data.done || {};
      const ackChecked = !!state.data.done.savedAck;

      const ack = el("label", { class: "save-ack" }, []);
      const ackBox = el("input", { type: "checkbox" });
      if (ackChecked) ackBox.setAttribute("checked", "checked");
      const ackText = el("span", {}, [
        "I've saved my credentials somewhere I can find them again — either the ",
        el("code", {}, [".crate-creds"]),
        state.route === "carrier" ? " file or my Worker's address + carrier secret written down (in " : " file or the 5 bucket strings written down (in ",
        el("a", { href: "https://tijori.naklitechie.com/", target: "_blank", rel: "noopener" }, ["Tijori"]),
        ", a password manager, a USB drive, wherever you keep credentials).",
      ]);
      ack.appendChild(ackBox);
      ack.appendChild(ackText);
      ackBox.addEventListener("change", () => {
        state.data.done.savedAck = ackBox.checked;
        // Toggle the Open Folder button's disabled state without a full re-render
        // (which would re-trigger first-time-setup logic).
        const openBtnEl = ack.parentElement?.querySelector?.(".btn.btn-primary.btn-block");
        if (openBtnEl){
          openBtnEl.disabled = !ackBox.checked;
          openBtnEl.title = ackBox.checked ? "" : "Tick the save-acknowledgement first.";
        }
      });

      const openBtn = el("button", {
        type: "button",
        class: "btn btn-primary btn-block",
        title: ackChecked ? "" : "Tick the save-acknowledgement first.",
      }, ["Open your folder"]);
      if (!ackChecked) openBtn.disabled = true;
      openBtn.addEventListener("click", () => {
        // Defence-in-depth — the checkbox can be tampered with via devtools,
        // but the user has actively opted out of the safety net at that point.
        if (!state.data.done?.savedAck) return;
        // Hand off to the folder UI. window.__CRATE_SESSION__ is the
        // bridge — set by runFirstTimeSetup above.
        if (typeof window !== "undefined" && typeof window.openCrateFolder === "function") {
          window.openCrateFolder(state.firstTimeSetup.session);
        } else {
          // No folder-UI mount yet — log and let the caller wire it.
          console.info("crate session ready", state.firstTimeSetup.session);
        }
      });
      const dlCredsBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, [
        "↓ Download credentials file",
      ]);
      dlCredsBtn.addEventListener("click", async () => {
        await downloadCredsFile();
      });
      const restartBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Start a new onboarding"]);
      restartBtn.addEventListener("click", () => reset());

      // NakliOS handoff — a primary one-click "Send to NakliOS" that
      // postMessages the encrypted creds envelope to the parent, so the
      // user skips the download + re-import. Only rendered when crate is
      // running inside an allowlisted NakliOS iframe. Download stays as
      // the fallback below it.
      let handoffActions = [];
      if (state.handoff) {
        const tone = state.handoffSend.tone;
        const sendMsg = el("p", {
          class: "field-help",
          role: "status",
          "aria-live": "polite",
          style: "margin: 0; min-height: 1.2em; color: " + toneColor(tone) + ";",
        }, [state.handoffSend.message || ""]);
        const sendBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, [
          "Send to NakliOS",
        ]);
        // reflect() is the single sink for send progress → persisted state
        // + live DOM, so a re-render replays the last message/tone.
        const reflect = (status, message, msgTone) => {
          state.handoffSend = { status, message, tone: msgTone || "" };
          sendMsg.textContent = message;
          sendMsg.style.color = toneColor(msgTone);
          // Disable only while awaiting an ack or after a terminal
          // success; re-enable on any non-success so the user can retry.
          sendBtn.disabled = status === "sending" || status === "sent";
        };
        if (state.handoffSend.status === "sent") sendBtn.disabled = true;
        else if (state.handoffSend.status === "sending") {
          // A re-render mid-flight: the prior in-flight listener/timeout
          // is still live via state._handoffCleanup. Reflect the pending
          // UI but don't restart the send.
          sendBtn.disabled = true;
        }
        sendBtn.addEventListener("click", () => { void sendToNakliOS(reflect); });
        handoffActions = [sendBtn, sendMsg];
      }

      actions = [...handoffActions, dlCredsBtn, ack, openBtn, restartBtn];
    }

    return makeFragment(
      el("section", { class: "stage stage-done" }, [
        el("h2", { id: "stage-title" }, [heading]),
        el("p", { class: "lead" }, [lead]),
        status === "done"
          ? el("div", { class: "hint-card" }, [
              el("div", { class: "hint-card-title" }, ["Save what you'll need to reopen this folder"]),
              el("p", { class: "muted small", style: "margin: 0;" }, [
                "Download your credentials file and keep it with your passphrase. On another device you unlock with this file + your passphrase. The file holds your connection details, encrypted — it does not replace your passphrase, and it is useless without it. Store it in ",
                el("a", { href: "https://tijori.naklitechie.com/", target: "_blank", rel: "noopener" }, ["Tijori"]),
                " (our own offline password manager), on a USB drive, wherever you keep secrets.",
              ]),
            ])
          : document.createTextNode(""),
        el("p", { class: "muted" }, [
          "Want the daemon? ",
          el("code", {}, ["crate-agent"]),
          " keeps a synced copy of this folder on your computer (macOS/Linux today, Windows v1.1). The daemon now reads ",
          el("code", {}, [".crate/crate.json"]),
          " automatically on start.",
        ]),
        el("div", { class: "stage-actions" }, actions),
      ]),
    );
  }

  // runFirstTimeSetup derives the master key, generates an empty manifest,
  // and writes .crate/crate.json + .crate/manifest.jsonl.enc to the bucket.
  // Returns the session handle the folder UI consumes.
  async function runFirstTimeSetup() {
    const data = state.data;
    const passphrase = data.passphrase?.value;
    if (!passphrase) throw new Error("setup: passphrase missing");
    const bucketConfig = currentBucketConfig();
    const credentials = currentCredentials();
    if (!credentials.accessKey || !credentials.secretKey) throw new Error("setup: credentials missing");

    const region = bucketConfig.region;
    const bucketBase = bucket.resolveBase(bucketConfig);

    // Derive master key from a fresh salt.
    const salt = cryptoLib.randomSalt();
    const masterKey = await cryptoLib.deriveMasterKey(passphrase, salt);

    // Build + PUT .crate/crate.json
    const crateJsonBytes = cratejson.build({
      salt,
      createdBy: cratejson.shortBrowserFingerprint(),
    });
    const crateJsonUrl = bucketBase + cratejson.CRATE_PATH;
    const putRes = await bucket.signedPut({
      url: crateJsonUrl,
      body: crateJsonBytes,
      contentType: "application/json",
      region,
      accessKey: credentials.accessKey,
      secretKey: credentials.secretKey,
    });
    if (!putRes.ok) {
      throw new Error(
        `setup: write .crate/crate.json failed (${putRes.status} ${putRes.code}: ${putRes.message})`,
      );
    }

    // Build + PUT empty manifest (encrypted).
    const manifest = new Manifest();
    const manifestBytes = await manifest.encryptToBytes(masterKey);
    const manifestPutUrl = bucketBase + ".crate/manifest.jsonl.enc";
    const putManifest = await bucket.signedPut({
      url: manifestPutUrl,
      body: manifestBytes,
      contentType: "application/octet-stream",
      region,
      accessKey: credentials.accessKey,
      secretKey: credentials.secretKey,
    });
    if (!putManifest.ok) {
      throw new Error(
        `setup: write manifest failed (${putManifest.status} ${putManifest.code}: ${putManifest.message})`,
      );
    }

    // Build the session handle the folder UI consumes. Master key is
    // memory-only; never written anywhere.
    //
    // manifestETag tracks the last-known R2 ETag of .crate/manifest.jsonl.enc
    // for If-Match conditional writes (concurrent-write safety).
    // lastFlushedEventCount marks the high-water mark of successfully PUT
    // events — used on 412 replay-after-conflict.
    const session = {
      bucketBase,
      bucket: { name: bucketConfig.name, accountId: bucketConfig.accountId, region, url: bucketConfig.url },
      region,
      accessKey: credentials.accessKey,
      secretKey: credentials.secretKey,
      // Passphrase is kept in session memory for the duration of the
      // unlocked session so the folder UI can re-emit a credentials
      // file on demand. Same memory tier as masterKey (and masterKey
      // already grants total access; the passphrase adjacent doesn't
      // meaningfully weaken the threat model). Never persists past tab.
      passphrase,
      masterKey,
      manifest,
      salt,
      manifestETag: putManifest.etag || null,
      lastFlushedEventCount: 0, // empty manifest just landed
    };

    // Stash an encrypted-creds blob in sessionStorage so a tab refresh
    // doesn't drop the user back to the 5-input unlock screen. The
    // passphrase + master key still aren't persisted — only the
    // passphrase-encrypted creds blob (which is useless without the
    // passphrase). See lib/credsfile.js for the format.
    try {
      await stashSessionCreds(currentCreds(), passphrase);
    } catch (e) {
      // Refresh-resume is an optimisation; failure to persist shouldn't
      // block setup completion. Logged for diagnostics.
      console.warn("session-creds stash failed", e);
    }
    // The carrier secret now lives inside the passphrase-wrapped creds;
    // the plaintext parking spot is no longer needed.
    pendingCarrier.clear();

    return session;
  }

  // The wizard's two routes describe the same thing in two shapes; these
  // three helpers are the only place that knows which route is active.
  function currentBucketConfig() {
    const d = state.data;
    if (state.route === "carrier") {
      const url = d.carrier.url.trim().replace(/\/+$/, "");
      if (!validCarrierUrl(url)) throw new Error("setup: carrier url missing");
      return { provider: "carrier", url, name: hostOf(url), accountId: bucket.CARRIER_ACCESS_KEY, region: bucket.CARRIER_REGION };
    }
    if (!d.bucket?.name || !d.bucket?.accountId) throw new Error("setup: bucket missing");
    return { provider: "r2", name: d.bucket.name.trim(), accountId: d.bucket.accountId.trim().toLowerCase(), region: "auto" };
  }
  function currentCredentials() {
    const d = state.data;
    if (state.route === "carrier") return { accessKey: bucket.CARRIER_ACCESS_KEY, secretKey: d.carrier.secret };
    return { accessKey: d.credentials.accessKey, secretKey: d.credentials.secretKey };
  }
  function currentCreds() {
    const b = currentBucketConfig();
    return { provider: b.provider, bucket: { name: b.name, accountId: b.accountId, region: b.region, url: b.url }, credentials: currentCredentials() };
  }

  // downloadCredsFile assembles the encrypted creds file from the
  // current wizard state and triggers a browser download. Called from
  // the Done stage's "Download credentials file" button.
  async function downloadCredsFile() {
    const data = state.data;
    const passphrase = data.passphrase?.value;
    if (!passphrase) {
      announce(liveRegion, "Passphrase no longer in memory — can't build creds file.");
      return;
    }
    try {
      const creds = currentCreds();
      const bytes = await credsfile.pack(creds, passphrase);
      const blob = new Blob([bytes], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = credsfile.suggestedFilename(creds.bucket.name);
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
      announce(liveRegion, "Credentials file downloaded.");
    } catch (e) {
      console.error("creds file download failed", e);
      announce(liveRegion, "Couldn't generate the credentials file: " + (e?.message ?? e));
    }
  }

  // buildEncryptedCredsString packs the same encrypted `.crate-creds`
  // envelope downloadCredsFile produces, but returns it as a UTF-8 JSON
  // STRING (credsfile.pack returns bytes). This is the exact payload the
  // NakliOS handoff forwards verbatim — no reshaping.
  async function buildEncryptedCredsString() {
    const data = state.data;
    const passphrase = data.passphrase?.value;
    if (!passphrase) throw new Error("Passphrase no longer in memory.");
    const bytes = await credsfile.pack(currentCreds(), passphrase);
    return new TextDecoder().decode(bytes);
  }

  // sendToNakliOS posts the encrypted creds envelope to the allowlisted
  // NakliOS parent over postMessage, then awaits an ack. Only ever fires
  // on an explicit click (never auto-send), only ever targets the
  // validated parentOrigin (never '*'), and only accepts an ack that
  // matches origin + source + nonce. `reflect(status, message, tone)`
  // updates the button + status line.
  async function sendToNakliOS(reflect) {
    const handoff = state.handoff;
    if (!handoff) return;
    // Cancel any prior in-flight attempt so listeners don't stack up.
    if (state._handoffCleanup) { try { state._handoffCleanup(); } catch {} state._handoffCleanup = null; }

    reflect("sending", "Sending to NakliOS…", "info");

    let encryptedCreds;
    try {
      encryptedCreds = await buildEncryptedCredsString();
    } catch (e) {
      reflect("error", "Couldn't build the setup payload: " + (e?.message ?? e), "error");
      return;
    }
    if (encryptedCreds.length > HANDOFF_MAX_CREDS_CHARS) {
      reflect("error", "Setup payload too large to send.", "error");
      return;
    }

    const { parentOrigin, nonce } = handoff;
    let settled = false;

    function cleanup() {
      settled = true;
      window.removeEventListener("message", onMessage);
      clearTimeout(timer);
      if (state._handoffCleanup === cleanup) state._handoffCleanup = null;
    }

    function onMessage(event) {
      if (settled) return;
      // Strict provenance: the ack must come from the exact parent origin
      // AND the parent window, and carry the matching nonce + type.
      if (event.origin !== parentOrigin) return;
      if (event.source !== window.parent) return;
      const d = event.data;
      if (!d || d.type !== HANDOFF_ACK_TYPE || d.nonce !== nonce) return;
      cleanup();
      const mapped = HANDOFF_ACK_MESSAGES[d.status]
        || { ok: false, message: "NakliOS could not accept the setup." };
      reflect(mapped.ok ? "sent" : "error", mapped.message, mapped.ok ? "ok" : "error");
    }

    const timer = setTimeout(() => {
      if (settled) return;
      cleanup();
      reflect("error", "No response from NakliOS — try again.", "error");
    }, HANDOFF_ACK_TIMEOUT_MS);

    window.addEventListener("message", onMessage);
    state._handoffCleanup = cleanup;

    // Exactly the frozen sender contract — no extra keys (the receiver
    // rejects unexpected ones), targeted at the validated origin.
    const msg = { type: HANDOFF_SETUP_TYPE, nonce, encryptedCreds, senderVersion: 1 };
    try {
      window.parent.postMessage(msg, parentOrigin);
    } catch (e) {
      cleanup();
      reflect("error", "Couldn't reach NakliOS: " + (e?.message ?? e), "error");
    }
  }

  // stashSessionCreds packs the bucket creds + passphrase into the same
  // wire format the downloadable file uses, then writes it to
  // sessionStorage under SESSION_CREDS_KEY. Tab-scoped: survives reload,
  // dies on tab close.
  async function stashSessionCreds(creds, passphrase) {
    if (typeof sessionStorage === "undefined") return;
    const bytes = await credsfile.pack(creds, passphrase);
    sessionStorage.setItem(SESSION_CREDS_KEY, new TextDecoder().decode(bytes));
  }

  function renderUnlock() {
    const data = state.data.unlock;
    const pill = makePill();
    if (data.status === "ok") pill.ok("✓ Unlocked");
    else if (data.status === "checking") pill.check("Unlocking…");
    else if (data.status === "fail") pill.fail("✗ " + (data.error || "unlock failed"));

    // Common unlock-success path used by both file + manual modes.
    async function doUnlock(bucketConfig, credentials, passphrase) {
      data.status = "checking"; data.error = null; pill.check("Unlocking…");
      try {
        const { Crate } = await import("./crate.js");
        // Try the typed form first, then the dash/space variants — see
        // passphraseCandidates. Only a wrong-passphrase failure moves on
        // to the next form; the form that opens becomes the session's.
        let crate = null;
        let lastErr = null;
        for (const candidate of passphraseCandidates(passphrase)) {
          try {
            crate = await Crate.open({ bucketConfig, credentials, passphrase: candidate });
            passphrase = candidate;
            break;
          } catch (e) {
            lastErr = e;
            if (!isWrongPassphraseError(e)) throw e;
          }
        }
        if (!crate) throw new Error(WRONG_PASSPHRASE_MSG, { cause: lastErr });
        data.status = "ok";
        const session = {
          bucketBase: crate._bucketBase,
          bucket: { name: bucketConfig.name, accountId: bucketConfig.accountId, region: crate._region, url: bucketConfig.url },
          region: crate._region,
          accessKey: crate._accessKey,
          secretKey: crate._secretKey,
          // Passphrase carried in session memory — see runFirstTimeSetup
          // for the rationale. Lets the folder UI re-emit the creds file
          // on demand without re-prompting.
          passphrase,
          masterKey: crate._masterKey,
          manifest: crate._manifest,
          salt: crate._salt,
          manifestETag: crate._manifestETag || null,
          lastFlushedEventCount: crate._manifest.events.length,
        };
        // Stash the session creds so a refresh keeps the tab "logged in"
        // (one-passphrase unlock instead of full restart).
        try {
          await stashSessionCreds({
            provider: bucketConfig.provider || "r2",
            bucket: { name: bucketConfig.name, accountId: bucketConfig.accountId, region: bucketConfig.region, url: bucketConfig.url },
            credentials,
          }, passphrase);
          pendingCarrier.clear();
        } catch (e) {
          console.warn("session-creds stash failed", e);
        }
        if (typeof window !== "undefined" && typeof window.openCrateFolder === "function") {
          window.openCrateFolder(session);
        } else {
          console.info("crate session ready (no folder UI handler)", session);
        }
      } catch (e) {
        console.error(e);
        data.status = "fail"; data.error = e.message ?? String(e);
        render();
      }
    }

    // --- file-mode renderer ---------------------------------------------
    function renderFileMode() {
      const wrap = el("div", { class: "stage-unlock-file" });

      // Drop zone + click-to-pick.
      const dz = el("div", {
        class: "creds-dropzone" + (data.fileBytes ? " creds-dropzone-loaded" : ""),
        tabindex: "0", role: "button",
        "aria-label": "Pick a .crate-creds file, or drop one here",
      });
      const dzMsg = el("p", { class: "creds-dropzone-msg" }, []);
      function repaintDz() {
        while (dzMsg.firstChild) dzMsg.removeChild(dzMsg.firstChild);
        if (data.fileBytes) {
          dzMsg.appendChild(document.createTextNode("✓ Loaded "));
          dzMsg.appendChild(el("strong", {}, [data.fileHint || "(no hint)"]));
          dzMsg.appendChild(document.createTextNode(data.fileFromSession ? " from this tab's session." : " from file."));
          const swap = el("button", { type: "button", class: "btn-link" }, ["Choose a different file"]);
          swap.addEventListener("click", (e) => {
            e.stopPropagation();
            data.fileBytes = null; data.fileHint = null; data.fileFromSession = false;
            data.status = "idle"; data.error = null;
            render();
          });
          wrap.appendChild(swap);
        } else {
          const icon = el("span", { class: "creds-dropzone-icon", "aria-hidden": "true" }, ["🔐"]);
          dzMsg.appendChild(icon);
          dzMsg.appendChild(document.createTextNode(" Drop your "));
          dzMsg.appendChild(el("code", {}, [".crate-creds"]));
          dzMsg.appendChild(document.createTextNode(" file here, or click to pick it."));
        }
      }
      dz.appendChild(dzMsg);
      repaintDz();

      const fileInput = el("input", {
        type: "file", accept: ".crate-creds,application/json",
        style: "display:none",
      });
      async function loadFile(file) {
        try {
          const bytes = new Uint8Array(await file.arrayBuffer());
          const hint = credsfile.peekHint(bytes);
          if (!hint && !credsfile.peekHint(new TextDecoder().decode(bytes))) {
            // peekHint returns null on malformed; if it can't even
            // identify the file type, refuse politely.
            data.status = "fail";
            data.error = "That doesn't look like a Crate credentials file.";
            render();
            return;
          }
          data.fileBytes = bytes;
          data.fileHint = hint;
          data.fileFromSession = false;
          data.status = "idle"; data.error = null;
          render();
        } catch (e) {
          data.status = "fail"; data.error = "Couldn't read the file: " + (e.message ?? e);
          render();
        }
      }
      fileInput.addEventListener("change", (e) => {
        const f = e.target.files?.[0];
        if (f) loadFile(f);
      });
      dz.addEventListener("click", () => fileInput.click());
      dz.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
      dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("creds-dropzone-active"); });
      dz.addEventListener("dragleave", () => dz.classList.remove("creds-dropzone-active"));
      dz.addEventListener("drop", (e) => {
        e.preventDefault();
        dz.classList.remove("creds-dropzone-active");
        const f = e.dataTransfer?.files?.[0];
        if (f) loadFile(f);
      });
      wrap.appendChild(dz);
      wrap.appendChild(fileInput);

      // Passphrase + unlock — only enabled once a file is loaded.
      const passInput = el("input", {
        type: "password", class: "input", autocomplete: "current-password",
        value: data.passphrase,
        placeholder: "Your folder passphrase",
        disabled: data.fileBytes ? false : true,
      });
      passInput.addEventListener("input", () => {
        data.passphrase = passInput.value;
        data.status = "idle"; data.error = null;
        pill.reset();
      });
      passInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && data.fileBytes && data.passphrase) {
          unlockBtn.click();
        }
      });

      const unlockBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, ["Unlock folder"]);
      unlockBtn.disabled = !(data.fileBytes && data.passphrase);
      unlockBtn.addEventListener("click", async () => {
        if (!data.fileBytes || !data.passphrase) return;
        unlockBtn.disabled = true;
        try {
          // The creds file is wrapped under the same passphrase as the
          // folder, so the form that opens the file is the form to use.
          let creds = null;
          let opened = data.passphrase;
          let lastErr = null;
          for (const candidate of passphraseCandidates(data.passphrase)) {
            try {
              creds = await credsfile.unpack(data.fileBytes, candidate);
              opened = candidate;
              break;
            } catch (e) {
              lastErr = e;
              if (!isWrongPassphraseError(e)) throw e;
            }
          }
          if (!creds) throw new Error("Wrong passphrase, or the credentials file is corrupt.", { cause: lastErr });
          await doUnlock(
            { provider: creds.provider, accountId: creds.bucket.accountId, name: creds.bucket.name, region: creds.bucket.region || "auto", url: creds.bucket.url },
            { accessKey: creds.credentials.accessKey, secretKey: creds.credentials.secretKey },
            opened,
          );
        } catch (e) {
          data.status = "fail";
          data.error = e?.message ?? String(e);
          unlockBtn.disabled = false;
          render();
        }
      });
      passInput.addEventListener("input", () => {
        unlockBtn.disabled = !(data.fileBytes && data.passphrase);
      });

      wrap.appendChild(el("div", { class: "field" }, [
        el("label", {}, ["Passphrase"]),
        passInput,
      ]));
      wrap.appendChild(el("div", { class: "row" }, [unlockBtn, pill.el]));

      // Fallback link to manual mode.
      const manualLink = el("button", { type: "button", class: "btn-link" }, ["No file? Enter the details manually."]);
      manualLink.addEventListener("click", () => { data.mode = "manual"; data.status = "idle"; data.error = null; render(); });
      wrap.appendChild(el("p", { class: "muted small" }, [manualLink]));

      return wrap;
    }

    // --- manual-mode renderer (fallback) ---------------------------------
    function renderManualMode() {
      const wrap = el("div", { class: "stage-unlock-manual" });
      function field(label, val, type, onInput, autocomplete, mono) {
        const input = el("input", {
          type, class: mono ? "input mono" : "input", value: val,
          autocomplete: autocomplete || "off",
        });
        input.addEventListener("input", () => {
          onInput(input.value);
          data.status = "idle"; data.error = null; pill.reset();
        });
        return el("div", { class: "field" }, [el("label", {}, [label]), input]);
      }
      // Two shapes of "the details": a carrier is Worker URL + secret; a
      // bucket is the four sig-v4 strings. Same passphrase either way.
      const carrierMode = data.manualKind === "carrier";
      const kindRow = el("div", { class: "row" }, [
        el("label", { class: "muted small" }, ["I set up with"]),
        el("button", { type: "button", class: `btn btn-secondary${carrierMode ? " active" : ""}` }, ["One click (carrier)"]),
        el("button", { type: "button", class: `btn btn-secondary${carrierMode ? "" : " active"}` }, ["My own bucket"]),
      ]);
      kindRow.children[1].addEventListener("click", () => { data.manualKind = "carrier"; data.status = "idle"; data.error = null; render(); });
      kindRow.children[2].addEventListener("click", () => { data.manualKind = "bucket"; data.status = "idle"; data.error = null; render(); });
      wrap.appendChild(kindRow);

      if (carrierMode) {
        wrap.appendChild(el("p", { class: "muted small" }, [
          "The Worker URL is under Workers & Pages in your Cloudflare dashboard. The secret is the CARRIER_SECRET you pasted at deploy; if you no longer have it, set a new one on the Worker (Settings → Variables and Secrets) and use that.",
        ]));
        wrap.appendChild(field("Worker URL", data.carrierUrl, "url", (v) => data.carrierUrl = v, "off", false));
        wrap.appendChild(field("Carrier secret (CARRIER_SECRET)", data.secretKey, "password", (v) => data.secretKey = v, "off", true));
      } else {
        wrap.appendChild(field("Bucket name", data.bucketName, "text", (v) => data.bucketName = v, "off", false));
        wrap.appendChild(field("Cloudflare Account ID", data.accountId, "text", (v) => data.accountId = v, "off", true));
        wrap.appendChild(field("Access Key", data.accessKey, "text", (v) => data.accessKey = v, "off", true));
        wrap.appendChild(field("Secret Access Key", data.secretKey, "password", (v) => data.secretKey = v, "off", true));
      }
      wrap.appendChild(field("Folder passphrase", data.passphrase, "password", (v) => data.passphrase = v, "current-password", false));

      const unlockBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, ["Unlock folder"]);
      unlockBtn.addEventListener("click", async () => {
        if (carrierMode) {
          const url = (data.carrierUrl || "").trim().replace(/\/+$/, "");
          if (!validCarrierUrl(url) || !data.secretKey || !data.passphrase) {
            data.status = "fail"; data.error = "Worker URL (https://…), secret and passphrase are all required"; render();
            return;
          }
          unlockBtn.disabled = true;
          await doUnlock(
            { provider: "carrier", url, name: hostOf(url), accountId: bucket.CARRIER_ACCESS_KEY, region: bucket.CARRIER_REGION },
            { accessKey: bucket.CARRIER_ACCESS_KEY, secretKey: data.secretKey.trim() },
            data.passphrase,
          );
          unlockBtn.disabled = false;
          return;
        }
        if (!data.bucketName || !data.accountId || !data.accessKey || !data.secretKey || !data.passphrase) {
          data.status = "fail"; data.error = "All fields required"; render();
          return;
        }
        unlockBtn.disabled = true;
        await doUnlock(
          { accountId: data.accountId.trim().toLowerCase(), name: data.bucketName.trim(), region: "auto" },
          { accessKey: data.accessKey.trim(), secretKey: data.secretKey.trim() },
          data.passphrase,
        );
        unlockBtn.disabled = false;
      });
      wrap.appendChild(el("div", { class: "row" }, [unlockBtn, pill.el]));

      const backLink = el("button", { type: "button", class: "btn-link" }, ["← Back to credentials-file unlock"]);
      backLink.addEventListener("click", () => { data.mode = "file"; data.status = "idle"; data.error = null; render(); });
      wrap.appendChild(el("p", { class: "muted small" }, [backLink]));
      return wrap;
    }

    const intro = data.fileFromSession
      ? "You unlocked this folder earlier in this tab. Enter your passphrase to reopen it — your credentials file is still in memory."
      : data.mode === "manual"
        ? "No credentials file? Enter the details from setup instead. Your passphrase unlocks the folder either way."
        : "Pick the credentials file you downloaded at first setup, then enter your folder passphrase. The file is useless without the passphrase.";

    return makeFragment(
      el("section", { class: "stage stage-unlock" }, [
        el("h2", { id: "stage-title" }, [
          data.fileFromSession ? `Welcome back to ${data.fileHint || "your folder"}` : "Open your folder",
        ]),
        el("p", { class: "muted" }, [intro]),
        data.mode === "manual" ? renderManualMode() : renderFileMode(),
      ]),
    );
  }

  const STAGE_RENDERERS = {
    welcome: renderWelcome,
    carrier: renderCarrier,
    bucket: renderBucket,
    credentials: renderCredentials,
    cors: renderCors,
    passphrase: renderPassphrase,
    done: renderDone,
    unlock: renderUnlock,
  };

  // --- Render + nav ----------------------------------------------------

  function render() {
    // Cancel any in-flight verify/test/preflight so a stage change doesn't
    // leave a stale fetch chasing detached DOM nodes.
    aborter.cancel();
    // The welcome stage is a landing, not a wizard step — hide the
    // progress tracker + Back/Next footer there so it stops reading as
    // "step 1 of 6". Every other stage shows the chrome.
    const isLanding = state.stage === "welcome";
    if (progressHost) progressHost.style.display = isLanding ? "none" : "";
    if (navHost) navHost.style.display = isLanding ? "none" : "";
    // The landing card centres vertically in the shell; wizard stages
    // read top-down with the sticky nav at the bottom.
    if (root.parentElement) root.parentElement.classList.toggle("is-landing", isLanding);
    const renderer = STAGE_RENDERERS[state.stage] || renderWelcome;
    while (root.firstChild) root.removeChild(root.firstChild);
    root.appendChild(renderer());
    renderProgress();
    updateNav();
    const heading = root.querySelector("#stage-title");
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: false });
    }
    announce(liveRegion, isLanding
      ? "Welcome to Crate"
      : `Step ${stageIndex().index + 1} of ${stageIndex().stages.length} — ${state.stage}`);
  }

  function renderProgress() {
    if (!progressHost) return;
    const { stages, index } = stageIndex();
    while (progressHost.firstChild) progressHost.removeChild(progressHost.firstChild);
    const wide = el("ol", { class: "progress-steps", "aria-hidden": "true" },
      stages.map((s, i) => el("li", {
        class: `progress-step${i === index ? " active" : ""}${i < index ? " done" : ""}`,
      }, [s])),
    );
    const narrow = el("div", { class: "progress-compact" }, [
      el("span", { class: "progress-label" }, [`Step ${index + 1} of ${stages.length} — ${state.stage}`]),
      el("progress", { value: index + 1, max: stages.length }),
    ]);
    progressHost.appendChild(wide);
    progressHost.appendChild(narrow);
  }

  function updateNav() {
    if (!backBtn || !nextBtn) return;
    const { index, stages } = stageIndex();
    backBtn.disabled = index === 0;
    const isLast = index === stages.length - 1;
    if (isLast) {
      nextBtn.disabled = true;
      nextBtn.textContent = "Done";
    } else {
      nextBtn.disabled = !canAdvance(state.stage);
      nextBtn.textContent = "Next →";
    }
  }

  // --- Wiring ----------------------------------------------------------

  function onHashChange() {
    const hash = location.hash.replace(/^#/, "") || "welcome";
    if (STAGES.includes(hash)) {
      if (hash !== state.stage) go(hash);
    } else {
      go("welcome");
    }
  }

  function init() {
    if (backBtn) backBtn.addEventListener("click", back);
    if (nextBtn) nextBtn.addEventListener("click", next);
    window.addEventListener("hashchange", onHashChange);
    return loadSession().then(() => {
      // Refresh-resume: if sessionStorage has an encrypted creds blob
      // from earlier in this tab session, route straight to the unlock
      // screen with the file pre-loaded — the user only needs to type
      // their passphrase.
      tryRestoreFromSession();
      // #carrier=<worker origin> — the Worker's "Continue to Crate" link.
      // Take the URL, drop it from the address bar, land on the carrier
      // stage with the parked secret (see pendingCarrier).
      const carrierLink = location.hash.match(/^#carrier=(.+)$/);
      if (carrierLink) {
        let url = "";
        try { url = decodeURIComponent(carrierLink[1]).trim().replace(/\/+$/, ""); } catch {}
        if (validCarrierUrl(url)) {
          state.route = "carrier";
          state.data.carrier.url = url;
          state.data.carrier.verified = false;
          const pending = pendingCarrier.load();
          if (pending) state.data.carrier.secret = pending.secret;
          state.stage = "carrier";
          try { history.replaceState(null, "", "#carrier"); } catch {}
        }
      }
      const hash = location.hash.replace(/^#/, "");
      if (hash && STAGES.includes(hash)) {
        state.stage = hash;
      }
      render();
    });
  }

  // tryRestoreFromSession reads the sessionStorage blob (if any) and
  // pre-fills state.data.unlock so renderUnlock shows the streamlined
  // "Welcome back — passphrase only" prompt. Silently no-ops if the
  // blob is absent or malformed.
  function tryRestoreFromSession() {
    if (typeof sessionStorage === "undefined") return;
    let raw;
    try { raw = sessionStorage.getItem(SESSION_CREDS_KEY); } catch { return; }
    if (!raw) return;
    const hint = credsfile.peekHint(raw);
    if (hint === null) {
      // Corrupt — discard so we don't keep tripping over it.
      try { sessionStorage.removeItem(SESSION_CREDS_KEY); } catch {}
      return;
    }
    state.data.unlock.mode = "file";
    state.data.unlock.fileBytes = new TextEncoder().encode(raw);
    state.data.unlock.fileHint = hint;
    state.data.unlock.fileFromSession = true;
    state.route = "unlock";
    state.stage = "unlock";
  }

  return {
    init,
    openHelp: (opts) => openHelpModal(opts || {}),
    go,
    next,
    back,
    reset,
    getState: () => ({ stage: state.stage, route: state.route, data: { ...state.data } }),
    STAGES,
  };
}
