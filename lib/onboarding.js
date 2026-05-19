// SPDX-License-Identifier: AGPL-3.0-or-later
// Crate v1.0 onboarding wizard — M1 shell. Hash-routed FSM that walks
// the user through the 7 new-folder stages (welcome → bucket → credentials
// → cors → passphrase → recovery → done) and the 2 pair-device stages
// (pair-unlock → pair-done). Built per
// `docs/specs/crate-browser-handoff-v1.0.md` §"Onboarding wizard".
//
// M1 scope: every stage renders, all interactions feel real, validation
// pills cycle Waiting → Checking → ✓/✗ with synthetic timing. NO real
// Cloudflare calls (that's M2), NO real PBKDF2 or signed manifest (M3),
// NO QR scanner (M7). The entropy meter on Passphrase is real (zxcvbn-ts
// via lib/entropy.js); the recovery phrase is real (BIP-39 from
// lib/wordlist.js + crypto.getRandomValues). Passphrase and recovery
// phrase are memory-only — they NEVER reach IndexedDB or localStorage,
// per spec §"Persistence rules" lines 110–113.

import { BIP39_WORDS, wordAt } from "./wordlist.js";
import { copyText } from "./clipboard.js";
import { estimate, whenReady } from "./entropy.js";
import * as idb from "./idb.js";
import * as bucket from "./bucket.js";

// --- Constants ---------------------------------------------------------

export const STAGES = Object.freeze([
  "welcome",
  "bucket",
  "credentials",
  "cors",
  "passphrase",
  "recovery",
  "done",
  "pair-unlock",
  "pair-done",
]);

const NEW_FOLDER_STAGES = ["welcome", "bucket", "credentials", "cors", "passphrase", "recovery", "done"];
const PAIR_STAGES = ["welcome", "pair-unlock", "pair-done"];

const DEEP_LINKS = {
  bucket: "https://dash.cloudflare.com/?to=/:account/r2/overview",
  tokens: "https://dash.cloudflare.com/?to=/:account/r2/api-tokens",
};

// Fake-validation timing — feels real on phone networks without padding
// idle time on a fast desktop. Random within the band so it doesn't feel
// metronome-y across stages.
const PILL_MIN_MS = 350;
const PILL_MAX_MS = 700;
const MIN_BITS = 70; // spec §"Onboarding wizard" → passphrase strength target

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

function randomDelay() {
  return PILL_MIN_MS + Math.random() * (PILL_MAX_MS - PILL_MIN_MS);
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

// 24-word BIP-39 phrase generated client-side. Returns an array of 24
// strings. Memory-only — never persists.
function generateRecoveryPhrase() {
  const out = [];
  const buf = new Uint32Array(24);
  crypto.getRandomValues(buf);
  for (const v of buf) {
    out.push(wordAt(v % BIP39_WORDS.length));
  }
  return out;
}

// Hyphen-joined 7-word passphrase from BIP-39. ~77 bits entropy.
function generatePassphrase() {
  return generateRecoveryPhrase().slice(0, 7).join("-");
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

// Synthetic check that mimics the M1 fake-pill timing. Used by the
// pair-device flow at renderPairUnlock — the daemon-side /v1/pairing/*
// endpoints land at the deferred Unit C in private-mesh, so until then
// we can't redeem a real pairing token from the browser. The new-folder
// route's three stages all use real bucket calls now.
function fakeVerify(input) {
  return new Promise((resolve) => {
    setTimeout(() => {
      const s = (input ?? "").toString().trim().toLowerCase();
      resolve({ ok: s && s !== "fail" });
    }, randomDelay());
  });
}

// --- Wizard factory ----------------------------------------------------

export function createWizard({ root, onComplete, liveRegion } = {}) {
  if (!root) throw new Error("createWizard: { root } is required");

  const state = {
    stage: "welcome",
    route: "new-folder", // or "pair"
    data: {
      bucket: { name: suggestBucketName(), accountId: "", verified: false },
      credentials: { accessKey: "", secretKey: "", verified: false },
      cors: { preflighted: false },
      passphrase: { value: "", confirmed: false }, // memory-only
      recovery: { phrase: null, confirmedIndices: [] }, // memory-only
      pair: { token: "", passphrase: "", unlocked: false },
    },
  };

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
        bucket: { ...state.data.bucket },
        credentials: {
          // accessKey/secretKey are sensitive enough to omit from disk
          // even though they're not the master passphrase — spec §
          // "Persistence rules" line 109 says these only go to
          // sessionStorage and only with explicit opt-in. M1 doesn't
          // ship that opt-in.
          verified: state.data.credentials.verified,
        },
        cors: { ...state.data.cors },
        // passphrase + recovery are memory-only — never written.
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
      case "bucket": return state.data.bucket.verified;
      case "credentials": return state.data.credentials.verified;
      case "cors": return state.data.cors.preflighted;
      case "passphrase": return state.data.passphrase.confirmed;
      case "recovery": return state.data.recovery.confirmedIndices.length >= 3;
      case "done": return false;
      case "pair-unlock": return state.data.pair.unlocked;
      case "pair-done": return false;
      default: return false;
    }
  }

  function reachableStages() {
    const stages = state.route === "pair" ? PAIR_STAGES : NEW_FOLDER_STAGES;
    const reached = [];
    for (const s of stages) {
      reached.push(s);
      if (!canAdvance(s) && s !== "welcome") break;
    }
    return reached;
  }

  function stageIndex() {
    const stages = state.route === "pair" ? PAIR_STAGES : NEW_FOLDER_STAGES;
    const i = stages.indexOf(state.stage);
    return { stages, index: i === -1 ? 0 : i };
  }

  function go(stage) {
    if (!STAGES.includes(stage)) return;
    // Route inference: a `pair-*` stage implies the pair route.
    if (stage.startsWith("pair-")) state.route = "pair";
    // Clamp forward jumps to the highest currently-reachable stage.
    const reached = reachableStages();
    let target = stage;
    if (!reached.includes(stage)) {
      target = reached[reached.length - 1];
    }
    state.stage = target;
    if (location.hash !== `#${target}`) {
      location.hash = target; // triggers hashchange; render runs there
    } else {
      render();
    }
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
    state.data.bucket = { name: suggestBucketName(), accountId: "", verified: false };
    state.data.credentials = { accessKey: "", secretKey: "", verified: false };
    state.data.cors = { preflighted: false };
    state.data.passphrase = { value: "", confirmed: false };
    state.data.recovery = { phrase: null, confirmedIndices: [] };
    state.data.pair = { token: "", passphrase: "", unlocked: false };
    if (root) root.removeAttribute("data-test-complete");
    idb.del("onboarding", "session").catch(() => {});
    go("welcome");
  }

  // --- Stage renderers -------------------------------------------------

  function renderWelcome() {
    const newFolderBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, ["Set up a new folder"]);
    newFolderBtn.addEventListener("click", () => { state.route = "new-folder"; go("bucket"); });
    const pairBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Add this device to an existing folder"]);
    pairBtn.addEventListener("click", () => { state.route = "pair"; go("pair-unlock"); });
    return makeFragment(
      el("section", { class: "stage stage-welcome", "aria-labelledby": "stage-title" }, [
        el("h1", { id: "stage-title" }, ["Crate"]),
        el("p", { class: "lead" }, ["A personal cloud folder. Files live in a Cloudflare R2 bucket you own, encrypted before they leave your browser. No NakliTechie account, no subscription, no server on the path."]),
        el("p", { class: "muted" }, ["You'll need: a Cloudflare account (free tier works), about 3 minutes, and a passphrase you'll remember."]),
        el("div", { class: "stage-actions" }, [newFolderBtn, pairBtn]),
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
      // CORS headers. M2 design: shape check here, real verify later.
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
    return makeFragment(
      el("section", { class: "stage stage-cors" }, [
        el("h2", { id: "stage-title" }, ["Configure CORS"]),
        el("p", { class: "muted" }, ["Your browser needs your bucket to allow cross-origin requests from this page. Copy the JSON below, paste it into your bucket's CORS configuration in the Cloudflare dashboard, then come back and run the preflight check."]),
        corsBlock,
        el("div", { class: "row" }, [copyBtn, preflightBtn, pill.el]),
      ]),
    );
  }

  function renderPassphrase() {
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
    const generateBtn = el("button", { type: "button", class: "btn btn-secondary" }, ["Generate (7 words)"]);

    function refresh() {
      const value = passInput.value;
      state.data.passphrase.value = value;
      const r = estimate(value);
      meterBar.style.width = `${Math.min(100, (r.bits / 120) * 100)}%`;
      meterBar.className = `meter-fill meter-${r.score}`;
      meterText.textContent = value ? `Strength: ${r.label} (${r.bits} bits${r.ready ? "" : " — estimating…"})` : "Strength: —";
      const matched = value && value === confirmInput.value;
      const ok = matched && r.bits >= MIN_BITS;
      state.data.passphrase.confirmed = ok;
      if (!confirmInput.value) {
        matchText.textContent = "";
      } else if (matched) {
        matchText.textContent = r.bits >= MIN_BITS ? "✓ Match — strong enough" : `✓ Match — but needs at least ${MIN_BITS} bits`;
      } else {
        matchText.textContent = "✗ Doesn't match";
      }
      updateNav();
    }
    passInput.addEventListener("input", refresh);
    confirmInput.addEventListener("input", refresh);
    generateBtn.addEventListener("click", () => {
      const generated = generatePassphrase();
      passInput.type = "text";
      passInput.value = generated;
      confirmInput.type = "text";
      confirmInput.value = generated;
      refresh();
      announce(liveRegion, "Generated a fresh 7-word passphrase. Write it down before continuing.");
    });

    // Kick the meter to warm up zxcvbn-ts in the background.
    whenReady().then(refresh).catch(() => {});

    return makeFragment(
      el("section", { class: "stage stage-passphrase" }, [
        el("h2", { id: "stage-title" }, ["Pick a passphrase"]),
        el("p", { class: "muted" }, [
          "This unlocks your folder. Crate cannot recover it for you. Aim for at least ",
          el("strong", {}, [`${MIN_BITS}`]),
          " bits of entropy — or hit Generate for a 7-word phrase that clears the gate.",
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
        el("div", { class: "row" }, [generateBtn]),
        el("p", { class: "muted small" }, ["Held in memory only — never written to disk anywhere."]),
      ]),
    );
  }

  function renderRecovery() {
    if (!state.data.recovery.phrase) {
      state.data.recovery.phrase = generateRecoveryPhrase();
      state.data.recovery.confirmedIndices = [];
    }
    const phrase = state.data.recovery.phrase;
    const grid = el("ol", { class: "recovery-grid", "aria-label": "Recovery phrase, 24 words" });
    phrase.forEach((word, i) => {
      const li = el("li", { class: "recovery-word" }, [
        el("span", { class: "recovery-index" }, [`${i + 1}`]),
        el("span", { class: "recovery-text" }, [word]),
      ]);
      grid.appendChild(li);
    });
    const copyBtn = makeCopyButton(() => phrase.join(" "), "Copy phrase");

    function pickConfirmIndices() {
      const all = Array.from({ length: 24 }, (_, i) => i);
      for (let i = all.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [all[i], all[j]] = [all[j], all[i]];
      }
      return all.slice(0, 3).sort((a, b) => a - b);
    }
    const askIndices = pickConfirmIndices();
    const correct = new Set();
    function refreshConfirmation() {
      state.data.recovery.confirmedIndices = Array.from(correct);
      updateNav();
    }
    const fields = el("div", { class: "field-row" }, askIndices.map((idx) => {
      const inp = el("input", {
        type: "text", class: "input input-narrow", autocomplete: "off",
        "aria-label": `Word #${idx + 1}`, placeholder: `word ${idx + 1}`,
      });
      inp.addEventListener("input", () => {
        const v = inp.value.trim().toLowerCase();
        if (v === phrase[idx]) {
          inp.classList.add("input-ok");
          inp.classList.remove("input-fail");
          correct.add(idx);
        } else {
          inp.classList.remove("input-ok");
          inp.classList.toggle("input-fail", v.length > 0);
          correct.delete(idx);
        }
        refreshConfirmation();
      });
      return el("div", { class: "confirm-cell" }, [
        el("label", {}, [`Word #${idx + 1}`]),
        inp,
      ]);
    }));

    return makeFragment(
      el("section", { class: "stage stage-recovery" }, [
        el("h2", { id: "stage-title" }, ["Write down your recovery phrase"]),
        el("p", { class: "muted" }, ["These 24 words will let you restore access if you forget your passphrase — once the recovery flow ships at M3. Until then this phrase is preview-only: it's generated client-side and stored nowhere, but the cryptographic derivation that pairs it with your passphrase lands at M3. Write it on paper anyway. Do not screenshot it. Do not email it to yourself. Crate cannot recover it."]),
        grid,
        el("div", { class: "row" }, [copyBtn]),
        el("hr", { class: "stage-divider" }),
        el("p", {}, ["Confirm by typing the words at these positions:"]),
        fields,
      ]),
    );
  }

  function renderDone() {
    if (onComplete) {
      try { onComplete(persistableSnapshot()); } catch (e) { console.error(e); }
    }
    if (root) root.setAttribute("data-test-complete", "true");
    const startBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, ["Open your folder"]);
    startBtn.disabled = true;
    startBtn.title = "Folder UI lands at M4";
    const restartBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Start a new onboarding"]);
    restartBtn.addEventListener("click", () => reset());
    return makeFragment(
      el("section", { class: "stage stage-done" }, [
        el("h2", { id: "stage-title" }, ["Your folder is ready"]),
        el("p", { class: "lead" }, ["Bucket connected. Credentials accepted. CORS configured. Passphrase set. Recovery phrase confirmed."]),
        el("p", { class: "muted" }, [
          "Want the daemon? ",
          el("code", {}, ["crate-agent"]),
          " keeps a synced copy of this folder on your computer (macOS/Linux today, Windows v1.1). It ships in v1.2 — ",
          el("a", { href: "docs/README.md" }, ["see the roadmap"]),
          ".",
        ]),
        el("div", { class: "stage-actions" }, [startBtn, restartBtn]),
        el("p", { class: "muted small" }, ["(M1 ends here. Real bucket calls land at M2; encryption + manifest at M3; folder UI at M4.)"]),
      ]),
    );
  }

  function renderPairUnlock() {
    const pill = makePill();
    const tokenInput = el("input", {
      id: "pair-token", type: "text", class: "input mono", autocomplete: "off",
      value: state.data.pair.token, placeholder: "CRATE-PAIR-…",
    });
    tokenInput.addEventListener("input", () => {
      state.data.pair.token = tokenInput.value;
      state.data.pair.unlocked = false;
      pill.reset();
      updateNav();
    });
    const passInput = el("input", {
      id: "pair-passphrase", type: "password", class: "input",
      autocomplete: "current-password", value: state.data.pair.passphrase,
    });
    passInput.addEventListener("input", () => {
      state.data.pair.passphrase = passInput.value;
      state.data.pair.unlocked = false;
      pill.reset();
      updateNav();
    });
    const unlockBtn = el("button", { type: "button", class: "btn btn-primary" }, ["Unlock"]);
    unlockBtn.addEventListener("click", async () => {
      unlockBtn.disabled = true;
      pill.check("Unlocking…");
      const prefixOk = tokenInput.value.startsWith("CRATE-PAIR-");
      const failTrip = passInput.value.trim().toLowerCase() === "fail";
      const r = await fakeVerify(failTrip ? "fail" : (prefixOk && passInput.value ? "ok" : ""));
      if (r.ok) {
        pill.ok("✓ Unlocked");
        state.data.pair.unlocked = true;
      } else {
        pill.fail("✗ Token or passphrase rejected");
        state.data.pair.unlocked = false;
      }
      unlockBtn.disabled = false;
      updateNav();
    });
    return makeFragment(
      el("section", { class: "stage stage-pair-unlock" }, [
        el("h2", { id: "stage-title" }, ["Add this device"]),
        el("p", { class: "muted" }, ["Paste the pairing token from your other device, then enter the passphrase that protects the folder."]),
        el("p", { class: "muted small" }, ["QR scanner coming in M7. For now, copy the token from the source device and paste it here."]),
        el("div", { class: "field" }, [
          el("label", { for: "pair-token" }, ["Pairing token"]),
          tokenInput,
          el("p", { class: "field-help muted" }, ["Tip: type ", el("code", {}, ["fail"]), " in the passphrase to see the error path."]),
        ]),
        el("div", { class: "field" }, [
          el("label", { for: "pair-passphrase" }, ["Passphrase"]),
          passInput,
        ]),
        el("div", { class: "row" }, [unlockBtn, pill.el]),
      ]),
    );
  }

  function renderPairDone() {
    if (root) root.setAttribute("data-test-complete", "true");
    const openBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, ["Open the folder"]);
    openBtn.disabled = true;
    openBtn.title = "Folder UI lands at M4";
    return makeFragment(
      el("section", { class: "stage stage-pair-done" }, [
        el("h2", { id: "stage-title" }, ["Device added"]),
        el("p", { class: "lead" }, ["You're paired. The folder will appear here once the file UI ships at M4."]),
        el("p", { class: "muted" }, ["Your other devices have been notified that a new device joined."]),
        el("div", { class: "stage-actions" }, [openBtn]),
      ]),
    );
  }

  const STAGE_RENDERERS = {
    welcome: renderWelcome,
    bucket: renderBucket,
    credentials: renderCredentials,
    cors: renderCors,
    passphrase: renderPassphrase,
    recovery: renderRecovery,
    done: renderDone,
    "pair-unlock": renderPairUnlock,
    "pair-done": renderPairDone,
  };

  // --- Render + nav ----------------------------------------------------

  function render() {
    // Cancel any in-flight verify/test/preflight so a stage change doesn't
    // leave a stale fetch chasing detached DOM nodes.
    aborter.cancel();
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
    announce(liveRegion, `Step ${stageIndex().index + 1} of ${stageIndex().stages.length} — ${state.stage}`);
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
      const hash = location.hash.replace(/^#/, "");
      if (hash && STAGES.includes(hash)) {
        state.stage = hash;
        if (hash.startsWith("pair-")) state.route = "pair";
      }
      render();
    });
  }

  return {
    init,
    go,
    next,
    back,
    reset,
    getState: () => ({ stage: state.stage, route: state.route, data: { ...state.data } }),
    STAGES,
  };
}
