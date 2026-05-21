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
import { Manifest } from "./manifest.js";

// Key under which we stash the encrypted creds blob in sessionStorage
// for refresh-resilience. sessionStorage scope = current tab, cleared
// on close. Same crypto as the downloadable file; passphrase still
// required to decrypt.
export const SESSION_CREDS_KEY = "crate:session-creds-v1";

// --- Constants ---------------------------------------------------------

export const STAGES = Object.freeze([
  "welcome",
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
const UNLOCK_STAGES = ["welcome", "unlock"];

const DEEP_LINKS = {
  bucket: "https://dash.cloudflare.com/?to=/:account/r2/overview",
  tokens: "https://dash.cloudflare.com/?to=/:account/r2/api-tokens",
};

const MIN_BITS = 70; // passphrase strength floor in bits (zxcvbn estimate)

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
  const buf = new Uint32Array(7);
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
      bucket: { name: suggestBucketName(), accountId: "", verified: false },
      credentials: { accessKey: "", secretKey: "", verified: false },
      cors: { preflighted: false },
      passphrase: { value: "", confirmed: false }, // memory-only
      unlock: {
        // Mode: "file" picks a .crate-creds file + passphrase (default).
        // Mode: "manual" falls back to the 5-input form.
        mode: "file",
        // File mode state — set when user picks a file or when we
        // auto-restore an in-tab session from sessionStorage.
        fileBytes: null, fileHint: null, fileFromSession: false,
        // Manual mode state — bucket + bucket-creds inputs.
        bucketName: "", accountId: "",
        accessKey: "", secretKey: "",
        // Shared.
        passphrase: "",
        status: "idle", error: null,
      },
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
      case "unlock": return UNLOCK_STAGES;
      default:       return NEW_FOLDER_STAGES;
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
    state.data.bucket = { name: suggestBucketName(), accountId: "", verified: false };
    state.data.credentials = { accessKey: "", secretKey: "", verified: false };
    state.data.cors = { preflighted: false };
    state.data.passphrase = { value: "", confirmed: false };
    state.data.unlock = {
      mode: "file",
      fileBytes: null, fileHint: null, fileFromSession: false,
      bucketName: "", accountId: "",
      accessKey: "", secretKey: "",
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
    const newFolderBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, ["Set up a new folder"]);
    newFolderBtn.addEventListener("click", () => { state.route = "new-folder"; go("bucket"); });
    const unlockBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Unlock an existing folder"]);
    unlockBtn.addEventListener("click", () => { state.route = "unlock"; go("unlock"); });

    const helpBtn = el("button", { type: "button", class: "btn btn-secondary btn-block", "aria-haspopup": "dialog" }, [
      "How this works (read first — 60 seconds)",
    ]);
    helpBtn.addEventListener("click", () => openHelpModal());

    return makeFragment(
      el("section", { class: "stage stage-welcome", "aria-labelledby": "stage-title" }, [
        el("h1", { id: "stage-title" }, ["Crate"]),
        el("p", { class: "lead" }, ["A personal cloud folder. Files live in a bucket you own (Cloudflare R2 by default), encrypted before they leave your browser. No NakliTechie account, no subscription, no server on the path."]),
        el("div", { class: "preview-banner" }, [
          el("strong", {}, ["v1.0."]),
          " End-to-end encrypted in this browser. The bucket owner (Cloudflare, Hetzner, B2, AWS) sees ciphertext + access patterns only. Bring your own bucket; no NakliTechie account on the path.",
        ]),
        el("p", { class: "muted" }, ["You'll need: a Cloudflare account (free tier works), about 3 minutes, and a passphrase you'll remember."]),
        el("div", { class: "stage-actions" }, [helpBtn, newFolderBtn, unlockBtn]),
        el("hr", { class: "stage-divider" }),
        el("p", { class: "muted small" }, [
          el("a", { href: "guide/", target: "_blank", rel: "noopener noreferrer" }, ["Guide"]),
          " · ",
          el("a", { href: "https://github.com/NakliTechie/crate", target: "_blank", rel: "noopener noreferrer" }, ["GitHub"]),
          " · ",
          el("a", { href: "docs/README.md" }, ["Docs"]),
          " · AGPL-3.0-or-later",
        ]),
      ]),
    );
  }

  // openHelpModal opens a modal walking the user through the Cloudflare
  // setup steps BEFORE they enter the wizard. Targets a first-time
  // visitor who has never seen Cloudflare R2.
  function openHelpModal() {
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
      document.body.removeChild(overlay);
    };
    function onKey(e) { if (e.key === "Escape") close(); }
    document.addEventListener("keydown", onKey);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

    const closeBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Got it — back to set-up"]);
    closeBtn.addEventListener("click", close);

    card.appendChild(el("h2", { id: "help-title" }, ["What you'll need + what each step does"]));
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
        "Write the passphrase down. On paper. In a password manager. Somewhere you'll still have access to in five years. There is no backup credential, no recovery phrase, no email-reset. The passphrase is the only credential.",
      ]),
    ]));

    card.appendChild(step(7, "Done — drop a file in", [
      el("p", {}, [
        "After the wizard's Done step you'll see the folder UI. Drag-drop or click Upload to encrypt and store a file. Refresh the page → choose ",
        el("strong", {}, ["Unlock an existing folder"]),
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
          " bits of entropy.",
        ]),
        el("div", { class: "hint-card" }, [
          el("div", { class: "hint-card-title" }, ["How to clear 70 bits — pick one:"]),
          el("ul", {}, [
            el("li", {}, [
              el("strong", {}, ["Easiest: hit Generate below."]),
              " 7 random dictionary words, ~77 bits. You write them down.",
            ]),
            el("li", {}, [
              el("strong", {}, ["Memorable: 4+ unrelated common words."]),
              " e.g. ",
              el("code", {}, ["correct-horse-battery-staple"]),
              " (~50 bits). Add a 5th for ~65, a 6th for ~75 — pick at least 5.",
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
        el("div", { class: "row" }, [generateBtn]),
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
      lead = "Bucket connected. Credentials accepted. CORS configured. Passphrase set. Encrypted metadata written to the bucket.";
      const openBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, ["Open your folder"]);
      openBtn.addEventListener("click", () => {
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
        "↓ Download credentials file (recommended)",
      ]);
      dlCredsBtn.addEventListener("click", async () => {
        await downloadCredsFile();
      });
      const restartBtn = el("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Start a new onboarding"]);
      restartBtn.addEventListener("click", () => reset());
      actions = [openBtn, dlCredsBtn, restartBtn];
    }

    return makeFragment(
      el("section", { class: "stage stage-done" }, [
        el("h2", { id: "stage-title" }, [heading]),
        el("p", { class: "lead" }, [lead]),
        status === "done"
          ? el("div", { class: "hint-card" }, [
              el("div", { class: "hint-card-title" }, ["Make future unlocks one step"]),
              el("p", { class: "muted small", style: "margin: 0;" }, [
                "Download a small encrypted credentials file. With this file + your passphrase, you can unlock from any device in two clicks instead of typing five strings. The file is useless without your passphrase. Keep it like a backup credential — store it in 1Password, on a USB drive, wherever you keep secrets.",
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
    if (!data.bucket?.name || !data.bucket?.accountId) throw new Error("setup: bucket missing");
    if (!data.credentials?.accessKey || !data.credentials?.secretKey) {
      throw new Error("setup: credentials missing");
    }

    const region = "auto"; // R2 for v1.0 (per spec §"Endpoint URL builders")
    const bucketBase = bucket.endpoints.R2(
      data.bucket.accountId.trim().toLowerCase(),
      data.bucket.name.trim(),
    );

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
      accessKey: data.credentials.accessKey,
      secretKey: data.credentials.secretKey,
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
      accessKey: data.credentials.accessKey,
      secretKey: data.credentials.secretKey,
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
      bucket: { name: data.bucket.name, accountId: data.bucket.accountId },
      region,
      accessKey: data.credentials.accessKey,
      secretKey: data.credentials.secretKey,
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
      await stashSessionCreds({
        provider: "r2",
        bucket: { name: data.bucket.name, accountId: data.bucket.accountId, region },
        credentials: { accessKey: data.credentials.accessKey, secretKey: data.credentials.secretKey },
      }, passphrase);
    } catch (e) {
      // Refresh-resume is an optimisation; failure to persist shouldn't
      // block setup completion. Logged for diagnostics.
      console.warn("session-creds stash failed", e);
    }

    return session;
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
      const bytes = await credsfile.pack({
        provider: "r2",
        bucket: { name: data.bucket.name, accountId: data.bucket.accountId, region: "auto" },
        credentials: { accessKey: data.credentials.accessKey, secretKey: data.credentials.secretKey },
      }, passphrase);
      const blob = new Blob([bytes], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = credsfile.suggestedFilename(data.bucket.name);
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
        const crate = await Crate.open({ bucketConfig, credentials, passphrase });
        data.status = "ok";
        const session = {
          bucketBase: crate._bucketBase,
          bucket: { name: bucketConfig.name, accountId: bucketConfig.accountId },
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
            provider: "r2",
            bucket: { name: bucketConfig.name, accountId: bucketConfig.accountId, region: bucketConfig.region },
            credentials,
          }, passphrase);
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
          const creds = await credsfile.unpack(data.fileBytes, data.passphrase);
          await doUnlock(
            { accountId: creds.bucket.accountId, name: creds.bucket.name, region: creds.bucket.region || "auto" },
            { accessKey: creds.credentials.accessKey, secretKey: creds.credentials.secretKey },
            data.passphrase,
          );
        } catch (e) {
          data.status = "fail";
          data.error = e?.message?.includes("Wrong passphrase")
            ? "Wrong passphrase, or the credentials file is corrupt."
            : (e?.message ?? String(e));
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
      const manualLink = el("button", { type: "button", class: "btn-link" }, ["No file? Enter the 5 details manually."]);
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
      wrap.appendChild(field("Bucket name", data.bucketName, "text", (v) => data.bucketName = v, "off", false));
      wrap.appendChild(field("Cloudflare Account ID", data.accountId, "text", (v) => data.accountId = v, "off", true));
      wrap.appendChild(field("Access Key", data.accessKey, "text", (v) => data.accessKey = v, "off", true));
      wrap.appendChild(field("Secret Access Key", data.secretKey, "password", (v) => data.secretKey = v, "off", true));
      wrap.appendChild(field("Folder passphrase", data.passphrase, "password", (v) => data.passphrase = v, "current-password", false));

      const unlockBtn = el("button", { type: "button", class: "btn btn-primary btn-block" }, ["Unlock folder"]);
      unlockBtn.addEventListener("click", async () => {
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
      : "Pick the credentials file you downloaded at first setup, then enter your folder passphrase. The file is useless without the passphrase.";

    return makeFragment(
      el("section", { class: "stage stage-unlock" }, [
        el("h2", { id: "stage-title" }, [
          data.fileFromSession ? `Welcome back to ${data.fileHint || "your folder"}` : "Unlock an existing folder",
        ]),
        el("p", { class: "muted" }, [intro]),
        data.mode === "manual" ? renderManualMode() : renderFileMode(),
      ]),
    );
  }

  const STAGE_RENDERERS = {
    welcome: renderWelcome,
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
      // Refresh-resume: if sessionStorage has an encrypted creds blob
      // from earlier in this tab session, route straight to the unlock
      // screen with the file pre-loaded — the user only needs to type
      // their passphrase.
      tryRestoreFromSession();
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
    go,
    next,
    back,
    reset,
    getState: () => ({ stage: state.stage, route: state.route, data: { ...state.data } }),
    STAGES,
  };
}
