// SPDX-License-Identifier: AGPL-3.0-or-later
// Folder UI — renders the manifest as a file tree; supports upload,
// download, delete, rename, mkdir, move, export, and device pairing.
// Mounts into #folder-root and replaces the wizard once first-time setup
// completes.
//
// All file operations:
//   - encrypt (push) / decrypt (pull) via lib/crypto.js
//   - signed PUT/GET/DELETE via lib/bucket.js
//   - append corresponding signed event to lib/manifest.js + re-encrypt + PUT
//
// Session handle shape (from wizard's first-time setup OR a future "Unlock
// existing folder" path):
//   {
//     bucketBase: "https://{acct}.r2.cloudflarestorage.com/{name}/",
//     region: "auto",
//     accessKey, secretKey,
//     masterKey: Uint8Array(32),
//     manifest: Manifest,
//     salt: Uint8Array(16),
//   }

import { icon, fileIconName } from "./icons.js";
import { formDialog, promptDialog } from "./dialog.js";
import { writeKeySlots } from "./vault.js";
import { entropyToMnemonic } from "./recovery.js";
import { estimate, MIN_BITS, HARD_MIN_BITS } from "./entropy.js";
import { copyText } from "./clipboard.js";
import * as cryptoLib from "./crypto.js";
import * as bucket from "./bucket.js";
import {
  Manifest, MANIFEST_PATH,
  createEvent, updateEvent, deleteEvent, moveEvent, mkdirEvent,
} from "./manifest.js";
import { flushManifest as sharedFlushManifest } from "./manifest-flush.js";
import * as anchor from "./anchor.js";
import * as qr from "./qr.js";
import { planExport, runExport, formatBytes as fmtExportBytes } from "./export.js";
import * as credsfile from "./credsfile.js";

const OBJECTS_PREFIX = "objects/";

// Files larger than this are not previewed in-tab — decrypting + holding
// 50+ MB in memory is fine on desktop but punishing on phones. The user
// can still download.
const PREVIEW_SIZE_CAP = 50 * 1024 * 1024;

// Files at or above this trigger the FSA streaming-write download path
// on browsers that support showSaveFilePicker — avoids the Blob copy
// and writes the decrypted plaintext directly to a user-picked file.
const LARGE_FILE_THRESHOLD = 50 * 1024 * 1024;

// previewable returns true if we know how to render this file inline.
// Conservative — extension OR mime check, whichever resolves first.
function previewable(entry) {
  const mime = (entry.entry?.mime || "").toLowerCase();
  if (mime.startsWith("text/")) return true;
  if (mime.startsWith("image/")) return true;
  if (mime === "application/json" || mime === "application/xml" || mime === "application/x-yaml" || mime === "application/yaml") return true;
  // Fall back to extension if mime is missing or generic.
  const name = (entry.name || "").toLowerCase();
  const ext = name.includes(".") ? name.split(".").pop() : "";
  if (["txt","md","markdown","json","xml","yaml","yml","js","jsx","ts","tsx","css","html","htm","csv","tsv","log","ini","conf","sh","py","go","rs","rb","java","c","h","cpp","sql"].includes(ext)) return true;
  if (["png","jpg","jpeg","gif","webp","bmp","svg","avif","ico"].includes(ext)) return true;
  return false;
}

function isImageMime(entry) {
  const mime = (entry.entry?.mime || "").toLowerCase();
  if (mime.startsWith("image/")) return true;
  const ext = (entry.name || "").toLowerCase().split(".").pop();
  return ["png","jpg","jpeg","gif","webp","bmp","svg","avif","ico"].includes(ext);
}

// shortDate renders a manifest timestamp as a compact human-readable
// label. Same-year dates drop the year. Empty input -> empty output.
function shortDate(ts) {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return "";
    const now = new Date();
    const sameYear = d.getFullYear() === now.getFullYear();
    const opts = sameYear
      ? { month: "short", day: "numeric" }
      : { year: "numeric", month: "short", day: "numeric" };
    return new Intl.DateTimeFormat(undefined, opts).format(d);
  } catch {
    return "";
  }
}

// FolderUI — construct via `FolderUI.mount(root, session, opts)`.
//
// opts.onChange(evt): optional callback fired after every successful
// mutation (upload / download / delete / rename / mkdir). The entrypoint
// wires this to SyncClient's broadcast so other tabs see local edits
// within ~200ms instead of waiting 15s for the next poll.
export class FolderUI {
  constructor(root, session, opts = {}) {
    this.root = root;
    this.session = session;
    this.onChange = opts.onChange || null;
    this.onLock = opts.onLock || null;
    this.onPassphraseChange = opts.onPassphraseChange || null;
    // The shell (lib/shell.js) owns the sidebar + topbar search; FolderUI
    // drives it: active view, stats line, the ··· menu. Optional so the
    // class still mounts bare (tests, the devtools surface).
    this.shell = opts.shell || null;
    this.view = "all"; // "all" | "recent" | "photos" | "devices" | "backup"
    this.currentDir = "/";
    this.busy = false;
    this.message = null;
    this.searchQuery = ""; // basename substring filter; empty = no filter
    // Multi-select: paths of selected file rows (folders are not
    // selectable — bulk ops are per-object). Cleared on navigation.
    this.selected = new Set();
    this._lastPick = null; // path of the last checkbox click, for shift-ranges
  }

  static mount(root, session, opts = {}) {
    const ui = new FolderUI(root, session, opts);
    ui._wireShell();
    ui.render();
    return ui;
  }

  _wireShell() {
    const shell = this.shell;
    if (!shell) return;
    shell.onNavigate((view) => this.setView(view));
    shell.onSearch((q) => {
      this.searchQuery = q;
      // Searching from a non-list view jumps to All files so the results
      // have somewhere to land.
      if (!["all", "recent", "photos"].includes(this.view)) {
        this.view = "all";
        this.render();
        return;
      }
      const treeRoot = this.root.querySelector(".folder-tree");
      if (treeRoot) treeRoot.replaceWith(this.buildTree());
      else this.render();
    });
    shell.setMenu([
      { label: "Refresh from storage", icon: "refresh", onClick: () => this.handleRefresh() },
      { label: "Lock", icon: "lock", danger: true, onClick: () => this.handleLock() },
    ]);
  }

  setView(view) {
    if (!["all", "recent", "photos", "devices", "backup"].includes(view)) view = "all";
    this.view = view;
    this.searchQuery = "";
    this.clearSelection(false);
    if (this.shell) this.shell.setSearch("");
    this.render();
  }

  _fireChange(evt) {
    if (this.onChange) {
      try { this.onChange(evt); } catch (e) { console.error("folder onChange threw", e); }
    }
  }

  // --- top-level render --------------------------------------------------

  render() {
    // A banner's auto-clear timer or a late sync tick can land after Lock
    // has torn the session down; there is nothing to draw then.
    if (!this.session?.manifest) return;
    while (this.root.firstChild) this.root.removeChild(this.root.firstChild);
    this.root.appendChild(this.buildHeader());
    if (this.view === "devices") this.root.appendChild(this.buildDevicesView());
    else if (this.view === "backup") this.root.appendChild(this.buildBackupView());
    else {
      this.root.appendChild(this.buildTree());
      if (this.view === "all") {
        this.root.appendChild(h("p", { class: "folder-dropzone-hint" }, [
          "Drop files anywhere here — they're encrypted before they leave this tab.",
        ]));
      }
    }
    if (this.message) this.root.appendChild(this.buildBanner());
    this._syncShell();
    // One-time wiring of page-level drag-and-drop. Listeners attach to
    // this.root which persists across re-renders.
    this._setupDragDrop();
  }

  // _syncShell pushes the derived state the sidebar shows: active view,
  // photo count, the storage line in the footer.
  _syncShell() {
    if (!this.shell) return;
    const stats = this.computeStats();
    this.shell.setActive(this.view);
    this.shell.setCounts({ photos: stats.photoCount });
    this.shell.setStats(stats.fileCount === 0
      ? "Nothing stored yet"
      : `${formatBytes(stats.totalBytes)} in ${stats.fileCount} ${stats.fileCount === 1 ? "file" : "files"} · encrypted`);
  }

  static VIEW_TITLES = { all: "All files", recent: "Recent", photos: "Photos", devices: "Devices", backup: "Backup" };

  buildHeader() {
    const wrap = h("header", { class: "folder-header" });
    if (this.selected.size > 0) {
      wrap.appendChild(this.buildSelectionBar());
      return wrap;
    }
    const titleRow = h("div", { class: "folder-title-row" }, [
      h("h1", {}, [FolderUI.VIEW_TITLES[this.view] || "All files"]),
    ]);

    if (this.view === "all") {
      // Toolbar: the two things you do in a folder. Everything else lives
      // in the sidebar (Devices, Backup) or the ··· menu (Refresh, Lock).
      const fileInput = h("input", { type: "file", id: "folder-upload-input", multiple: "multiple", style: "display:none" });
      fileInput.addEventListener("change", (e) => this.handleUploadFiles(e.target.files));
      const mkdirBtn = h("button", { type: "button", class: "btn btn-secondary" }, [icon("folder-plus", { size: 16 }), "New folder"]);
      mkdirBtn.addEventListener("click", () => this.handleMkdir());
      const uploadBtn = h("button", { type: "button", class: "btn btn-primary folder-upload-btn" }, [icon("upload", { size: 16 }), "Upload"]);
      uploadBtn.addEventListener("click", () => fileInput.click());
      titleRow.appendChild(h("div", { class: "folder-toolbar" }, [mkdirBtn, uploadBtn, fileInput]));
    }
    wrap.appendChild(titleRow);

    // Path breadcrumb — only below the root, only in All files.
    if (this.view === "all" && this.currentDir !== "/") {
      const crumb = h("nav", { class: "folder-breadcrumb", "aria-label": "Current folder" });
      const segs = this.currentDir.replace(/\/$/, "").split("/").filter((s) => s.length > 0);
      crumb.appendChild(this.crumbLink("/", "All files", false));
      let acc = "";
      segs.forEach((s, i) => {
        acc += "/" + s;
        crumb.appendChild(h("span", { class: "crumb-sep", "aria-hidden": "true" }, ["›"]));
        crumb.appendChild(this.crumbLink(acc + "/", s, i === segs.length - 1));
      });
      wrap.appendChild(crumb);
    }
    return wrap;
  }

  // --- multi-select ----------------------------------------------------

  clearSelection(rerender = true) {
    if (this.selected.size === 0) return;
    this.selected.clear();
    this._lastPick = null;
    if (rerender) this.render();
  }

  // selectedEntries resolves the selected paths against the current list
  // (a path that has vanished — synced delete — simply drops out).
  selectedEntries() {
    const entries = this.view === "all" ? this.entriesInCurrentDir() : this.entriesForView(this.view);
    return entries.filter((e) => !e.isDir && this.selected.has(e.path));
  }

  // togglePick handles a checkbox click: plain toggles one row; shift
  // selects the range from the last pick, in the order rows are shown.
  togglePick(entry, shiftKey) {
    const visible = this.visibleRows().filter((e) => !e.isDir).map((e) => e.path);
    if (shiftKey && this._lastPick && visible.includes(this._lastPick)) {
      const a = visible.indexOf(this._lastPick), b = visible.indexOf(entry.path);
      const [lo, hi] = a < b ? [a, b] : [b, a];
      for (let i = lo; i <= hi; i++) this.selected.add(visible[i]);
    } else if (this.selected.has(entry.path)) {
      this.selected.delete(entry.path);
    } else {
      this.selected.add(entry.path);
    }
    this._lastPick = entry.path;
    this.render();
  }

  // visibleRows is the list buildTree draws, in its order.
  visibleRows() {
    let entries = this.view === "all" ? this.entriesInCurrentDir() : this.entriesForView(this.view);
    if (this.searchQuery.trim()) {
      const q = this.searchQuery.trim().toLowerCase();
      entries = entries.filter((e) => e.name.toLowerCase().includes(q));
    }
    if (this.view === "all") {
      const folders = entries.filter((e) => e.isDir).sort((a, b) => a.name.localeCompare(b.name));
      const files = entries.filter((e) => !e.isDir).sort((a, b) => a.name.localeCompare(b.name));
      entries = folders.concat(files);
    }
    return entries;
  }

  buildSelectionBar() {
    const picked = this.selectedEntries();
    const n = picked.length;
    const bytes = picked.reduce((t, e) => t + (e.entry?.size || 0), 0);
    const clearBtn = h("button", { type: "button", class: "btn-icon", title: "Clear selection", "aria-label": "Clear selection" }, [icon("x", { size: 16 })]);
    clearBtn.addEventListener("click", () => this.clearSelection());
    const allBtn = h("button", { type: "button", class: "btn-link" }, ["Select all"]);
    allBtn.addEventListener("click", () => {
      for (const e of this.visibleRows()) if (!e.isDir) this.selected.add(e.path);
      this.render();
    });
    const dlBtn = h("button", { type: "button", class: "btn btn-secondary" }, [icon("download", { size: 16 }), "Download"]);
    dlBtn.addEventListener("click", () => this.handleBulkDownload());
    const mvBtn = h("button", { type: "button", class: "btn btn-secondary" }, [icon("folder", { size: 16 }), "Move to…"]);
    mvBtn.addEventListener("click", () => this.handleBulkMove());
    const delBtn = h("button", { type: "button", class: "btn btn-danger-secondary" }, [icon("trash", { size: 16 }), "Delete"]);
    delBtn.addEventListener("click", () => this.handleBulkDelete());
    return h("div", { class: "folder-title-row selection-bar", role: "toolbar", "aria-label": "Selection" }, [
      h("div", { class: "selection-count" }, [
        clearBtn,
        h("span", {}, [`${n} selected`, h("span", { class: "muted" }, [` · ${formatBytes(bytes)}`])]),
        allBtn,
      ]),
      h("div", { class: "folder-toolbar" }, [dlBtn, mvBtn, delBtn]),
    ]);
  }

  // handleBulkDownload zips the selection through the export machinery
  // (one file at a time; streams to disk when the browser can).
  async handleBulkDownload() {
    const picked = this.selectedEntries();
    if (picked.length === 0) return;
    if (picked.length === 1) return this.handleDownload(picked[0]);
    if (this.busy) { this.setMessage("error", "Another operation is in flight"); return; }
    this.busy = true;
    try {
      const plan = planExport(this.session, { paths: picked.map((e) => e.path) });
      if (plan.tier === "too-large") throw new Error("That selection is too large to zip in the browser — pick fewer files, or use Backup → Export everything to stream to disk.");
      const stamp = new Date().toISOString().slice(0, 10);
      this.setMessage("info", `Preparing ${picked.length} files…`);
      await runExport(this.session, plan, {
        suggestedName: `crate-selection-${stamp}.zip`,
        onProgress: (p) => { if (p.phase === "file") this._progress(`${p.fileIndex} of ${p.fileCount} files`); },
      });
      this.setMessage("info", `Downloaded ${picked.length} files as a zip.`);
    } catch (e) {
      if (e?.name === "AbortError") { this.message = null; this.render(); return; }
      console.error(e);
      this.setMessage("error", `Download failed: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  // _progress updates the banner text without a full re-render.
  _progress(text) {
    const b = this.root.querySelector(".banner");
    if (b) b.textContent = text; else this.setMessage("info", text);
  }

  // handleBulkMove appends one move event per selected file into a folder
  // chosen from the tree (or a new one, typed).
  async handleBulkMove() {
    const picked = this.selectedEntries();
    if (picked.length === 0) return;
    if (this.busy) { this.setMessage("error", "Another operation is in flight"); return; }
    const tree = this.session.manifest.materialise();
    const dirs = new Set(["/"]);
    for (const [path, entry] of tree.entries()) {
      const p = entry.isDir ? (path.endsWith("/") ? path : path + "/") : path.slice(0, path.lastIndexOf("/") + 1);
      // every ancestor of every path is a destination
      const segs = p.split("/").filter(Boolean);
      let acc = "/";
      for (const sgm of segs) { acc += sgm + "/"; dirs.add(acc); }
    }
    const options = [...dirs].sort();
    const answer = await formDialog({
      title: `Move ${picked.length} ${picked.length === 1 ? "file" : "files"}`,
      description: "Type the destination folder. Existing folders are listed; a new name creates the folder.",
      fields: [{ key: "dest", label: "Destination", value: this.currentDir, autofocus: true, help: options.map((d) => (d === "/" ? "All files" : d)).join("  ·  ") }],
      confirmLabel: "Move",
      validate: (v) => {
        const d = normalizeDir(v.dest);
        if (d === null) return "Enter a folder path, like /Work/2026.";
        const clash = picked.find((e) => tree.has(d + e.name) && d + e.name !== e.path);
        if (clash) return `“${clash.name}” already exists in ${d === "/" ? "All files" : d}.`;
        return null;
      },
    });
    if (!answer) return;
    const dest = normalizeDir(answer.dest);
    this.busy = true;
    try {
      let moved = 0;
      if (dest !== "/" && !tree.has(dest)) {
        await this.session.manifest.append(mkdirEvent({ path: dest }), this.session.masterKey);
      }
      for (const e of picked) {
        const newPath = dest + e.name;
        if (newPath === e.path || !e.entry?.uuid) continue;
        await this.session.manifest.append(moveEvent({ uuid: e.entry.uuid, newPath }), this.session.masterKey);
        moved += 1;
      }
      await this.flushManifest();
      this.clearSelection(false);
      this.setMessage("info", `Moved ${moved} ${moved === 1 ? "file" : "files"} to ${dest === "/" ? "All files" : dest}`);
      this._fireChange({ op: "move", source: "local" });
    } catch (e) {
      console.error(e);
      this.setMessage("error", `Move failed: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  // handleBulkDelete confirms once for the whole selection, then deletes
  // each object and appends its delete event; a single flush at the end.
  async handleBulkDelete() {
    const picked = this.selectedEntries();
    if (picked.length === 0) return;
    if (picked.length === 1) return this.handleDelete(picked[0]);
    if (this.busy) { this.setMessage("error", "Another operation is in flight"); return; }
    const modalRoot = document.createElement("div");
    modalRoot.className = "delete-modal";
    document.body.appendChild(modalRoot);
    let ok = false;
    try {
      ok = await renderDeleteConfirmModal(modalRoot, {
        isDir: false,
        count: picked.length,
        name: `${picked.length} files`,
        path: picked.slice(0, 6).map((e) => e.name).join(", ") + (picked.length > 6 ? `, … (${picked.length - 6} more)` : ""),
      });
    } finally {
      document.body.removeChild(modalRoot);
    }
    if (!ok) return;
    this.busy = true;
    let done = 0;
    try {
      for (const e of picked) {
        if (!e.entry?.uuid) continue;
        await this.deleteObject(e.entry.uuid);
        await this.session.manifest.append(deleteEvent({ uuid: e.entry.uuid }), this.session.masterKey);
        done += 1;
      }
      await this.flushManifest();
      this.clearSelection(false);
      this.setMessage("info", `Deleted ${done} files`);
      this._fireChange({ op: "delete", source: "local" });
    } catch (e) {
      console.error(e);
      // Keep what was already appended: flush so successful deletes are recorded.
      try { await this.flushManifest(); } catch {}
      this.setMessage("error", `Delete stopped after ${done}: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  // deleteObject removes objects/{uuid} from the bucket. 404 counts as gone.
  async deleteObject(uuid) {
    const del = await bucket.signedDelete({
      url: this.session.bucketBase + OBJECTS_PREFIX + uuid,
      region: this.session.region,
      accessKey: this.session.accessKey,
      secretKey: this.session.secretKey,
    });
    if (!del.ok) throw new Error(`DELETE object failed: ${del.status} ${del.message}`);
  }

  // Devices: the daemon story. One card, one action (the existing pair
  // modal). Photos of the daemon's ~/crate/ folder would be theatre; the
  // copy says what it does.
  buildDevicesView() {
    const pairBtn = h("button", { type: "button", class: "btn btn-secondary" }, [icon("devices", { size: 16 }), "Pair an agent"]);
    pairBtn.addEventListener("click", () => this.handlePair());
    return h("div", { class: "view-cards" }, [
      h("div", { class: "view-card" }, [
        h("div", { class: "view-card-body" }, [
          h("h2", {}, ["This browser"]),
          h("p", {}, ["Open this same link on any device, pick your credentials file, enter your passphrase — the folder is there. Nothing to install."]),
        ]),
      ]),
      h("div", { class: "view-card" }, [
        h("div", { class: "view-card-body" }, [
          h("h2", {}, ["A laptop folder that stays in sync"]),
          h("p", {}, ["crate-agent is a small program for macOS and Linux that mirrors this folder to ~/crate/ on disk as ordinary files, and uploads what you drop there. Pair it once."]),
        ]),
        pairBtn,
      ]),
    ]);
  }

  // Backup: the two things you keep (credentials file + passphrase) and
  // the one-shot copy of everything.
  buildBackupView() {
    const credsBtn = h("button", { type: "button", class: "btn btn-secondary" }, [icon("key", { size: 16 }), "Download credentials file"]);
    if (!this.session.passphrase) credsBtn.disabled = true;
    credsBtn.addEventListener("click", () => this.handleDownloadCreds());
    const exportBtn = h("button", { type: "button", class: "btn btn-secondary" }, [icon("download", { size: 16 }), "Export everything"]);
    exportBtn.addEventListener("click", () => this.handleExport());

    // Recovery phrase: set up once, then it just is. Setting it on a v1.0
    // folder also moves the key file to v1.1 (see vault.js migrateV10).
    const hasRecovery = !!this.session.hasRecovery;
    const recBtn = h("button", { type: "button", class: "btn btn-secondary" }, [icon("shield", { size: 16 }), hasRecovery ? "Replace recovery phrase" : "Set up a recovery phrase"]);
    if (!this.session.crateJson || !this.session.passphrase) recBtn.disabled = true;
    recBtn.addEventListener("click", () => this.handleEnableRecovery());

    const passBtn = h("button", { type: "button", class: "btn btn-secondary" }, [icon("lock", { size: 16 }), "Change passphrase"]);
    if (!this.session.crateJson || !this.session.passphrase) passBtn.disabled = true;
    passBtn.addEventListener("click", () => this.handleChangePassphrase());

    return h("div", { class: "view-cards" }, [
      h("div", { class: "view-card" }, [
        h("div", { class: "view-card-body" }, [
          h("h2", {}, ["Recovery phrase"]),
          h("p", {}, [hasRecovery
            ? "Set up. If you ever lose your passphrase: open this link, choose Already set up → Lost your passphrase, enter your connection details and the 24 words, and pick a new passphrase."
            : "Not set up. Twenty-four words on paper that open this folder if you ever lose your passphrase. Takes a minute; nothing in the folder is re-encrypted."]),
        ]),
        recBtn,
      ]),
      h("div", { class: "view-card" }, [
        h("div", { class: "view-card-body" }, [
          h("h2", {}, ["Passphrase"]),
          h("p", {}, ["Nobody can reset it — not us, not your storage provider. Changing it here re-seals the key for every device; the files stay as they are. Devices that have the folder open keep working until they lock."]),
        ]),
        passBtn,
      ]),
      h("div", { class: "view-card" }, [
        h("div", { class: "view-card-body" }, [
          h("h2", {}, ["Credentials file"]),
          h("p", {}, ["Your connection details, encrypted under your passphrase. Together with the passphrase it opens this folder on any device; alone it is useless. Keep it with a password manager or on a USB stick."]),
        ]),
        credsBtn,
      ]),
      h("div", { class: "view-card" }, [
        h("div", { class: "view-card-body" }, [
          h("h2", {}, ["A plain copy of your files"]),
          h("p", {}, ["Decrypts everything in this tab and saves it as one zip (or streams straight to a folder on disk for large collections). Your storage holds the only copy until you make another."]),
        ]),
        exportBtn,
      ]),
    ]);
  }

  // _writeKeySlots applies a credential change to .crate/crate.json with
  // If-Match on the copy this session read, then adopts the new doc.
  async _writeKeySlots({ passphrase = null, recoveryEntropy = null } = {}) {
    const s = this.session;
    const r = await writeKeySlots({
      bucketBase: s.bucketBase, region: s.region, accessKey: s.accessKey, secretKey: s.secretKey,
      crateJson: s.crateJson, crateJsonETag: s.crateJsonETag || null, masterKey: s.masterKey,
      // A v1.0 folder needs the current passphrase to gain its first slot.
      passphrase: passphrase || (s.crateJson?.version === "1.1" ? null : s.passphrase),
      recoveryEntropy,
    });
    s.crateJson = r.crateJson;
    s.crateJsonETag = r.crateJsonETag;
    s.salt = r.crateJson.passphraseWrap.saltBytes;
    s.hasRecovery = !!r.crateJson.recoveryWrap;
    return r;
  }

  // handleEnableRecovery shows 24 fresh words, asks for three back, then
  // writes the recovery slot. Replacing an existing phrase invalidates
  // the old one — said in the dialog.
  async handleEnableRecovery() {
    if (this.busy) return;
    const s = this.session;
    const entropy = cryptoLib.randomBytes(32);
    const words = await entropyToMnemonic(entropy);
    const legacy = s.crateJson?.version !== "1.1";
    const confirmed = await renderRecoveryModal({ words, replacing: !!s.hasRecovery, legacy });
    if (!confirmed) { cryptoLib.zero(entropy); return; }
    this.busy = true;
    try {
      await this._writeKeySlots({ recoveryEntropy: entropy });
      this.setMessage("info", s.hasRecovery ? "Recovery phrase saved. Keep the paper." : "Recovery phrase saved.");
    } catch (e) {
      console.error(e);
      this.setMessage("error", `Couldn't save the recovery phrase: ${e.message ?? e}`);
    } finally {
      cryptoLib.zero(entropy);
      this.busy = false;
    }
  }

  // handleChangePassphrase re-wraps the key under a new passphrase and
  // tells the entrypoint so the refresh-resume stash follows.
  async handleChangePassphrase() {
    if (this.busy) return;
    const s = this.session;
    const answer = await formDialog({
      title: "Change passphrase",
      description: s.crateJson?.version === "1.1"
        ? "Pick a new passphrase for this folder. Your recovery phrase, if set, keeps working."
        : "Pick a new passphrase. This also moves the folder's key file to the current format; a paired crate-agent older than v1.2 will need updating.",
      fields: [
        { key: "next", label: "New passphrase", type: "password", autofocus: true, help: `At least ${HARD_MIN_BITS} bits; ${MIN_BITS}+ recommended — five unrelated words, or twelve random mixed characters.` },
        { key: "again", label: "Type it again", type: "password" },
      ],
      confirmLabel: "Change passphrase",
      validate: (v) => {
        const next = v.next;
        if (!next) return "Enter a new passphrase.";
        if (next === s.passphrase) return "That is the current passphrase.";
        const r = estimate(next);
        if (r.bits < HARD_MIN_BITS) return `Too weak (${r.bits} bits) — under ${HARD_MIN_BITS} bits is guessable in minutes.`;
        if (v.again !== next) return v.again ? "The two entries don't match." : `Type it again to confirm (${r.bits} bits${r.bits < MIN_BITS ? " — weaker than recommended" : ""}).`;
        return null;
      },
    });
    if (!answer) return;
    this.busy = true;
    try {
      await this._writeKeySlots({ passphrase: answer.next });
      s.passphrase = answer.next;
      if (typeof this.onPassphraseChange === "function") {
        try { await this.onPassphraseChange(answer.next); } catch (e) { console.warn("passphrase stash refresh failed", e); }
      }
      this.setMessage("info", "Passphrase changed. Download a fresh credentials file if you keep one.");
    } catch (e) {
      console.error(e);
      this.setMessage("error", `Couldn't change the passphrase: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  // Attaches drag-enter / drag-over / drag-leave / drop listeners on
  // this.root exactly once. Files dropped anywhere in the folder area
  // trigger an upload; the overlay class adds a visible drop affordance.
  _setupDragDrop() {
    if (this._dragDropWired) return;
    this._dragDropWired = true;
    // Escape clears a selection unless a dialog is up (dialogs own Escape).
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape" || this.selected.size === 0) return;
      if (document.querySelector(".pair-overlay, .help-overlay")) return;
      this.clearSelection();
    });
    let depth = 0;
    this.root.addEventListener("dragenter", (e) => {
      // Only count file drags, not text/link drags.
      if (!e.dataTransfer || !Array.from(e.dataTransfer.types || []).includes("Files")) return;
      e.preventDefault();
      depth++;
      this.root.classList.add("folder-drop-active");
    });
    this.root.addEventListener("dragover", (e) => {
      if (!Array.from(e.dataTransfer?.types || []).includes("Files")) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "copy";
    });
    this.root.addEventListener("dragleave", () => {
      depth = Math.max(0, depth - 1);
      if (depth === 0) this.root.classList.remove("folder-drop-active");
    });
    this.root.addEventListener("drop", (e) => {
      if (!e.dataTransfer?.files?.length) return;
      e.preventDefault();
      depth = 0;
      this.root.classList.remove("folder-drop-active");
      // Drops land in the current folder; from Recent/Photos that means
      // the root, which is where All files opens anyway.
      if (this.view !== "all") { this.view = "all"; this.currentDir = "/"; }
      this.handleUploadFiles(e.dataTransfer.files);
    });
  }

  // computeStats returns { fileCount, totalBytes, photoCount } across the
  // whole Crate (not just the current dir). Used by the sidebar footer.
  computeStats() {
    const tree = this.session.manifest.materialise();
    let fileCount = 0;
    let totalBytes = 0;
    let photoCount = 0;
    for (const [path, entry] of tree.entries()) {
      if (entry.isDir) continue;
      fileCount += 1;
      totalBytes += typeof entry.size === "number" ? entry.size : 0;
      if (isImageMime({ name: basename(path), entry })) photoCount += 1;
    }
    return { fileCount, totalBytes, photoCount };
  }

  crumbLink(path, label, isCurrent) {
    const cls = isCurrent ? "folder-crumb folder-crumb-current" : "folder-crumb";
    const a = h("a", { href: "#", class: cls, "aria-current": isCurrent ? "page" : false }, [label]);
    a.addEventListener("click", (e) => {
      e.preventDefault();
      this.currentDir = path;
      this.searchQuery = ""; // clear filter on navigation
      this.clearSelection(false);
      if (this.shell) this.shell.setSearch("");
      this.render();
    });
    return a;
  }

  buildTree() {
    const wrap = h("ul", { class: "folder-tree" + (this.selected.size ? " has-selection" : ""), "aria-label": FolderUI.VIEW_TITLES[this.view] });
    const entries = this.visibleRows();
    if (entries.length === 0) {
      wrap.appendChild(this.buildEmptyState());
      return wrap;
    }
    wrap.appendChild(h("li", { class: "folder-tree-head", "aria-hidden": "true" }, [
      h("span", {}, [""]),
      h("span", {}, ["Name"]),
      h("span", { class: "col-date" }, ["Modified"]),
      h("span", { class: "col-size" }, ["Size"]),
    ]));
    for (const e of entries) wrap.appendChild(this.buildTreeRow(e));
    return wrap;
  }

  buildEmptyState() {
    if (this.searchQuery.trim()) {
      return h("li", { class: "folder-empty muted" }, [
        `No matches for “${this.searchQuery.trim()}” here.`,
      ]);
    }
    if (this.view === "recent") {
      return h("li", { class: "folder-empty" }, [
        h("div", { class: "empty-icon", "aria-hidden": "true" }, [icon("clock", { size: 28 })]),
        h("p", { class: "empty-title" }, ["Nothing recent yet."]),
        h("p", { class: "muted small" }, ["Files you add or change show up here, newest first."]),
      ]);
    }
    if (this.view === "photos") {
      return h("li", { class: "folder-empty" }, [
        h("div", { class: "empty-icon", "aria-hidden": "true" }, [icon("image", { size: 28 })]),
        h("p", { class: "empty-title" }, ["No photos yet."]),
        h("p", { class: "muted small" }, ["Images from anywhere in your folder collect here."]),
      ]);
    }
    return h("li", { class: "folder-empty" }, [
      h("div", { class: "empty-icon", "aria-hidden": "true" }, [icon("upload", { size: 28 })]),
      h("p", { class: "empty-title" }, ["This folder is empty."]),
      h("p", { class: "muted small" }, [
        "Drop files here, or click ",
        h("strong", {}, ["Upload"]),
        ". Anything you add is encrypted before it leaves this tab.",
      ]),
    ]);
  }

  // entriesForView projects the whole tree into a flat list for the
  // Recent and Photos views. Each entry carries `sub` — the parent folder
  // — so a row says where the file lives.
  entriesForView(view) {
    const tree = this.session.manifest.materialise();
    const out = [];
    for (const [path, entry] of tree.entries()) {
      if (entry.isDir) continue;
      const name = basename(path);
      const item = { name, isDir: false, entry, path, sub: parentLabel(path) };
      if (view === "photos" && !isImageMime(item)) continue;
      out.push(item);
    }
    out.sort((a, b) => (b.entry?.ts || 0) - (a.entry?.ts || 0));
    return view === "recent" ? out.slice(0, 50) : out;
  }

  // entriesInCurrentDir returns the immediate children of this.currentDir.
  // Materialises the manifest, groups entries by the directory just below
  // this.currentDir; deeper paths surface as folder placeholders even if
  // no explicit mkdir event exists for that folder.
  entriesInCurrentDir() {
    const tree = this.session.manifest.materialise(); // Map<path, entry>
    const out = new Map(); // name → { name, isDir, entry?, path }
    const prefix = this.currentDir; // always ends with "/" except "/"

    // Walk every materialised entry and project it into this dir.
    for (const [path, entry] of tree.entries()) {
      if (!path.startsWith(prefix === "/" ? "/" : prefix)) continue;
      const rest = path.slice(prefix.length).replace(/^\//, "");
      if (rest.length === 0) continue; // entry IS the current dir
      const slash = rest.indexOf("/");
      if (slash === -1) {
        // Immediate child file (or virtual dir if entry.isDir).
        out.set(rest, {
          name: rest, isDir: !!entry.isDir, entry, path,
        });
      } else {
        // Deeper — surface as a virtual folder if not already.
        const dirName = rest.slice(0, slash);
        if (!out.has(dirName)) {
          out.set(dirName, {
            name: dirName, isDir: true,
            path: (prefix === "/" ? "/" : prefix) + dirName + "/",
            virtual: true,
          });
        }
      }
    }
    return [...out.values()];
  }

  buildTreeRow(entry) {
    const row = h("li", {
      class: entry.isDir ? "folder-row folder-row-dir" : "folder-row folder-row-file",
      tabindex: "0",
      role: entry.isDir ? "button" : "listitem",
    });

    const isSel = this.selected.has(entry.path);
    if (isSel) row.classList.add("selected");
    if (entry.isDir) {
      row.appendChild(h("span", { class: "folder-icon", "aria-hidden": "true" }, [icon(fileIconName(entry), { size: 16 })]));
    } else {
      // Icon by default; a checkbox on hover, when selected, or while any
      // selection exists. Shift-click extends the range.
      const check = h("input", { type: "checkbox", class: "folder-check", "aria-label": `Select ${entry.name}` });
      check.checked = isSel;
      check.addEventListener("click", (e) => { e.stopPropagation(); this.togglePick(entry, e.shiftKey); });
      const cell = h("span", { class: "folder-icon folder-icon-pick" }, [icon(fileIconName(entry), { size: 16 }), check]);
      // The whole 30px cell is the target; a click on the icon toggles too.
      cell.addEventListener("click", (e) => { if (e.target !== check) { e.stopPropagation(); this.togglePick(entry, e.shiftKey); } });
      row.appendChild(cell);
    }

    // Main column: name, plus the parent folder in the flat views.
    const main = h("div", { class: "folder-main" });
    main.appendChild(h("div", { class: "folder-name" }, [entry.name]));
    if (entry.sub) main.appendChild(h("div", { class: "folder-sub" }, [entry.sub]));
    row.appendChild(main);

    // Modified + size; swapped for the action buttons on hover/focus.
    const ts = entry.entry?.ts;
    row.appendChild(h("span", { class: "folder-date folder-meta" }, [ts ? shortDate(ts) : ""]));
    row.appendChild(h("span", { class: "folder-size folder-meta" }, [
      entry.isDir ? "—" : formatBytes(entry.entry?.size ?? 0),
    ]));

    const actions = h("span", { class: "folder-row-actions" });
    const action = (glyph, title, onClick, extra = "") => {
      const b = h("button", { type: "button", class: "btn-sm" + extra, title, "aria-label": title }, [icon(glyph, { size: 16 })]);
      b.addEventListener("click", (e) => { e.stopPropagation(); onClick(); });
      return b;
    };
    if (!entry.isDir && previewable(entry)) actions.appendChild(action("eye", "Preview", () => this.handlePreview(entry)));
    if (!entry.isDir) actions.appendChild(action("download", "Download", () => this.handleDownload(entry)));
    actions.appendChild(action("pencil", "Rename", () => this.handleRename(entry)));
    if (!entry.isDir) actions.appendChild(action("history", "View history", () => this.handleHistory(entry)));
    actions.appendChild(action("trash", "Delete", () => this.handleDelete(entry), " btn-danger"));
    row.appendChild(actions);

    // Row-level click: navigate into folders / open preview for previewable
    // files. Clicks on actions stop propagation above, so those still
    // fire their own handlers cleanly.
    const activate = () => {
      if (entry.isDir) {
        this.currentDir = entry.path.endsWith("/") ? entry.path : entry.path + "/";
        this.searchQuery = "";
        this.clearSelection(false);
        if (this.shell) this.shell.setSearch("");
        this.render();
      } else if (previewable(entry)) {
        this.handlePreview(entry);
      } else {
        // Non-previewable file row: default to download (most common
        // user intent when clicking a non-folder).
        this.handleDownload(entry);
      }
    };
    row.addEventListener("click", activate);
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        activate();
      }
    });

    return row;
  }

  buildBanner() {
    const cls = this.message.kind === "error" ? "banner banner-error" : "banner";
    const node = h("div", { class: cls, role: "status" }, [this.message.text]);
    return node;
  }

  setMessage(kind, text) {
    this.message = { kind, text };
    this.render();
    // Auto-clear non-errors after 4s.
    if (kind !== "error") {
      setTimeout(() => {
        if (this.message?.text === text) {
          this.message = null;
          this.render();
        }
      }, 4000);
    }
  }

  // --- operations --------------------------------------------------------

  async handleUploadFiles(fileList) {
    if (!fileList || fileList.length === 0) return;
    if (this.busy) { this.setMessage("error", "Another operation is in flight"); return; }
    this.busy = true;
    // uploadOne PUTs the object THEN appends its create event in memory.
    // We flush once at the end for batch efficiency — but if a file fails
    // mid-batch, the already-PUT objects + their appended events MUST still
    // be flushed, or the ciphertext is orphaned in the bucket and the events
    // are lost on the next reload/lock. So: catch the upload error, flush
    // whatever succeeded, THEN surface the failure.
    let uploaded = 0;
    let uploadError = null;
    try {
      for (const file of fileList) {
        await this.uploadOne(file);
        uploaded++;
      }
    } catch (e) {
      console.error(e);
      uploadError = e;
    }
    try {
      if (uploaded > 0) {
        await this.flushManifest();
        this._fireChange({ op: "create", source: "local" });
      }
    } catch (e) {
      console.error(e);
      uploadError = uploadError || e;
    }
    this.busy = false;
    if (uploadError) {
      this.setMessage("error", `Upload failed after ${uploaded} file(s): ${uploadError.message ?? uploadError}`);
    } else {
      this.setMessage("info", `Uploaded ${uploaded} file(s)`);
    }
  }

  async uploadOne(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const uuid = cryptoLib.newULID();
    const dataKey = cryptoLib.randomDataKey();
    const wrapped = await cryptoLib.wrapDataKey(this.session.masterKey, dataKey, uuid);
    // Chunked v2 body — framing documented in lib/crypto.js::sealObject.
    const sealed = await cryptoLib.sealObject(dataKey, bytes, uuid);

    const objUrl = this.session.bucketBase + OBJECTS_PREFIX + uuid;
    const put = await bucket.signedPut({
      url: objUrl,
      body: sealed.body,
      contentType: "application/octet-stream",
      region: this.session.region,
      accessKey: this.session.accessKey,
      secretKey: this.session.secretKey,
    });
    if (!put.ok) {
      throw new Error(`PUT object ${uuid} failed: ${put.status} ${put.message}`);
    }

    cryptoLib.zero(dataKey);

    const path = joinPath(this.currentDir, file.name);
    await this.session.manifest.append(
      createEvent({
        uuid, path, size: file.size, mime: file.type || "application/octet-stream",
        dataKeyIv: wrapped.iv, dataKeyCt: wrapped.ciphertext,
        contentIv: sealed.contentIv, chunkSize: sealed.chunkSize,
      }),
      this.session.masterKey,
    );
  }

  async handleDownload(entry) {
    if (this.busy) { this.setMessage("error", "Another operation is in flight"); return; }
    if (!entry.entry?.uuid) { this.setMessage("error", "Missing uuid"); return; }

    // Files >= LARGE_FILE_THRESHOLD on browsers with showSaveFilePicker
    // use the FSA streaming-write path: user picks a destination
    // upfront, we write plaintext straight to disk without
    // materialising a Blob copy. Memory peak drops from ~3× to ~2×.
    //
    // True streaming (chunked AEAD) would need a wire format change
    // and isn't v1 — see CHANGELOG.md for the deferred entry. The
    // 2× cap means mobile (no FSA + tighter memory) still can't
    // download multi-GB files; we tell the user to use the daemon.
    const size = entry.entry?.size ?? 0;
    const useFsa = size >= LARGE_FILE_THRESHOLD && typeof window !== "undefined" && typeof window.showSaveFilePicker === "function";

    // Open the save picker FIRST so we don't waste a decrypt if the
    // user cancels. (Picker call before busy=true; the user can pick
    // freely; if they cancel we abort cleanly.)
    let writableStream = null;
    if (useFsa) {
      try {
        const handle = await window.showSaveFilePicker({
          suggestedName: entry.name,
          types: [{
            description: entry.entry?.mime || "File",
            accept: { [entry.entry?.mime || "application/octet-stream"]: ["." + (entry.name.split(".").pop() || "bin")] },
          }],
        });
        writableStream = await handle.createWritable();
      } catch (e) {
        // User cancelled the picker — that's not an error.
        if (e?.name === "AbortError") return;
        // Any other error means we should fall back to the Blob path
        // rather than fail the download outright.
        writableStream = null;
      }
    }

    this.busy = true;
    try {
      const objUrl = this.session.bucketBase + OBJECTS_PREFIX + entry.entry.uuid;
      const get = await bucket.signedGet({
        url: objUrl,
        region: this.session.region,
        accessKey: this.session.accessKey,
        secretKey: this.session.secretKey,
      });
      if (!get.ok) throw new Error(`GET object failed: ${get.status} ${get.message}`);
      // openObject handles v1 blob vs v2 chunked and enforces the
      // manifest-signed content_iv rollback anchor. See lib/crate.js::read.
      const dataKey = await cryptoLib.unwrapDataKey(
        this.session.masterKey,
        cryptoLib.fromBase64(entry.entry.data_key_iv),
        cryptoLib.fromBase64(entry.entry.data_key_ct),
        entry.entry.uuid,
      );
      let plaintext;
      try {
        plaintext = await cryptoLib.openObject(dataKey, get.body, entry.entry);
      } finally {
        cryptoLib.zero(dataKey);
      }

      if (writableStream) {
        // FSA path: write directly to the user-picked file. We chunk
        // the write so the underlying stream can flush to disk
        // incrementally rather than materialise the whole buffer at
        // once on the OS side.
        const CHUNK = 4 * 1024 * 1024;
        for (let off = 0; off < plaintext.length; off += CHUNK) {
          await writableStream.write(plaintext.subarray(off, Math.min(off + CHUNK, plaintext.length)));
        }
        await writableStream.close();
        this.setMessage("info", `Saved ${entry.name}`);
      } else {
        // Fallback (small file OR no FSA): Blob URL + anchor click.
        const blob = new Blob([plaintext], { type: entry.entry.mime || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = h("a", { href: url, download: entry.name, style: "display:none" });
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        this.setMessage("info", `Downloaded ${entry.name}`);
      }
    } catch (e) {
      console.error(e);
      // If we opened a writable but failed mid-way, abort it so the
      // partial file doesn't sit on disk.
      if (writableStream) {
        try { await writableStream.abort(e); } catch {}
      }
      this.setMessage("error", `Download failed: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  async handleDelete(entry) {
    if (this.busy) { this.setMessage("error", "Another operation is in flight"); return; }
    if (entry.isDir && !entry.entry?.uuid) {
      // Virtual folder — no explicit mkdir to delete; just refuse for v1.0.
      // (To delete a non-empty folder, the user deletes its contents.)
      this.setMessage("error", "Empty the folder first (v1.0 limitation)");
      return;
    }
    if (!await this.confirmDelete(entry)) return;
    if (this.busy) {
      this.setMessage("error", "Another operation is in flight");
      return;
    }
    this.busy = true;
    try {
      if (entry.entry?.uuid && !entry.isDir) await this.deleteObject(entry.entry.uuid);
      const evt = entry.isDir
        ? deleteEvent({ uuid: entry.entry?.uuid ?? "dir-placeholder" })
        : deleteEvent({ uuid: entry.entry.uuid });
      await this.session.manifest.append(evt, this.session.masterKey);
      await this.flushManifest();
      this.setMessage("info", `Deleted ${entry.name}`);
      this._fireChange({ op: "delete", source: "local" });
    } catch (e) {
      console.error(e);
      this.setMessage("error", `Delete failed: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  async confirmDelete(entry) {
    if (this._deleteModalOpen) return false;
    this._deleteModalOpen = true;
    const returnFocus = document.activeElement;
    const modalRoot = document.createElement("div");
    modalRoot.className = "delete-modal";
    document.body.appendChild(modalRoot);
    try {
      return await renderDeleteConfirmModal(modalRoot, entry);
    } finally {
      document.body.removeChild(modalRoot);
      this._deleteModalOpen = false;
      if (returnFocus && typeof returnFocus.focus === "function") {
        try { returnFocus.focus(); } catch {}
      }
    }
  }

  async handleRename(entry) {
    const siblings = new Set(this.entriesInCurrentDir().map((e) => e.name));
    const newName = await promptDialog({
      title: entry.isDir ? "Rename folder" : "Rename file",
      label: "New name",
      value: entry.name,
      confirmLabel: "Rename",
      validate: (v) => validName(v, siblings, { kind: entry.isDir ? "folder" : "file", current: entry.name }),
    });
    if (!newName || newName === entry.name) return;
    if (entry.isDir && !entry.entry?.uuid) {
      this.setMessage("error", "Cannot rename a virtual folder (v1.0 limitation)");
      return;
    }
    this.busy = true;
    try {
      const newPath = joinPath(this.currentDir, newName);
      await this.session.manifest.append(
        moveEvent({ uuid: entry.entry.uuid, newPath }),
        this.session.masterKey,
      );
      await this.flushManifest();
      this.setMessage("info", `Renamed to ${newName}`);
      this._fireChange({ op: "move", source: "local" });
    } catch (e) {
      console.error(e);
      this.setMessage("error", `Rename failed: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  async handleMkdir() {
    const siblings = new Set(this.entriesInCurrentDir().map((e) => e.name));
    const name = await promptDialog({
      title: "New folder",
      label: "Name",
      placeholder: "Folder name",
      confirmLabel: "Create",
      validate: (v) => validName(v, siblings, { kind: "folder" }),
    });
    if (!name) return;
    this.busy = true;
    try {
      const dirPath = joinPath(this.currentDir, name) + "/";
      await this.session.manifest.append(
        mkdirEvent({ path: dirPath }),
        this.session.masterKey,
      );
      await this.flushManifest();
      this.setMessage("info", `Created ${name}/`);
      this._fireChange({ op: "mkdir", source: "local" });
    } catch (e) {
      console.error(e);
      this.setMessage("error", `mkdir failed: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  async handleRefresh() {
    if (this.busy) return;
    this.busy = true;
    try {
      const manifestUrl = this.session.bucketBase + MANIFEST_PATH;
      const get = await bucket.signedGet({
        url: manifestUrl,
        region: this.session.region,
        accessKey: this.session.accessKey,
        secretKey: this.session.secretKey,
      });
      if (!get.ok) throw new Error(`GET manifest failed: ${get.status} ${get.message}`);
      const fresh = await Manifest.loadFromBytes(get.body, this.session.masterKey);
      // Validate against the rollback anchor BEFORE trusting the refetch —
      // same H2 protection that crate.open / flushManifest's 412-replay /
      // SyncClient._pollManifest all apply. Without this, a bucket-only
      // attacker who replays an older valid manifest would be accepted on
      // a manual Refresh, and the lastFlushedEventCount below would regress
      // the saved anchor on the next flush. (2026-05 audit H2.)
      const prior = await anchor.loadAnchor(this.session.bucketBase);
      const v = anchor.validate(fresh.events, prior);
      if (!v.ok) {
        throw new anchor.ManifestRollbackError(v.reason, v.detail);
      }
      await anchor.saveAnchor(this.session.bucketBase, v.anchor);
      // Mutate in place so shared references (SyncClient's view) stay synced.
      this.session.manifest.events = fresh.events;
      this.session.manifest._lastSig = fresh._lastSig;
      this.session.manifestETag = get.etag || null;
      this.session.lastFlushedEventCount = this.session.manifest.events.length;
      this.setMessage("info", "Refreshed");
    } catch (e) {
      console.error(e);
      this.setMessage("error", `Refresh failed: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  // flushManifest delegates to the shared implementation in
  // lib/manifest-flush.js. The session object already matches that
  // module's expected shape (unprefixed manifest / masterKey /
  // bucketBase / region / accessKey / secretKey, and read+write
  // manifestETag + lastFlushedEventCount), so it passes through
  // directly with no adapter.
  //
  // Caller has already set `this.busy = true` so this method doesn't
  // need its own concurrency guard.
  async flushManifest() {
    return sharedFlushManifest(this.session, {
      errorFactory: (m) => new Error(m),
    });
  }

  // --- device pairing UI -----------------------------------------------

  // handlePair opens a modal that mints a CRATE-PAIR token via
  // POST /v1/pairing/intent against the transport, displays the token
  // (text + future QR), shows a countdown, and offers a Cancel button.
  //
  // The transport endpoint is read from this.session.transportEndpoint.
  // First-time-setup doesn't yet collect this — for v1.0 the user pastes
  // it manually in the pair modal. Once NakliOS Settings ships, the
  // transport URL is part of the bucket-registration record.
  async handlePair() {
    if (this._pairModalOpen) return;
    this._pairModalOpen = true;
    // A carrier folder has no hub and no pairing token: the daemon pairs
    // with the Worker URL + the carrier secret directly. Show the command.
    if (this.session.region === "carrier") {
      this.renderCarrierPairModal();
      return;
    }
    // Hub-based folder: the daemon pairs through a transport (a Hub or a
    // CF Worker) with a Grant that authorises identity:pair. For v1.x the
    // user pastes both; once NakliOS Settings ships, a Grant for the
    // active bucket is part of the session and this dialog goes away.
    const answer = await formDialog({
      title: "Pair an agent",
      description: "The daemon reaches your folder through a transport you run. Paste its address and a Grant that allows identity:pair.",
      fields: [
        { key: "transportUrl", label: "Transport URL", type: "url", value: this.session.transportEndpoint || "", placeholder: "https://my-hub.example.com", autofocus: true },
        { key: "grant", label: "Grant (base64 macaroon)", multiline: true, rows: 3, mono: true, placeholder: "From: nakli-cli grant mint …" },
      ],
      confirmLabel: "Continue",
      validate: (v) => {
        const u = v.transportUrl.trim();
        if (!/^https?:\/\/\S+$/.test(u)) return "Enter the transport's full address, starting with https://.";
        if (!v.grant.trim()) return "Paste the Grant.";
        return null;
      },
    });
    if (!answer) {
      this._pairModalOpen = false;
      return;
    }
    this.session.transportEndpoint = answer.transportUrl.trim();
    const grant = answer.grant;

    const modalRoot = document.createElement("div");
    modalRoot.className = "pair-modal";
    document.body.appendChild(modalRoot);
    const ctx = {
      modalRoot,
      transportUrl: this.session.transportEndpoint,
      grant: grant.trim(),
      secret: null,
      expiresAt: null,
      cancelled: false,
      ui: this,
    };
    try {
      await renderPairModal(ctx);
    } catch (e) {
      console.error("pair flow failed", e);
    } finally {
      document.body.removeChild(modalRoot);
      this._pairModalOpen = false;
    }
  }

  // handleExport opens the tiered export modal. Plan first (manifest scan
  // is fast), then user confirms, then run with live progress. The
  // session object is shaped exactly as lib/export.js's `source` arg
  // expects.
  async handleExport() {
    if (this._exportModalOpen) return;
    this._exportModalOpen = true;
    const modalRoot = document.createElement("div");
    modalRoot.className = "pair-modal";
    document.body.appendChild(modalRoot);
    try {
      await renderExportModal(modalRoot, this.session);
    } catch (e) {
      console.error("export flow failed", e);
    } finally {
      document.body.removeChild(modalRoot);
      this._exportModalOpen = false;
    }
  }

  // handleDownloadCreds builds the encrypted .crate-creds file from the
  // current session and triggers a browser download. Mirror of the
  // wizard's Done-stage download — same file format, same filename
  // convention. Always available from the folder UI so users who
  // skipped the Done-stage download (or who came in via the manual
  // 5-input unlock) can opt in later without re-onboarding.
  async handleDownloadCreds() {
    if (!this.session?.passphrase) {
      this.setMessage("error", "Can't build credentials file — session is missing passphrase. Reload + Unlock with passphrase.");
      return;
    }
    const bucketName = this.session.bucket?.name;
    const accountId = this.session.bucket?.accountId;
    if (!bucketName || !accountId) {
      this.setMessage("error", "Can't build credentials file — session is missing bucket name or account ID.");
      return;
    }
    try {
      const carrier = this.session.region === "carrier";
      const bytes = await credsfile.pack({
        provider: carrier ? "carrier" : "r2",
        bucket: { name: bucketName, accountId, region: this.session.region || "auto", url: this.session.bucket?.url },
        credentials: { accessKey: this.session.accessKey, secretKey: this.session.secretKey },
      }, this.session.passphrase);
      const blob = new Blob([bytes], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = h("a", { href: url, download: credsfile.suggestedFilename(bucketName), style: "display:none" });
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
      this.setMessage("info", `Saved ${credsfile.suggestedFilename(bucketName)} — keep it somewhere safe.`);
    } catch (e) {
      console.error("creds download failed", e);
      this.setMessage("error", `Couldn't generate credentials file: ${e?.message ?? e}`);
    }
  }

  // handleLock asks the host (via opts.onLock) to tear down the session
  // and return to the wizard. The actual zeroing of secrets +
  // sessionStorage clearing happens in entrypoint.js's lockCrateFolder,
  // which has the references it needs (SyncClient, masterKey buffer,
  // wizard handle). FolderUI just signals "user clicked lock."
  handleLock() {
    if (typeof this.onLock === "function") {
      this.onLock();
    } else {
      console.warn("FolderUI: no onLock handler wired");
      this.setMessage("error", "Lock not wired — close the tab to clear the session.");
    }
  }

  // handlePreview decrypts the file in memory and shows it in a modal.
  // Text → <pre>; image → blob-URL <img>. Files over PREVIEW_SIZE_CAP
  // get a "too large to preview" message instead.
  async handlePreview(entry) {
    if (this._previewModalOpen) return;
    if (this.busy) { this.setMessage("error", "Another operation is in flight"); return; }
    if (!entry.entry?.uuid) { this.setMessage("error", "Missing uuid"); return; }
    this._previewModalOpen = true;
    this.busy = true;
    const modalRoot = document.createElement("div");
    modalRoot.className = "pair-modal";
    document.body.appendChild(modalRoot);
    try {
      const size = entry.entry?.size ?? 0;
      let bytes = null;
      if (size <= PREVIEW_SIZE_CAP) {
        // Reuse the same crypto path handleDownload uses.
        const objUrl = this.session.bucketBase + OBJECTS_PREFIX + entry.entry.uuid;
        const get = await bucket.signedGet({
          url: objUrl,
          region: this.session.region,
          accessKey: this.session.accessKey,
          secretKey: this.session.secretKey,
        });
        if (!get.ok) throw new Error(`GET object failed: ${get.status} ${get.message ?? ""}`);
        const dataKey = await cryptoLib.unwrapDataKey(
          this.session.masterKey,
          cryptoLib.fromBase64(entry.entry.data_key_iv),
          cryptoLib.fromBase64(entry.entry.data_key_ct),
          entry.entry.uuid,
        );
        try {
          bytes = await cryptoLib.openObject(dataKey, get.body, entry.entry);
        } finally {
          cryptoLib.zero(dataKey);
        }
      }
      await renderPreviewModal(modalRoot, entry, bytes);
    } catch (e) {
      console.error("preview failed", e);
      this.setMessage("error", `Preview failed: ${e.message ?? e}`);
    } finally {
      document.body.removeChild(modalRoot);
      this._previewModalOpen = false;
      this.busy = false;
    }
  }

  // handleHistory opens a modal showing every manifest event affecting
  // the entry's path: when it was created, updated, moved, deleted.
  // Read-only — the manifest data is already in memory.
  async handleHistory(entry) {
    if (this._historyModalOpen) return;
    this._historyModalOpen = true;
    const modalRoot = document.createElement("div");
    modalRoot.className = "pair-modal";
    document.body.appendChild(modalRoot);
    try {
      const events = (this.session.manifest.events || []).filter((e) => {
        if (e.path === entry.path) return true;
        if (e.op === "move" && e.from === entry.path) return true;
        return false;
      });
      await renderHistoryModal(modalRoot, entry, events);
    } catch (e) {
      console.error("history flow failed", e);
    } finally {
      document.body.removeChild(modalRoot);
      this._historyModalOpen = false;
    }
  }
}

// --- helpers --------------------------------------------------------------

// validName is the rule both New folder and Rename apply while typing:
// non-empty, no slashes, not "." / "..", and not already taken in `taken`
// (a Set of sibling names). Returns an error string or null.
function validName(name, taken, { kind = "name", current = null } = {}) {
  const n = name.trim();
  if (!n) return `Give the ${kind} a name.`;
  if (n.includes("/")) return "Names can't contain slashes.";
  if (n === "." || n === "..") return "That name is reserved.";
  if (n !== current && taken.has(n)) return `Something called “${n}” is already here.`;
  return null;
}

function basename(path) {
  const t = path.replace(/\/+$/, "");
  return t.slice(t.lastIndexOf("/") + 1);
}

// parentLabel renders the folder a file lives in, for the flat views:
// "/" → "All files", "/Work/2025/" → "Work › 2025".
function parentLabel(path) {
  const segs = path.split("/").filter(Boolean);
  segs.pop();
  return segs.length === 0 ? "All files" : segs.join(" › ");
}

// normalizeDir turns typed input into a canonical "/a/b/" directory path,
// or null when it cannot be one.
function normalizeDir(input) {
  let d = String(input ?? "").trim().replace(/\\/g, "/");
  if (d === "" || d === "/" || d.toLowerCase() === "all files") return "/";
  d = "/" + d.split("/").filter((x) => x.length > 0).join("/") + "/";
  if (/\/\.\.?\//.test(d)) return null;
  return d;
}

function joinPath(dir, name) {
  if (dir === "/" || dir === "") return "/" + name;
  if (!dir.endsWith("/")) dir = dir + "/";
  return dir + name;
}


function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

// h — tiny createElement wrapper.
function h(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    if (typeof c === "string") node.appendChild(document.createTextNode(c));
    else node.appendChild(c);
  }
  return node;
}

// renderRecoveryModal shows 24 words and asks for three back; resolves
// true when the user confirmed, false when dismissed. Same overlay as
// the other dialogs; the grid reuses the wizard's .recovery-* styles.
function renderRecoveryModal({ words, replacing, legacy }) {
  return new Promise((resolve) => {
    const overlay = h("div", { class: "pair-overlay" });
    const card = h("div", { class: "pair-card recovery-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "rec-title" });
    overlay.appendChild(card);
    card.appendChild(h("h2", { id: "rec-title" }, [replacing ? "New recovery phrase" : "Your recovery phrase"]));
    card.appendChild(h("p", { class: "muted" }, [
      "If you ever lose your passphrase, these 24 words open the folder and let you set a new one. Write them on paper, in order. Don't screenshot them; don't email them to yourself.",
    ]));
    if (replacing) card.appendChild(h("p", { class: "muted small" }, ["Saving these words replaces the phrase you had before; the old one stops working."]));
    if (legacy) card.appendChild(h("p", { class: "muted small" }, ["This also moves the folder's key file to the current format. A paired crate-agent older than v1.2 will need updating before it can open the folder again."]));
    card.appendChild(h("ol", { class: "recovery-grid", "aria-label": "Recovery phrase, 24 words" },
      words.map((w, i) => h("li", { class: "recovery-word" }, [
        h("span", { class: "recovery-index", "aria-hidden": "true" }, [String(i + 1)]),
        h("span", { class: "recovery-text" }, [w]),
      ]))));
    const copyBtn = h("button", { type: "button", class: "btn btn-secondary copy-btn" }, ["Copy phrase"]);
    copyBtn.addEventListener("click", async () => {
      const ok = await copyText(words.join(" "));
      copyBtn.textContent = ok ? "✓ Copied" : "Copy failed";
      copyBtn.classList.toggle("copy-ok", ok); copyBtn.classList.toggle("copy-fail", !ok);
      setTimeout(() => { copyBtn.textContent = "Copy phrase"; copyBtn.classList.remove("copy-ok", "copy-fail"); }, 1600);
    });
    card.appendChild(h("div", { class: "row" }, [copyBtn]));
    card.appendChild(h("p", {}, ["Type three of the words back to confirm you have them:"]));
    const all = Array.from({ length: 24 }, (_, i) => i);
    for (let i = all.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [all[i], all[j]] = [all[j], all[i]]; }
    const ask = all.slice(0, 3).sort((a, b) => a - b);
    const correct = new Set();
    const saveBtn = h("button", { type: "button", class: "btn btn-primary" }, ["Save recovery phrase"]);
    saveBtn.disabled = true;
    const fields = h("div", { class: "field-row" }, ask.map((idx) => {
      const inp = h("input", { type: "text", class: "input input-narrow", autocomplete: "off", autocapitalize: "none", spellcheck: "false", "aria-label": `Word ${idx + 1}`, placeholder: `word ${idx + 1}` });
      inp.addEventListener("input", () => {
        const ok = inp.value.trim().toLowerCase() === words[idx];
        inp.classList.toggle("input-ok", ok);
        inp.classList.toggle("input-fail", !ok && inp.value.trim().length > 0);
        if (ok) correct.add(idx); else correct.delete(idx);
        saveBtn.disabled = correct.size < 3;
      });
      return h("div", { class: "confirm-cell" }, [h("label", {}, [`Word ${idx + 1}`]), inp]);
    }));
    card.appendChild(fields);
    const cancelBtn = h("button", { type: "button", class: "btn btn-secondary" }, ["Cancel"]);
    card.appendChild(h("div", { class: "dialog-actions" }, [cancelBtn, saveBtn]));

    let settled = false;
    const close = (v) => { if (settled) return; settled = true; document.removeEventListener("keydown", onKey, true); overlay.remove(); resolve(v); };
    const onKey = (e) => { if (e.key === "Escape") { e.preventDefault(); close(false); } };
    cancelBtn.addEventListener("click", () => close(false));
    saveBtn.addEventListener("click", () => close(true));
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(false); });
    document.addEventListener("keydown", onKey, true);
    document.body.appendChild(overlay);
    const first = fields.querySelector("input");
    if (first) first.focus();
  });
}

// renderDeleteConfirmModal keeps destructive confirmation inside Crate's
// own UI instead of using a blocking browser popup.
function renderDeleteConfirmModal(modalRoot, entry) {
  return new Promise((resolve) => {
    const overlay = h("div", { class: "pair-overlay delete-overlay" });
    const card = h("div", {
      class: "pair-card delete-card",
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "delete-dialog-title",
      "aria-describedby": "delete-dialog-description",
    });
    overlay.appendChild(card);
    modalRoot.appendChild(overlay);

    const many = entry.count > 1;
    card.appendChild(h("h2", { id: "delete-dialog-title" }, [
      many ? `Delete ${entry.count} files?` : entry.isDir ? "Delete folder?" : "Delete file?",
    ]));
    card.appendChild(h("p", {
      id: "delete-dialog-description",
      class: "muted",
    }, [
      many
        ? "These files will be removed from your Crate. This can't be undone."
        : entry.isDir
          ? "This empty folder will be removed from your Crate. This can't be undone."
          : "This file will be removed from your Crate. This can't be undone.",
    ]));
    card.appendChild(h("p", { class: "delete-dialog-path mono" }, [
      entry.path || entry.name,
    ]));

    const cancelBtn = h("button", {
      type: "button",
      class: "btn btn-secondary",
    }, ["Cancel"]);
    const deleteBtn = h("button", {
      type: "button",
      class: "btn btn-danger-primary",
    }, [many ? `Delete ${entry.count} files` : entry.isDir ? "Delete folder" : "Delete file"]);
    card.appendChild(h("div", { class: "dialog-actions" }, [cancelBtn, deleteBtn]));

    let settled = false;
    const close = (confirmed) => {
      if (settled) return;
      settled = true;
      document.removeEventListener("keydown", onKey);
      resolve(confirmed);
    };
    const onKey = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close(false);
        return;
      }
      if (event.key !== "Tab") return;
      if (event.shiftKey && document.activeElement === cancelBtn) {
        event.preventDefault();
        deleteBtn.focus();
      } else if (!event.shiftKey && document.activeElement === deleteBtn) {
        event.preventDefault();
        cancelBtn.focus();
      }
    };

    cancelBtn.addEventListener("click", () => close(false));
    deleteBtn.addEventListener("click", () => close(true));
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) close(false);
    });
    document.addEventListener("keydown", onKey);
    cancelBtn.focus();
  });
}

// --- carrier pairing: just a command -------------------------------------

FolderUI.prototype.renderCarrierPairModal = function renderCarrierPairModal() {
  const url = String(this.session.bucket?.url || "").replace(/\/+$/, "");
  const cmd = `crate-agent pair --carrier ${url}`;
  const modalRoot = h("div", { class: "pair-overlay" });
  const close = () => { if (modalRoot.parentNode) modalRoot.parentNode.removeChild(modalRoot); this._pairModalOpen = false; };
  const copyBtn = (label, text) => {
    const b = h("button", { type: "button", class: "btn btn-secondary" }, [label]);
    b.addEventListener("click", async () => {
      const ok = await copyText(text);
      b.textContent = ok ? "✓ Copied" : "Copy failed";
      setTimeout(() => { b.textContent = label; }, 1500);
    });
    return b;
  };
  const cmdBox = h("pre", { class: "pair-cmd" }, [cmd]);
  const closeBtn = h("button", { type: "button", class: "btn btn-primary btn-block" }, ["Close"]);
  closeBtn.addEventListener("click", close);
  modalRoot.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  modalRoot.appendChild(h("div", { class: "pair-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "pair-title" }, [
    h("h2", { id: "pair-title" }, ["Sync this folder to a computer"]),
    h("p", { class: "muted" }, [
      "Install ", h("a", { href: "https://github.com/NakliTechie/crate-agent#install", target: "_blank", rel: "noopener noreferrer" }, ["crate-agent"]),
      " (v1.3 or later), then run this in a terminal:",
    ]),
    cmdBox,
    h("div", { class: "row" }, [copyBtn("Copy command", cmd), copyBtn("Copy carrier secret", this.session.secretKey || "")]),
    h("p", { class: "muted small" }, [
      "It asks for the carrier secret (the CARRIER_SECRET you pasted at deploy — the second button copies it) and your folder passphrase, then keeps ",
      h("code", {}, ["~/crate/"]), " in sync. The daemon holds the secret encrypted under your passphrase; rotate CARRIER_SECRET on the Worker to revoke it.",
    ]),
    closeBtn,
  ]));
  document.body.appendChild(modalRoot);
  closeBtn.focus();
};

// --- device-pairing flow -------------------------------------------------

// renderPairModal mints a CRATE-PAIR token via /v1/pairing/intent and
// renders the result (QR + text + countdown + cancel) into ctx.modalRoot.
// Returns a promise that resolves when the modal closes (any reason).
async function renderPairModal(ctx) {
  return new Promise(async (resolve) => {
    const overlay = h("div", { class: "pair-overlay" });
    const card = h("div", { class: "pair-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "pair-title" });
    overlay.appendChild(card);
    ctx.modalRoot.appendChild(overlay);

    const title = h("h2", { id: "pair-title" }, ["Pair an agent"]);
    const status = h("p", { class: "muted small" }, ["Minting pairing token…"]);
    card.appendChild(title);
    card.appendChild(status);

    const close = (reason) => {
      try { document.removeEventListener("keydown", onKey); } catch {}
      resolve(reason);
    };
    function onKey(e) { if (e.key === "Escape") close("escape"); }
    document.addEventListener("keydown", onKey);

    // Build the pairing-intent payload per crate-pairing-protocol-v1.0.
    const payload = await buildIntentPayload(ctx.ui.session);
    let resp;
    try {
      resp = await fetch(ctx.transportUrl.replace(/\/+$/, "") + "/v1/pairing/intent", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Fabric-Grant": ctx.grant,
          // crate runs in a browser at the user's request, so the
          // calling principal is always a human. Assert it so the
          // Hub's strict caveat-binding mode (private-mesh PR #5)
          // accepts a `principal-type in [human]` caveat. Harmless
          // when the grant carries no such caveat.
          "X-Fabric-Principal-Type": "human",
        },
        body: JSON.stringify(payload),
      });
    } catch (e) {
      status.textContent = "Could not reach the transport: " + (e.message ?? e);
      const closeBtn = h("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Close"]);
      closeBtn.addEventListener("click", () => close("network-error"));
      card.appendChild(closeBtn);
      return;
    }
    if (!resp.ok) {
      const txt = await resp.text().catch(() => "");
      status.textContent = "Mint failed (HTTP " + resp.status + "). " + txt.slice(0, 200);
      const closeBtn = h("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Close"]);
      closeBtn.addEventListener("click", () => close("mint-error"));
      card.appendChild(closeBtn);
      return;
    }

    ctx.secret = payload.secret;
    ctx.expiresAt = payload.expires_at;
    const token = "CRATE-PAIR-" + base64URLEncode(JSON.stringify(payload));

    // Wipe the "minting…" placeholder + render the token.
    while (card.firstChild) card.removeChild(card.firstChild);
    card.appendChild(title);
    card.appendChild(h("p", { class: "muted small" }, [
      "On your other device, choose ",
      h("strong", {}, ["Add this device to an existing folder"]),
      " and paste this token.",
    ]));

    const qrHost = h("div", { class: "pair-qr" });
    qr.renderTo(qrHost, token);
    card.appendChild(qrHost);

    const tokenBlock = h("pre", { class: "code-block", tabindex: "0" }, [token]);
    card.appendChild(tokenBlock);

    const copyBtn = h("button", { type: "button", class: "btn btn-primary" }, ["Copy token"]);
    copyBtn.addEventListener("click", async () => {
      const ok = await copyText(token);
      copyBtn.textContent = ok ? "✓ Copied" : "✗ Copy failed";
      setTimeout(() => { copyBtn.textContent = "Copy token"; }, 1500);
    });

    const cancelBtn = h("button", { type: "button", class: "btn btn-secondary" }, ["Cancel"]);
    cancelBtn.addEventListener("click", async () => {
      cancelBtn.disabled = true;
      try {
        await fetch(ctx.transportUrl.replace(/\/+$/, "") + "/v1/pairing/intent/cancel", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Fabric-Grant": ctx.grant,
            "X-Fabric-Principal-Type": "human",
          },
          body: JSON.stringify({ secret: ctx.secret }),
        });
      } catch {}
      close("cancel");
    });

    card.appendChild(h("div", { class: "row" }, [copyBtn, cancelBtn]));

    const countdown = h("p", { class: "muted small", role: "status", "aria-live": "polite" }, [""]);
    card.appendChild(countdown);

    const tick = () => {
      const now = Math.floor(Date.now() / 1000);
      const left = ctx.expiresAt - now;
      if (left <= 0) {
        countdown.textContent = "Token expired. Close + try again.";
        copyBtn.disabled = true;
        cancelBtn.disabled = true;
        clearInterval(timer);
        return;
      }
      const mins = Math.floor(left / 60);
      const secs = left % 60;
      countdown.textContent = `Expires in ${mins}m ${secs}s. Single-use — once the other device pairs, this token is consumed.`;
    };
    tick();
    const timer = setInterval(tick, 1000);
  });
}

// buildIntentPayload constructs the CRATE-PAIR-... payload per
// crate-pairing-protocol-v1.0.md §"Wire format". 15-minute TTL.
async function buildIntentPayload(session) {
  const secretBytes = crypto.getRandomValues(new Uint8Array(32));
  const secret = base64URLEncode(arrayToString(secretBytes));
  const now = Math.floor(Date.now() / 1000);
  return {
    v: 1,
    type: "crate.pairing.token",
    secret,
    transport_endpoint: session.transportEndpoint || "",
    transport_type: guessTransportType(session.transportEndpoint || ""),
    bucket_id: session.bucketBase, // stand-in until NakliOS Settings provides a real bucket_id
    identity_pubkey: "browser-stub", // real Ed25519 pubkey lands with NakliOS Identity binding
    issued_at: now,
    expires_at: now + 900,
  };
}

function arrayToString(arr) {
  let s = "";
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return s;
}

function base64URLEncode(s) {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function guessTransportType(url) {
  if (!url) return "hub";
  if (url.includes("workers.dev") || url.includes("/cf/")) return "cf-worker";
  return "hub";
}

// renderPreviewModal shows decrypted file content inline. Caller passes
// either Uint8Array bytes (file ≤ PREVIEW_SIZE_CAP) or null (too large
// — modal shows the "use Download" message). Caller is responsible for
// the actual decrypt + size guard.
async function renderPreviewModal(modalRoot, entry, bytes) {
  return new Promise((resolve) => {
    const overlay = h("div", { class: "pair-overlay" });
    const card = h("div", { class: "pair-card preview-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "preview-title" });
    overlay.appendChild(card);
    modalRoot.appendChild(overlay);

    let blobUrl = null;
    const close = (reason) => {
      try { document.removeEventListener("keydown", onKey); } catch {}
      if (blobUrl) {
        try { URL.revokeObjectURL(blobUrl); } catch {}
        blobUrl = null;
      }
      resolve(reason);
    };
    function onKey(e) { if (e.key === "Escape") close("escape"); }
    document.addEventListener("keydown", onKey);

    card.appendChild(h("h2", { id: "preview-title" }, [entry.name]));
    card.appendChild(h("p", { class: "muted small mono" }, [entry.path]));

    if (bytes === null) {
      card.appendChild(h("p", {}, [
        `This file is larger than ${formatBytes(PREVIEW_SIZE_CAP)} — too big to preview inline. Use the Download button to fetch it.`,
      ]));
    } else if (isImageMime(entry)) {
      const mime = entry.entry?.mime || "image/*";
      const blob = new Blob([bytes], { type: mime });
      blobUrl = URL.createObjectURL(blob);
      const img = h("img", { src: blobUrl, alt: entry.name, class: "preview-image" });
      card.appendChild(img);
    } else {
      // Text path. Best-effort UTF-8 decode; if the file isn't UTF-8 the
      // decoder substitutes replacement chars rather than throwing.
      let text;
      try {
        text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      } catch (e) {
        text = `(could not decode as text: ${e.message ?? e})`;
      }
      const pre = h("pre", { class: "preview-text code-block" }, [text]);
      card.appendChild(pre);
    }

    const closeBtn = h("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Close"]);
    closeBtn.addEventListener("click", () => close("close"));
    card.appendChild(closeBtn);
  });
}

// renderHistoryModal shows the event log for a single file: when it was
// created, every update + size delta, any move-rename, and the delete
// if present. Read-only — the data is materialised from the in-memory
// manifest, no network calls.
async function renderHistoryModal(modalRoot, entry, events) {
  return new Promise((resolve) => {
    const overlay = h("div", { class: "pair-overlay" });
    const card = h("div", { class: "pair-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "history-title" });
    overlay.appendChild(card);
    modalRoot.appendChild(overlay);

    const close = (reason) => {
      try { document.removeEventListener("keydown", onKey); } catch {}
      resolve(reason);
    };
    function onKey(e) { if (e.key === "Escape") close("escape"); }
    document.addEventListener("keydown", onKey);

    card.appendChild(h("h2", { id: "history-title" }, ["File history"]));
    card.appendChild(h("p", { class: "muted small mono" }, [entry.path]));

    if (events.length === 0) {
      card.appendChild(h("p", {}, ["No history events found. (This shouldn't happen — every file has at least a create event.)"]));
    } else {
      const list = h("ol", { class: "history-list" });
      // Newest first.
      const sorted = events.slice().sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
      for (const ev of sorted) {
        const op = ev.op || "?";
        const ts = ev.ts || "?";
        let detail = "";
        if (op === "create" || op === "update") {
          detail = typeof ev.size === "number" ? `${formatBytes(ev.size)}` : "";
        } else if (op === "move") {
          detail = `from ${ev.from || "?"} to ${ev.path || "?"}`;
        } else if (op === "delete") {
          detail = "removed";
        } else if (op === "mkdir") {
          detail = "directory created";
        }
        const item = h("li", { class: "history-row" }, [
          h("span", { class: "history-op" }, [op]),
          h("time", { class: "history-ts muted small mono" }, [ts]),
          h("span", { class: "history-detail muted small" }, [detail]),
        ]);
        list.appendChild(item);
      }
      card.appendChild(list);
    }

    const closeBtn = h("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Close"]);
    closeBtn.addEventListener("click", () => close("close"));
    card.appendChild(closeBtn);
  });
}

// renderExportModal plans the export, shows the user what tier we'll use
// (memory blob / FSA stream / too-large with daemon prompt), lets them
// confirm, then runs with live progress. Returns a promise that resolves
// when the modal closes for any reason.
async function renderExportModal(modalRoot, session) {
  return new Promise(async (resolve) => {
    const overlay = h("div", { class: "pair-overlay" });
    const card = h("div", { class: "pair-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "export-title" });
    overlay.appendChild(card);
    modalRoot.appendChild(overlay);

    const close = (reason) => {
      try { document.removeEventListener("keydown", onKey); } catch {}
      resolve(reason);
    };
    function onKey(e) { if (e.key === "Escape") close("escape"); }
    document.addEventListener("keydown", onKey);

    card.appendChild(h("h2", { id: "export-title" }, ["Export folder"]));

    let plan;
    try {
      plan = planExport(session);
    } catch (e) {
      card.appendChild(h("p", { class: "error" }, ["Couldn't read the manifest: " + (e.message ?? e)]));
      const closeBtn = h("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Close"]);
      closeBtn.addEventListener("click", () => close("plan-error"));
      card.appendChild(closeBtn);
      return;
    }

    // Empty folder — nothing to export.
    if (plan.tier === "empty") {
      card.appendChild(h("p", {}, ["This folder is empty. Add some files first, then export."]));
      const closeBtn = h("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Close"]);
      closeBtn.addEventListener("click", () => close("empty"));
      card.appendChild(closeBtn);
      return;
    }

    const summary = h("p", { class: "muted" }, [
      `${plan.fileCount} ${plan.fileCount === 1 ? "file" : "files"} · ${fmtExportBytes(plan.totalBytes)} total`,
    ]);
    card.appendChild(summary);

    // Tier 3 (too-large): show the daemon-install prompt + done.
    if (plan.tier === "too-large") {
      card.appendChild(h("p", {}, [
        "This folder is larger than 500 MB and your browser doesn't support streaming exports (Firefox, Safari, or mobile). For backups this size, install ",
        h("a", { href: "https://github.com/NakliTechie/crate-agent", target: "_blank", rel: "noopener noreferrer" }, ["crate-agent"]),
        " — it mirrors the bucket to a plaintext folder on your laptop, and you point Time Machine / restic / rsync at that.",
      ]));
      card.appendChild(h("p", { class: "muted small" }, [
        "Full backup runbook: ",
        h("a", { href: "docs/backup.md", target: "_blank" }, ["docs/backup.md"]),
        ".",
      ]));
      const closeBtn = h("button", { type: "button", class: "btn btn-secondary btn-block" }, ["Close"]);
      closeBtn.addEventListener("click", () => close("too-large"));
      card.appendChild(closeBtn);
      return;
    }

    // Tiers memory + stream: explain the path, then confirm.
    const explain = h("p", {});
    if (plan.tier === "memory") {
      explain.appendChild(document.createTextNode(
        "We'll build a zip in this tab's memory and download it as one file. About ",
      ));
      explain.appendChild(h("strong", {}, [fmtExportBytes(plan.totalBytes)]));
      explain.appendChild(document.createTextNode(" — fast on any browser."));
    } else {
      explain.appendChild(document.createTextNode(
        "We'll stream the zip directly to a file you pick on disk. Click ",
      ));
      explain.appendChild(h("strong", {}, ["Start export"]));
      explain.appendChild(document.createTextNode(", then pick a destination in the save dialog. Peak memory stays low even for "));
      explain.appendChild(h("strong", {}, [fmtExportBytes(plan.totalBytes)]));
      explain.appendChild(document.createTextNode("."));
    }
    card.appendChild(explain);

    card.appendChild(h("p", { class: "muted small" }, [
      "The exported zip is plaintext — handle it like any other sensitive file. See ",
      h("a", { href: "docs/backup.md", target: "_blank" }, ["docs/backup.md"]),
      " for the threat-model breakdown.",
    ]));

    const startBtn = h("button", { type: "button", class: "btn btn-primary" }, ["Start export"]);
    const cancelBtn = h("button", { type: "button", class: "btn btn-secondary" }, ["Cancel"]);
    const progress = h("p", { class: "muted small", role: "status", "aria-live": "polite" }, [""]);
    const buttonRow = h("div", { class: "row" }, [startBtn, cancelBtn]);
    card.appendChild(buttonRow);
    card.appendChild(progress);

    cancelBtn.addEventListener("click", () => close("cancel"));

    const ac = new AbortController();
    startBtn.addEventListener("click", async () => {
      startBtn.disabled = true;
      cancelBtn.textContent = "Stop";
      cancelBtn.onclick = () => {
        ac.abort();
        cancelBtn.disabled = true;
        progress.textContent = "Stopping…";
      };
      progress.textContent = "Decrypting…";
      try {
        const result = await runExport(session, plan, {
          signal: ac.signal,
          onProgress: (p) => {
            if (p.phase === "file") {
              progress.textContent = `${p.fileIndex} / ${p.fileCount} · ${fmtExportBytes(p.bytesDone)} of ${fmtExportBytes(p.totalBytes)} · ${p.path}`;
            } else if (p.phase === "done") {
              progress.textContent = `Done — ${p.fileCount} files, ${fmtExportBytes(p.totalBytes)}.`;
            }
          },
        });
        progress.textContent = result.tier === "stream"
          ? `Saved as ${result.savedAs}.`
          : `Downloaded ${result.downloadedName} (${fmtExportBytes(result.bytes)}).`;
        startBtn.style.display = "none";
        cancelBtn.textContent = "Close";
        cancelBtn.disabled = false;
        cancelBtn.onclick = () => close("done");
      } catch (e) {
        if (e?.name === "AbortError") {
          progress.textContent = "Cancelled.";
        } else {
          console.error("export failed", e);
          progress.textContent = "Export failed: " + (e.message ?? e);
        }
        startBtn.style.display = "none";
        cancelBtn.textContent = "Close";
        cancelBtn.disabled = false;
        cancelBtn.onclick = () => close("error");
      }
    });
  });
}
