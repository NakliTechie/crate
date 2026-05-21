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

import * as cryptoLib from "./crypto.js";
import * as bucket from "./bucket.js";
import {
  Manifest, MANIFEST_PATH,
  createEvent, updateEvent, deleteEvent, moveEvent, mkdirEvent,
} from "./manifest.js";
import { copyText } from "./clipboard.js";
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

// iconFor picks a recognisable emoji per entry type — folder, image,
// audio, video, archive, text, code, or generic file. Keeps the visual
// hierarchy readable at a glance.
function iconFor(entry) {
  if (entry.isDir) return "📁";
  const mime = (entry.entry?.mime || "").toLowerCase();
  const ext = (entry.name || "").toLowerCase().split(".").pop();
  if (mime.startsWith("image/") || ["png","jpg","jpeg","gif","webp","svg","bmp","avif","ico"].includes(ext)) return "🖼";
  if (mime.startsWith("audio/") || ["mp3","wav","flac","ogg","aac","m4a","opus"].includes(ext)) return "🎵";
  if (mime.startsWith("video/") || ["mp4","mov","avi","mkv","webm","m4v"].includes(ext)) return "🎬";
  if (mime === "application/pdf" || ext === "pdf") return "📕";
  if (["zip","tar","gz","tgz","bz2","xz","7z","rar"].includes(ext)) return "📦";
  if (["js","jsx","ts","tsx","html","htm","css","sh","py","go","rs","rb","java","c","h","cpp","hpp","sql","swift","kt","php","lua","r"].includes(ext)) return "🧾";
  if (mime.startsWith("text/") || mime === "application/json" || mime === "application/xml" ||
      ["txt","md","markdown","json","xml","yaml","yml","csv","tsv","log","ini","conf","toml"].includes(ext)) return "📝";
  return "📄";
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
    this.currentDir = "/";
    this.busy = false;
    this.message = null;
    this.searchQuery = ""; // basename substring filter; empty = no filter
  }

  static mount(root, session, opts = {}) {
    const ui = new FolderUI(root, session, opts);
    ui.render();
    return ui;
  }

  _fireChange(evt) {
    if (this.onChange) {
      try { this.onChange(evt); } catch (e) { console.error("folder onChange threw", e); }
    }
  }

  // --- top-level render --------------------------------------------------

  render() {
    while (this.root.firstChild) this.root.removeChild(this.root.firstChild);
    this.root.appendChild(this.buildHeader());
    this.root.appendChild(this.buildTree());
    if (this.message) this.root.appendChild(this.buildBanner());
    // One-time wiring of page-level drag-and-drop. Listeners attach to
    // this.root which persists across re-renders.
    this._setupDragDrop();
  }

  buildHeader() {
    const wrap = h("header", { class: "folder-header" });

    // Title row: H1 + stats inline so the page has a clear identity
    // and the "this is a folder of X files" fact is always visible.
    const stats = this.computeStats();
    const titleRow = h("div", { class: "folder-title-row" }, [
      h("h1", {}, ["Your Crate"]),
      h("span", { class: "folder-stats muted small" }, [
        `${stats.fileCount} ${stats.fileCount === 1 ? "file" : "files"} · ${formatBytes(stats.totalBytes)} · encrypted`,
      ]),
    ]);
    wrap.appendChild(titleRow);

    // Toolbar — primary actions left, utility actions right.
    const fileInput = h("input", { type: "file", id: "folder-upload-input", multiple: "multiple", style: "display:none" });
    fileInput.addEventListener("change", (e) => this.handleUploadFiles(e.target.files));

    const uploadBtn = h("button", { type: "button", class: "btn btn-primary folder-upload-btn" }, [
      h("span", { "aria-hidden": "true" }, ["⬆"]), " Upload",
    ]);
    uploadBtn.addEventListener("click", () => fileInput.click());

    const mkdirBtn = h("button", { type: "button", class: "btn btn-secondary" }, [
      h("span", { "aria-hidden": "true" }, ["📁"]), " New folder",
    ]);
    mkdirBtn.addEventListener("click", () => this.handleMkdir());

    const refreshBtn = h("button", { type: "button", class: "btn-icon", title: "Refresh", "aria-label": "Refresh from bucket" }, ["⟳"]);
    refreshBtn.addEventListener("click", () => this.handleRefresh());

    const pairBtn = h("button", { type: "button", class: "btn btn-secondary btn-utility" }, ["Pair an agent"]);
    pairBtn.addEventListener("click", () => this.handlePair());

    const exportBtn = h("button", { type: "button", class: "btn btn-secondary btn-utility" }, ["Export"]);
    exportBtn.addEventListener("click", () => this.handleExport());

    // Always-available "Save credentials" entry — lets users who skipped
    // the Done-stage download (or who came in via manual unlock) emit a
    // .crate-creds file at any time. Disabled if the session is missing
    // its passphrase (shouldn't happen post-v1.1, but defensive).
    const credsBtn = h("button", { type: "button", class: "btn btn-secondary btn-utility", title: "Download an encrypted credentials file you can use to unlock in 2 clicks next time" }, [
      "🔐 Credentials",
    ]);
    if (!this.session.passphrase) credsBtn.disabled = true;
    credsBtn.addEventListener("click", () => this.handleDownloadCreds());

    wrap.appendChild(h("div", { class: "folder-toolbar" }, [
      h("div", { class: "toolbar-primary" }, [uploadBtn, mkdirBtn, fileInput]),
      h("div", { class: "toolbar-utility" }, [refreshBtn, credsBtn, pairBtn, exportBtn]),
    ]));

    // Search input — filters the current tree view by basename substring.
    // Replace-only-the-tree on input so the search field doesn't lose focus.
    const searchInput = h("input", {
      type: "search", class: "input folder-search-input", id: "folder-search",
      placeholder: "Filter files in this folder…", autocomplete: "off",
      value: this.searchQuery,
      "aria-label": "Filter files in this folder by name",
    });
    searchInput.addEventListener("input", (e) => {
      this.searchQuery = e.target.value;
      const treeRoot = this.root.querySelector(".folder-tree");
      if (treeRoot) treeRoot.replaceWith(this.buildTree());
    });
    wrap.appendChild(h("div", { class: "folder-search" }, [searchInput]));

    // Path breadcrumb with chevron separators.
    const crumb = h("nav", { class: "folder-breadcrumb", "aria-label": "Current folder" });
    const segs = this.currentDir === "/" ? [] : this.currentDir.replace(/\/$/, "").split("/").filter((s) => s.length > 0);
    crumb.appendChild(this.crumbLink("/", "Home", segs.length === 0));
    if (segs.length > 0) {
      let acc = "";
      segs.forEach((s, i) => {
        acc += "/" + s;
        crumb.appendChild(h("span", { class: "crumb-sep", "aria-hidden": "true" }, ["›"]));
        crumb.appendChild(this.crumbLink(acc + "/", s, i === segs.length - 1));
      });
    }
    wrap.appendChild(crumb);

    return wrap;
  }

  // Attaches drag-enter / drag-over / drag-leave / drop listeners on
  // this.root exactly once. Files dropped anywhere in the folder area
  // trigger an upload; the overlay class adds a visible drop affordance.
  _setupDragDrop() {
    if (this._dragDropWired) return;
    this._dragDropWired = true;
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
      this.handleUploadFiles(e.dataTransfer.files);
    });
  }

  // computeStats returns { fileCount, totalBytes } across the whole Crate
  // (not just the current dir). Used by the header line.
  computeStats() {
    const tree = this.session.manifest.materialise();
    let fileCount = 0;
    let totalBytes = 0;
    for (const [, entry] of tree.entries()) {
      if (entry.isDir) continue;
      fileCount += 1;
      totalBytes += typeof entry.size === "number" ? entry.size : 0;
    }
    return { fileCount, totalBytes };
  }

  crumbLink(path, label, isCurrent) {
    const cls = isCurrent ? "folder-crumb folder-crumb-current" : "folder-crumb";
    const a = h("a", { href: "#", class: cls, "aria-current": isCurrent ? "page" : false }, [label]);
    a.addEventListener("click", (e) => {
      e.preventDefault();
      this.currentDir = path;
      this.searchQuery = ""; // clear filter on navigation
      this.render();
    });
    return a;
  }

  buildTree() {
    const wrap = h("ul", { class: "folder-tree", "aria-label": "Files in this folder" });
    let entries = this.entriesInCurrentDir();
    if (this.searchQuery.trim()) {
      const q = this.searchQuery.trim().toLowerCase();
      entries = entries.filter((e) => e.name.toLowerCase().includes(q));
    }
    if (entries.length === 0) {
      wrap.appendChild(this.buildEmptyState());
      return wrap;
    }
    // Folders first, then files; both alphabetical.
    const folders = entries.filter((e) => e.isDir).sort((a, b) => a.name.localeCompare(b.name));
    const files = entries.filter((e) => !e.isDir).sort((a, b) => a.name.localeCompare(b.name));
    for (const e of folders.concat(files)) {
      wrap.appendChild(this.buildTreeRow(e));
    }
    return wrap;
  }

  buildEmptyState() {
    if (this.searchQuery.trim()) {
      return h("li", { class: "folder-empty muted" }, [
        `No matches for “${this.searchQuery.trim()}”. Try a different filter, or click Home in the breadcrumb above.`,
      ]);
    }
    return h("li", { class: "folder-empty" }, [
      h("div", { class: "empty-icon", "aria-hidden": "true" }, ["⬆"]),
      h("p", { class: "empty-title" }, ["This folder is empty."]),
      h("p", { class: "muted small" }, [
        "Drop files here, or click ",
        h("strong", {}, ["Upload"]),
        " above. Anything you add is end-to-end encrypted before it leaves the browser.",
      ]),
    ]);
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

    // File-type icon (folder, image, audio, video, archive, text, code, generic)
    row.appendChild(h("span", { class: "folder-icon", "aria-hidden": "true" }, [iconFor(entry)]));

    // Main column: name + modified date
    const main = h("div", { class: "folder-main" });
    main.appendChild(h("div", { class: "folder-name" }, [entry.name]));
    const ts = entry.entry?.ts;
    if (ts) {
      main.appendChild(h("div", { class: "folder-date muted small" }, [shortDate(ts)]));
    }
    row.appendChild(main);

    // Size (folders show "—")
    row.appendChild(h("span", { class: "folder-size muted small" }, [
      entry.isDir ? "—" : formatBytes(entry.entry?.size ?? 0),
    ]));

    // Action buttons — hidden by default, shown on row hover/focus.
    const actions = h("span", { class: "folder-row-actions" });
    if (!entry.isDir && previewable(entry)) {
      const prevBtn = h("button", { type: "button", class: "btn-sm", title: "Preview" }, ["👁"]);
      prevBtn.addEventListener("click", (e) => { e.stopPropagation(); this.handlePreview(entry); });
      actions.appendChild(prevBtn);
    }
    if (!entry.isDir) {
      const dlBtn = h("button", { type: "button", class: "btn-sm", title: "Download" }, ["↓"]);
      dlBtn.addEventListener("click", (e) => { e.stopPropagation(); this.handleDownload(entry); });
      actions.appendChild(dlBtn);
    }
    const renameBtn = h("button", { type: "button", class: "btn-sm", title: "Rename" }, ["✎"]);
    renameBtn.addEventListener("click", (e) => { e.stopPropagation(); this.handleRename(entry); });
    actions.appendChild(renameBtn);
    if (!entry.isDir) {
      const histBtn = h("button", { type: "button", class: "btn-sm", title: "View history" }, ["⏱"]);
      histBtn.addEventListener("click", (e) => { e.stopPropagation(); this.handleHistory(entry); });
      actions.appendChild(histBtn);
    }
    const delBtn = h("button", { type: "button", class: "btn-sm btn-danger", title: "Delete" }, ["✕"]);
    delBtn.addEventListener("click", (e) => { e.stopPropagation(); this.handleDelete(entry); });
    actions.appendChild(delBtn);
    row.appendChild(actions);

    // Row-level click: navigate into folders / open preview for previewable
    // files. Clicks on actions stop propagation above, so those still
    // fire their own handlers cleanly.
    const activate = () => {
      if (entry.isDir) {
        this.currentDir = entry.path.endsWith("/") ? entry.path : entry.path + "/";
        this.searchQuery = "";
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
    try {
      for (const file of fileList) {
        await this.uploadOne(file);
      }
      await this.flushManifest();
      this.setMessage("info", `Uploaded ${fileList.length} file(s)`);
      this._fireChange({ op: "create", source: "local" });
    } catch (e) {
      console.error(e);
      this.setMessage("error", `Upload failed: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  async uploadOne(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const uuid = cryptoLib.newULID();
    const dataKey = cryptoLib.randomDataKey();
    const wrapped = await cryptoLib.wrapDataKey(this.session.masterKey, dataKey, uuid);
    const sealed = await cryptoLib.encrypt(dataKey, bytes, new TextEncoder().encode(uuid));
    // Object body layout: 12-byte content IV || ciphertext || GCM tag
    const body = new Uint8Array(sealed.iv.length + sealed.ciphertext.length);
    body.set(sealed.iv, 0);
    body.set(sealed.ciphertext, sealed.iv.length);

    const objUrl = this.session.bucketBase + OBJECTS_PREFIX + uuid;
    const put = await bucket.signedPut({
      url: objUrl,
      body,
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
        contentIv: sealed.iv,
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
      // Layout: 12-byte IV || ciphertext.
      if (get.body.length < 12) throw new Error("ciphertext too short (missing IV)");
      const iv = get.body.subarray(0, 12);
      const ct = get.body.subarray(12);
      const dataKey = await cryptoLib.unwrapDataKey(
        this.session.masterKey,
        cryptoLib.fromBase64(entry.entry.data_key_iv),
        cryptoLib.fromBase64(entry.entry.data_key_ct),
        entry.entry.uuid,
      );
      let plaintext;
      try {
        plaintext = await cryptoLib.decrypt(dataKey, iv, ct, new TextEncoder().encode(entry.entry.uuid));
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
    if (!confirm(`Delete ${entry.name}? This can't be undone.`)) return;
    this.busy = true;
    try {
      if (entry.entry?.uuid && !entry.isDir) {
        const objUrl = this.session.bucketBase + OBJECTS_PREFIX + entry.entry.uuid;
        const del = await bucket.signedDelete({
          url: objUrl,
          region: this.session.region,
          accessKey: this.session.accessKey,
          secretKey: this.session.secretKey,
        });
        if (!del.ok) throw new Error(`DELETE object failed: ${del.status} ${del.message}`);
      }
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

  async handleRename(entry) {
    const newName = prompt(`Rename "${entry.name}" to:`, entry.name);
    if (!newName || newName === entry.name) return;
    if (newName.includes("/")) {
      this.setMessage("error", "Names cannot contain slashes (use Move for that)");
      return;
    }
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
    const name = prompt("New folder name:");
    if (!name) return;
    if (name.includes("/")) { this.setMessage("error", "Folder names cannot contain slashes"); return; }
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

  // flushManifest re-encrypts the current in-memory manifest and PUTs it
  // back to the bucket with If-Match against session.manifestETag
  // (concurrent-write safety). On 412 (a peer wrote between our last GET
  // and this PUT) we re-GET, replay our pending events on top, and retry.
  // Caller has already set `this.busy = true`.
  async flushManifest() {
    const maxRetries = 3;
    let localEventsToReplay = this.session.manifest.events.slice(
      this.session.lastFlushedEventCount ?? 0,
    );

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const bytes = await this.session.manifest.encryptToBytes(this.session.masterKey);
      const manifestUrl = this.session.bucketBase + MANIFEST_PATH;
      const put = await bucket.signedPut({
        url: manifestUrl,
        body: bytes,
        contentType: "application/octet-stream",
        ifMatch: this.session.manifestETag,
        region: this.session.region,
        accessKey: this.session.accessKey,
        secretKey: this.session.secretKey,
      });
      if (put.ok) {
        this.session.manifestETag = put.etag || null;
        this.session.lastFlushedEventCount = this.session.manifest.events.length;
        return;
      }
      if (put.preconditionFailed && attempt < maxRetries) {
        const got = await bucket.signedGet({
          url: manifestUrl,
          region: this.session.region,
          accessKey: this.session.accessKey,
          secretKey: this.session.secretKey,
        });
        if (!got.ok) throw new Error(`flushManifest: re-GET after 412 failed (${got.status})`);
        const fresh = await Manifest.loadFromBytes(got.body, this.session.masterKey);
        this.session.manifest.events = fresh.events;
        this.session.manifest._lastSig = fresh._lastSig;
        for (const e of localEventsToReplay) {
          const partial = { ...e };
          delete partial.v;
          delete partial.ts;
          delete partial.prev_sig;
          delete partial.sig;
          await this.session.manifest.append(partial, this.session.masterKey);
        }
        this.session.manifestETag = got.etag || null;
        continue;
      }
      throw new Error(`PUT manifest failed: ${put.status} ${put.message}`);
    }
    throw new Error("flushManifest: too many ETag-conflict retries");
  }

  // --- device pairing UI -----------------------------------------------

  // handlePair opens a modal that mints a CRATE-PAIR token via
  // POST /v1/pairing/intent against the transport, displays the token
  // (text + future QR), shows a countdown, and offers a Cancel button.
  //
  // The transport endpoint is read from this.session.transportEndpoint.
  // First-time-setup doesn't yet collect this — for v1.0 the user pastes
  // it manually in the pair modal. Once nakliOS Settings ships, the
  // transport URL is part of the bucket-registration record.
  async handlePair() {
    if (this._pairModalOpen) return;
    this._pairModalOpen = true;
    const transportUrl = window.prompt(
      "Transport URL (e.g. https://my-hub.example.com or your CF Worker URL):",
      this.session.transportEndpoint || "",
    );
    if (!transportUrl) {
      this._pairModalOpen = false;
      return;
    }
    this.session.transportEndpoint = transportUrl.trim();

    // The user also needs a Grant that authorises identity:pair. For
    // v1.0 the simplest path is asking the user to paste it. Once nakliOS
    // Settings ships, a Grant for the active bucket is part of the
    // session and this prompt goes away.
    const grant = window.prompt(
      "Paste an identity-pair Grant (base64 macaroon from nakli-cli grant mint):",
      "",
    );
    if (!grant) {
      this._pairModalOpen = false;
      return;
    }

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
      const bytes = await credsfile.pack({
        provider: "r2",
        bucket: { name: bucketName, accountId, region: this.session.region || "auto" },
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
        if (get.body.length < 12) throw new Error("ciphertext too short");
        const iv = get.body.subarray(0, 12);
        const ct = get.body.subarray(12);
        const dataKey = await cryptoLib.unwrapDataKey(
          this.session.masterKey,
          cryptoLib.fromBase64(entry.entry.data_key_iv),
          cryptoLib.fromBase64(entry.entry.data_key_ct),
          entry.entry.uuid,
        );
        try {
          bytes = await cryptoLib.decrypt(dataKey, iv, ct, new TextEncoder().encode(entry.entry.uuid));
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
    bucket_id: session.bucketBase, // stand-in until nakliOS Settings provides a real bucket_id
    identity_pubkey: "browser-stub", // real Ed25519 pubkey lands with nakliOS Identity binding
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
