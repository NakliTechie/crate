// SPDX-License-Identifier: AGPL-3.0-or-later
// M4 — folder UI. Renders the manifest as a file tree; supports upload,
// download, delete, rename, mkdir, move. Mounts into #folder-root and
// replaces the wizard once first-time setup completes.
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

const OBJECTS_PREFIX = "objects/";

// FolderUI — the M4 surface. Construct via `mount(root, session, opts)`.
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
  }

  buildHeader() {
    const wrap = h("header", { class: "folder-header" });
    wrap.appendChild(h("h1", {}, ["Your Crate"]));
    wrap.appendChild(h("p", { class: "muted small" }, [
      "Files are end-to-end encrypted in the bucket. Only this device, with this passphrase, can read them.",
    ]));

    const fileInput = h("input", { type: "file", id: "folder-upload-input", multiple: "multiple", style: "display:none" });
    fileInput.addEventListener("change", (e) => this.handleUploadFiles(e.target.files));

    const uploadBtn = h("button", { type: "button", class: "btn btn-primary" }, ["Upload file"]);
    uploadBtn.addEventListener("click", () => fileInput.click());

    const mkdirBtn = h("button", { type: "button", class: "btn btn-secondary" }, ["New folder"]);
    mkdirBtn.addEventListener("click", () => this.handleMkdir());

    const refreshBtn = h("button", { type: "button", class: "btn btn-secondary" }, ["Refresh"]);
    refreshBtn.addEventListener("click", () => this.handleRefresh());

    wrap.appendChild(h("div", { class: "folder-actions row" }, [
      uploadBtn, mkdirBtn, refreshBtn, fileInput,
    ]));

    // Path breadcrumb.
    const crumb = h("nav", { class: "folder-breadcrumb", "aria-label": "Current folder" });
    const segs = this.currentDir === "/" ? ["/"] : this.currentDir.replace(/\/$/, "").split("/").filter((s) => s.length > 0);
    crumb.appendChild(this.crumbLink("/", "Home"));
    if (this.currentDir !== "/") {
      let acc = "";
      for (const s of segs) {
        acc += "/" + s;
        crumb.appendChild(document.createTextNode(" / "));
        crumb.appendChild(this.crumbLink(acc + "/", s));
      }
    }
    wrap.appendChild(crumb);

    return wrap;
  }

  crumbLink(path, label) {
    const a = h("a", { href: "#", class: "deep-link folder-crumb" }, [label]);
    a.addEventListener("click", (e) => {
      e.preventDefault();
      this.currentDir = path;
      this.render();
    });
    return a;
  }

  buildTree() {
    const wrap = h("ul", { class: "folder-tree", "aria-label": "Files in this folder" });
    const entries = this.entriesInCurrentDir();
    if (entries.length === 0) {
      wrap.appendChild(h("li", { class: "folder-empty muted" }, ["(empty)"]));
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
    const row = h("li", { class: entry.isDir ? "folder-row folder-row-dir" : "folder-row folder-row-file" });

    const label = entry.isDir
      ? h("a", { href: "#", class: "folder-name folder-name-dir" }, ["📁 " + entry.name])
      : h("span", { class: "folder-name" }, ["📄 " + entry.name]);
    if (entry.isDir) {
      label.addEventListener("click", (e) => {
        e.preventDefault();
        this.currentDir = entry.path.endsWith("/") ? entry.path : entry.path + "/";
        this.render();
      });
    }
    row.appendChild(label);

    const meta = h("span", { class: "folder-meta muted small" }, [
      entry.isDir ? "" : formatBytes(entry.entry?.size ?? 0),
    ]);
    row.appendChild(meta);

    // Per-row actions.
    const actions = h("span", { class: "folder-row-actions" });
    if (!entry.isDir) {
      const dlBtn = h("button", { type: "button", class: "btn-sm btn-secondary", title: "Download" }, ["↓"]);
      dlBtn.addEventListener("click", () => this.handleDownload(entry));
      actions.appendChild(dlBtn);
    }
    const renameBtn = h("button", { type: "button", class: "btn-sm btn-secondary", title: "Rename" }, ["✎"]);
    renameBtn.addEventListener("click", () => this.handleRename(entry));
    actions.appendChild(renameBtn);
    const delBtn = h("button", { type: "button", class: "btn-sm btn-danger", title: "Delete" }, ["✕"]);
    delBtn.addEventListener("click", () => this.handleDelete(entry));
    actions.appendChild(delBtn);
    row.appendChild(actions);

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
      const plaintext = await cryptoLib.decrypt(dataKey, iv, ct, new TextEncoder().encode(entry.entry.uuid));
      cryptoLib.zero(dataKey);

      // Trigger browser download.
      const blob = new Blob([plaintext], { type: entry.entry.mime || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = h("a", { href: url, download: entry.name, style: "display:none" });
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      this.setMessage("info", `Downloaded ${entry.name}`);
    } catch (e) {
      console.error(e);
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
      this.session.manifest = await Manifest.loadFromBytes(get.body, this.session.masterKey);
      this.setMessage("info", "Refreshed");
    } catch (e) {
      console.error(e);
      this.setMessage("error", `Refresh failed: ${e.message ?? e}`);
    } finally {
      this.busy = false;
    }
  }

  // flushManifest re-encrypts the current in-memory manifest and PUTs it
  // back to the bucket. Called after every mutating operation. Caller has
  // already set `this.busy = true`.
  async flushManifest() {
    const bytes = await this.session.manifest.encryptToBytes(this.session.masterKey);
    const manifestUrl = this.session.bucketBase + MANIFEST_PATH;
    const put = await bucket.signedPut({
      url: manifestUrl,
      body: bytes,
      contentType: "application/octet-stream",
      region: this.session.region,
      accessKey: this.session.accessKey,
      secretKey: this.session.secretKey,
    });
    if (!put.ok) throw new Error(`PUT manifest failed: ${put.status} ${put.message}`);
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
