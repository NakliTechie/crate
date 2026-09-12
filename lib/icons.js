// SPDX-License-Identifier: AGPL-3.0-or-later
// Inline stroke icons for the shell and the folder UI. One consistent
// 24-unit grid, 2px strokes, recoloured through `currentColor`. Built as
// DOM nodes (no innerHTML on user-controlled strings — every path here
// is a literal). Emoji were the previous icon set; they render
// differently per platform and read as decoration, so they are gone.

const PATHS = {
  folder: ['<path d="M3 7h6l2 2h10v10H3z"/>'],
  "folder-plus": ['<path d="M3 7h6l2 2h10v10H3z"/>', '<path d="M12 12v5M9.5 14.5h5"/>'],
  file: ['<path d="M6 3h8l4 4v14H6z"/>', '<path d="M14 3v4h4"/>'],
  image: ['<rect x="3" y="5" width="18" height="14" rx="2"/>', '<path d="M3 16l5-5 4 4 3-3 6 6"/>', '<circle cx="16" cy="9" r="1.5"/>'],
  audio: ['<path d="M9 18V6l10-2v12"/>', '<circle cx="6.5" cy="18" r="2.5"/>', '<circle cx="16.5" cy="16" r="2.5"/>'],
  video: ['<rect x="3" y="6" width="13" height="12" rx="2"/>', '<path d="M16 10l5-3v10l-5-3"/>'],
  pdf: ['<path d="M6 3h8l4 4v14H6z"/>', '<path d="M14 3v4h4"/>', '<path d="M9 17v-5h1.5a1.5 1.5 0 010 3H9"/>'],
  archive: ['<rect x="3" y="4" width="18" height="5" rx="1"/>', '<path d="M5 9v11h14V9"/>', '<path d="M10 13h4"/>'],
  code: ['<path d="M8 8l-4 4 4 4"/>', '<path d="M16 8l4 4-4 4"/>', '<path d="M13.5 5l-3 14"/>'],
  text: ['<path d="M6 3h8l4 4v14H6z"/>', '<path d="M14 3v4h4"/>', '<path d="M9 12h6M9 16h6"/>'],
  clock: ['<circle cx="12" cy="12" r="9"/>', '<path d="M12 7v5l3 2"/>'],
  devices: ['<rect x="3" y="4" width="18" height="12" rx="2"/>', '<path d="M8 20h8"/>'],
  backup: ['<path d="M12 3v12"/>', '<path d="M7 10l5 5 5-5"/>', '<path d="M4 19h16"/>'],
  upload: ['<path d="M12 19V6"/>', '<path d="M6 12l6-6 6 6"/>'],
  download: ['<path d="M12 5v13"/>', '<path d="M6 12l6 6 6-6"/>'],
  search: ['<circle cx="11" cy="11" r="7"/>', '<path d="M20 20l-3.5-3.5"/>'],
  lock: ['<rect x="4" y="10" width="16" height="11" rx="2"/>', '<path d="M8 10V7a4 4 0 018 0v3"/>'],
  key: ['<circle cx="8" cy="14" r="4"/>', '<path d="M11 11l9-9"/>', '<path d="M16 4l3 3M18 6l2-2"/>'],
  refresh: ['<path d="M20 12a8 8 0 01-14.5 4.6"/>', '<path d="M4 12a8 8 0 0114.5-4.6"/>', '<path d="M4 4v4h4"/>', '<path d="M20 20v-4h-4"/>'],
  more: ['<circle cx="5" cy="12" r="1.6" fill="currentColor" stroke="none"/>', '<circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none"/>', '<circle cx="19" cy="12" r="1.6" fill="currentColor" stroke="none"/>'],
  eye: ['<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/>', '<circle cx="12" cy="12" r="3"/>'],
  pencil: ['<path d="M4 20h4l11-11-4-4L4 16z"/>', '<path d="M13 7l4 4"/>'],
  history: ['<path d="M4 12a8 8 0 108-8"/>', '<path d="M4 4v4h4"/>', '<path d="M12 8v4l3 2"/>'],
  trash: ['<path d="M4 7h16"/>', '<path d="M9 7V4h6v3"/>', '<path d="M6 7l1 13h10l1-13"/>'],
  x: ['<path d="M6 6l12 12M18 6L6 18"/>'],
  shield: ['<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/>'],
  bucket: ['<path d="M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z"/>', '<path d="M4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7"/>'],
  slash: ['<circle cx="12" cy="12" r="9"/>', '<path d="M6 6l12 12"/>'],
};

const tpl = document.createElement("template");

// icon(name, { size, class }) → <svg> element. Unknown names fall back to
// the generic file glyph so a typo never renders an empty box.
export function icon(name, { size = 18, className = "" } = {}) {
  const paths = PATHS[name] || PATHS.file;
  tpl.innerHTML =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${size}" height="${size}" ` +
    `fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ` +
    `aria-hidden="true" focusable="false"${className ? ` class="${className}"` : ""}>${paths.join("")}</svg>`;
  return tpl.content.firstElementChild.cloneNode(true);
}

// fileIconName picks the glyph for a folder-UI entry from its mime type
// or extension: folder, image, audio, video, pdf, archive, code, text,
// or the generic file.
export function fileIconName(entry) {
  if (entry.isDir) return "folder";
  const mime = (entry.entry?.mime || "").toLowerCase();
  const ext = (entry.name || "").toLowerCase().split(".").pop();
  if (mime.startsWith("image/") || ["png","jpg","jpeg","gif","webp","svg","bmp","avif","ico","heic"].includes(ext)) return "image";
  if (mime.startsWith("audio/") || ["mp3","wav","flac","ogg","aac","m4a","opus"].includes(ext)) return "audio";
  if (mime.startsWith("video/") || ["mp4","mov","avi","mkv","webm","m4v"].includes(ext)) return "video";
  if (mime === "application/pdf" || ext === "pdf") return "pdf";
  if (["zip","tar","gz","tgz","bz2","xz","7z","rar"].includes(ext)) return "archive";
  if (["js","jsx","ts","tsx","html","htm","css","sh","py","go","rs","rb","java","c","h","cpp","hpp","sql","swift","kt","php","lua","r"].includes(ext)) return "code";
  if (mime.startsWith("text/") || mime === "application/json" || mime === "application/xml" ||
      ["txt","md","markdown","json","xml","yaml","yml","csv","tsv","log","ini","conf","toml"].includes(ext)) return "text";
  return "file";
}
