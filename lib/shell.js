// SPDX-License-Identifier: AGPL-3.0-or-later
// The app shell: topbar (wordmark, search, actions) + sidebar (views).
// The markup is static in index.html; this module wires it and exposes
// a small surface the wizard entrypoint and FolderUI drive:
//
//   shell.setLocked(bool)        dim + inert sidebar, disable search
//   shell.setActive(view)        highlight a sidebar item
//   shell.onNavigate(fn)         fn(view) on sidebar click
//   shell.onSearch(fn)           fn(query) on topbar search input
//   shell.setSearch(value)       programmatic clear / set
//   shell.setStats(text)         the sidebar footer line
//   shell.setCounts({photos})    per-view counts next to the label
//   shell.setMenu([{label, icon, onClick, danger}])   the ··· menu
//   shell.onHelp(fn)             "How it works" in the locked topbar
//
// The shell is always on screen — locked, it frames the landing card
// and the wizard; unlocked, it frames the folder.

import { icon } from "./icons.js";

export function createShell({ root }) {
  if (!root) throw new Error("createShell: { root } is required");

  const sidebar = root.querySelector(".sidebar");
  const items = [...root.querySelectorAll(".side-item[data-view]")];
  const searchInput = root.querySelector("#shell-search");
  const helpBtn = root.querySelector("#shell-help");
  const encPill = root.querySelector("#shell-enc");
  const menuBtn = root.querySelector("#shell-menu-btn");
  const menuHost = root.querySelector("#shell-menu");
  const stats = root.querySelector("#side-stats");

  let navHandler = null;
  let searchHandler = null;
  let helpHandler = null;
  let menuItems = [];
  let locked = true;

  for (const item of items) {
    item.addEventListener("click", () => {
      if (locked) return;
      if (navHandler) navHandler(item.dataset.view);
    });
  }
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      if (searchHandler) searchHandler(e.target.value);
    });
    searchInput.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && searchInput.value) {
        searchInput.value = "";
        if (searchHandler) searchHandler("");
      }
    });
  }
  if (helpBtn) helpBtn.addEventListener("click", () => { if (helpHandler) helpHandler(helpBtn); });

  // ··· menu: a plain popover of buttons. Closes on outside click,
  // Escape, or after any item fires.
  function closeMenu() {
    if (!menuHost) return;
    menuHost.hidden = true;
    if (menuBtn) menuBtn.setAttribute("aria-expanded", "false");
    document.removeEventListener("pointerdown", onOutside, true);
    document.removeEventListener("keydown", onKey, true);
  }
  function onOutside(e) {
    if (menuHost.contains(e.target) || menuBtn.contains(e.target)) return;
    closeMenu();
  }
  function onKey(e) {
    if (e.key === "Escape") { closeMenu(); menuBtn.focus(); }
  }
  function openMenu() {
    if (!menuHost || menuItems.length === 0) return;
    while (menuHost.firstChild) menuHost.removeChild(menuHost.firstChild);
    for (const it of menuItems) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "shell-menu-item" + (it.danger ? " danger" : "");
      b.setAttribute("role", "menuitem");
      if (it.icon) b.appendChild(icon(it.icon, { size: 16 }));
      b.appendChild(document.createTextNode(it.label));
      b.addEventListener("click", () => { closeMenu(); it.onClick(); });
      menuHost.appendChild(b);
    }
    menuHost.hidden = false;
    menuBtn.setAttribute("aria-expanded", "true");
    const first = menuHost.querySelector("button");
    if (first) first.focus();
    document.addEventListener("pointerdown", onOutside, true);
    document.addEventListener("keydown", onKey, true);
  }
  if (menuBtn) {
    menuBtn.addEventListener("click", () => {
      if (menuHost.hidden) openMenu(); else closeMenu();
    });
  }

  function setLocked(v) {
    locked = !!v;
    root.classList.toggle("shell-locked", locked);
    if (sidebar) sidebar.setAttribute("aria-hidden", locked ? "true" : "false");
    for (const item of items) item.disabled = locked;
    if (searchInput) {
      searchInput.disabled = locked;
      if (locked) searchInput.value = "";
    }
    if (helpBtn) helpBtn.hidden = !locked;
    if (encPill) encPill.hidden = locked;
    if (menuBtn) menuBtn.hidden = locked;
    if (locked) { closeMenu(); setStats(""); setCounts({}); setActive("all"); }
  }

  function setActive(view) {
    for (const item of items) {
      const on = item.dataset.view === view;
      item.classList.toggle("active", on);
      if (on) item.setAttribute("aria-current", "page"); else item.removeAttribute("aria-current");
    }
  }

  function setStats(text) {
    if (stats) stats.textContent = text || "";
  }

  function setCounts(counts) {
    for (const item of items) {
      const badge = item.querySelector(".side-count");
      if (!badge) continue;
      const n = counts[item.dataset.view];
      badge.textContent = typeof n === "number" && n > 0 ? String(n) : "";
    }
  }

  function setSearch(value) {
    if (searchInput) searchInput.value = value || "";
  }

  setLocked(true);

  return {
    setLocked,
    setActive,
    setStats,
    setCounts,
    setSearch,
    setMenu(items) { menuItems = Array.isArray(items) ? items : []; closeMenu(); },
    onNavigate(fn) { navHandler = fn; },
    onSearch(fn) { searchHandler = fn; },
    onHelp(fn) { helpHandler = fn; },
    focusSearch() { if (searchInput && !searchInput.disabled) searchInput.focus(); },
  };
}
