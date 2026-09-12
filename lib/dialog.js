// SPDX-License-Identifier: AGPL-3.0-or-later
// In-app form dialog — replaces window.prompt(). A prompt() is browser
// chrome: it ignores the theme, blocks the tab, cannot validate as you
// type, and on a phone a mis-aimed tap has frozen the renderer (2026-09-10
// walk). This is the same overlay + card the delete confirmation uses,
// with one or more labelled fields, inline validation, Enter to confirm,
// Escape to cancel, a focus trap, and focus returned to the opener.
//
//   const r = await formDialog({
//     title: "New folder",
//     fields: [{ key: "name", label: "Name", value: "", autofocus: true }],
//     confirmLabel: "Create",
//     validate: (values) => values.name ? null : "Give the folder a name.",
//   });
//   // r === null on cancel, else { name: "…" }
//
// promptDialog() is the one-field shortcut that resolves the string.

function node(tag, attrs = {}, children = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else n.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return n;
}

let counter = 0;

// formDialog opens the dialog and resolves with the field values (an
// object keyed by field.key) or null when dismissed. `validate(values)`
// returns an error string to block confirmation, or null/undefined to
// allow it; it runs on every input so the message tracks the typing.
export function formDialog({
  title,
  description = "",
  fields = [],
  confirmLabel = "OK",
  cancelLabel = "Cancel",
  danger = false,
  validate = null,
  returnFocus = null,
} = {}) {
  const opener = returnFocus || document.activeElement;
  const id = `dlg-${++counter}`;

  return new Promise((resolve) => {
    const overlay = node("div", { class: "pair-overlay form-overlay" });
    const card = node("form", {
      class: "pair-card form-card",
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": `${id}-title`,
      "aria-describedby": description ? `${id}-desc` : null,
      novalidate: "novalidate",
    });
    overlay.appendChild(card);
    card.appendChild(node("h2", { id: `${id}-title` }, [title]));
    if (description) card.appendChild(node("p", { id: `${id}-desc`, class: "muted" }, [description]));

    const inputs = new Map();
    fields.forEach((f, i) => {
      const fid = `${id}-${f.key}`;
      const common = {
        id: fid,
        class: "input" + (f.mono ? " mono" : ""),
        placeholder: f.placeholder || null,
        autocomplete: "off",
        spellcheck: "false",
        "aria-describedby": `${id}-error`,
      };
      let input;
      if (f.type === "select") {
        input = node("select", { ...common });
        for (const o of f.options || []) {
          const opt = node("option", { value: o.value }, [o.label]);
          if (String(o.value) === String(f.value)) opt.selected = true;
          input.appendChild(opt);
        }
      } else {
        input = f.multiline
          ? node("textarea", { ...common, rows: String(f.rows || 4) })
          : node("input", { ...common, type: f.type || "text" });
        input.value = f.value ?? "";
        if (f.readonly) input.readOnly = true;
      }
      if (f.autofocus || (i === 0 && !fields.some((x) => x.autofocus))) input.dataset.autofocus = "1";
      inputs.set(f.key, input);
      const extras = [];
      if (f.copy) {
        const copyBtn = node("button", { type: "button", class: "btn btn-secondary copy-btn" }, ["Copy"]);
        copyBtn.addEventListener("click", async () => {
          let ok = false;
          try { await navigator.clipboard.writeText(input.value); ok = true; } catch {}
          copyBtn.textContent = ok ? "✓ Copied" : "Copy failed";
          copyBtn.classList.toggle("copy-ok", ok); copyBtn.classList.toggle("copy-fail", !ok);
          setTimeout(() => { copyBtn.textContent = "Copy"; copyBtn.classList.remove("copy-ok", "copy-fail"); }, 1600);
        });
        extras.push(node("div", { class: "row" }, [copyBtn]));
      }
      card.appendChild(node("div", { class: "field" }, [
        node("label", { for: fid }, [f.label]),
        input,
        f.help ? node("p", { class: "field-help muted" }, [f.help]) : null,
        ...extras,
      ]));
    });

    const error = node("p", { id: `${id}-error`, class: "form-error", role: "alert", hidden: "hidden" });
    card.appendChild(error);

    const cancelBtn = node("button", { type: "button", class: "btn btn-secondary" }, [cancelLabel || "Cancel"]);
    const okBtn = node("button", { type: "submit", class: danger ? "btn btn-danger-primary" : "btn btn-primary" }, [confirmLabel]);
    card.appendChild(node("div", { class: "dialog-actions" }, [cancelLabel === null ? null : cancelBtn, okBtn]));

    const values = () => {
      const out = {};
      for (const [k, el] of inputs) out[k] = el.value;
      return out;
    };
    const check = () => {
      const msg = validate ? validate(values()) : null;
      if (msg) {
        error.textContent = msg;
        error.hidden = false;
        okBtn.disabled = true;
      } else {
        error.hidden = true;
        okBtn.disabled = false;
      }
      return !msg;
    };
    let settled = false;
    const close = (result) => {
      if (settled) return;
      settled = true;
      document.removeEventListener("keydown", onKey, true);
      overlay.remove();
      resolve(result);
      if (opener && typeof opener.focus === "function") {
        try { opener.focus(); } catch {}
      }
    };
    const focusables = () => [...card.querySelectorAll("input, textarea, button:not([disabled])")];
    const onKey = (event) => {
      if (event.key === "Escape") { event.preventDefault(); close(null); return; }
      if (event.key !== "Tab") return;
      const list = focusables();
      if (list.length === 0) return;
      const first = list[0], last = list[list.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };

    for (const el of inputs.values()) {
      el.addEventListener("input", check);
      el.addEventListener("change", check);
      // Enter in a single-line field confirms (explicitly, not via the
      // browser's implicit submission, so it behaves the same everywhere);
      // in a textarea it inserts a newline.
      if (el.tagName === "INPUT") {
        el.addEventListener("keydown", (event) => {
          if (event.key === "Enter" && !event.isComposing) {
            event.preventDefault();
            if (check()) close(values());
          }
        });
      }
    }

    card.addEventListener("submit", (event) => {
      event.preventDefault();
      if (check()) close(values());
    });
    cancelBtn.addEventListener("click", () => close(null));
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) close(null);
    });
    document.addEventListener("keydown", onKey, true);

    document.body.appendChild(overlay);
    check();
    const first = card.querySelector("[data-autofocus]") || focusables()[0] || okBtn;
    if (first) {
      first.focus();
      if (typeof first.select === "function" && (first.tagName === "INPUT" || first.readOnly)) first.select();
    }
  });
}

// promptDialog: one text field, resolves the trimmed string or null.
export async function promptDialog({ title, description, label, value = "", placeholder, confirmLabel = "OK", validate = null, returnFocus = null, mono = false } = {}) {
  const r = await formDialog({
    title, description, confirmLabel, returnFocus,
    fields: [{ key: "value", label, value, placeholder, mono, autofocus: true }],
    validate: validate ? (v) => validate(v.value.trim()) : null,
  });
  return r === null ? null : r.value.trim();
}
