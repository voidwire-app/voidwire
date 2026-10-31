// Shared fake DOM for the Devices window tests: loads the real devices.js
// against a permissive fake DOM and a stubbed core.
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SRC = fs.readFileSync(path.join(__dirname, "..", "ui", "devices.js"), "utf8");

// A fake element: real props for what the tests read, no-ops for the rest.
function el(tag) {
  const store = { tag, children: [], listeners: {}, style: {}, dataset: {}, value: "", textContent: "" };
  const classes = new Set();
  store.classList = {
    add: (...c) => c.forEach((x) => classes.add(x)),
    remove: (...c) => c.forEach((x) => classes.delete(x)),
    toggle: (c, on) => ((on === undefined ? !classes.has(c) : on) ? classes.add(c) : classes.delete(c)),
    contains: (c) => classes.has(c),
  };
  store.append = (...c) => store.children.push(...c);
  store.appendChild = (c) => (store.children.push(c), c);
  store.replaceChildren = (...c) => store.children.splice(0, store.children.length, ...c);
  store.addEventListener = (ev, fn) => (store.listeners[ev] = fn);
  store.querySelector = () => null;
  store.querySelectorAll = () => [];
  return new Proxy(store, {
    get: (t, k) => (k in t ? t[k] : typeof k === "string" && /^[a-z]/.test(k) ? () => {} : undefined),
    set: (t, k, v) => ((t[k] = v), true),
  });
}

async function flush() {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
}

const A = "a".repeat(64);
const B = "b".repeat(64);
const DEVICES = [
  { id: A, name: "Pixel", platform: "android" },
  { id: B, name: "Desk", platform: "windows" },
];

function load({ pending = null, saved = "", failSet = 0, old = false } = {}) {
  const els = {};
  const calls = [];
  const answer = (cmd, args) => {
    if (cmd === "settings_get") {
      const s = { pc_name: "Desk PC", pc_id: "x", listening: ["0.0.0.0:1"], theme: "system", app_version: "0", core_version: "0", send_clipboard_shortcut: true, send_clipboard_shortcut_device: saved, pending_ui_send_error: pending, old_pairings_dropped: old };
      pending = null; // consumed once, like the core
      return s;
    }
    if (cmd === "devices_list") return DEVICES;
    if (cmd === "send_clipboard_to_phone") return { delivery_path: "direct" };
    if (cmd === "settings_set_send_clipboard_shortcut_device") {
      if (failSet > 0) {
        failSet--;
        throw "Command not allowed";
      }
      saved = args.id;
      return null;
    }
    return null;
  };
  const document = {
    hidden: false,
    activeElement: null,
    getElementById: (id) => (els[id] = els[id] || el(id)),
    createElement: (tag) => el(tag),
    addEventListener: () => {},
    querySelector: () => null,
    querySelectorAll: () => [],
    documentElement: el("html"),
    body: el("body"),
  };
  const window = {
    __TAURI__: {
      core: { invoke: (cmd, args) => (calls.push({ cmd, args }), Promise.resolve().then(() => answer(cmd, args))) },
      event: { listen: () => Promise.resolve(() => {}) },
    },
    addEventListener: () => {},
    matchMedia: () => ({ matches: false, addEventListener: () => {} }),
    location: { search: "" },
  };
  const ctx = Object.assign(window, {
    document,
    navigator: { platform: "Win32", userAgent: "Windows" },
    setTimeout: () => 0,
    clearTimeout: () => {},
    setInterval: () => 0,
    clearInterval: () => {},
    console,
    Promise,
  });
  ctx.window = ctx; // the page's globals live on window, as in a browser
  vm.createContext(ctx);
  vm.runInContext(SRC, ctx);
  // A device row as devices.js builds it, and a child element inside it.
  const makeRow = (id) => {
    const row = el("div");
    row.className = "card row";
    row.dataset.deviceId = id;
    const inner = el("span");
    inner.closest = (sel) => (sel === ".row[data-device-id]" ? row : null);
    row.inner = inner;
    return row;
  };
  return { els, calls, $: document.getElementById, ctx, document, makeRow, makeEl: el };
}


module.exports = { el, load, flush, A, B, DEVICES };
