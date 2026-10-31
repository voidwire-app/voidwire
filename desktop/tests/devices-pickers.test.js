// Devices window, M4.5 pickers: the hotkey's clipboard picker (2+ devices,
// no fixed device) and the shortcut's "Sends to" select. Loads the real
// devices.js against a permissive fake DOM and a stubbed core. Runs with
// `node --test desktop/tests/devices-pickers.test.js`.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
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

function load({ pending = null, saved = "", failSet = 0 } = {}) {
  const els = {};
  const calls = [];
  const answer = (cmd, args) => {
    if (cmd === "settings_get") {
      const s = { pc_name: "Desk PC", pc_id: "x", listening: ["0.0.0.0:1"], theme: "system", app_version: "0", core_version: "0", send_clipboard_shortcut: true, send_clipboard_shortcut_device: saved, pending_ui_send_error: pending };
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
  return { els, calls, $: document.getElementById, ctx, document };
}

test("hotkey with 2+ devices: the clipboard picker lists every device and sends to the chosen one", async () => {
  const p = load({ pending: { error: "__pick_device_clipboard__", device_id: "", file_path: null } });
  await flush();
  const modal = p.$("relay-modal");
  assert.ok(!modal.classList.contains("hidden"), "picker shown");
  assert.strictEqual(p.$("relay-modal-title").textContent, "Send clipboard to…");
  const sel = p.$("relay-modal-body").children.find((c) => c.tag === "select");
  assert.ok(sel, "a device select");
  assert.deepStrictEqual(sel.children.map((o) => o.value), [A, B], "every device, nothing else");
  sel.value = B;
  await p.$("relay-modal-confirm").onclick();
  await flush();
  const send = p.calls.find((c) => c.cmd === "send_clipboard_to_phone");
  assert.deepStrictEqual(JSON.parse(JSON.stringify(send.args)), { id: B, relayDecision: null });
});

test("Explorer with 2+ devices: the file picker lists every device (and nothing else)", async () => {
  const p = load({ pending: { error: "__pick_phone__", device_id: "", file_path: "C:\\x\\report.pdf" } });
  await flush();
  assert.match(p.$("relay-modal-title").textContent, /^Choose a device for report\.pdf$/);
  const sel = p.$("relay-modal-body").children.find((c) => c.tag === "select");
  assert.deepStrictEqual(sel.children.map((o) => o.value), [A, B]);
});

test('"Sends to" lists Ask each time plus every device and saves the choice', async () => {
  const p = load({ saved: B });
  await flush();
  const sel = p.$("clipshortcut-device");
  assert.deepStrictEqual(sel.children.map((o) => o.value), ["", A, B]);
  assert.strictEqual(sel.children[0].textContent, "Ask each time");
  assert.strictEqual(sel.value, B, "the saved device is selected");
  await sel.listeners.change({ target: { value: "" } });
  await flush();
  const set = p.calls.filter((c) => c.cmd === "settings_set_send_clipboard_shortcut_device");
  assert.deepStrictEqual(JSON.parse(JSON.stringify(set.map((c) => c.args))), [{ id: "" }]);
});

test('"Sends to" falls back to Ask when the saved device is no longer paired', async () => {
  const p = load({ saved: "c".repeat(64) });
  await flush();
  assert.strictEqual(p.$("clipshortcut-device").value, "");
});

test('"Sends to" a PC saves it, shows no error, and switching back to Ask clears it', async () => {
  const p = load();
  await flush();
  const sel = p.$("clipshortcut-device");
  sel.value = B; // "Desk", a PC
  await sel.listeners.change({ target: sel });
  await flush();
  assert.strictEqual(p.$("clipshortcut-err").textContent, "");
  assert.strictEqual(sel.value, B);
  sel.value = "";
  await sel.listeners.change({ target: sel });
  await flush();
  assert.strictEqual(p.$("clipshortcut-err").textContent, "");
  assert.strictEqual(sel.value, "");
  const set = p.calls.filter((c) => c.cmd === "settings_set_send_clipboard_shortcut_device");
  assert.deepStrictEqual(JSON.parse(JSON.stringify(set.map((c) => c.args))), [{ id: B }, { id: "" }]);
});

test('"Sends to": a failed save reverts the select and the next good save clears the error', async () => {
  const p = load({ failSet: 1 });
  await flush();
  const sel = p.$("clipshortcut-device");
  p.document.activeElement = sel; // still focused after picking
  sel.value = B;
  await sel.listeners.change({ target: sel });
  await flush();
  assert.notStrictEqual(p.$("clipshortcut-err").textContent, "");
  assert.strictEqual(sel.value, "", "back on what the core holds (Ask), not the failed choice");
  sel.value = A;
  await sel.listeners.change({ target: sel });
  await flush();
  assert.strictEqual(p.$("clipshortcut-err").textContent, "");
  assert.strictEqual(sel.value, A);
});
