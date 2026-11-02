// U1: Settings → Updates and the update banner (update.js). The exact
// strings are the approved ones (docs/UPDATES.md); the page only reads
// the state the app reports and never polls.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SRC = fs.readFileSync(path.join(__dirname, "..", "ui", "update.js"), "utf8");
const HTML = fs.readFileSync(path.join(__dirname, "..", "ui", "devices.html"), "utf8");

function el() {
  const classes = new Set();
  const e = { listeners: {}, textContent: "", checked: false, disabled: false };
  e.classList = {
    toggle: (c, on) => (on ? classes.add(c) : classes.delete(c)),
    contains: (c) => classes.has(c),
  };
  e.addEventListener = (ev, fn) => (e.listeners[ev] = fn);
  return e;
}

async function flush() {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
}

const BASE = {
  available_in_build: true, version: "1.0.0", kind: "windows", checks_on: true, test_builds: false,
  auto_install: false, status: "", offer_version: null, offer_size: null, phase: "", percent: 0,
  error: null, dismissed: false,
};

function load(state) {
  const els = {};
  const calls = [];
  const timers = [];
  const ctx = {
    document: { getElementById: (id) => (els[id] = els[id] || el()) },
    window: {
      __TAURI__: {
        core: {
          invoke: async (cmd, args) => {
            calls.push([cmd, args]);
            return cmd === "update_state" ? { ...BASE, ...state } : null;
          },
        },
      },
    },
    setTimeout: (...a) => timers.push(a),
    setInterval: (...a) => timers.push(a),
  };
  vm.runInNewContext(SRC, ctx);
  return { $: (id) => ctx.document.getElementById(id), calls, timers, window: ctx.window };
}

test("the Updates section has the approved strings", () => {
  for (const s of [
    ">Updates<",
    ">Check for updates<",
    "At most once a day, when Voidwire starts or you open this window. Only asks GitHub for the latest version; nothing about you or your devices is sent.",
    ">Test builds<",
    "Get early versions before everyone else. They may have bugs.",
    ">Install updates automatically<",
    ">Check now<",
    ">Update available<",
    ">What's new<",
    ">Not now<",
  ]) {
    assert.ok(HTML.includes(s), s);
  }
});

test("up to date, failed and off status lines", async () => {
  let p = load({ status: "uptodate" });
  await flush();
  assert.strictEqual(p.$("upd-status").textContent, "You're up to date (Voidwire 1.0.0).");
  assert.strictEqual(p.$("upd-version").textContent, "Version 1.0.0");
  assert.ok(p.$("upd-banner").classList.contains("hidden"));
  p = load({ status: "failed" });
  await flush();
  assert.strictEqual(p.$("upd-status").textContent, "Couldn't check for updates. Try again later.");
  p = load({ checks_on: false });
  await flush();
  assert.strictEqual(p.$("upd-status").textContent, "Update checks are off.");
  p = load({ status: "checking" });
  await flush();
  assert.strictEqual(p.$("upd-status").textContent, "Checking…");
});

test("banner: offer, Not now, download progress, ready, AppImage, deb", async () => {
  let p = load({ offer_version: "1.1.0", offer_size: 12 * 1024 * 1024 });
  await flush();
  assert.ok(!p.$("upd-banner").classList.contains("hidden"));
  assert.strictEqual(p.$("upd-body").textContent, "Voidwire 1.1.0 is ready to download (12.0 MB).");
  assert.strictEqual(p.$("upd-go").textContent, "Update");
  p = load({ offer_version: "1.1.0", offer_size: 1, dismissed: true });
  await flush();
  assert.ok(p.$("upd-banner").classList.contains("hidden"));
  p = load({ offer_version: "1.1.0", offer_size: 1, phase: "downloading", percent: 42 });
  await flush();
  assert.strictEqual(p.$("upd-body").textContent, "Downloading… 42%");
  p = load({ offer_version: "1.1.0", offer_size: 1, phase: "verifying" });
  await flush();
  assert.strictEqual(p.$("upd-body").textContent, "Checking the download…");
  p = load({ offer_version: "1.1.0", offer_size: 1, phase: "ready" });
  await flush();
  assert.strictEqual(p.$("upd-body").textContent, "Ready to install. Voidwire will close and start again.");
  assert.strictEqual(p.$("upd-go").textContent, "Install now");
  assert.strictEqual(p.$("upd-later").textContent, "Later");
  p = load({ offer_version: "1.1.0", offer_size: 1, phase: "ready", auto_install: true });
  await flush();
  assert.strictEqual(p.$("upd-body").textContent, "Update ready. It will install when you quit Voidwire.");
  p = load({ kind: "appimage", offer_version: "1.1.0", offer_size: 1, phase: "installed" });
  await flush();
  assert.strictEqual(p.$("upd-body").textContent, "Update installed. Restart Voidwire to use it.");
  assert.strictEqual(p.$("upd-go").textContent, "Restart now");
  p = load({ kind: "deb", offer_version: "1.1.0", offer_size: 1 });
  await flush();
  assert.strictEqual(p.$("upd-go").textContent, "Download");
  assert.ok(p.$("upd-auto-row").classList.contains("hidden"));
  p = load({ offer_version: "1.1.0", offer_size: 1, error: "The installer was cancelled." });
  await flush();
  assert.strictEqual(p.$("upd-err").textContent, "The installer was cancelled.");
});

test("clicks go to the app; no timers; builds without updates hide everything", async () => {
  let p = load({ offer_version: "1.1.0", offer_size: 1 });
  await flush();
  await p.$("upd-go").listeners.click({ isTrusted: true });
  await p.$("upd-later").listeners.click({ isTrusted: true });
  await p.$("upd-check").listeners.click({ isTrusted: true });
  await p.$("upd-checks").listeners.change({ isTrusted: true, target: { checked: false } });
  await p.$("upd-go").listeners.click({ isTrusted: false });
  const cmds = p.calls.map((c) => c[0]).filter((c) => c !== "update_state");
  assert.deepStrictEqual(cmds, ["update_start", "update_not_now", "update_check_now", "update_set_checks"]);
  assert.strictEqual(JSON.stringify(p.calls.find((c) => c[0] === "update_set_checks")[1]), "{\"on\":false}");
  assert.strictEqual(p.timers.length, 0);
  assert.strictEqual(typeof p.window.vwUpdate, "function");
  p = load({ available_in_build: false, offer_version: "1.1.0" });
  await flush();
  assert.ok(p.$("upd-section").classList.contains("hidden"));
  assert.ok(p.$("upd-banner").classList.contains("hidden"));
});
