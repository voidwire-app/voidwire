// Popup behavior after a send (M4.2): success shows for AUTO_CLOSE_MS and
// then closes the popup; a failure or a relay question keeps it open.
// Runs with `node --test extension/tests/popup.test.js` (no browser needed).
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SRC = fs.readFileSync(path.join(__dirname, "..", "popup.js"), "utf8");

function el(id) {
  const listeners = {};
  const classes = new Set(id === "relay-card" ? ["hidden"] : []);
  return {
    id,
    value: "",
    disabled: false,
    textContent: "",
    title: "",
    className: "",
    classList: {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      toggle: (c, on) => (on ? classes.add(c) : classes.delete(c)),
      contains: (c) => classes.has(c),
    },
    addEventListener: (ev, fn) => (listeners[ev] = fn),
    replaceChildren: () => {},
    append: () => {},
    fire: (ev, arg) => listeners[ev](arg || { key: "", preventDefault() {} }),
  };
}

// Load popup.js against a fake DOM and extension API. `reply(req)` answers
// each host request (the status probe included).
function loadPopup(reply, flavor = "chromium") {
  const els = {};
  const timers = [];
  const win = { closed: 0 };
  const api = {
    runtime: {
      lastError: null,
      sendMessage: (req, cb) => Promise.resolve().then(() => cb(reply(req))),
    },
    tabs: { query: (_q, cb) => cb([{ url: "https://example.com/page" }]) },
  };
  const ctx = {
    // Firefox exposes `browser`; Chromium only `chrome`.
    ...(flavor === "firefox" ? { browser: api } : { chrome: api }),
    document: {
      getElementById: (id) => (els[id] = els[id] || el(id)),
      createElement: () => el("option"),
    },
    window: { close: () => (win.closed += 1) },
    setTimeout: (fn, ms) => {
      timers.push({ fn, ms });
      return timers.length;
    },
    console,
  };
  vm.runInNewContext(SRC, ctx, { filename: "popup.js" });
  return { els, timers, win, $: ctx.document.getElementById };
}

const flush = () => new Promise((r) => setImmediate(r));

function status(req) {
  if (req.op === "status") {
    return { ok: true, running: true, phones: [{ id: "a".repeat(64), label: "Phone" }] };
  }
  return null;
}

for (const flavor of ["chromium", "firefox"])
for (const [btn, setup] of [
  ["send-tab-btn", () => {}],
  ["send-custom-btn", ($) => ($("custom-input").value = "hello")],
  ["send-clip-btn", () => {}],
]) {
  test(`${flavor} ${btn}: success shows the result, then closes after 600 ms`, async () => {
    const p = loadPopup((req) => status(req) || { ok: true, sent_to: "Phone" }, flavor);
    await flush();
    setup(p.$);
    p.$(btn).fire("click");
    await flush();
    await flush();
    assert.match(p.$("feedback").textContent, /^Sent to Phone/);
    assert.strictEqual(p.$("feedback").className, "feedback ok");
    assert.strictEqual(p.timers.length, 1);
    assert.strictEqual(p.timers[0].ms, 600);
    assert.strictEqual(p.win.closed, 0, "still open while the result shows");
    p.timers[0].fn();
    assert.strictEqual(p.win.closed, 1);
  });
}

for (const flavor of ["chromium", "firefox"])
test(`${flavor}: failure keeps the popup open and shows the error`, async () => {
  const p = loadPopup((req) => status(req) || { ok: false, error: "Phone not reachable." }, flavor);
  await flush();
  p.$("send-tab-btn").fire("click");
  await flush();
  await flush();
  assert.strictEqual(p.$("feedback").textContent, "Phone not reachable.");
  assert.strictEqual(p.$("feedback").className, "feedback err");
  assert.strictEqual(p.timers.length, 0);
  assert.strictEqual(p.win.closed, 0);
});

test("a relay question keeps the popup open; confirming then closes it", async () => {
  let n = 0;
  const p = loadPopup(
    (req) => status(req) || (n++ === 0 ? { ok: false, relay_prompt: true } : { ok: true, sent_to: "Phone" })
  );
  await flush();
  p.$("custom-input").value = "a long text";
  p.$("send-custom-btn").fire("click");
  await flush();
  await flush();
  assert.ok(!p.$("relay-card").classList.contains("hidden"));
  assert.strictEqual(p.timers.length, 0);
  p.$("relay-confirm-btn").fire("click");
  await flush();
  await flush();
  assert.strictEqual(p.timers.length, 1);
  p.timers[0].fn();
  assert.strictEqual(p.win.closed, 1);
});

test("the desktop app not running keeps the popup open", async () => {
  const p = loadPopup(() => ({ ok: false, running: false, error: "not running" }));
  await flush();
  assert.ok(!p.$("offline-card").classList.contains("hidden"));
  assert.strictEqual(p.timers.length, 0);
  assert.strictEqual(p.win.closed, 0);
});

test("two quick successes close once", async () => {
  const p = loadPopup((req) => status(req) || { ok: true, sent_to: "Phone" });
  await flush();
  p.$("send-clip-btn").fire("click");
  p.$("send-clip-btn").fire("click");
  await flush();
  await flush();
  assert.strictEqual(p.timers.length, 1);
});
