// Pair a device window: the countdown uses the core's code
// lifetime, "New code" asks the core for a fresh code (which replaces the
// old one and deletes its relay card), and an expired code offers
// "New code" in place. Runs with `node --test desktop/tests/pair.test.js`.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SRC = fs.readFileSync(path.join(__dirname, "..", "ui", "pair.js"), "utf8");

function el(id) {
  const listeners = {};
  const classes = new Set();
  return {
    id,
    value: "",
    disabled: false,
    textContent: "",
    src: "",
    style: {},
    classList: {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      toggle: (c, on) => (on ? classes.add(c) : classes.delete(c)),
      contains: (c) => classes.has(c),
    },
    addEventListener: (ev, fn) => (listeners[ev] = fn),
    appendChild: () => {},
    focus: () => {},
    fire: (ev, arg) => listeners[ev](arg || { key: "" }),
  };
}

function load(answer) {
  const els = {};
  const calls = [];
  const intervals = [];
  let now = 1_000_000;
  const ctx = {
    window: {
      __TAURI__: {
        core: {
          invoke: (cmd, args) => {
            calls.push({ cmd, args });
            return Promise.resolve().then(() => answer(cmd, args, now));
          },
        },
      },
    },
    document: {
      hidden: false,
      getElementById: (id) => (els[id] = els[id] || el(id)),
      createElement: () => el("option"),
      addEventListener: () => {},
    },
    Date: { now: () => now },
    setInterval: (fn, ms) => (intervals.push({ fn, ms }), intervals.length),
    clearInterval: () => {},
    btoa: (s) => Buffer.from(s).toString("base64"),
    String,
    Math,
  };
  vm.runInNewContext(SRC, ctx);
  return {
    els,
    calls,
    intervals,
    advance: (ms) => (now += ms),
    hidden: (id) => els[id].classList.contains("hidden"),
  };
}

const flush = () => new Promise((r) => setImmediate(r));
let seq = 0;
function core(state) {
  return (cmd, _args, now) => {
    if (cmd === "pair2_relays") return [];
    if (cmd === "pair2_show") {
      seq += 1;
      return { code: "VW-CODE-" + seq, svg: "<svg/>", expires_at_ms: now + 300000, ttl_ms: 300000 };
    }
    if (cmd === "pair2_status") return state.status;
    return null;
  };
}

test("shows a 5:00 countdown and a New code button", async () => {
  const w = load(core({ status: { state: "showing" } }));
  w.els["go-show"].fire("click");
  await flush();
  assert.match(w.els.pcode.textContent, /^VW-CODE-/);
  assert.strictEqual(w.els.left.textContent, "5:00");
  assert.strictEqual(w.els.bar.style.width, "100.0%");
  assert.ok(!w.hidden("newcode"), "New code visible while a code shows");
  w.advance(150000);
  await w.intervals.at(-1).fn();
  assert.strictEqual(w.els.left.textContent, "2:30");
  assert.strictEqual(w.els.bar.style.width, "50.0%");
});

test("New code asks the core for a fresh code", async () => {
  const w = load(core({ status: { state: "showing" } }));
  w.els["go-show"].fire("click");
  await flush();
  const first = w.els.pcode.textContent;
  w.els.newcode.fire("click");
  await flush();
  assert.strictEqual(w.calls.filter((c) => c.cmd === "pair2_show").length, 2);
  assert.notStrictEqual(w.els.pcode.textContent, first);
  assert.strictEqual(w.els.left.textContent, "5:00");
});

// 0.8.1 field test: codes ran out and stayed out. While the window is open
// an expired code is replaced by a fresh one with a new countdown.
test("an expired code renews itself with a fresh countdown", async () => {
  const state = { status: { state: "showing" } };
  const w = load(core(state));
  w.els["go-show"].fire("click");
  await flush();
  const first = w.els.pcode.textContent;
  w.advance(300000);
  state.status = { state: "expired" };
  await w.intervals.at(-1).fn();
  await flush();
  state.status = { state: "showing" };
  assert.strictEqual(w.calls.filter((c) => c.cmd === "pair2_show").length, 2);
  assert.notStrictEqual(w.els.pcode.textContent, first);
  assert.strictEqual(w.els.left.textContent, "5:00");
  assert.strictEqual(w.els.msg.textContent, "", "no error line for a renewal");
  assert.ok(!w.hidden("show"));
});

test("after the renewal cap the screen says Code expired and offers New code", async () => {
  const state = { status: { state: "showing" } };
  const w = load(core(state));
  w.els["go-show"].fire("click");
  await flush();
  for (let i = 0; i < 6; i++) {
    w.advance(300000);
    state.status = { state: "expired" };
    await w.intervals.at(-1).fn();
    await flush();
  }
  assert.strictEqual(w.calls.filter((c) => c.cmd === "pair2_show").length, 6, "1 + 5 renewals");
  assert.match(w.els.codehint.textContent, /^Code expired\. Click New code/);
  assert.ok(!w.hidden("newcode"));
  assert.strictEqual(w.els.msg.textContent, "");
  // Clicking the expired code copies nothing.
  w.els.pcode.fire("click");
  await flush();
  assert.ok(!w.calls.some((c) => c.cmd === "pair2_copy_code"));
  assert.strictEqual(w.els.msg.textContent, "", "no 'no code to copy' error");
  // New code starts over (and resets the renewal count).
  state.status = { state: "showing" };
  w.els.newcode.fire("click");
  await flush();
  assert.strictEqual(w.els.codehint.textContent, "Click the code to copy it. A phone can scan the QR.");
});

test("polling only reads local status (no other commands)", async () => {
  const w = load(core({ status: { state: "showing" } }));
  w.els["go-show"].fire("click");
  await flush();
  const before = w.calls.length;
  for (let i = 0; i < 5; i++) await w.intervals.at(-1).fn();
  const polled = w.calls.slice(before).map((c) => c.cmd);
  assert.deepStrictEqual([...new Set(polled)], ["pair2_status"]);
});

test("the 6-digit step shows a labelled field and Enter pairs", async () => {
  const state = { status: { state: "showing" } };
  const w = load((cmd, args, now) => (cmd === "pair2_submit_code" ? { name: "PC B", refreshed: false } : core(state)(cmd, args, now)));
  w.els["go-show"].fire("click");
  await flush();
  state.status = { state: "awaiting_code", device_name: "PC B" };
  await w.intervals.at(-1).fn();
  assert.ok(!w.hidden("verify"), "the code step is on screen");
  assert.ok(w.hidden("show"));
  assert.strictEqual(w.els.joiner2.textContent, "PC B");
  w.els.sasin.value = "123 456";
  w.els.sasin.fire("keydown", { key: "Enter" });
  await flush();
  const sub = w.calls.find((c) => c.cmd === "pair2_submit_code");
  assert.strictEqual(sub.args.code, "123456");
  assert.ok(!w.hidden("done"));
});

test("clicking the code copies it through the core; the hint line changes in place", async () => {
  const w = load(core({ status: { state: "showing" } }));
  w.els["go-show"].fire("click");
  await flush();
  assert.strictEqual(w.els.codehint.textContent, "Click the code to copy it. A phone can scan the QR.");
  w.els.pcode.fire("click");
  await flush();
  const c = w.calls.find((x) => x.cmd === "pair2_copy_code");
  assert.ok(c, "copied through the core, not the web clipboard");
  assert.strictEqual(c.args, undefined, "the window can't choose what is copied");
  assert.strictEqual(w.els.codehint.textContent, "Copied. It leaves the clipboard when pairing ends.");
  w.els.pcode.fire("keydown", { key: "Enter" });
  await flush();
  assert.strictEqual(w.calls.filter((x) => x.cmd === "pair2_copy_code").length, 2, "Enter copies too");
});

test("only the QR works: the hint says why and clicking copies nothing", async () => {
  const w = load((cmd) =>
    cmd === "pair2_show" ? { code: null, svg: "<svg/>", expires_at_ms: 2_000_000, ttl_ms: 300000 } : cmd === "pair2_status" ? { state: "showing" } : [],
  );
  w.els["go-show"].fire("click");
  await flush();
  assert.match(w.els.codehint.textContent, /only the QR code works/);
  w.els.pcode.fire("click");
  await flush();
  assert.ok(!w.calls.some((c) => c.cmd === "pair2_copy_code"));
});

test("re-pairing a device that was already paired says so after the handshake", async () => {
  const state = { status: { state: "showing" } };
  const w = load((cmd, args, now) => (cmd === "pair2_submit_code" ? { name: "PC B", refreshed: true } : core(state)(cmd, args, now)));
  w.els["go-show"].fire("click");
  await flush();
  state.status = { state: "awaiting_code", device_name: "PC B" };
  await w.intervals.at(-1).fn();
  w.els.sasin.value = "123456";
  w.els.sasin.fire("keydown", { key: "Enter" });
  await flush();
  assert.ok(!w.hidden("done"));
  assert.strictEqual(w.els.donenote.textContent, "Already paired with PC B, pairing refreshed.");
});

test("an error clears when the typed text changes and when the screen changes", async () => {
  const w = load((cmd) => (cmd === "pair2_open_code" ? Promise.reject("That code has a typo.") : []));
  w.els["go-enter"].fire("click");
  w.els.codein.value = "VW-BAD";
  w.els.codein.fire("keydown", { key: "Enter" });
  await flush();
  await flush();
  assert.strictEqual(w.els.msg.textContent, "That code has a typo.");
  w.els.codein.fire("input");
  assert.strictEqual(w.els.msg.textContent, "");
  w.els.codein.fire("keydown", { key: "Enter" });
  await flush();
  await flush();
  assert.strictEqual(w.els.msg.textContent, "That code has a typo.");
  w.els.again.fire("click");
  assert.strictEqual(w.els.msg.textContent, "");
});

// 0.8.1 field test: a stray "X" text node sat between two sections and
// pushed the buttons down. No page may have loose text outside an element.
test("no loose text between elements in any window", () => {
  const dir = path.join(__dirname, "..", "ui");
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".html"))) {
    const html = fs.readFileSync(path.join(dir, f), "utf8").replace(/<!--[\s\S]*?-->/g, "");
    const body = html.slice(html.indexOf("<body"));
    const loose = body.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("<"));
    assert.deepStrictEqual(loose, [], f + " has loose text: " + loose.join(" | "));
  }
});

// v0.7.1: the 6-digit field must be a labelled, focused, visible input.
test("the 6-digit field is labelled and focused", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "ui", "pair.html"), "utf8");
  assert.match(html, /<label[^>]*for="sasin"[^>]*>Type the 6-digit code shown on/);
  assert.match(html, /<input id="sasin"[^>]*autofocus/);
});
