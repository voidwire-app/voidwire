// Pair-with-a-code window (M4.3): the countdown uses the core's code
// lifetime, "New code" asks the core for a fresh code (which replaces the
// old one and deletes its relay card), and an expired code offers
// "New code" in place. Runs with `node --test desktop/tests/pair2.test.js`.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SRC = fs.readFileSync(path.join(__dirname, "..", "ui", "pair2.js"), "utf8");

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

test("an expired code offers New code in place, not an error screen", async () => {
  const state = { status: { state: "showing" } };
  const w = load(core(state));
  w.els["go-show"].fire("click");
  await flush();
  state.status = { state: "failed", message: "That code expired." };
  await w.intervals.at(-1).fn();
  assert.strictEqual(w.els.msg.textContent, "That code expired.");
  assert.ok(!w.hidden("newcode"));
  assert.ok(w.hidden("again"));
  assert.ok(!w.hidden("show"), "stays on the code screen");
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
