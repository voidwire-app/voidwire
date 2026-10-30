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

// v0.7.1: the 6-digit field was invisible because its section had id="sas",
// and pair.css (shared with the old pair window) hides #sas.
test("no element in pair2.html is hidden by an id rule from pair.css", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "ui", "pair2.html"), "utf8");
  const css = fs.readFileSync(path.join(__dirname, "..", "ui", "pair.css"), "utf8");
  const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
  const cssIds = new Set([...css.matchAll(/#([A-Za-z][\w-]*)/g)].map((m) => m[1]));
  const clash = [...ids].filter((i) => cssIds.has(i));
  assert.deepStrictEqual(clash, [], "pair.css styles these pair2 ids: " + clash.join(", "));
  assert.match(html, /<label[^>]*for="sasin"[^>]*>Type the 6-digit code shown on/);
  assert.match(html, /<input id="sasin"[^>]*autofocus/);
});

test("the 6-digit step shows a labelled field and Enter pairs", async () => {
  const state = { status: { state: "showing" } };
  const w = load((cmd, args, now) => (cmd === "pair2_submit_code" ? "PC B" : core(state)(cmd, args, now)));
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

test("Copy asks the core to copy the shown code", async () => {
  const w = load(core({ status: { state: "showing" } }));
  w.els["go-show"].fire("click");
  await flush();
  assert.ok(!w.hidden("copy"), "Copy shows next to a code");
  assert.ok(w.hidden("copied"));
  w.els.copy.fire("click");
  await flush();
  const c = w.calls.find((x) => x.cmd === "pair2_copy_code");
  assert.ok(c, "copied through the core, not the web clipboard");
  assert.strictEqual(c.args, undefined, "the window can't choose what is copied");
  assert.ok(!w.hidden("copied"));
});

test("no Copy button when only the QR code works", async () => {
  const w = load((cmd) =>
    cmd === "pair2_show" ? { code: null, svg: "<svg/>", expires_at_ms: 2_000_000, ttl_ms: 300000 } : cmd === "pair2_status" ? { state: "showing" } : [],
  );
  w.els["go-show"].fire("click");
  await flush();
  assert.ok(w.hidden("copy"));
});
