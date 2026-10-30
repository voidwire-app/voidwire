// Settings → Relays and Change relay (M4.4). Runs with
// `node --test desktop/tests/relays.test.js`.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SRC = fs.readFileSync(path.join(__dirname, "..", "ui", "relays.js"), "utf8");

function node(tag) {
  const listeners = {};
  const classes = new Set();
  const n = {
    tag,
    children: [],
    dataset: {},
    value: "",
    disabled: false,
    textContent: "",
    className: "",
    classList: {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      contains: (c) => classes.has(c),
    },
    setAttribute() {},
    addEventListener: (ev, fn) => (listeners[ev] = fn),
    append: (...c) => n.children.push(...c),
    replaceChildren: (...c) => (n.children = c),
    querySelector: () => null,
    focus() {},
    select() {},
    click: () => listeners.click({ isTrusted: true }),
  };
  return n;
}

function texts(n, out = []) {
  if (typeof n === "string") out.push(n);
  else if (n) {
    if (n.textContent) out.push(n.textContent);
    (n.children || []).forEach((c) => texts(c, out));
  }
  return out;
}

function buttons(n, out = []) {
  if (n && n.tag === "button") out.push(n);
  ((n && n.children) || []).forEach((c) => buttons(c, out));
  return out;
}

async function load(state) {
  const els = {};
  const ids = ["relays-list", "relays-count", "relay-add", "relay-add-input", "relay-add-mailbox",
    "relaychg-ask", "relaychg-ask-title", "relaychg-ask-body", "relaychg-allow", "relaychg-decline",
    "relaychg-pick", "relaychg-select", "relaychg-pick-title", "relaychg-pick-body", "relaychg-go",
    "relaychg-cancel", "msg"];
  ids.forEach((id) => (els[id] = node("div")));
  ["relay-add", "relaychg-allow", "relaychg-decline", "relaychg-go", "relaychg-cancel"].forEach(
    (id) => (els[id].tag = "button")
  );
  els["relaychg-ask"].classList.add("hidden");
  els["relaychg-pick"].classList.add("hidden");
  const calls = [];
  const win = {
    __TAURI__: {
      core: {
        invoke: async (cmd, args) => {
          calls.push([cmd, args]);
          if (cmd === "relays_list") return state.relays;
          if (cmd === "pairing_relays") return state.pairings;
          if (cmd === "relay_changes") return state.changes;
          return null;
        },
      },
    },
  };
  const ctx = {
    window: win,
    document: {
      getElementById: (id) => els[id],
      createElement: (t) => node(t),
      querySelectorAll: () => [],
    },
    navigator: { clipboard: { writeText: async () => {} } },
    toast: () => {},
    setTimeout: (f) => f(),
    Promise,
    JSON,
    Map,
    Date,
  };
  vm.runInNewContext(SRC, ctx);
  await new Promise((r) => setImmediate(r));
  return { els, calls, win };
}

const PUBLIC = { nickname: "relay.voidwire.app", url: "https://relay.voidwire.app", host: "relay.voidwire.app",
  mailboxId: "aa", home: true, builtin: true, usedBy: 1, status: "connected", downSinceMs: 0, link: "voidwire:relay?r=x" };
const MINE = { nickname: "home lab", url: "https://r.example", host: "r.example", mailboxId: "bb",
  home: false, builtin: false, usedBy: 0, status: "unreachable", downSinceMs: 1700000000000, link: "voidwire:relay?r=y" };

test("saved relays list: status, and Remove only for unused own relays", async () => {
  const { els } = await load({ relays: [PUBLIC, MINE], pairings: [], changes: { requests: [], mine: [] } });
  const rows = els["relays-list"].children;
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(els["relays-count"].textContent, "2 / 8 saved");
  const pub = buttons(rows[0]).map((b) => b.textContent);
  const own = buttons(rows[1]).map((b) => b.textContent);
  assert.ok(!pub.includes("Remove") && !pub.includes("Make home"));
  assert.ok(own.includes("Remove") && own.includes("Retry") && own.includes("Make home"));
  assert.ok(texts(rows[1]).some((t) => t.startsWith("Can't reach since")));
});

test("a request from the other device asks, and Allow answers it", async () => {
  const req = { peerId: "p1", peerName: "Pixel", host: "r.example", newRelay: true };
  const { els, calls } = await load({ relays: [PUBLIC], pairings: [], changes: { requests: [req], mine: [] } });
  assert.ok(!els["relaychg-ask"].classList.contains("hidden"));
  assert.match(els["relaychg-ask-title"].textContent, /Pixel wants to move your pairing to r\.example/);
  els["relaychg-allow"].click();
  await new Promise((r) => setImmediate(r));
  assert.strictEqual(
    JSON.stringify(calls.find((c) => c[0] === "relay_change_answer")),
    JSON.stringify(["relay_change_answer", { peerId: "p1", allow: true }])
  );
});

test("Change relay… asks the other device for the chosen relay", async () => {
  const { els, calls, win } = await load({
    relays: [PUBLIC, MINE],
    pairings: [{ peerId: "p1", url: "https://relay.voidwire.app", host: "relay.voidwire.app" }],
    changes: { requests: [], mine: [] },
  });
  const meta = node("div");
  const bar = node("div");
  win.vwRelayRow({ id: "p1", name: "Pixel" }, meta, bar);
  bar.children[0].click();
  assert.ok(!els["relaychg-pick"].classList.contains("hidden"));
  assert.strictEqual(els["relaychg-select"].children.length, 1); // current relay left out
  els["relaychg-select"].value = "https://r.example";
  els["relaychg-go"].click();
  await new Promise((r) => setImmediate(r));
  assert.strictEqual(
    JSON.stringify(calls.find((c) => c[0] === "relay_change_propose")),
    JSON.stringify(["relay_change_propose", { peerId: "p1", url: "https://r.example" }])
  );
});
