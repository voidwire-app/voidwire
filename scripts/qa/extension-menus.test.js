#!/usr/bin/env node
// M3.2.1: right-click menus in extension/background.js, run against a mock
// Chromium extension API (no browser needed).
//   node scripts/qa/extension-menus.test.js
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const assert = require("assert");

const SRC = fs.readFileSync(path.join(__dirname, "../../extension/background.js"), "utf8");
const A = "a".repeat(64);
const B = "b".repeat(64);
const C = "c".repeat(64);

// Fake Chrome API callbacks run async, as in Chrome. tick() waits until every
// one has run (and whatever it chained), not a fixed 20 ms: a busy CI runner
// can take longer than that for a menu rebuild (tag ci 41169746218).
let pending = 0;
const later = (fn) => {
  pending++;
  setTimeout(() => {
    pending--;
    fn();
  }, 0);
};

function load(phones) {
  const st = { phones: phones.slice(), menus: new Map(), sent: [], listeners: {}, error: null };
  const ev = (name) => ({ addListener: (fn) => (st.listeners[name] = fn) });
  const chrome = {
    runtime: {
      lastError: null,
      onInstalled: ev("installed"),
      onStartup: ev("startup"),
      onMessage: ev("message"),
      sendNativeMessage(_host, req, cb) {
        st.sent.push(JSON.parse(JSON.stringify(req)));
        later(() => {
          if (req.op === "status") {
            cb({ ok: true, running: true, devices: st.phones.map((p) => ({ ...p })) });
            return;
          }
          if (st.error) {
            cb({ ok: false, error: st.error });
            return;
          }
          cb({ ok: true, sent_to: "x" });
        });
      },
    },
    contextMenus: {
      removeAll(cb) {
        st.menus.clear();
        later(cb);
      },
      create(props, cb) {
        assert(!st.menus.has(props.id), "duplicate menu id " + props.id);
        if (props.parentId) assert(st.menus.has(props.parentId), "parent missing");
        st.menus.set(props.id, { ...props });
        later(cb);
      },
      onClicked: ev("clicked"),
    },
    action: { setBadgeBackgroundColor() {}, setBadgeTextColor() {}, setBadgeText() {} },
  };
  vm.runInNewContext(SRC, { chrome, setTimeout, clearTimeout, console, String, Promise, Array, Boolean, JSON });
  return st;
}
const tick = async () => {
  const until = Date.now() + 5000;
  do {
    await new Promise((r) => setTimeout(r, 1));
    assert(Date.now() < until, "fake Chrome callbacks never settled");
  } while (pending > 0);
  await new Promise((r) => setTimeout(r, 1));
};
const tops = (st) => [...st.menus.values()].filter((m) => !m.parentId).map((m) => m.id).sort();
const kids = (st, parent) => [...st.menus.values()].filter((m) => m.parentId === parent);
const lastSend = (st) => st.sent.filter((r) => r.op !== "status").pop();

(async () => {
  // One phone: three flat items, sends carry that phone's id.
  {
    const st = load([{ id: A, label: "Pixel" }]);
    st.listeners.installed();
    await tick();
    assert.deepStrictEqual(tops(st), ["voidwire-send-link", "voidwire-send-page", "voidwire-send-selection"]);
    assert.strictEqual(st.menus.size, 3);
    st.listeners.clicked({ menuItemId: "voidwire-send-link", linkUrl: " https://a.example/x " }, {});
    await tick();
    assert.deepStrictEqual(lastSend(st), { op: "send_url", url: "https://a.example/x", pop_ui_on_error: true, device_id: A });
  }
  // Two phones: each item is a parent with one child per phone.
  {
    const st = load([{ id: A, label: "Pixel" }, { id: B, label: "Tab & Co" }]);
    st.listeners.installed();
    await tick();
    assert.strictEqual(st.menus.size, 9);
    for (const p of ["voidwire-send-link", "voidwire-send-selection", "voidwire-send-page"]) {
      assert.deepStrictEqual(kids(st, p).map((m) => m.title), ["Pixel", "Tab & Co"]);
      assert.deepStrictEqual(kids(st, p).map((m) => m.contexts), [st.menus.get(p).contexts, st.menus.get(p).contexts]);
    }
    st.listeners.clicked({ menuItemId: "voidwire-send-selection::" + B, selectionText: "hello" }, {});
    await tick();
    assert.deepStrictEqual(lastSend(st), { op: "send_text", text: "hello", pop_ui_on_error: true, device_id: B });
    st.listeners.clicked({ menuItemId: "voidwire-send-page::" + A, pageUrl: "https://p.example/" }, {});
    await tick();
    assert.deepStrictEqual(lastSend(st), { op: "send_url", url: "https://p.example/", pop_ui_on_error: true, device_id: A });

    // Phone B unpaired + a third paired: the "no longer paired" answer rebuilds the menus.
    st.phones = [{ id: A, label: "Pixel" }, { id: C, label: "Fold" }];
    st.error = "Selected device is no longer paired.";
    st.listeners.clicked({ menuItemId: "voidwire-send-link::" + B, linkUrl: "https://l.example/" }, {});
    await tick();
    assert.deepStrictEqual(kids(st, "voidwire-send-link").map((m) => m.title), ["Pixel", "Fold"]);

    // Down to one phone (seen via popup status): back to flat items.
    st.error = null;
    st.phones = [{ id: C, label: "Fold" }];
    let resp;
    st.listeners.message({ op: "status" }, {}, (r) => (resp = r));
    await tick();
    assert(resp && resp.ok);
    assert.strictEqual(st.menus.size, 3);
    st.listeners.clicked({ menuItemId: "voidwire-send-link", linkUrl: "https://z.example/" }, {});
    await tick();
    assert.strictEqual(lastSend(st).device_id, C);
  }
  // 2+ phones: one child per device and no multi-device child.
  {
    const st = load([
      { id: A, label: "Pixel", mobile: true },
      { id: B, label: "Desk", mobile: false },
    ]);
    st.listeners.installed();
    await tick();
    assert.deepStrictEqual(kids(st, "voidwire-send-link").map((m) => m.title), ["Pixel", "Desk"]);
    st.phones.push({ id: C, label: "Fold", mobile: true });
    st.listeners.message({ op: "status" }, {}, () => {});
    await tick();
    for (const p of ["voidwire-send-link", "voidwire-send-selection", "voidwire-send-page"]) {
      assert.deepStrictEqual(kids(st, p).map((m) => m.title), ["Pixel", "Desk", "Fold"]);
    }
    st.listeners.clicked({ menuItemId: "voidwire-send-link::" + C, linkUrl: "https://a.example/" }, {});
    await tick();
    assert.deepStrictEqual(lastSend(st), { op: "send_url", url: "https://a.example/", pop_ui_on_error: true, device_id: C });
  }
  // Popup open with a new second phone: flat -> submenus.
  {
    const st = load([{ id: A, label: "Pixel" }]);
    st.listeners.startup();
    await tick();
    assert.strictEqual(st.menus.size, 3);
    st.phones.push({ id: B, label: "Tab" });
    st.listeners.message({ op: "status" }, {}, () => {});
    await tick();
    assert.strictEqual(st.menus.size, 9);
  }
  // Nothing persisted: background.js never touches storage.
  assert(!/\.storage\b/.test(SRC), "background.js must not use extension storage");
  console.log("extension-menus: ok");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
