// "Start Voidwire when I sign in": off by default, the switch shows the state
// the OS entry is really in (the command answers with it).
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { load, flush } = require("./devices-harness.js");

test("off by default, on when the entry is there", async () => {
  const off = load({});
  await flush();
  assert.strictEqual(off.$("autostart").checked, false);
  const on = load({ settings: { autostart: true } });
  await flush();
  assert.strictEqual(on.$("autostart").checked, true);
});

test("turning it on shows what the OS has afterwards", async () => {
  const p = load({ answers: { settings_set_autostart: (a) => a.on } });
  await flush();
  p.$("autostart").checked = true;
  await p.$("autostart").listeners.change({ target: p.$("autostart") });
  await flush();
  assert.ok(p.calls.some((c) => c.cmd === "settings_set_autostart" && c.args.on === true));
  assert.strictEqual(p.$("autostart").checked, true);
});

test("the OS kept it off: the switch goes back off", async () => {
  const p = load({ answers: { settings_set_autostart: () => false } });
  await flush();
  p.$("autostart").checked = true;
  await p.$("autostart").listeners.change({ target: p.$("autostart") });
  await flush();
  assert.strictEqual(p.$("autostart").checked, false);
});

test("an error (mac disk image) puts the switch back and says why", async () => {
  const p = load({
    settings: { os: "macos" },
    answers: { settings_set_autostart: () => Promise.reject("Move Voidwire to Applications first, then turn this on.") },
  });
  await flush();
  p.$("autostart").checked = true;
  await p.$("autostart").listeners.change({ target: p.$("autostart") });
  await flush();
  assert.strictEqual(p.$("autostart").checked, false);
  assert.match(p.$("msg").textContent, /Move Voidwire to Applications/);
  assert.match(p.$("autostart-hint").textContent, /menu bar when you log in/);
});
