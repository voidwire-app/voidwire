// L3 (approved 10-31): on Wayland the desktop's portal owns the shortcut's
// keys; the setting shows them read-only, or "Not available on this desktop".
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { load, flush } = require("./devices-harness.js");

test("portal: the bound keys show read-only, with Change in system settings", async () => {
  const p = load({
    settings: { os: "linux", send_clipboard_shortcut_kind: "portal", send_clipboard_shortcut_trigger: "Ctrl+Shift+V" },
  });
  await flush();
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Ctrl+Shift+V");
  assert.strictEqual(p.$("clipshortcut-sys").textContent, "Change in system settings");
  assert.ok(p.$("clipshortcut-record").classList.contains("hidden"));
  assert.ok(p.$("clipshortcut-reset").classList.contains("hidden"));
  assert.match(p.$("clipshortcut-hint").textContent, /your desktop asks which keys/);
});

test("portal: turning it on refreshes to show the desktop's keys", async () => {
  const p = load({
    settings: { os: "linux", send_clipboard_shortcut: false, send_clipboard_shortcut_kind: "portal" },
  });
  await flush();
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Set by your desktop");
  const before = p.calls.filter((c) => c.cmd === "settings_get").length;
  p.$("clipshortcut").checked = true;
  await p.$("clipshortcut").listeners.change({ target: p.$("clipshortcut") });
  await flush();
  assert.ok(p.calls.some((c) => c.cmd === "settings_set_send_clipboard_shortcut" && c.args.on === true));
  assert.ok(p.calls.filter((c) => c.cmd === "settings_get").length > before);
});

test("unavailable: disabled, with the reason", async () => {
  const p = load({
    settings: { os: "linux", send_clipboard_shortcut: false, send_clipboard_shortcut_kind: "unavailable" },
  });
  await flush();
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Not available on this desktop");
  assert.strictEqual(p.$("clipshortcut").disabled, true);
  assert.match(p.$("clipshortcut-hint").textContent, /^Not available on this desktop\./);
});

test("keys (Windows, X11): recorded in the app as before", async () => {
  const p = load({ settings: { send_clipboard_shortcut_accel: "Ctrl+Alt+K" } });
  await flush();
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Ctrl+Alt+K");
  assert.ok(!p.$("clipshortcut-record").classList.contains("hidden"));
  assert.strictEqual(p.$("clipshortcut").disabled, false);
});
