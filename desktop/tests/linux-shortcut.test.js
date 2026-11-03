// L3 (approved 10-31): on Wayland the desktop's portal owns the shortcut's
// keys; the setting shows them read-only, or "Not available on this desktop".
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { load, flush } = require("./devices-harness.js");

test("portal: the bound keys show read-only, with Change in system settings", async () => {
  const p = load({
    settings: { os: "linux", send_clipboard_shortcut_kind: "portal", send_clipboard_shortcut_trigger: "Ctrl+Shift+Alt+V" },
  });
  await flush();
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Ctrl+Shift+Alt+V");
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
  assert.ok(p.$("gnome-sc-row").classList.contains("hidden"), "no GNOME button off GNOME");
});

test("GNOME without the portal: Add shortcut in GNOME settings, then Remove", async () => {
  let keys = "";
  const p = load({
    settings: {
      os: "linux",
      send_clipboard_shortcut: false,
      send_clipboard_shortcut_kind: "unavailable",
      gnome_shortcut_offered: true,
      gnome_shortcut: "",
    },
    answers: {
      gnome_shortcut_add: () => (keys = "Ctrl+Shift+Alt+V"),
      gnome_shortcut_remove: () => ((keys = ""), null),
    },
  });
  await flush();
  assert.ok(!p.$("gnome-sc-row").classList.contains("hidden"));
  assert.strictEqual(p.$("gnome-sc-add").textContent, "Add shortcut in GNOME settings");
  assert.ok(p.$("gnome-sc-remove").classList.contains("hidden"));
  assert.match(p.$("gnome-sc-status").textContent, /^Adds Ctrl\+Shift\+Alt\+V to GNOME settings/);
  assert.match(p.$("clipshortcut-hint").textContent, /Add the shortcut to GNOME settings instead \(Ctrl\+Shift\+Alt\+V\)/);

  await p.$("gnome-sc-add").listeners.click();
  await flush();
  assert.ok(p.calls.some((c) => c.cmd === "gnome_shortcut_add"));
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Ctrl+Shift+Alt+V");
  assert.ok(!p.$("gnome-sc-remove").classList.contains("hidden"));
  assert.match(p.$("gnome-sc-status").textContent, /^Added to GNOME settings: Ctrl\+Shift\+Alt\+V/);
  assert.strictEqual(p.$("gnome-sc-add").textContent, "Update shortcut in GNOME settings");

  await p.$("gnome-sc-remove").listeners.click();
  await flush();
  assert.ok(p.calls.some((c) => c.cmd === "gnome_shortcut_remove"));
  assert.ok(p.$("gnome-sc-remove").classList.contains("hidden"));
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Not available on this desktop");
});

test("GNOME: an entry added earlier shows with Remove", async () => {
  const p = load({
    settings: {
      os: "linux",
      send_clipboard_shortcut_kind: "unavailable",
      gnome_shortcut_offered: true,
      gnome_shortcut: "Super+F5",
    },
  });
  await flush();
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Super+F5");
  assert.ok(!p.$("gnome-sc-remove").classList.contains("hidden"));
});

test("GNOME: a failed add shows the reason", async () => {
  const p = load({
    settings: { os: "linux", send_clipboard_shortcut_kind: "unavailable", gnome_shortcut_offered: true },
    answers: { gnome_shortcut_add: () => Promise.reject("Couldn't add it: no schema") },
  });
  await flush();
  await p.$("gnome-sc-add").listeners.click();
  await flush();
  assert.strictEqual(p.$("clipshortcut-err").textContent, "Couldn't add it: no schema");
  assert.ok(p.$("gnome-sc-remove").classList.contains("hidden"));
});

test("keys (Windows, X11): recorded in the app as before", async () => {
  const p = load({ settings: { send_clipboard_shortcut_accel: "Ctrl+Alt+K" } });
  await flush();
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Ctrl+Alt+K");
  assert.ok(!p.$("clipshortcut-record").classList.contains("hidden"));
  assert.strictEqual(p.$("clipshortcut").disabled, false);
  assert.ok(p.$("gnome-sc-row").classList.contains("hidden"));
});

test("default keys come from the core: badge, hint and Reset", async () => {
  const p = load({
    settings: { send_clipboard_shortcut_accel: "Ctrl+Alt+K" },
    answers: { settings_set_send_clipboard_shortcut_accel: (a) => a.accel },
  });
  await flush();
  await p.$("clipshortcut-reset").listeners.click();
  await flush();
  const reset = p.calls.find((c) => c.cmd === "settings_set_send_clipboard_shortcut_accel");
  assert.strictEqual(reset.args.accel, "Ctrl+Shift+Alt+V");
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Ctrl+Shift+Alt+V");
  assert.match(p.$("clipshortcut-hint").textContent, /press Ctrl\+Shift\+Alt\+V to send/);
});

test("untouched default: the core's accel is shown", async () => {
  const p = load({ settings: { send_clipboard_shortcut_accel: "Ctrl+Shift+Alt+V" } });
  await flush();
  assert.strictEqual(p.$("clipshortcut-badge").textContent, "Ctrl+Shift+Alt+V");
});
