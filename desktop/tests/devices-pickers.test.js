// Devices window, M4.5 pickers: the hotkey's clipboard picker (2+ devices,
// no fixed device) and the shortcut's "Sends to" select. Loads the real
// devices.js against a permissive fake DOM and a stubbed core. Runs with
// `node --test desktop/tests/devices-pickers.test.js`.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { load, flush, A, B } = require("./devices-harness.js");

test("hotkey with 2+ devices: the clipboard picker lists every device and sends to the chosen one", async () => {
  const p = load({ pending: { error: "__pick_device_clipboard__", device_id: "", file_path: null } });
  await flush();
  const modal = p.$("relay-modal");
  assert.ok(!modal.classList.contains("hidden"), "picker shown");
  assert.strictEqual(p.$("relay-modal-title").textContent, "Send clipboard to…");
  const sel = p.$("relay-modal-body").children.find((c) => c.tag === "select");
  assert.ok(sel, "a device select");
  assert.deepStrictEqual(sel.children.map((o) => o.value), [A, B], "every device, nothing else");
  sel.value = B;
  await p.$("relay-modal-confirm").onclick();
  await flush();
  const send = p.calls.find((c) => c.cmd === "send_clipboard_to_phone");
  assert.deepStrictEqual(JSON.parse(JSON.stringify(send.args)), { id: B, relayDecision: null });
});

test("Explorer with 2+ devices: the file picker lists every device (and nothing else)", async () => {
  const p = load({ pending: { error: "__pick_phone__", device_id: "", file_path: "C:\\x\\report.pdf" } });
  await flush();
  assert.match(p.$("relay-modal-title").textContent, /^Choose a device for report\.pdf$/);
  const sel = p.$("relay-modal-body").children.find((c) => c.tag === "select");
  assert.deepStrictEqual(sel.children.map((o) => o.value), [A, B]);
});

test('"Sends to" lists Ask each time plus every device and saves the choice', async () => {
  const p = load({ saved: B });
  await flush();
  const sel = p.$("clipshortcut-device");
  assert.deepStrictEqual(sel.children.map((o) => o.value), ["", A, B]);
  assert.strictEqual(sel.children[0].textContent, "Ask each time");
  assert.strictEqual(sel.value, B, "the saved device is selected");
  await sel.listeners.change({ target: { value: "" } });
  await flush();
  const set = p.calls.filter((c) => c.cmd === "settings_set_send_clipboard_shortcut_device");
  assert.deepStrictEqual(JSON.parse(JSON.stringify(set.map((c) => c.args))), [{ id: "" }]);
});

test('"Sends to" falls back to Ask when the saved device is no longer paired', async () => {
  const p = load({ saved: "c".repeat(64) });
  await flush();
  assert.strictEqual(p.$("clipshortcut-device").value, "");
});

test('"Sends to" a PC saves it, shows no error, and switching back to Ask clears it', async () => {
  const p = load();
  await flush();
  const sel = p.$("clipshortcut-device");
  sel.value = B; // "Desk", a PC
  await sel.listeners.change({ target: sel });
  await flush();
  assert.strictEqual(p.$("clipshortcut-err").textContent, "");
  assert.strictEqual(sel.value, B);
  sel.value = "";
  await sel.listeners.change({ target: sel });
  await flush();
  assert.strictEqual(p.$("clipshortcut-err").textContent, "");
  assert.strictEqual(sel.value, "");
  const set = p.calls.filter((c) => c.cmd === "settings_set_send_clipboard_shortcut_device");
  assert.deepStrictEqual(JSON.parse(JSON.stringify(set.map((c) => c.args))), [{ id: B }, { id: "" }]);
});

test('"Sends to": a failed save reverts the select and the next good save clears the error', async () => {
  const p = load({ failSet: 1 });
  await flush();
  const sel = p.$("clipshortcut-device");
  p.document.activeElement = sel; // still focused after picking
  sel.value = B;
  await sel.listeners.change({ target: sel });
  await flush();
  assert.notStrictEqual(p.$("clipshortcut-err").textContent, "");
  assert.strictEqual(sel.value, "", "back on what the core holds (Ask), not the failed choice");
  sel.value = A;
  await sel.listeners.change({ target: sel });
  await flush();
  assert.strictEqual(p.$("clipshortcut-err").textContent, "");
  assert.strictEqual(sel.value, A);
});
