// L2 (approved 10-31): on Linux the right-click setting names the file
// managers it covers; Windows keeps its File Explorer wording.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { load, flush } = require("./devices-harness.js");

test("Linux wording names Files, Dolphin and Nemo", async () => {
  const lin = load({ settings: { os: "linux", context_menu_enabled: false } });
  await flush();
  assert.match(lin.$("ctxmenu-title").textContent, /file manager's right-click menu/);
  assert.match(lin.$("ctxmenu-hint").textContent, /Files \(under Scripts\), Dolphin or Nemo/);
  assert.strictEqual(lin.$("ctxmenu").checked, false);
});

test("Windows wording is unchanged", async () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "ui", "devices.html"), "utf8");
  assert.match(html, /id="ctxmenu-title">Show "Send with Voidwire" in File Explorer right-click menu</);
  const win = load({ settings: { os: "windows" } });
  await flush();
  assert.doesNotMatch(win.$("ctxmenu-title").textContent, /Dolphin|file manager/);
});
