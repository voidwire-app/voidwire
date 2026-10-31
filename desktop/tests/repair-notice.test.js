// The re-pair notice (owner decision, 10-31): after an upgrade dropped the
// old pairings, the Devices window shows exactly this line, with no dismiss
// button; it goes away once a new device is paired (the core clears the flag).
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { load, flush } = require("./devices-harness.js");

const TEXT = "The app was upgraded, and to improve security, your devices will need to be re-paired.";
const HTML = fs.readFileSync(path.join(__dirname, "..", "ui", "devices.html"), "utf8");

test("the notice is exactly the agreed text, with no button", () => {
  const m = HTML.match(/<p id="oldpairings"[^>]*>([\s\S]*?)<\/p>/);
  assert.ok(m, "the notice line exists");
  assert.strictEqual(m[1], TEXT);
  assert.doesNotMatch(m[1], /<button|<a\b/i, "nothing to click: no dismiss");
});

test("shown while the old pairings are gone, hidden once a device is paired", async () => {
  const shown = load({ old: true });
  await flush();
  assert.ok(!shown.$("oldpairings").classList.contains("hidden"));
  const after = load({ old: false });
  await flush();
  assert.ok(after.$("oldpairings").classList.contains("hidden"));
});
