// L1 (approved 10-31): when the Linux desktop has no tray host, the app opens
// the Devices window at start and shows exactly this line; otherwise hidden.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { load, flush } = require("./devices-harness.js");

const TEXT = "Your desktop has no tray. Install the AppIndicator extension to keep Voidwire in the top bar.";
const HTML = fs.readFileSync(path.join(__dirname, "..", "ui", "devices.html"), "utf8");

test("the no-tray line is exactly the approved text, hidden by default", () => {
  const m = HTML.match(/<p id="notray" class="([^"]*)">([\s\S]*?)<\/p>/);
  assert.ok(m, "the line exists");
  assert.strictEqual(m[2], TEXT);
  assert.match(m[1], /\bhidden\b/);
});

test("shown only when the app reports no tray", async () => {
  const none = load({ settings: { no_tray: true } });
  await flush();
  assert.ok(!none.$("notray").classList.contains("hidden"));
  const tray = load({ settings: { no_tray: false } });
  await flush();
  assert.ok(tray.$("notray").classList.contains("hidden"));
  const old = load();
  await flush();
  assert.ok(old.$("notray").classList.contains("hidden"));
});
