// M5.2 (approved S37): on macOS the right-click switch is hidden (Finder's
// Services menu has "Send with Voidwire"), M3's line shows only when the app
// runs from the disk image or a translocated copy, and a recorded Command
// key is saved as Cmd.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { load, flush } = require("./devices-harness.js");

const TEXT = "Move Voidwire to Applications so the browser extension can find it.";
const HTML = fs.readFileSync(path.join(__dirname, "..", "ui", "devices.html"), "utf8");

test("the move-to-Applications line is exactly the approved text, hidden by default", () => {
  const m = HTML.match(/<p id="movetoapps" class="([^"]*)">([\s\S]*?)<\/p>/);
  assert.ok(m, "the line exists");
  assert.strictEqual(m[2], TEXT);
  assert.match(m[1], /\bhidden\b/);
});

test("the line shows only when the app reports a blocked location", async () => {
  const blocked = load({ settings: { os: "macos", native_host_blocked: true } });
  await flush();
  assert.ok(!blocked.$("movetoapps").classList.contains("hidden"));
  const ok = load({ settings: { os: "macos", native_host_blocked: false } });
  await flush();
  assert.ok(ok.$("movetoapps").classList.contains("hidden"));
});

test("macOS hides the right-click switch; other systems keep it", async () => {
  const mac = load({ settings: { os: "macos" } });
  await flush();
  assert.ok(mac.$("ctxmenu-card").classList.contains("hidden"));
  for (const os of ["windows", "linux"]) {
    const p = load({ settings: { os } });
    await flush();
    assert.ok(!p.$("ctxmenu-card").classList.contains("hidden"), os);
  }
});
