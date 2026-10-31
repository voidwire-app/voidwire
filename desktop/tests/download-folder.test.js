// Download folder (M4.5 polish): choosing a folder applies it at once.
// There is no Save button; Browse… picks and saves, Reset goes back.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { load, flush } = require("./devices-harness.js");

const HTML = fs.readFileSync(path.join(__dirname, "..", "ui", "devices.html"), "utf8");

test("the download folder card has Browse and Reset, no Save", () => {
  const card = HTML.match(/Download folder<\/span>[\s\S]*?id="dldir-note"/);
  assert.ok(card, "the card exists");
  const buttons = [...card[0].matchAll(/<button[^>]*>([^<]*)<\/button>/g)].map((m) => m[1]);
  assert.deepStrictEqual(buttons, ["Browse…", "Reset"]);
});

test("choosing a folder saves it with no further step", async () => {
  const settings = { download_dir: "C:\\Downloads\\Voidwire" };
  const pick = () => ((settings.download_dir = "D:\\Files"), { download_dir: "D:\\Files" });
  const h = load({ settings, answers: { pick_download_dir: pick } });
  await flush();
  h.$("dl-dir-browse").listeners.click();
  await flush();
  assert.ok(h.calls.some((c) => c.cmd === "pick_download_dir"), "the picker both chooses and saves");
  assert.strictEqual(h.$("dldir-input").value, "D:\\Files");
  assert.match(h.$("dldir-note").textContent, /^Saved\./);
});
