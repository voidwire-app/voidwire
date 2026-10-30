// Every Pair a device screen fits its 440x660 window with no scrollbar, at
// 100% and 125% display scaling, with the longest content it can show (an
// error line, long names). Renders the real page in headless Chrome with a
// stubbed core. Runs with `node --test desktop/tests/layout.test.js`; CI
// fails if Chrome is missing, a local run without Chrome skips.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const UI = path.join(__dirname, "..", "ui");
const HERE = path.join(__dirname, "layout");
const STATES = ["choose", "show", "verify", "enter", "addrelay", "joined", "done"];
const W = 440;
const H = 660; // main.rs PAIR_WINDOW inner size
const SLACK = 12;

function chrome() {
  for (const c of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    try { execFileSync("which", [c], { stdio: "ignore" }); return c; } catch (_) { /* next */ }
  }
  return null;
}

function stage() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vw-layout-"));
  fs.cpSync(UI, dir, { recursive: true });
  for (const f of ["stub.js", "drive.js"]) fs.copyFileSync(path.join(HERE, f), path.join(dir, f));
  const page = path.join(dir, "pair.html");
  let html = fs.readFileSync(page, "utf8");
  assert.ok(html.includes('<script src="pair.js" defer></script>'), "pair.html loads pair.js");
  html = html.replace('<script src="pair.js" defer></script>',
    '<script src="stub.js"></script><script src="pair.js" defer></script><script src="drive.js" defer></script>');
  fs.writeFileSync(page, html);
  // One fixed-size frame per screen: the frame is the window's client area.
  const frames = STATES.map((s) => `<iframe id="${s}" src="pair.html?state=${s}" style="border:0;width:${W}px;height:${H}px"></iframe>`).join("");
  fs.writeFileSync(path.join(dir, "frame.html"), `<!doctype html><body style="margin:0">${frames}<script>
const t0 = Date.now();
(function check() {
  const r = [...document.querySelectorAll("iframe")].map((f) => f.contentWindow.VW_RESULT);
  if (r.every(Boolean) || Date.now() - t0 > 15000) document.title = "R" + JSON.stringify(r);
  else setTimeout(check, 100);
})();
</script></body>`);
  return dir;
}

function measure(bin, dir, scale) {
  const out = execFileSync(bin, [
    "--headless=new", "--no-sandbox", "--disable-gpu", "--allow-file-access-from-files",
    "--hide-scrollbars", `--window-size=${W + 40},${H * STATES.length + 40}`,
    `--force-device-scale-factor=${scale}`, "--virtual-time-budget=20000",
    "--dump-dom", "file://" + path.join(dir, "frame.html"),
  ], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 90000 });
  const m = out.match(/<title>R(.*?)<\/title>/s);
  assert.ok(m, "the layout page reported nothing");
  if (process.env.VW_LAYOUT_DEBUG) console.log(m[1]);
  return JSON.parse(m[1].replace(/&quot;/g, '"').replace(/&amp;/g, "&"));
}

const bin = chrome();
for (const scale of [1, 1.25]) {
  test(`every Pair a device screen fits 440x660 at ${scale * 100}%`, { skip: !bin && !process.env.CI && "no Chrome" }, () => {
    assert.ok(bin, "CI needs Chrome for the layout test");
    const dir = stage();
    try {
      const res = measure(bin, dir, scale);
      STATES.forEach((s, i) => {
        const r = res[i];
        assert.ok(r, `${s}: the screen never finished`);
        assert.strictEqual(r.shown, s, `${s}: shows ${r.shown}`);
        assert.ok(r.sh <= r.ch, `${s}: ${r.sh - r.ch}px taller than the window (scrollbar)`);
        // Room for font rendering differences between Chrome and the OS webview.
        assert.ok(r.need + SLACK <= r.ch, `${s}: needs ${r.need}px, less than ${SLACK}px spare in ${r.ch}px`);
        assert.ok(r.sw <= r.cw, `${s}: ${r.sw - r.cw}px wider than the window`);
      });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}
