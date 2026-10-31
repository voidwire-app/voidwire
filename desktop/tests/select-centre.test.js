// Every desktop <select> shows its chosen text vertically centred, in dark and
// light, at the fixed 30px settings height (.s-input: Sends to, the send
// picker, Change relay) and the padded Pair a device relay picker
// (.vw-select). Renders the real stylesheets in headless Chrome, which uses
// the same base-select layout as WebView2, and measures the text's pixels.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const { execFileSync } = require("node:child_process");

const UI = path.join(__dirname, "..", "ui");
const W = 440;
const H = 360;
const BOXES = [
  ["s-input", "Ask each time"],
  ["s-input mono", "relay.example.net"],
  ["vw-select", "relay.example.net"],
];

function chrome() {
  for (const c of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    try { execFileSync("which", [c], { stdio: "ignore" }); return c; } catch (_) { /* next */ }
  }
  return null;
}

// Decodes the 8-bit, non-interlaced RGB/RGBA PNG Chrome writes.
function png(buf) {
  let p = 8, w = 0, h = 0, ch = 0;
  const idat = [];
  while (p < buf.length) {
    const len = buf.readUInt32BE(p), type = buf.toString("latin1", p + 4, p + 8), d = buf.subarray(p + 8, p + 8 + len);
    if (type === "IHDR") {
      w = d.readUInt32BE(0); h = d.readUInt32BE(4);
      assert.strictEqual(d[8], 8, "8-bit PNG"); assert.strictEqual(d[12], 0, "not interlaced");
      ch = { 2: 3, 6: 4 }[d[9]]; assert.ok(ch, "RGB or RGBA PNG");
    }
    if (type === "IDAT") idat.push(d);
    p += 12 + len;
  }
  const raw = zlib.inflateSync(Buffer.concat(idat)), stride = w * ch, px = Buffer.alloc(h * stride);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)], row = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let x = 0; x < stride; x++) {
      const a = x >= ch ? px[y * stride + x - ch] : 0, b = y ? px[(y - 1) * stride + x] : 0;
      const c = x >= ch && y ? px[(y - 1) * stride + x - ch] : 0;
      let v = row[x];
      if (f === 1) v += a;
      else if (f === 2) v += b;
      else if (f === 3) v += (a + b) >> 1;
      else if (f === 4) { const q = a + b - c, pa = Math.abs(q - a), pb = Math.abs(q - b), pc = Math.abs(q - c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      px[y * stride + x] = v & 255;
    }
  }
  return { w, h, at: (x, y) => { const i = y * stride + x * ch; return [px[i], px[i + 1], px[i + 2]]; } };
}

function page(dir, theme, script) {
  const sel = BOXES.map(([c, t], i) => `<div class="s-input-row" style="margin:14px 0;width:300px"><select id="s${i}" class="${c}"><option>${t}</option></select></div>`).join("");
  const f = path.join(dir, `${theme}.html`);
  fs.writeFileSync(f, `<!doctype html><html data-theme="${theme}"><head>
<link rel="stylesheet" href="tokens.css"><link rel="stylesheet" href="fonts.css"><link rel="stylesheet" href="shapes.css">
<link rel="stylesheet" href="app.css"><link rel="stylesheet" href="devices.css"><link rel="stylesheet" href="pair.css">
<style>html,body{margin:0;background:var(--vw-color-surface)}body{padding:20px}</style></head><body>${sel}${script}</body></html>`);
  return "file://" + f;
}

const ARGS = ["--headless=new", "--no-sandbox", "--disable-gpu", "--allow-file-access-from-files", "--hide-scrollbars",
  `--window-size=${W},${H}`, "--force-device-scale-factor=1", "--virtual-time-budget=5000"];

function measure(bin, dir, theme) {
  const report = `<script>document.fonts.ready.then(()=>{document.title="R"+JSON.stringify([...document.querySelectorAll("select")].map(s=>{const r=s.getBoundingClientRect();return [r.left,r.top,r.width,r.height]}))})</script>`;
  const dom = execFileSync(bin, [...ARGS, "--dump-dom", page(dir, theme, report)], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 60000 });
  const m = dom.match(/<title>R(.*?)<\/title>/s);
  assert.ok(m, "the page reported no boxes");
  const rects = JSON.parse(m[1].replace(/&quot;/g, "\"").replace(/&amp;/g, "&"));
  if (process.env.VW_SELECT_DEBUG) console.log(rects);
  const shot = path.join(dir, theme + ".png");
  execFileSync(bin, [...ARGS, "--screenshot=" + shot, page(dir, theme, "")], { stdio: "ignore", timeout: 60000 });
  const img = png(fs.readFileSync(shot));
  return rects.map(([l, t, w, h]) => {
    // Inside the border, left of the arrow: rows whose pixels differ from the
    // box's own fill are the text.
    const x0 = Math.ceil(l) + 3, x1 = Math.min(img.w, Math.floor(l + w)) - 34, y0 = Math.ceil(t) + 3, y1 = Math.floor(t + h) - 3;
    // The box's fill: the most common colour inside it.
    const seen = new Map();
    for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x += 3) { const k = img.at(x, y).join(); seen.set(k, (seen.get(k) || 0) + 1); }
    const bg = [...seen].sort((a, b) => b[1] - a[1])[0][0].split(",").map(Number);
    const ink = [];
    for (let y = y0; y < y1; y++) {
      for (let x = x0; x < x1; x++) {
        const c = img.at(x, y);
        if (Math.abs(c[0] - bg[0]) + Math.abs(c[1] - bg[1]) + Math.abs(c[2] - bg[2]) > 90) { ink.push(y); break; }
      }
    }
    assert.ok(ink.length > 4, "found the text in a select");
    return { above: ink[0] - y0, below: y1 - 1 - ink[ink.length - 1], h };
  });
}

const bin = chrome();
for (const theme of ["dark", "light"]) {
  test(`select text is vertically centred (${theme})`, { skip: !bin && !process.env.CI && "no Chrome" }, () => {
    assert.ok(bin, "CI needs Chrome for the select test");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vw-select-"));
    try {
      fs.cpSync(UI, dir, { recursive: true });
      measure(bin, dir, theme).forEach((r, i) => {
        if (process.env.VW_SELECT_DEBUG) console.log(theme, BOXES[i][0], r);
        // Glyphs sit a little off the box centre (descenders), so allow 3px.
        assert.ok(Math.abs(r.above - r.below) <= 3,
          `${BOXES[i][0]} (${theme}): ${r.above}px above the text, ${r.below}px below in a ${r.h}px box`);
      });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}
