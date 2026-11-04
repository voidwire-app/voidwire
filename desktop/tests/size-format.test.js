// Every desktop size formatter (accept prompt in confirm.js; rows and the
// relay prompt in devices.js) renders up to 1 TiB in GB/TB without overflow.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function fmtFrom(file) {
  const src = fs.readFileSync(path.join(__dirname, "..", "ui", file), "utf8");
  const m = src.match(/function fmtBytes\(n\) \{[\s\S]*?\n\}/);
  assert.ok(m, file + " defines fmtBytes");
  return vm.runInNewContext("(" + m[0] + ")");
}

const KiB = 1024;
const MiB = KiB * 1024;
const GiB = MiB * 1024;
const TiB = GiB * 1024;

for (const file of ["confirm.js", "devices.js"]) {
  const fmt = fmtFrom(file);
  test(file + ": small sizes keep their format", () => {
    assert.strictEqual(fmt(0), "0 B");
    assert.strictEqual(fmt(1023), "1023 B");
    assert.strictEqual(fmt(1536), "1.5 KB");
    assert.strictEqual(fmt(700 * KiB), "700 KB");
    assert.strictEqual(fmt(25 * MiB), "25.0 MB");
    assert.strictEqual(fmt(-1), "0 B");
    assert.strictEqual(fmt("junk"), "0 B");
  });
  test(file + ": GB and TB up to 1 TiB", () => {
    assert.strictEqual(fmt(GiB - 1), "1.00 GB");
    assert.strictEqual(fmt(2 * GiB), "2.00 GB");
    assert.strictEqual(fmt(2 * GiB + 1), "2.00 GB");
    assert.strictEqual(fmt(4 * GiB + 1), "4.00 GB");
    assert.strictEqual(fmt(500 * GiB), "500.00 GB");
    assert.strictEqual(fmt(TiB - 1), "1.00 TB");
    assert.strictEqual(fmt(TiB), "1.00 TB");
    // Sizes arrive as JSON numbers or strings.
    assert.strictEqual(fmt(String(TiB)), "1.00 TB");
    assert.strictEqual(fmt(TiB + TiB / 2), "1.50 TB");
  });
}
