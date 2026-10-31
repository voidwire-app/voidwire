// Devices window, OS file drops: the file goes to the device row under the
// pointer (never the first row or the last one hovered), the row under the
// drag is highlighted, and a drop anywhere else asks which device. Loads the
// real devices.js against the same fake DOM as devices-pickers.test.js.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { load, flush, A, B } = require("./devices-harness.js");

// Two device rows stacked, 100 CSS px each from y=100; a 2x display.
function rows(p) {
  const rowA = p.makeRow(A), rowB = p.makeRow(B), other = p.makeEl("header");
  p.document.elementFromPoint = (x, y) => (y >= 100 && y < 200 ? rowA.inner : y >= 200 && y < 300 ? rowB.inner : other);
  p.ctx.devicePixelRatio = 2;
  return { rowA, rowB };
}
const sends = (p) => p.calls.filter((c) => c.cmd === "send_file_to_phone_pick").map((c) => [c.args.id, c.args.path]);

test("a file dropped on the second row goes to that device, not the first", async () => {
  const p = load();
  await flush();
  rows(p);
  await p.ctx.vwDropAt(40, 2 * 250, ["C:\\x\\report.pdf", "C:\\x\\b.txt"]);
  await flush();
  assert.deepStrictEqual(sends(p), [[B, "C:\\x\\report.pdf"], [B, "C:\\x\\b.txt"]]);
  assert.doesNotMatch(p.$("relay-modal-title").textContent, /Choose a device/, "no picker");
});

test("the row under the drag is highlighted, only that one, and cleared on leave", async () => {
  const p = load();
  await flush();
  const { rowA, rowB } = rows(p);
  p.ctx.vwDragOver(40, 2 * 150);
  assert.ok(rowA.classList.contains("drop-target") && !rowB.classList.contains("drop-target"));
  p.ctx.vwDragOver(40, 2 * 250);
  assert.ok(!rowA.classList.contains("drop-target") && rowB.classList.contains("drop-target"));
  p.ctx.vwDragOver(40, 2 * 20);
  assert.ok(!rowA.classList.contains("drop-target") && !rowB.classList.contains("drop-target"));
  p.ctx.vwDragOver(40, 2 * 150);
  p.ctx.vwDragOver(null, null);
  assert.ok(!rowA.classList.contains("drop-target"), "leave clears it");
});

test("a drop outside every row asks which device and sends nothing until chosen", async () => {
  const p = load();
  await flush();
  rows(p);
  p.ctx.vwDragOver(40, 2 * 150); // hovered the first row on the way
  await p.ctx.vwDropAt(40, 2 * 20, ["C:\\x\\report.pdf"]);
  await flush();
  assert.deepStrictEqual(sends(p), [], "no default device");
  assert.ok(!p.$("relay-modal").classList.contains("hidden"), "picker shown");
  assert.strictEqual(p.$("relay-modal-title").textContent, "Choose a device for report.pdf");
  const sel = p.$("relay-modal-body").children.find((c) => c.tag === "select");
  assert.deepStrictEqual(sel.children.map((o) => o.value), [A, B]);
  sel.value = B;
  await p.$("relay-modal-confirm").onclick();
  await flush();
  assert.deepStrictEqual(sends(p), [[B, "C:\\x\\report.pdf"]]);
});

test("several files dropped outside the rows: one picker for all of them", async () => {
  const p = load();
  await flush();
  rows(p);
  await p.ctx.vwDropAt(0, 0, ["C:\\a.txt", "C:\\b.txt"]);
  await flush();
  assert.strictEqual(p.$("relay-modal-title").textContent, "Choose a device for 2 files");
  const sel = p.$("relay-modal-body").children.find((c) => c.tag === "select");
  sel.value = A;
  await p.$("relay-modal-confirm").onclick();
  await flush();
  assert.deepStrictEqual(sends(p), [[A, "C:\\a.txt"], [A, "C:\\b.txt"]]);
});
