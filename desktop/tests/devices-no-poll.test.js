// The Devices window does not poll the core: one read when it opens, then a
// read when the app nudges it (window.vwChanged, sent on every core event)
// or when it gets focus. Before 1.1.1 it re-read everything every 3 s.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { load, flush } = require("./devices-harness.js");

const reads = (p) => p.calls.filter((c) => c.cmd === "settings_get").length;
// Run the recorded timeouts of at most `maxMs` (the harness never runs them).
// The clock moves past them first.
const runTimeouts = (p, maxMs) => {
  p.clock.now += maxMs;
  const due = p.timeouts.filter((t) => t.ms <= maxMs);
  p.timeouts.splice(0, p.timeouts.length, ...p.timeouts.filter((t) => t.ms > maxMs));
  due.forEach((t) => t.fn());
};

test("opens with one read and no repeating timer", async () => {
  const p = load({});
  await flush();
  assert.strictEqual(reads(p), 1);
  assert.deepStrictEqual(p.intervals, []);
  assert.ok(!p.timeouts.some((t) => t.fn.name === "refresh"), "no setTimeout(refresh)");
});

test("a change nudge re-reads once, however many arrive", async () => {
  const p = load({});
  await flush();
  for (let i = 0; i < 5; i++) p.ctx.vwChanged();
  await flush();
  runTimeouts(p, 250);
  await flush();
  assert.strictEqual(reads(p), 2);
  // Quiet afterwards: nothing left that reads again by itself.
  runTimeouts(p, 250);
  await flush();
  assert.strictEqual(reads(p), 2);
  assert.deepStrictEqual(p.intervals, []);
});

test("a nudge during a read runs one more read after it", async () => {
  let release;
  let first = true;
  const p = load({
    answers: {
      devices_list: () => {
        if (!first) return [];
        first = false;
        return new Promise((r) => (release = () => r([])));
      },
    },
  });
  await flush();
  assert.strictEqual(reads(p), 1);
  p.ctx.vwChanged();
  p.ctx.vwChanged();
  release();
  await flush();
  runTimeouts(p, 250);
  await flush();
  assert.strictEqual(reads(p), 2);
});

test("focus re-reads", async () => {
  const p = load({});
  await flush();
  assert.strictEqual(typeof p.winListeners.focus, "function");
  p.winListeners.focus();
  await flush();
  runTimeouts(p, 250);
  await flush();
  assert.strictEqual(reads(p), 2);
});

test("transfers: progress comes as nudges; an ended row gets one re-read when due", async () => {
  const out = { transfer_id: "t1", to: "Pixel", size: 10, chunks_sent: 1, chunk_count: 4, waiting_for_accept: false };
  const active = load({ answers: { outgoing_files_list: () => [out] } });
  await flush();
  assert.deepStrictEqual(active.timeouts.filter((t) => t.ms >= 500), [], "no fast poll while sending");
  const ended = load({ answers: { outgoing_files_list: () => [{ ...out, ended: "declined" }] } });
  await flush();
  const due = ended.timeouts.filter((t) => t.ms > 10000);
  assert.strictEqual(due.length, 1);
  assert.ok(due[0].ms <= 11000);
  due[0].fn();
  runTimeouts(ended, 250); // the test runs it at once; really 10 s later
  await flush();
  assert.strictEqual(reads(ended), 2);
});
