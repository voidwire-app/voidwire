// Send-result toasts name the path the send actually took: directly, via
// the pairing's relay host, or queued on that relay for its hold time.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { load } = require("./devices-harness.js");

const toast = (res) => load().ctx.formatSendToast("Pixel", res);

test("a direct send says so", () => {
  assert.strictEqual(toast({ delivery_path: "direct" }), "Sent directly to Pixel.");
  assert.strictEqual(
    toast({ delivery_path: "direct", filename: "a.pdf" }),
    "Sent directly to Pixel: a.pdf.",
  );
});

test("a relayed send names the relay host", () => {
  assert.strictEqual(
    toast({ delivery_path: "relay", relay_host: "relay.example.test", filename: "a.pdf", waiting_for_accept: true }),
    "Sent via relay.example.test to Pixel: a.pdf. Waiting for Pixel to accept.",
  );
});

test("a queued send names the relay and its hold time", () => {
  assert.strictEqual(
    toast({ delivery_path: "device_inbox", relay_host: "relay.example.test", hold_minutes: 120 }),
    "Queued for Pixel on relay.example.test. It arrives when Pixel is online and connected to that relay (kept up to 120 min).",
  );
  assert.match(toast({ delivery_path: "device_inbox" }), /on the relay\. .*kept up to 60 min\)\.$/);
});
