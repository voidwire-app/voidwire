// Every command the UI invokes must be registered (main.rs), listed in
// build.rs (so Tauri generates its permission) and allowed in the window's
// capability. A command missing from the ACL fails at run time with an error
// the user sees (Settings > Sends to, test sheet v0.9.0 step 10).
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");

const main = read("src/main.rs");
const handler = main.slice(main.indexOf("generate_handler!["));
const registered = new Set(
  [...handler.slice(0, handler.indexOf("]")).matchAll(/commands::(\w+)/g)].map((m) => m[1])
);
const build = read("build.rs");
const inBuild = new Set([...build.matchAll(/"(\w+)",/g)].map((m) => m[1]));

for (const [ui, cap] of [
  ["ui/devices.js", "capabilities/devices.json"],
  ["ui/relays.js", "capabilities/devices.json"],
  ["ui/pair.js", "capabilities/pair.json"],
  ["ui/confirm.js", "capabilities/confirm.json"],
]) {
  if (!fs.existsSync(path.join(root, ui))) continue;
  test(`${ui}: every invoked command is registered and allowed`, () => {
    const allowed = new Set(JSON.parse(read(cap)).permissions);
    const src = read(ui);
    // invoke("x"), call("x") (relays.js) and invoke(c ? "x" : "y") (confirm.js).
    const used = new Set(
      [...src.matchAll(/\b(?:invoke|call)\(\s*(?:[\w.]+\s*\?\s*"(\w+)"\s*:\s*)?"(\w+)"/g)]
        .flatMap((m) => [m[1], m[2]])
        .filter(Boolean)
    );
    assert.ok(used.size > 0);
    for (const c of used) {
      assert.ok(registered.has(c), `${c}: not in generate_handler!`);
      assert.ok(inBuild.has(c), `${c}: not in build.rs commands`);
      assert.ok(allowed.has("allow-" + c.replace(/_/g, "-")), `${c}: not allowed in ${cap}`);
    }
  });
}
