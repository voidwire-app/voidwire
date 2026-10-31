// Every desktop <select> gets themed list items: hover and selected use tokens,
// never a hard-coded white, in both themes (the tokens switch with the theme).
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const ui = path.join(__dirname, "..", "ui");
const css = fs.readFileSync(path.join(ui, "app.css"), "utf8");

// Bodies of every rule whose selector list names `selector` exactly.
function rules(selector) {
  const out = [];
  for (const m of css.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (m[1].split(",").map((x) => x.trim()).includes(selector)) out.push(m[2]);
  }
  assert.ok(out.length > 0, "app.css has a rule for " + selector);
  return out;
}

test("option, hover and selected states use theme tokens", () => {
  for (const sel of ["select option", "select option:checked", "select option:hover", "::picker(select)"]) {
    const bodies = rules(sel);
    assert.ok(bodies.some((b) => /background(-color)?:[^;]*var\(--vw-color-/.test(b)), sel + " background is a token");
    for (const b of bodies) assert.doesNotMatch(b, /#fff\b|#ffffff\b|\bwhite\b/i, sel + " has no literal white");
  }
});

test("every page with a select loads app.css", () => {
  for (const f of fs.readdirSync(ui).filter((n) => n.endsWith(".html"))) {
    const html = fs.readFileSync(path.join(ui, f), "utf8");
    const js = f.replace(/\.html$/, ".js");
    const script = fs.existsSync(path.join(ui, js)) ? fs.readFileSync(path.join(ui, js), "utf8") : "";
    if (/<select\b/.test(html) || /createElement\("select"\)/.test(script)) {
      assert.match(html, /href="app\.css"/, f + " loads app.css");
    }
  }
});
