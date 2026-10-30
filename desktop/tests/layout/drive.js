// Puts pair.js in one screen (?state=), with an error line showing, then
// reports whether `main` overflows its 440x660 window.
"use strict";
(async function () {
  const st = new URLSearchParams(location.search).get("state");
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const ERR = "The relay couldn't be reached. Check the connection and try again.";
  await wait(200);
  if (st === "show" || st === "verify") { await startShow(false); if (st === "verify") await poll(); }
  if (st === "enter" || st === "addrelay" || st === "joined") {
    startEnter();
    if (st !== "enter") { document.getElementById("codein").value = "VW-X"; openCode(); }
  }
  if (st === "done") done(window.VW_LONG, true);
  await wait(300);
  if (st !== "joined" && st !== "done") say(ERR);
  await (document.fonts ? document.fonts.ready : wait(0));
  await wait(300);
  const m = document.querySelector("main");
  const vis = [...document.querySelectorAll("main > section")].filter((s) => !s.classList.contains("hidden")).map((s) => s.id);
  const sh = m.scrollHeight, ch = m.clientHeight;
  // How tall the screen wants to be (slack = room left before a scrollbar).
  m.style.height = "auto";
  const need = m.offsetHeight;
  m.style.height = "";
  window.VW_RESULT = { state: st, shown: vis.join(","), sh, ch, need, sw: m.scrollWidth, cw: m.clientWidth };
})();
