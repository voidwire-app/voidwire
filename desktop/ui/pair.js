// Pair window. Talks only to its own commands (capabilities/pair.json).
//
// M1.1: the core refreshes the QR 10 s before it expires (one live secret,
// the old one revoked at once) for up to 10 minutes; this page polls, shows
// the newest QR, and pauses when the window is hidden or minimized or the
// 10 minutes are up. Layout per brand/voidwire/ui/SPEC.md 2.3 (scan / paused /
// code / done). Paused is the scan section in its paused variant (round 3,
// screens/16): the QR slot stays put, so nothing jumps when the code returns.
"use strict";
const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);
const QR_TTL_MS = 120000;
let expiresAt = 0;
let shownSeq = null;
let phase = "scan";

function buttons(...ids) {
  for (const b of ["cancel", "confirm", "again", "close"]) $(b).classList.toggle("hidden", !ids.includes(b));
}

function show(section) {
  const sec = section === "paused" ? "scan" : section;
  for (const s of ["scan", "code", "done"]) $(s).classList.toggle("hidden", s !== sec);
  const paused = section === "paused";
  $("scan").classList.toggle("is-paused", paused);
  $("scanstep").textContent = paused ? "· paused" : "· step 1 of 2";
  $("scantitle").textContent = paused ? "Pairing paused" : "Scan this with your phone";
  const was = phase;
  phase = section;
  if (paused && was !== "paused") $("resume").focus(); // SPEC: autofocused
  if (section === "code") buttons("cancel", "confirm");
  else if (section === "done") buttons("again", "close");
  else buttons();
}

function showQr(qr) {
  $("qr").src = "data:image/svg+xml;base64," + btoa(qr.svg);
  expiresAt = qr.expires_at_ms;
  shownSeq = qr.qr_seq;
  tick();
}

// "SINGLE USE · EXPIRES IN m:ss" plus a bar that shrinks with the time left.
function tick() {
  const ms = Math.max(0, expiresAt - Date.now());
  const s = Math.ceil(ms / 1000);
  $("left").textContent = Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
  $("bar").style.width = Math.min(100, (ms / QR_TTL_MS) * 100).toFixed(1) + "%";
}

function fail(text) {
  $("msg").textContent = text;
  buttons("again");
}

// SPEC 2.3 done state: title in the header band, success card, NEXT steps
// naming this PC (screens/17).
function showDone(st) {
  $("paired").textContent = st.device_name;
  $("paired2").textContent = st.device_name;
  $("paired2").title = st.device_name;
  const when = st.paired_at_ms ? new Date(st.paired_at_ms).toLocaleDateString() : "";
  $("pairedmeta").textContent = (st.platform || "Phone") + (when ? " · paired " + when : "");
  if (st.pc_name) $("pcname").textContent = st.pc_name;
  show("done");
}

async function start() {
  $("msg").textContent = "";
  setCode("");
  try {
    showQr(await invoke("pair_start"));
    show("scan");
  } catch (e) {
    fail(String(e));
  }
}

async function poll() {
  if (document.hidden) return; // paused below; never refresh unseen
  try {
    const st = await invoke("pair_status", { haveSeq: shownSeq });
    if (st.state === "waiting_for_scan") {
      if (st.qr) showQr(st.qr);
      if (phase !== "scan") show("scan");
    } else if (st.state === "paused") {
      shownSeq = null;
      $("qr").removeAttribute("src");
      $("pausedtxt").textContent = st.message;
      if (phase !== "paused" && phase !== "done") show("paused");
    } else if (st.state === "awaiting_code" && phase === "scan") {
      $("joiner").textContent = st.device_name;
      show("code");
      $("sas").focus();
    } else if (st.state === "paired") {
      if (phase !== "done") showDone(st);
    } else if (st.state === "failed" && phase !== "done") {
      fail(st.message);
    }
  } catch (e) {
    $("msg").textContent = String(e);
  }
}

// Six visual cells over the one real input (paste/IME keep working).
function digits() {
  return $("sas").value.replace(/\D/g, "").slice(0, 6);
}
function setCode(v) {
  $("sas").value = v;
  render();
}
function render() {
  const d = digits();
  const cells = $("digits").querySelectorAll(".d");
  cells.forEach((c, i) => {
    c.textContent = d[i] || "";
    c.classList.toggle("cur", i === Math.min(d.length, 5));
  });
  $("confirm").disabled = d.length !== 6;
}

async function submit() {
  const code = digits();
  if (code.length !== 6) {
    $("msg").textContent = "Enter the 6 digits shown on the phone.";
    return;
  }
  $("confirm").disabled = true;
  $("msg").textContent = "";
  try {
    const name = await invoke("pair_submit_code", { code });
    let st = null;
    try { st = await invoke("pair_status", { haveSeq: shownSeq }); } catch (_) { /* fall back to the name */ }
    showDone(st && st.state === "paired" ? st : { device_name: name });
  } catch (e) {
    fail(String(e));
  }
}

// Hidden or minimized: stop refreshing and revoke the shown QR. The Rust
// side also pauses on minimize (main.rs), in case the webview isn't told.
document.addEventListener("visibilitychange", () => {
  if (document.hidden && phase === "scan") invoke("pair_pause").catch(() => {});
  else if (!document.hidden) poll();
});

$("sas").addEventListener("input", render);
$("sas").addEventListener("focus", () => $("digits").classList.add("focus"));
$("sas").addEventListener("blur", () => $("digits").classList.remove("focus"));
$("sas").addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
$("confirm").addEventListener("click", submit);
// Cancel burns the QR and closes the window (pair_cancel does both).
$("cancel").addEventListener("click", () => invoke("pair_cancel").catch((e) => fail(String(e))));
$("close").addEventListener("click", () => invoke("pair_cancel").catch(() => {}));
$("again").addEventListener("click", start);
$("resume").addEventListener("click", start);
// The autofocused Show a new code button shows its ring even though the focus
// was programmatic (SPEC 2.3 / screens/16; shapes.css .is-focused).
$("resume").addEventListener("focus", () => $("resume").classList.add("is-focused"));
$("resume").addEventListener("blur", () => $("resume").classList.remove("is-focused"));
start();
setInterval(poll, 500);
setInterval(() => { if (phase === "scan") tick(); }, 250);
