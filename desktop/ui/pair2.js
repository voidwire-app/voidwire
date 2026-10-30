// Pair-with-a-code window (M4.3). Talks only to its own commands
// (capabilities/pair2.json). This PC either shows a code (and a v=2 QR for
// phones) or types the code another device shows. Cancel closes the window
// quietly: no error screen for a pairing the user stopped.
"use strict";
const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);
let ttlMs = 300000; // replaced by the core's value on each show
let phase = "choose";
let expiresAt = 0;
let polling = null;

function show(sec, btns) {
  for (const s of ["choose", "show", "sas", "enter", "addrelay", "joined", "done"]) $(s).classList.toggle("hidden", s !== sec);
  for (const b of ["cancel", "newcode", "next", "again", "close"]) $(b).classList.toggle("hidden", !btns.includes(b));
  phase = sec;
}
function say(t) { $("msg").textContent = t || ""; }
function fail(t) {
  stopPoll();
  say(t);
  // A code that expired (or failed) while showing: offer a new one in place.
  show(phase, phase === "show" ? ["cancel", "newcode"] : ["cancel", "again"]);
}
function relay() { return $("relay").value || null; }

async function loadRelays() {
  let list = [];
  try { list = await invoke("pair2_relays"); } catch (_) { /* default relay */ }
  const sel = $("relay");
  sel.textContent = "";
  for (const r of list) {
    const o = document.createElement("option");
    o.value = r.url;
    o.textContent = r.nickname + (r.home ? " (home)" : "");
    if (r.home) o.selected = true;
    sel.appendChild(o);
  }
  // The picker only matters when there's a choice.
  $("relayrow").classList.toggle("hidden", list.length < 2);
}

function tick() {
  const ms = Math.max(0, expiresAt - Date.now());
  const s = Math.ceil(ms / 1000);
  $("left").textContent = Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
  $("bar").style.width = Math.min(100, (ms / ttlMs) * 100).toFixed(1) + "%";
}
function stopPoll() { if (polling) { clearInterval(polling); polling = null; } }

// --- This PC shows the code ---
async function startShow() {
  say("");
  stopPoll();
  show("show", ["cancel", "newcode"]);
  $("newcode").disabled = true;
  $("pcode").textContent = "…";
  try {
    const s = await invoke("pair2_show", { relayUrl: relay() });
    $("pcode").textContent = s.code || "";
    $("nocode").classList.toggle("hidden", !!s.code);
    $("qr").src = "data:image/svg+xml;base64," + btoa(s.svg);
    expiresAt = s.expires_at_ms;
    if (s.ttl_ms) ttlMs = s.ttl_ms;
    tick();
    stopPoll();
    // Local status only (no network): the window's own state while open.
    polling = setInterval(poll, 500);
  } catch (e) {
    fail(String(e));
  } finally {
    $("newcode").disabled = false;
  }
}
async function poll() {
  if (document.hidden) return;
  if (phase === "show") tick();
  let st;
  try { st = await invoke("pair2_status"); } catch (e) { return say(String(e)); }
  if (st.state === "awaiting_code" && phase === "show") {
    $("joiner").textContent = st.device_name;
    $("sasin").value = "";
    show("sas", ["cancel", "next"]);
    $("next").textContent = "Pair";
    $("sasin").focus();
  } else if (st.state === "paired") {
    done(st.device_name);
  } else if (st.state === "failed" && phase !== "done") {
    fail(st.message);
  }
}
async function submitSas() {
  const code = $("sasin").value.replace(/\D/g, "");
  if (code.length !== 6) return say("Type the 6 digits shown on the other device.");
  $("next").disabled = true;
  say("");
  try { done(await invoke("pair2_submit_code", { code })); }
  catch (e) { fail(String(e)); }
  finally { $("next").disabled = false; }
}

// --- This PC types the other device's code ---
function startEnter() {
  say("");
  $("codein").value = "";
  show("enter", ["cancel", "next"]);
  $("next").textContent = "Next";
  $("codein").focus();
}
async function openCode() {
  const code = $("codein").value.trim();
  if (!code) return say("Type the code shown on the other device.");
  $("next").disabled = true;
  say("");
  try {
    const o = await invoke("pair2_open_code", { code, relayUrl: relay() });
    if (o.inviter_name) $("inviter").textContent = o.inviter_name;
    if (o.relay_state === "ask") {
      $("addtitle").textContent = "This pairing uses " + o.relay_host + ". Add it?";
      $("addtext").textContent = "Both devices pass sealed data through this relay. It can't read it.";
      show("addrelay", ["cancel", "next"]);
      $("next").textContent = "Add and pair";
      return;
    }
    if (o.relay_state === "full") {
      $("addtitle").textContent = "This pairing uses " + o.relay_host + ".";
      $("addtext").textContent = "This PC already has the most relays it can use. Remove one in Settings first.";
      return show("addrelay", ["cancel"]);
    }
    await join();
  } catch (e) {
    say(String(e));
  } finally {
    $("next").disabled = false;
  }
}
async function addRelayAndJoin() {
  $("next").disabled = true;
  try { await invoke("pair2_add_relay"); await join(); }
  catch (e) { fail(String(e)); }
  finally { $("next").disabled = false; }
}
async function join() {
  const sas = await invoke("pair2_join");
  $("mysas").textContent = sas.slice(0, 3) + " " + sas.slice(3);
  show("joined", ["cancel"]);
  try { done(await invoke("pair2_join_wait")); }
  catch (e) { if (phase === "joined") fail(String(e)); }
}

function done(name) {
  stopPoll();
  $("paired").textContent = name;
  say("");
  show("done", ["close"]);
  $("close").focus();
}

$("go-show").addEventListener("click", startShow);
$("go-enter").addEventListener("click", startEnter);
// New code: the core replaces the live code (and deletes its relay card).
$("newcode").addEventListener("click", startShow);
$("next").addEventListener("click", () => {
  if (phase === "sas") submitSas();
  else if (phase === "enter") openCode();
  else if (phase === "addrelay") addRelayAndJoin();
});
$("sasin").addEventListener("keydown", (e) => { if (e.key === "Enter") submitSas(); });
$("codein").addEventListener("keydown", (e) => { if (e.key === "Enter") openCode(); });
// Cancel stops the code (and its relay card) and closes the window.
$("cancel").addEventListener("click", () => { stopPoll(); invoke("pair2_cancel").catch(() => {}); });
$("close").addEventListener("click", () => invoke("pair2_cancel").catch(() => {}));
$("again").addEventListener("click", () => { stopPoll(); say(""); show("choose", []); $("cancel").classList.remove("hidden"); });
document.addEventListener("visibilitychange", () => { if (!document.hidden && polling) poll(); });
loadRelays();
show("choose", ["cancel"]);
