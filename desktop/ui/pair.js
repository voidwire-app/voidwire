// Pair a device window (the only pairing window; v=2 codes). Talks only to
// its own commands (capabilities/pair.json). This PC either shows a code (and a v=2 QR for
// phones) or types the code another device shows. Cancel closes the window
// quietly: no error screen for a pairing the user stopped.
"use strict";
const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);
let ttlMs = 300000; // replaced by the core's value on each show
let phase = "choose";
let expiresAt = 0;
let polling = null;
// While the window is open, an expired code is replaced by a fresh one with
// a new countdown, up to this many times in a row (30 min of 5-min codes);
// then the screen says "Code expired" and offers New code. A hidden window
// doesn't poll, so it renews when it's shown again, not in the background.
const MAX_AUTO_RENEW = 5;
let renewals = 0;
let hasCode = false;
const HINT_COPY = "Click the code to copy it. A phone can scan the QR.";
const HINT_COPIED = "Copied. It leaves the clipboard when pairing ends.";
const HINT_NOCODE = "The relay couldn't be reached, so only the QR code works.";

function show(sec, btns) {
  for (const s of ["choose", "show", "verify", "enter", "addrelay", "joined", "done"]) $(s).classList.toggle("hidden", s !== sec);
  for (const b of ["cancel", "newcode", "next", "again", "close"]) $(b).classList.toggle("hidden", !btns.includes(b));
  // Errors belong to the screen they were shown on.
  if (sec !== phase) say("");
  phase = sec;
}
function say(t) { $("msg").textContent = t || ""; }
function hint(t) { $("codehint").textContent = t; }
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
// `auto`: the window renewed an expired code by itself (keeps the count).
async function startShow(auto) {
  if (auto !== true) renewals = 0;
  say("");
  stopPoll();
  show("show", ["cancel", "newcode"]);
  $("newcode").disabled = true;
  $("pcode").textContent = "…";
  $("pcode").classList.remove("expired");
  hasCode = false;
  hint("");
  try {
    const s = await invoke("pair2_show", { relayUrl: relay() });
    hasCode = !!s.code;
    $("pcode").textContent = s.code || "";
    $("pcode").classList.toggle("nocopy", !hasCode);
    hint(hasCode ? HINT_COPY : HINT_NOCODE);
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
// The shown code ran out: a fresh one while the window is open, else stop.
function expired() {
  if (renewals < MAX_AUTO_RENEW) {
    renewals += 1;
    return startShow(true);
  }
  stopPoll();
  hasCode = false;
  $("pcode").classList.add("expired", "nocopy");
  hint("Code expired. Click New code for another one.");
  show("show", ["cancel", "newcode"]);
}
async function poll() {
  if (document.hidden) return;
  if (phase === "show") tick();
  let st;
  try { st = await invoke("pair2_status"); } catch (e) { return say(String(e)); }
  if (st.state === "awaiting_code" && phase === "show") {
    $("joiner").textContent = st.device_name;
    $("joiner2").textContent = st.device_name;
    $("sasin").value = "";
    show("verify", ["cancel", "next"]);
    $("next").textContent = "Pair";
    $("sasin").focus();
  } else if (st.state === "paired") {
    done(st.device_name, st.refreshed);
  } else if (st.state === "expired" && phase === "show") {
    expired();
  } else if (st.state === "failed" && phase !== "done") {
    fail(st.message);
  }
}
async function submitSas() {
  const code = $("sasin").value.replace(/\D/g, "");
  if (code.length !== 6) return say("Type the 6 digits shown on the other device.");
  $("next").disabled = true;
  say("");
  try { const r = await invoke("pair2_submit_code", { code }); done(r.name, r.refreshed); }
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
  try { const r = await invoke("pair2_join_wait"); done(r.name, r.refreshed); }
  catch (e) { if (phase === "joined") fail(String(e)); }
}

// `refreshed`: this device was already paired; the old pairing's keys,
// inbox and relay were replaced by the new one (one entry, never two).
function done(name, refreshed) {
  stopPoll();
  $("paired").textContent = name;
  $("donenote").textContent = refreshed
    ? "Already paired with " + name + ", pairing refreshed."
    : "It's in Paired devices. You can forget it there any time.";
  say("");
  show("done", ["close"]);
  $("close").focus();
}

$("go-show").addEventListener("click", () => startShow(false));
$("go-enter").addEventListener("click", startEnter);
// New code: the core replaces the live code (and deletes its relay card).
$("newcode").addEventListener("click", () => startShow(false));
// Click the code to copy it: the core copies the code it handed out, marked
// private on Windows (no clipboard history or cloud sync), and clears it
// when pairing ends, only if it's still the clipboard text.
async function copyCode() {
  if (!hasCode || phase !== "show") return;
  try {
    await invoke("pair2_copy_code");
    hint(HINT_COPIED);
  } catch (e) {
    say(String(e));
  }
}
$("pcode").addEventListener("click", copyCode);
$("pcode").addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { if (e.preventDefault) e.preventDefault(); copyCode(); } });
$("next").addEventListener("click", () => {
  if (phase === "verify") submitSas();
  else if (phase === "enter") openCode();
  else if (phase === "addrelay") addRelayAndJoin();
});
$("sasin").addEventListener("keydown", (e) => { if (e.key === "Enter") submitSas(); });
$("codein").addEventListener("keydown", (e) => { if (e.key === "Enter") openCode(); });
// An error clears as soon as the user changes what they typed.
$("sasin").addEventListener("input", () => say(""));
$("codein").addEventListener("input", () => say(""));
// Cancel stops the code (and its relay card) and closes the window.
$("cancel").addEventListener("click", () => { stopPoll(); invoke("pair2_cancel").catch(() => {}); });
$("close").addEventListener("click", () => invoke("pair2_cancel").catch(() => {}));
$("again").addEventListener("click", () => { stopPoll(); say(""); show("choose", []); $("cancel").classList.remove("hidden"); });
document.addEventListener("visibilitychange", () => {
  if (document.hidden) say(""); // leaving the screen clears its error
  else if (polling) poll();
});
loadRelays();
show("choose", ["cancel"]);
