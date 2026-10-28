// Paired devices + Settings, one window with two tabs (SPEC 2.4).
// Own commands only (capabilities/devices.json).
//
// Forget (SPEC R3): the first click arms the button for 4 s ("Click again to
// forget", with a bar that runs out). The second click removes the row at
// once (200 ms collapse), updates the count, then asks the core. Success: a
// toast "Forgot <name>. Its links are refused until you pair it again."
// Failure: the row comes back in place with the error.
"use strict";
const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);
const ARM_MS = 4000;
const ACCEPT_ARM_MS = 1000;
const TOAST_MS = 6000;
let armed = null;
let armTimer = 0;
let toastTimer = 0;
// null, not "": with no phones paired key([]) is "", and the first refresh
// must still render the empty state ("No phones paired yet.").
let shownKey = null;
let shownTransfersKey = null;
let devs = [];
const inFlight = new Set();
const transferRows = new Map();
const acceptArmedAt = new Map();

function fmtBytes(n) {
  const b = Number(n) || 0;
  if (b < 1024) return b + " B";
  if (b < 1024 * 1024) return (b / 1024).toFixed(b < 10 * 1024 ? 1 : 0) + " KB";
  if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + " MB";
  return (b / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

// Privacy (M1.2 + M2.7): clear cached phone names and session transfer UI when hidden.
window.vwClear = function () {
  devs = [];
  shownKey = null;
  shownTransfersKey = null;
  inFlight.clear();
  transferRows.clear();
  acceptArmedAt.clear();
  const tl = $("transfers-list");
  if (tl) tl.replaceChildren();
};
document.addEventListener("visibilitychange", () => {
  if (document.hidden) window.vwClear();
});

// Tabs. main.rs sets window.__VW_TAB at creation and calls vwTab() when the
// tray's "Settings…" / "Paired devices…" re-shows the window.
window.vwTab = function (t) {
  const s = t === "settings";
  $("tab-devices").classList.toggle("on", !s);
  $("tab-settings").classList.toggle("on", s);
  $("tab-devices").setAttribute("aria-selected", String(!s));
  $("tab-settings").setAttribute("aria-selected", String(s));
  $("devices").classList.toggle("hidden", s);
  $("settings").classList.toggle("hidden", !s);
};

// SPEC r3 §4 name truncation: identifiers in mono rows keep their tail
// (head(n-7) + "…" + tail(6)); the full name goes in the tooltip.
function midEllipsis(name, n) {
  const c = Array.from(name);
  return c.length <= n ? name : c.slice(0, n - 7).join("") + "…" + c.slice(-6).join("");
}

function fmtDate(ms) {
  return ms ? new Date(ms).toLocaleDateString() : "";
}

function setCount() {
  const n = devs.filter((d) => !d.gone).length;
  $("count").textContent = String(n);
  $("empty").classList.toggle("hidden", n > 0);
}

const CUT_MD = ["vw-cut", "vw-cut-md", "vw-cut-frame"];

function forgetLabel(btn, text) {
  btn.replaceChildren(vwIcon("unlink"), document.createTextNode(text));
}

function disarm() {
  armed = null;
  clearTimeout(armTimer);
  for (const b of $("list").querySelectorAll("button.armed")) {
    b.classList.remove("armed", ...CUT_MD);
    forgetLabel(b, "Forget");
  }
}

function toast(text) {
  const i = text.indexOf(". ");
  const b = document.createElement("b");
  b.textContent = i > 0 ? text.slice(0, i + 1) : text;
  $("toasttxt").replaceChildren(b, i > 0 ? " " + text.slice(i + 2) : "");
  $("toast").classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $("toast").classList.add("hidden"), TOAST_MS);
}

async function forget(d, row, btn, err) {
  if (inFlight.has(d.id)) return;
  if (armed !== d.id) {
    disarm();
    armed = d.id;
    btn.classList.add("armed", ...CUT_MD); // the only other filled chamfer (SPEC 1.6)
    forgetLabel(btn, "Click again to forget");
    armTimer = setTimeout(disarm, ARM_MS);
    return;
  }
  disarm();
  inFlight.add(d.id);
  btn.disabled = true;
  err.textContent = "";
  $("msg").textContent = "";
  // Optimistic: the row goes now, not after the 3 s poll.
  row.classList.add("going");
  d.gone = true;
  setCount();
  try {
    const r = await invoke("device_forget", { id: d.id });
    setTimeout(() => row.remove(), 220);
    devs = devs.filter((x) => x !== d);
    shownKey = key(devs);
    toast(r.message);
  } catch (e) {
    // The core rolled the removal back (save failed): still paired, the
    // phone was told nothing, and the next poll lists it as before.
    d.gone = false;
    row.classList.remove("going");
    btn.disabled = false;
    err.textContent = "Not forgotten: " + String(e);
    setCount();
  } finally {
    inFlight.delete(d.id);
  }
}

function key(list) {
  return list.map((d) => d.id + d.name).join("|");
}

let shortcutEnabled = false;

function formatSendToast(deviceName, res) {
  if (res && res.delivery_path === "device_inbox") {
    return "Queued for " + deviceName + ". Will deliver when the phone checks its blind inbox.";
  }
  return "Sent to " + deviceName + ". Delivered via encrypted channel.";
}

function makeRow(d) {
  const row = document.createElement("div");
  row.className = "card row row-stack vw-cut vw-cut-lg vw-cut-frame";
  const head = document.createElement("div");
  head.className = "row-head";
  const ic = document.createElement("div");
  ic.className = "ic";
  ic.append(vwIcon("phone"));
  const meta = document.createElement("div");
  meta.className = "meta";
  const name = document.createElement("p");
  name.className = "t-title-small";
  const bdi = document.createElement("bdi");
  bdi.textContent = d.name;
  name.title = d.name; // card names wrap to 2 lines, then end ellipsis (SPEC r3 §4)
  name.className += " name2";
  name.append(bdi);
  const sub = document.createElement("p");
  sub.className = "t-code-small muted";
  sub.textContent = d.platform + (d.paired_at_ms ? " · paired " + fmtDate(d.paired_at_ms) : "");
  const err = document.createElement("p");
  err.className = "rowerr";
  err.setAttribute("role", "alert");
  meta.append(name, sub, err);

  const actGroup = document.createElement("div");
  actGroup.className = "row-actions";

  const clipBtn = document.createElement("button");
  clipBtn.type = "button";
  clipBtn.className = "btn btn-outline";
  clipBtn.append(vwIcon("copy"), document.createTextNode("Send clipboard"));
  clipBtn.addEventListener("click", async (ev) => {
    if (!ev.isTrusted || clipBtn.disabled) return;
    clipBtn.disabled = true;
    err.textContent = "";
    try {
      const res = await invoke("send_clipboard_to_phone", { id: d.id });
      toast(formatSendToast(d.name, res));
    } catch (e) {
      err.textContent = String(e);
    } finally {
      clipBtn.disabled = false;
    }
  });

  const fileBtn = document.createElement("button");
  fileBtn.type = "button";
  fileBtn.className = "btn btn-outline";
  fileBtn.append(vwIcon("file"), document.createTextNode("Send file…"));
  fileBtn.addEventListener("click", async (ev) => {
    if (!ev.isTrusted || fileBtn.disabled) return;
    fileBtn.disabled = true;
    err.textContent = "";
    try {
      const res = await invoke("send_file_to_phone_pick", { id: d.id });
      if (res) {
        if (res.waiting_for_accept) {
          toast("Queued " + res.filename + ". Waiting for " + d.name + " to accept.");
        } else {
          toast("Sent " + res.filename + ". Delivered to " + d.name + ".");
        }
        shownTransfersKey = null;
        refresh();
      }
    } catch (e) {
      err.textContent = String(e);
    } finally {
      fileBtn.disabled = false;
    }
  });

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-danger";
  forgetLabel(btn, "Forget");
  btn.addEventListener("click", () => forget(d, row, btn, err));

  actGroup.append(clipBtn, fileBtn, btn);
  head.append(ic, meta, actGroup);

  const sendRow = document.createElement("div");
  sendRow.className = "s-input-row row-send";
  const textInput = document.createElement("input");
  textInput.type = "text";
  textInput.className = "s-input";
  textInput.placeholder = "Paste or type a link or text to send…";
  textInput.setAttribute("aria-label", "Send link or text to " + d.name);
  const sendBtn = document.createElement("button");
  sendBtn.type = "button";
  sendBtn.className = "btn btn-outline s-btn";
  sendBtn.append(vwIcon("send"), document.createTextNode("Send"));

  const triggerTextSend = async (ev) => {
    if (ev && !ev.isTrusted) return;
    const val = (textInput.value || "").trim();
    if (!val || sendBtn.disabled) return;
    sendBtn.disabled = true;
    err.textContent = "";
    try {
      const res = await invoke("send_text_to_phone", { id: d.id, text: val });
      textInput.value = "";
      toast(formatSendToast(d.name, res));
    } catch (e) {
      err.textContent = String(e);
    } finally {
      sendBtn.disabled = false;
    }
  };
  sendBtn.addEventListener("click", triggerTextSend);
  textInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      triggerTextSend(ev);
    }
  });
  sendRow.append(textInput, sendBtn);
  row.append(head, sendRow);
  row.dataset.deviceId = d.id;

  const markDropTarget = () => {
    invoke("set_drop_target_phone", { id: d.id }).catch(() => {});
  };
  row.addEventListener("mouseenter", markDropTarget);
  row.addEventListener("dragenter", (ev) => {
    ev.preventDefault();
    row.classList.add("drop-target");
    markDropTarget();
  });
  row.addEventListener("dragover", (ev) => {
    ev.preventDefault();
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = "copy";
    row.classList.add("drop-target");
    markDropTarget();
  });
  row.addEventListener("dragleave", (ev) => {
    if (!row.contains(ev.relatedTarget)) {
      row.classList.remove("drop-target");
    }
  });
  row.addEventListener("drop", async (ev) => {
    ev.preventDefault();
    row.classList.remove("drop-target");
    markDropTarget();
    const dt = ev.dataTransfer;
    if (!dt || (dt.files && dt.files.length > 0)) {
      // Native OS file drops are handled in Rust via WindowEvent::DragDrop.
      return;
    }
    const raw = (dt.getData("text/uri-list") || dt.getData("text/plain") || "").trim();
    if (!raw || raw.startsWith("file://")) return;
    err.textContent = "";
    try {
      const res = await invoke("send_text_to_phone", { id: d.id, text: raw });
      toast(formatSendToast(d.name, res));
    } catch (e) {
      err.textContent = String(e);
    }
  });
  return row;
}

async function refresh() {
  if (inFlight.size > 0) return; // don't rebuild under a pending Forget
  try {
    const s = await invoke("settings_get");
    $("pcname").textContent = midEllipsis(s.pc_name, 16);
    $("pcname").title = s.pc_name;
    $("pcid").textContent = s.pc_id;
    $("askfirst").checked = !s.no_prompt; // "Ask before opening" = confirm mode
    $("diag").checked = s.diagnostics;
    $("version").textContent = "VOIDWIRE " + s.app_version + " · CORE " + s.core_version;
    const on = s.listening.length > 0;
    $("listening").className = "chip vw-cut-all vw-cut-sm " + (on ? "ok" : "err");
    showTheme(s.theme);
    $("listeningtxt").textContent = on ? "Listening on LAN" : "Not listening";
    if (s.removal_check_warning) {
      $("msg").textContent = s.removal_check_warning;
    } else {
      $("msg").textContent = "";
    }
    const list = await invoke("devices_list");
    if (inFlight.size > 0) return;
    if ($("autoclip")) $("autoclip").checked = !!s.auto_copy_clipboard;
    if ($("clipshortcut")) $("clipshortcut").checked = !!s.send_clipboard_shortcut;
    shortcutEnabled = !!s.send_clipboard_shortcut;
    if ($("connstats")) $("connstats").checked = !!s.connection_stats_enabled;
    if ($("neverrelay")) $("neverrelay").checked = !!s.never_send_files_over_relay;
    if ($("filehist")) $("filehist").checked = !!s.keep_file_history;
    if ($("pcname-input") && document.activeElement !== $("pcname-input")) {
      $("pcname-input").value = s.pc_name || "";
    }
    if ($("dldir-input") && document.activeElement !== $("dldir-input")) {
      $("dldir-input").value = s.download_dir || "";
      $("dldir-input").dataset.defaultDir = s.default_download_dir || "";
    }
    if ($("relayurl-input") && document.activeElement !== $("relayurl-input")) {
      $("relayurl-input").value = s.relay_url || "";
      $("relayurl-input").dataset.defaultRelay = s.default_relay_url || "";
    }
    if ($("mailboxid-input") && document.activeElement !== $("mailboxid-input")) {
      $("mailboxid-input").value = s.mailbox_id || "";
      $("mailboxid-input").dataset.defaultMailbox = s.default_mailbox_id || "";
    }
    refreshConnStatsSummary(!!s.connection_stats_enabled);
    const [incoming, completed, outgoing] = await Promise.all([
      invoke("incoming_files_list").catch(() => []),
      invoke("completed_files_list").catch(() => []),
      invoke("outgoing_files_list").catch(() => []),
    ]);
    if ($("filehist-clear")) {
      $("filehist-clear").classList.toggle("hidden", !s.keep_file_history || completed.length === 0);
    }
    renderTransfers(incoming, completed, outgoing, !!s.keep_file_history, s.download_dir);
    const k = key(list);
    if (k === shownKey) return; // keep focus/arming while nothing changed
    shownKey = k;
    disarm();
    devs = list;
    $("list").replaceChildren(...devs.map(makeRow));
    setCount();
  } catch (e) {
    $("msg").textContent = String(e);
  }
}

let currentDownloadDirLabel = "Downloads/Voidwire";

function transferSubText(f, isCompleted) {
  const sender = f.sender_name || f.from || "Phone";
  const pct = f.size > 0 ? Math.min(100, Math.floor((f.bytes_received / f.size) * 100)) : 100;
  if (isCompleted) {
    return "from " + sender + " · " + fmtBytes(f.size) + " · Saved to " + currentDownloadDirLabel;
  }
  if (f.accepted) {
    return "from " + sender + " · " + fmtBytes(f.bytes_received) + " / " + fmtBytes(f.size) + " (" + pct + "%)";
  }
  return "from " + sender + " · " + fmtBytes(f.size) + " · Waiting for confirmation";
}

function makeTransferRow(f, isCompleted) {
  const row = document.createElement("div");
  row.className = "card trow vw-cut vw-cut-lg vw-cut-frame";
  const head = document.createElement("div");
  head.className = "trow-head";
  const ic = document.createElement("div");
  ic.className = "ic";
  ic.append(vwIcon("file"));
  const meta = document.createElement("div");
  meta.className = "meta";
  const name = document.createElement("p");
  name.className = "t-title-small name2";
  const bdi = document.createElement("bdi");
  bdi.textContent = f.filename;
  name.title = f.filename;
  name.append(bdi);
  const sub = document.createElement("p");
  sub.className = "t-code-small muted";
  sub.textContent = transferSubText(f, isCompleted);
  meta.append(name, sub);

  const act = document.createElement("div");
  act.className = "trow-act";
  head.append(ic, meta, act);
  row.append(head);

  if (f.is_executable) {
    const warn = document.createElement("div");
    warn.className = "chip err vw-cut-all vw-cut-sm texec-warn";
    warn.append(vwIcon("warn"), document.createTextNode("Executable file — save only, verify before running"));
    row.append(warn);
  }

  const track = document.createElement("div");
  track.className = "tprog-track" + (!isCompleted && f.accepted ? "" : " hidden");
  const fill = document.createElement("div");
  fill.className = "tprog-fill";
  const pct = f.size > 0 ? Math.min(100, Math.floor((f.bytes_received / f.size) * 100)) : 100;
  fill.style.width = pct + "%";
  track.append(fill);
  row.append(track);

  const entry = { row, sub, act, track, fill, f, isCompleted, wasAccepted: Boolean(f.accepted), busy: false };
  populateTransferActions(entry);
  return entry;
}

function populateTransferActions(entry) {
  const { act, f, isCompleted } = entry;
  act.replaceChildren();
  if (isCompleted) {
    const saved = document.createElement("span");
    saved.className = "chip ok vw-cut-all vw-cut-sm";
    saved.textContent = "Saved";
    act.append(saved);
  } else if (f.accepted) {
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "btn btn-outline";
    cancelBtn.textContent = "Cancel";
    cancelBtn.addEventListener("click", async (ev) => {
      if (!ev.isTrusted || entry.busy) return;
      entry.busy = true;
      cancelBtn.disabled = true;
      try { await invoke("cancel_file", { transferId: entry.f.transfer_id }); }
      catch (err) { $("msg").textContent = String(err); }
      finally { entry.busy = false; }
      refresh();
    });
    act.append(cancelBtn);
  } else {
    const declineBtn = document.createElement("button");
    declineBtn.type = "button";
    declineBtn.className = "btn btn-outline";
    declineBtn.textContent = "Decline";
    declineBtn.addEventListener("click", async (ev) => {
      if (!ev.isTrusted || entry.busy) return;
      entry.busy = true;
      declineBtn.disabled = true;
      try { await invoke("cancel_file", { transferId: entry.f.transfer_id }); }
      catch (err) { $("msg").textContent = String(err); }
      finally { entry.busy = false; }
      refresh();
    });
    const acceptBtn = document.createElement("button");
    acceptBtn.type = "button";
    acceptBtn.className = "btn btn-primary vw-cut vw-cut-md vw-cut-frame";
    acceptBtn.textContent = "Accept";
    if (!acceptArmedAt.has(f.transfer_id)) {
      acceptArmedAt.set(f.transfer_id, Date.now());
    }
    const elapsed = Date.now() - acceptArmedAt.get(f.transfer_id);
    if (elapsed < ACCEPT_ARM_MS) {
      acceptBtn.disabled = true;
      setTimeout(() => {
        if (!entry.busy) acceptBtn.disabled = false;
      }, ACCEPT_ARM_MS - elapsed);
    }
    acceptBtn.addEventListener("click", async (ev) => {
      if (!ev.isTrusted || acceptBtn.disabled || entry.busy) return;
      entry.busy = true;
      acceptBtn.disabled = true;
      declineBtn.disabled = true;
      try { await invoke("accept_file", { transferId: entry.f.transfer_id }); }
      catch (err) { $("msg").textContent = String(err); }
      finally { entry.busy = false; }
      refresh();
    });
    act.append(declineBtn, acceptBtn);
  }
}

function updateTransferRow(entry, f, isCompleted) {
  entry.f = f;
  entry.sub.textContent = transferSubText(f, isCompleted);
  const pct = f.size > 0 ? Math.min(100, Math.floor((f.bytes_received / f.size) * 100)) : 100;
  entry.fill.style.width = pct + "%";
  entry.track.classList.toggle("hidden", isCompleted || !f.accepted);
  const nowAccepted = Boolean(f.accepted);
  if (entry.wasAccepted !== nowAccepted) {
    entry.wasAccepted = nowAccepted;
    populateTransferActions(entry);
  }
}

function makeOutgoingTransferRow(o) {
  const row = document.createElement("div");
  row.className = "card trow vw-cut vw-cut-lg vw-cut-frame";
  const head = document.createElement("div");
  head.className = "trow-head";
  const ic = document.createElement("div");
  ic.className = "ic";
  ic.append(vwIcon("send"));
  const meta = document.createElement("div");
  meta.className = "meta";
  const name = document.createElement("p");
  name.className = "t-title-small name2";
  const bdi = document.createElement("bdi");
  bdi.textContent = o.filename;
  name.title = o.filename;
  name.append(bdi);
  const sub = document.createElement("p");
  sub.className = "t-code-small muted";
  meta.append(name, sub);

  const act = document.createElement("div");
  act.className = "trow-act";
  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "btn btn-outline";
  cancelBtn.textContent = "Cancel";
  head.append(ic, meta, act);
  act.append(cancelBtn);
  row.append(head);

  const track = document.createElement("div");
  track.className = "tprog-track";
  const fill = document.createElement("div");
  fill.className = "tprog-fill";
  track.append(fill);
  row.append(track);

  const entry = { row, sub, act, track, fill, f: o, isOutgoing: true, busy: false };
  cancelBtn.addEventListener("click", async (ev) => {
    if (!ev.isTrusted || entry.busy) return;
    entry.busy = true;
    cancelBtn.disabled = true;
    try { await invoke("cancel_outgoing_file", { transferId: entry.f.transfer_id }); }
    catch (err) { $("msg").textContent = String(err); }
    finally { entry.busy = false; }
    shownTransfersKey = null;
    refresh();
  });
  updateOutgoingTransferRow(entry, o);
  return entry;
}

function updateOutgoingTransferRow(entry, o) {
  entry.f = o;
  const pct = o.chunk_count > 0 ? Math.min(100, Math.floor((o.chunks_sent / o.chunk_count) * 100)) : 100;
  if (o.waiting_for_accept) {
    entry.sub.textContent = "to " + o.to + " · " + fmtBytes(o.size) + " · Waiting for " + o.to + "…";
    entry.track.classList.add("hidden");
  } else {
    entry.sub.textContent = "to " + o.to + " · " + fmtBytes(o.size) + " · Sending (" + pct + "%)";
    entry.track.classList.remove("hidden");
    entry.fill.style.width = pct + "%";
  }
}

function renderTransfers(incoming, completed, outgoing, keepFileHistory, downloadDir) {
  const sec = $("transfers-sec");
  const listEl = $("transfers-list");
  if (!sec || !listEl) return;
  if (downloadDir) currentDownloadDirLabel = downloadDir;
  const outList = outgoing || [];
  const total = incoming.length + completed.length + outList.length;
  const tk = String(Boolean(keepFileHistory)) + "::" + currentDownloadDirLabel + "::"
    + incoming.map((f) => [f.transfer_id, f.accepted, f.bytes_received, f.is_executable].join(":")).join("|")
    + "##" + completed.map((f) => [f.transfer_id, f.size, f.is_executable].join(":")).join("|")
    + "##" + outList.map((o) => [o.transfer_id, o.chunks_sent, o.waiting_for_accept].join(":")).join("|");
  if (tk === shownTransfersKey) return;
  shownTransfersKey = tk;
  sec.classList.remove("hidden");
  $("transfers-count").textContent = String(total);

  const items = [
    ...outList.map((o) => ({ key: "out:" + o.transfer_id, f: o, isOutgoing: true, isCompleted: false })),
    ...incoming.map((f) => ({ key: "inc:" + f.transfer_id, f, isOutgoing: false, isCompleted: false })),
    ...completed.map((f) => ({ key: "done:" + f.transfer_id, f, isOutgoing: false, isCompleted: true })),
  ];
  const liveKeys = new Set(items.map((it) => it.key));
  for (const [k, entry] of transferRows) {
    if (!liveKeys.has(k)) {
      entry.row.remove();
      transferRows.delete(k);
    }
  }
  const oldEmpty = $("transfers-empty");
  if (oldEmpty) oldEmpty.remove();
  if (total === 0) {
    const emptyP = document.createElement("p");
    emptyP.id = "transfers-empty";
    emptyP.className = "t-body-small muted";
    emptyP.textContent = keepFileHistory
      ? "No file transfers in this session."
      : "File transfer history is disabled by default for privacy. You can enable it in Settings.";
    listEl.append(emptyP);
    return;
  }
  for (const it of items) {
    const existing = transferRows.get(it.key);
    if (!existing) {
      const entry = it.isOutgoing
        ? makeOutgoingTransferRow(it.f)
        : makeTransferRow(it.f, it.isCompleted);
      transferRows.set(it.key, entry);
      listEl.append(entry.row);
    } else if (it.isOutgoing) {
      updateOutgoingTransferRow(existing, it.f);
    } else {
      updateTransferRow(existing, it.f, it.isCompleted);
    }
  }
}

async function refreshConnStatsSummary(enabled) {
  const el = $("connstats-summary");
  if (!el) return;
  if (!enabled) {
    el.textContent = "";
    el.classList.add("hidden");
    return;
  }
  const rows = await invoke("connection_stats_list").catch(() => []);
  let directCount = 0;
  let relayCount = 0;
  let directBytes = 0;
  let relayBytes = 0;
  for (const r of rows) {
    directCount += r.direct_count || 0;
    relayCount += r.relay_count || 0;
    directBytes += r.direct_bytes || 0;
    relayBytes += r.relay_bytes || 0;
  }
  el.textContent = "Direct: " + directCount + " (" + fmtBytes(directBytes) + ") · Relay: " + relayCount + " (" + fmtBytes(relayBytes) + ")";
  el.classList.remove("hidden");
}

// Appearance > Theme (SPEC 2.6): System (default) | Dark | Light. Rust stores
// it, then re-themes every open window (caption + <html data-theme>).
let themeBusy = false;
function showTheme(t) {
  if (themeBusy) return;
  for (const b of $("theme").querySelectorAll("button")) {
    const on = b.dataset.theme === t;
    b.classList.toggle("on", on);
    b.setAttribute("aria-checked", String(on));
  }
}
for (const b of $("theme").querySelectorAll("button")) {
  b.addEventListener("click", async () => {
    const before = $("theme").querySelector("button.on")?.dataset.theme || "system";
    showTheme(b.dataset.theme);
    themeBusy = true;
    try { await invoke("settings_set_theme", { theme: b.dataset.theme }); }
    catch (err) { $("msg").textContent = String(err); themeBusy = false; showTheme(before); }
    finally { themeBusy = false; }
  });
}

$("tab-devices").addEventListener("click", () => vwTab("devices"));
$("tab-settings").addEventListener("click", () => vwTab("settings"));
$("pairbtn").addEventListener("click", () => {
  invoke("open_pair_window").catch((e) => { $("msg").textContent = String(e); });
});
$("toastx").addEventListener("click", () => $("toast").classList.add("hidden"));
$("askfirst").addEventListener("change", async (e) => {
  try { await invoke("settings_set_no_prompt", { on: !e.target.checked }); }
  catch (err) { $("msg").textContent = String(err); e.target.checked = !e.target.checked; }
});
if ($("autoclip")) {
  $("autoclip").addEventListener("change", async (e) => {
    try { await invoke("settings_set_auto_copy_clipboard", { on: e.target.checked }); }
    catch (err) { $("msg").textContent = String(err); e.target.checked = !e.target.checked; }
  });
}
if ($("clipshortcut")) {
  $("clipshortcut").addEventListener("change", async (e) => {
    try {
      await invoke("settings_set_send_clipboard_shortcut", { on: e.target.checked });
      shortcutEnabled = e.target.checked;
    } catch (err) {
      $("msg").textContent = String(err);
      e.target.checked = !e.target.checked;
    }
  });
}
document.addEventListener("keydown", async (ev) => {
  if (!ev.isTrusted || !shortcutEnabled) return;
  if ((ev.ctrlKey || ev.metaKey) && ev.shiftKey && (ev.key === "V" || ev.key === "v")) {
    ev.preventDefault();
    try {
      const target = devs.find((d) => !d.gone);
      const res = await invoke("send_clipboard_to_phone", { id: target ? target.id : "" });
      toast(formatSendToast(target ? target.name : "phone", res));
    } catch (e) {
      $("msg").textContent = String(e);
    }
  }
});
$("diag").addEventListener("change", async (e) => {
  try { await invoke("settings_set_diagnostics", { on: e.target.checked }); }
  catch (err) { $("msg").textContent = String(err); e.target.checked = !e.target.checked; }
});
if ($("neverrelay")) {
  $("neverrelay").addEventListener("change", async (e) => {
    try { await invoke("settings_set_never_relay_files", { never: e.target.checked }); }
    catch (err) { $("msg").textContent = String(err); e.target.checked = !e.target.checked; }
  });
}
if ($("filehist")) {
  $("filehist").addEventListener("change", async (e) => {
    try {
      await invoke("settings_set_file_history", { on: e.target.checked });
      shownTransfersKey = null;
      refresh();
    } catch (err) {
      $("msg").textContent = String(err);
      e.target.checked = !e.target.checked;
    }
  });
}
if ($("filehist-clear")) {
  $("filehist-clear").addEventListener("click", async () => {
    try {
      await invoke("completed_files_clear");
      shownTransfersKey = null;
      refresh();
    } catch (err) {
      $("msg").textContent = String(err);
    }
  });
}
if ($("pcname-save")) {
  $("pcname-save").addEventListener("click", async () => {
    const val = ($("pcname-input")?.value || "").trim();
    try {
      const saved = await invoke("settings_set_pc_name", { name: val });
      if ($("pcname-input")) $("pcname-input").value = saved;
      toast("Saved PC name. Paired phones will see the updated name.");
      refresh();
    } catch (err) {
      $("msg").textContent = String(err);
    }
  });
}
if ($("dl-dir-browse")) {
  $("dl-dir-browse").addEventListener("click", async () => {
    const prev = ($("dldir-input")?.value || "").trim();
    try {
      const snap = await invoke("pick_download_dir");
      const picked = typeof snap === "string" ? snap : (snap?.download_dir || "");
      if (picked && $("dldir-input")) {
        $("dldir-input").value = picked;
      }
      if (picked && picked !== prev) {
        toast("Updated download folder. Incoming files will be saved there.");
        shownTransfersKey = null;
        refresh();
      }
    } catch (err) {
      $("msg").textContent = String(err);
    }
  });
}
if ($("dldir-save")) {
  $("dldir-save").addEventListener("click", async () => {
    const val = ($("dldir-input")?.value || "").trim();
    try {
      const saved = await invoke("settings_set_download_dir", { path: val });
      if ($("dldir-input")) $("dldir-input").value = saved;
      toast("Updated download folder. Incoming files will be saved there.");
      shownTransfersKey = null;
      refresh();
    } catch (err) {
      $("msg").textContent = String(err);
    }
  });
}
if ($("dldir-reset")) {
  $("dldir-reset").addEventListener("click", async () => {
    try {
      const saved = await invoke("settings_set_download_dir", { path: "" });
      if ($("dldir-input")) $("dldir-input").value = saved;
      toast("Reset download folder. Incoming files will use the default folder.");
      shownTransfersKey = null;
      refresh();
    } catch (err) {
      $("msg").textContent = String(err);
    }
  });
}
if ($("relaycfg-save")) {
  $("relaycfg-save").addEventListener("click", async () => {
    const relayUrl = ($("relayurl-input")?.value || "").trim();
    const mailboxId = ($("mailboxid-input")?.value || "").trim();
    try {
      await invoke("settings_set_relay_config", { relayUrl, mailboxId });
      toast("Saved relay configuration. Reconnecting with updated relay settings.");
      refresh();
    } catch (err) {
      $("msg").textContent = String(err);
    }
  });
}
if ($("relaycfg-reset")) {
  $("relaycfg-reset").addEventListener("click", async () => {
    try {
      await invoke("settings_set_relay_config", { relayUrl: "", mailboxId: "" });
      if ($("relayurl-input")) $("relayurl-input").value = $("relayurl-input").dataset.defaultRelay || "";
      if ($("mailboxid-input")) $("mailboxid-input").value = $("mailboxid-input").dataset.defaultMailbox || "";
      toast("Reset relay configuration. Using official Voidwire relay and mailbox.");
      refresh();
    } catch (err) {
      $("msg").textContent = String(err);
    }
  });
}
if ($("connstats")) {
  $("connstats").addEventListener("change", async (e) => {
    try {
      await invoke("settings_set_connection_stats", { on: e.target.checked });
      await refreshConnStatsSummary(e.target.checked);
    } catch (err) {
      $("msg").textContent = String(err);
      e.target.checked = !e.target.checked;
    }
  });
}
vwTab(window.__VW_TAB || "devices");
refresh();
setInterval(refresh, 3000);

// Platform-aware Settings copy (QA 8ee9a16: Linux showed Windows wording).
// WebView2 reports "Windows" in its user agent; WebKitGTK does not.
(function platformCopy() {
  if (!/Windows/.test(navigator.userAgent)) return;
  const hint = document.getElementById("themehint");
  if (hint) hint.textContent = "System follows Windows; dark if Windows doesn't say.";
})();
