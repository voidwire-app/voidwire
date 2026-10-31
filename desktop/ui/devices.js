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
// must still render the empty state ("No devices paired yet.").
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
  if (document.hidden) {
    window.vwClear();
    clearMsg();
  }
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
  clearMsg();
};

// The red banner floats (it never moves the layout) and goes when its
// moment has passed: on typing, on a tab change, when the window hides.
function clearMsg() {
  const m = $("msg");
  if (m) m.textContent = "";
  refreshMsg = "";
}
document.addEventListener("input", clearMsg, true);

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
  // Pairing is the main action only until something is paired.
  const pb = $("pairbtn");
  for (const c of ["btn-primary", "vw-cut", "vw-cut-md", "vw-cut-frame"]) pb.classList.toggle(c, n === 0);
  pb.classList.toggle("btn-outline", n > 0);
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
let shortcutAccel = "Ctrl+Shift+V";
let recordingShortcut = false;
let fastPollTimer = 0;

function formatSendToast(deviceName, res) {
  if (res && res.delivery_path === "device_inbox") {
    return "Queued for " + deviceName + ". Will deliver when the phone checks its blind inbox.";
  }
  return "Sent to " + deviceName + ". Delivered via encrypted channel.";
}

// Wrappers that can precede a relay-policy tag (M3.1.2). Older builds sent
// "protocol error: relay_prompt_required: ..." and every startsWith() missed.
const SEND_ERR_WRAPPERS = ["protocol error: ", "file_offer_rejected: "];

function stripSendErrWrappers(first) {
  let s = String(first || "").trim();
  let phoneSide = false;
  for (let again = true; again; ) {
    again = false;
    for (const w of SEND_ERR_WRAPPERS) {
      if (s.startsWith(w)) {
        if (w.startsWith("file_offer_rejected")) phoneSide = true;
        s = s.slice(w.length).trim();
        again = true;
      }
    }
  }
  return { tag: s, phoneSide };
}

function parseSendErrorMeta(raw) {
  const lines = String(raw || "").split("\n");
  const stripped = stripSendErrWrappers(lines[0] || "");
  const first = stripped.tag;
  const meta = { raw: first };
  for (let i = 1; i < lines.length; i++) {
    const eq = lines[i].indexOf("=");
    if (eq > 0) {
      meta[lines[i].slice(0, eq).trim()] = lines[i].slice(eq + 1).trim();
    }
  }
  const szMatch = /size=(\d+)/.exec(first);
  const capMatch = /cap=(\d+)/.exec(first);
  if (szMatch) meta.size = Number(szMatch[1]);
  if (capMatch) meta.cap = Number(capMatch[1]);
  meta.phoneSide = meta.side === "phone" || stripped.phoneSide;
  let kind = meta.kind;
  if (!kind) {
    if (first.startsWith("relay_prompt_required:")) kind = "relay_prompt";
    else if (first.startsWith("exceeds_relay_cap")) {
      kind =
        first.includes("never_send_files_over_relay") || (meta.phoneSide && meta.cap === 0)
          ? "relay_never"
          : "relay_cap";
    } else kind = "error";
  }
  meta.kind = kind;
  meta.isPrompt = kind === "relay_prompt";
  meta.isCap = kind === "relay_cap" || kind === "relay_never";
  meta.isNeverRelay = kind === "relay_never";
  return meta;
}

function closeRelayModal() {
  const modal = $("relay-modal");
  if (modal) modal.classList.add("hidden");
}

function showRelayModal({ eyebrow, title, body, confirmText, showCancel, onConfirm }) {
  const modal = $("relay-modal");
  if (!modal) return;
  $("relay-modal-eyebrow").textContent = eyebrow || "Relay transfer policy";
  $("relay-modal-title").textContent = title || "";
  $("relay-modal-body").textContent = body || "";
  const cancelBtn = $("relay-modal-cancel");
  const confirmBtn = $("relay-modal-confirm");
  cancelBtn.classList.toggle("hidden", !showCancel);
  confirmBtn.textContent = confirmText || "OK";
  confirmBtn.disabled = false;
  cancelBtn.onclick = () => closeRelayModal();
  // Close first: a failed retry opens the modal again with its own message.
  confirmBtn.onclick = () => {
    closeRelayModal();
    if (onConfirm) onConfirm();
  };
  modal.classList.remove("hidden");
  confirmBtn.focus();
}

// The device picker (M4.5, never a guess): Explorer's "Send with Voidwire"
// with a file, or the clipboard shortcut (`filePath` null) with 2+ devices.
function showPhonePickerModal(filePath, list) {
  const modal = $("relay-modal");
  if (!modal || !list || list.length === 0) return;
  const fname = filePath ? filePath.split(/[\\/]/).pop() || "file" : "";
  $("relay-modal-eyebrow").textContent = "Send with Voidwire";
  $("relay-modal-title").textContent = filePath ? "Choose a device for " + fname : "Send clipboard to…";
  const bodyEl = $("relay-modal-body");
  bodyEl.textContent = filePath
    ? "Select which paired device should receive this file:"
    : "Select which paired device should receive this PC's clipboard:";
  const sel = document.createElement("select");
  sel.className = "s-input";
  sel.style.marginTop = "10px";
  sel.style.width = "100%";
  for (const d of list) {
    const opt = document.createElement("option");
    opt.value = d.id;
    opt.textContent = d.name;
    sel.append(opt);
  }
  bodyEl.append(sel);
  const cancelBtn = $("relay-modal-cancel");
  const confirmBtn = $("relay-modal-confirm");
  cancelBtn.classList.remove("hidden");
  confirmBtn.textContent = filePath ? "Send file" : "Send";
  confirmBtn.disabled = false;
  cancelBtn.onclick = () => closeRelayModal();
  confirmBtn.onclick = async () => {
    const chosenDev = list.find((d) => d.id === sel.value);
    closeRelayModal();
    if (!chosenDev) return;
    try {
      if (!filePath) {
        await invoke("send_clipboard_to_phone", { id: chosenDev.id, relayDecision: null });
        toast("Sent clipboard to " + chosenDev.name + ".");
        return;
      }
      const res = await invoke("send_file_to_phone_pick", {
        id: chosenDev.id,
        path: filePath,
        relayDecision: null,
      });
      if (res) {
        if (res.waiting_for_accept) {
          toast("Queued " + res.filename + ". Waiting for " + chosenDev.name + " to accept.");
        } else {
          toast("Sent " + res.filename + ". Delivered to " + chosenDev.name + ".");
        }
        shownTransfersKey = null;
        refresh();
      }
    } catch (e) {
      handleFileSendError(e, chosenDev.id, chosenDev.name, null, filePath || null);
    }
  };
  modal.classList.remove("hidden");
  sel.focus();
}

// One plain dialog for any send failure (no toast, no vanishing red text).
function showSendErrorModal(phoneName, text) {
  showRelayModal({
    eyebrow: "Send failed",
    title: "Couldn't send to " + phoneName,
    body: text,
    confirmText: "OK",
    showCancel: false,
    onConfirm: null,
  });
}

// Every PC -> phone send failure from any trigger (row buttons, text box,
// tray, hotkey, drag-and-drop) ends here. `retryText` resends typed or dropped
// text after a relay confirmation; otherwise a file path retries that file and
// no path retries the clipboard.
function handleFileSendError(rawErr, fallbackPhoneId, fallbackPhoneName, errEl, fallbackPath, retryText) {
  if (errEl) errEl.textContent = "";
  const meta = parseSendErrorMeta(rawErr);
  const phoneId = meta.device_id || meta.phone_id || fallbackPhoneId || "";
  const phoneName = meta.phone_name || fallbackPhoneName || "your phone";
  const filePath = meta.path || fallbackPath || "";
  const isText = typeof retryText === "string" || (!filePath && !meta.filename);
  const filename =
    meta.filename ||
    (filePath ? filePath.split(/[\\/]/).pop() : typeof retryText === "string" ? "this text" : isText ? "the clipboard text" : "this file");
  const sizeStr = meta.size ? fmtBytes(meta.size) : "";
  const capStr = meta.cap ? fmtBytes(meta.cap) : "25.0 MB";
  const what = filename + (sizeStr ? " (" + sizeStr + ")" : "");
  const What = what.charAt(0).toUpperCase() + what.slice(1);

  if (meta.isNeverRelay) {
    const body = meta.phoneSide
      ? What + " wasn't sent. " + phoneName + " isn't on the same Wi-Fi / LAN as this PC, so the only way to reach it is the encrypted relay, and 'Never send files over relay' is turned on in the phone's Settings. Connect both devices to the same network, or turn that setting off on the phone."
      : What + " wasn't sent. " + phoneName + " isn't on the same Wi-Fi / LAN as this PC, so the only way to reach it is the encrypted relay, and 'Never send files over relay' is turned on in Settings. Connect both devices to the same network, or turn that setting off.";
    showRelayModal({
      eyebrow: "Relay blocked",
      title: "Relay file transfers are turned off",
      body,
      confirmText: "OK",
      showCancel: false,
      onConfirm: null,
    });
    return;
  }

  if (meta.isCap) {
    showRelayModal({
      eyebrow: "Relay limit",
      title: "Too large for the relay",
      body:
        What + " wasn't sent. " + phoneName + " isn't on the same Wi-Fi / LAN as this PC, so it can only be reached through the encrypted relay, which carries files up to " + capStr + ". Connect both devices to the same network to send it directly.",
      confirmText: "OK",
      showCancel: false,
      onConfirm: null,
    });
    return;
  }

  if (meta.isPrompt) {
    showRelayModal({
      eyebrow: "Relay confirmation",
      title: "Send over the relay?",
      body:
        phoneName + " isn't on the same Wi-Fi / LAN as this PC, so " + what + " can only go through the encrypted relay (end-to-end encrypted; the relay can't read it). Items over 256 KB ask first; the relay limit is " + capStr + ".",
      confirmText: "Send over relay",
      showCancel: true,
      onConfirm: async () => {
        toast("Sending over relay. " + What + " to " + phoneName + ".");
        try {
          if (typeof retryText === "string") {
            const res = await invoke("send_text_to_phone", {
              id: phoneId,
              text: retryText,
              relayDecision: "send_via_relay",
            });
            toast(formatSendToast(phoneName, res));
          } else if (filePath) {
            const res = await invoke("send_file_to_phone_pick", {
              id: phoneId,
              path: filePath,
              relayDecision: "send_via_relay",
            });
            if (res) {
              if (res.waiting_for_accept) {
                toast("Queued " + res.filename + ". Waiting for " + phoneName + " to accept.");
              } else {
                toast("Sent " + res.filename + ". Delivered to " + phoneName + ".");
              }
            }
          } else {
            const res = await invoke("send_clipboard_to_phone", {
              id: phoneId,
              relayDecision: "send_via_relay",
            });
            toast(formatSendToast(phoneName, res));
          }
          shownTransfersKey = null;
          refresh();
        } catch (e2) {
          handleFileSendError(e2, phoneId, phoneName, null, filePath, retryText);
        }
      },
    });
    return;
  }

  showSendErrorModal(phoneName, meta.raw || String(rawErr));
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

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-danger";
  forgetLabel(btn, "Forget");
  btn.addEventListener("click", () => forget(d, row, btn, err));

  head.append(ic, meta, btn);

  const sendBar = document.createElement("div");
  sendBar.className = "phone-send-bar";

  const clipBtn = document.createElement("button");
  clipBtn.type = "button";
  clipBtn.className = "btn btn-outline";
  clipBtn.append(vwIcon("copy"), document.createTextNode("Send clipboard"));
  clipBtn.addEventListener("click", async (ev) => {
    if (!ev.isTrusted || clipBtn.disabled) return;
    clipBtn.disabled = true;
    err.textContent = "";
    try {
      const res = await invoke("send_clipboard_to_phone", { id: d.id, relayDecision: null });
      toast(formatSendToast(d.name, res));
      shownTransfersKey = null;
      refresh();
    } catch (e) {
      handleFileSendError(e, d.id, d.name, err, null);
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
      const res = await invoke("send_file_to_phone_pick", {
        id: d.id,
        path: null,
        relayDecision: null,
      });
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
      handleFileSendError(e, d.id, d.name, err, null);
    } finally {
      fileBtn.disabled = false;
    }
  });

  const dropHint = document.createElement("span");
  dropHint.className = "drop-hint";
  dropHint.textContent = "or drop a file here";
  sendBar.append(clipBtn, fileBtn, dropHint);
  if (window.vwRelayRow) window.vwRelayRow(d, meta, head, btn);

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
      handleFileSendError(e, d.id, d.name, err, null, val);
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
  row.append(head, sendBar, sendRow);
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
      handleFileSendError(e, d.id, d.name, err, null, raw);
    }
  });
  return row;
}

// The 3 s poll only clears banner text it wrote itself (M3.1.2): it used to
// blank #msg every tick, wiping send errors before they could be read.
var refreshMsg = ""; // var: clearMsg() may run before this line
function setRefreshMsg(text) {
  const el = $("msg");
  if (text) {
    el.textContent = text;
    refreshMsg = text;
  } else if (refreshMsg) {
    if (el.textContent === refreshMsg) el.textContent = "";
    refreshMsg = "";
  }
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
    setRefreshMsg("");
    const list = await invoke("devices_list");
    if (inFlight.size > 0) return;
    if ($("autoclip")) $("autoclip").checked = !!s.auto_copy_clipboard;
    if ($("clipshortcut")) $("clipshortcut").checked = !!s.send_clipboard_shortcut;
    fillShortcutDevice(list, s.send_clipboard_shortcut_device || "");
    if ($("ctxmenu")) $("ctxmenu").checked = s.context_menu_enabled !== false;
    shortcutEnabled = !!s.send_clipboard_shortcut;
    shortcutAccel = s.send_clipboard_shortcut_accel || "Ctrl+Shift+V";
    if (!recordingShortcut) {
      updateShortcutUi(shortcutAccel);
    }
    if (s.pending_ui_send_error) {
      const pe = s.pending_ui_send_error;
      if (pe.error === "__pick_phone__" && pe.file_path && list.length > 1) {
        showPhonePickerModal(pe.file_path, list);
      } else if (pe.error === "__pick_device_clipboard__" && list.length > 1) {
        showPhonePickerModal(null, list);
      } else {
        const peId = pe.device_id || pe.phone_id;
        const targetDev = peId ? list.find((d) => d.id === peId) : null;
        handleFileSendError(
          pe.error,
          peId || "",
          targetDev ? targetDev.name : "your device",
          null,
          pe.file_path || null,
          pe.retry_text !== undefined && pe.retry_text !== null ? pe.retry_text : undefined
        );
      }
    }
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
    refreshConnStatsSummary(!!s.connection_stats_enabled);
    if (window.vwRelaysRefresh) window.vwRelaysRefresh();
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
    setRefreshMsg(String(e));
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
    entry.sub.textContent = "Queued for " + o.to + " — waiting for phone to accept (0%) · " + fmtBytes(o.size);
    entry.track.classList.remove("hidden");
    entry.fill.style.width = "0%";
  } else {
    const bytesSent = Math.min(o.size, (o.chunks_sent || 0) * 262144);
    entry.sub.textContent = "Sending to " + o.to + " · " + fmtBytes(bytesSent) + " / " + fmtBytes(o.size) + " (" + pct + "%)";
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
  const hasActive = incoming.length > 0 || outList.length > 0;
  clearTimeout(fastPollTimer);
  if (hasActive) {
    fastPollTimer = setTimeout(refresh, 700);
  }
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

// Appearance > Theme (SPEC 2.6): Dark (default) | System | Light. Rust stores
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
    const before = $("theme").querySelector("button.on")?.dataset.theme || "dark";
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
if ($("ctxmenu")) {
  $("ctxmenu").addEventListener("change", async (e) => {
    try {
      const saved = await invoke("settings_set_context_menu", { on: e.target.checked });
      $("ctxmenu").checked = !!saved;
    } catch (err) {
      $("msg").textContent = String(err);
      e.target.checked = !e.target.checked;
    }
  });
}
// The shortcut's "Sends to": Ask each time (default) or one paired device.
// An unpaired saved device shows as Ask (the shortcut ignores it too).
function fillShortcutDevice(list, saved) {
  const sel = $("clipshortcut-device");
  if (!sel || document.activeElement === sel) return;
  sel.replaceChildren();
  const ask = document.createElement("option");
  ask.value = "";
  ask.textContent = "Ask each time";
  sel.append(ask);
  for (const d of list) {
    const opt = document.createElement("option");
    opt.value = d.id;
    opt.textContent = d.name;
    sel.append(opt);
  }
  sel.value = list.some((d) => d.id === saved) ? saved : "";
}
if ($("clipshortcut-device")) {
  $("clipshortcut-device").addEventListener("change", async (e) => {
    setShortcutErr("");
    try {
      await invoke("settings_set_send_clipboard_shortcut_device", { id: e.target.value });
    } catch (err) {
      setShortcutErr(String(err));
      refresh();
    }
  });
}

function updateShortcutUi(accel) {
  const badge = $("clipshortcut-badge");
  const hint = $("clipshortcut-hint");
  const recBtn = $("clipshortcut-record");
  if (badge) {
    badge.textContent = accel;
    badge.classList.remove("recording");
  }
  if (hint) {
    hint.textContent =
      "Off: disabled by default. On: press " +
      accel +
      " to send this PC's clipboard. With more than one device it asks which one.";
  }
  if (recBtn) {
    recBtn.textContent = "Record shortcut…";
  }
}

function setShortcutErr(text) {
  const el = $("clipshortcut-err");
  if (!el) return;
  el.textContent = text || "";
  el.title = text || "";
}

function eventToAccel(ev) {
  const mods = [];
  if (ev.ctrlKey) mods.push("Ctrl");
  if (ev.altKey) mods.push("Alt");
  if (ev.shiftKey) mods.push("Shift");
  if (ev.metaKey) mods.push("Win");
  const k = ev.key;
  if (!k || k === "Control" || k === "Shift" || k === "Alt" || k === "Meta") {
    return null;
  }
  if (mods.length === 0) return null;
  let keyToken = null;
  if (k.length === 1) {
    const ch = k.toUpperCase();
    if ((ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9")) {
      keyToken = ch;
    } else if (k === " ") {
      keyToken = "Space";
    } else if ([";", "=", ",", "-", ".", "/", "`", "[", "\\", "]", "'"].includes(k)) {
      keyToken = k;
    }
  } else if (/^F([1-9]|1[0-9]|2[0-4])$/i.test(k)) {
    keyToken = k.toUpperCase();
  } else {
    const map = {
      Tab: "Tab",
      Enter: "Enter",
      Backspace: "Backspace",
      Delete: "Delete",
      Insert: "Insert",
      Home: "Home",
      End: "End",
      PageUp: "PageUp",
      PageDown: "PageDown",
      ArrowUp: "Up",
      ArrowDown: "Down",
      ArrowLeft: "Left",
      ArrowRight: "Right",
    };
    keyToken = map[k] || null;
  }
  if (!keyToken) return null;
  return [...mods, keyToken].join("+");
}

if ($("clipshortcut")) {
  $("clipshortcut").addEventListener("change", async (e) => {
    setShortcutErr("");
    try {
      await invoke("settings_set_send_clipboard_shortcut", { on: e.target.checked });
      shortcutEnabled = e.target.checked;
    } catch (err) {
      setShortcutErr(String(err));
      e.target.checked = !e.target.checked;
    }
  });
}
if ($("clipshortcut-record")) {
  $("clipshortcut-record").addEventListener("click", () => {
    setShortcutErr("");
    if (recordingShortcut) {
      recordingShortcut = false;
      updateShortcutUi(shortcutAccel);
      return;
    }
    recordingShortcut = true;
    const badge = $("clipshortcut-badge");
    if (badge) {
      badge.textContent = "Press keys…";
      badge.classList.add("recording");
    }
    $("clipshortcut-record").textContent = "Cancel";
  });
}
if ($("clipshortcut-reset")) {
  $("clipshortcut-reset").addEventListener("click", async () => {
    recordingShortcut = false;
    setShortcutErr("");
    try {
      const saved = await invoke("settings_set_send_clipboard_shortcut_accel", {
        accel: "Ctrl+Shift+V",
      });
      shortcutAccel = saved;
      updateShortcutUi(shortcutAccel);
      toast("Reset clipboard shortcut to " + saved + ".");
    } catch (err) {
      setShortcutErr(String(err));
    }
  });
}
document.addEventListener("keydown", async (ev) => {
  if (!ev.isTrusted) return;
  if (recordingShortcut) {
    if (ev.key === "Escape") {
      ev.preventDefault();
      recordingShortcut = false;
      updateShortcutUi(shortcutAccel);
      return;
    }
    if (["Control", "Shift", "Alt", "Meta"].includes(ev.key)) return;
    ev.preventDefault();
    ev.stopPropagation();
    const candidate = eventToAccel(ev);
    if (!candidate) {
      setShortcutErr("Press Ctrl, Alt, or Shift together with a letter, number, or F1–F12 key.");
      return;
    }
    recordingShortcut = false;
    try {
      const saved = await invoke("settings_set_send_clipboard_shortcut_accel", {
        accel: candidate,
      });
      shortcutAccel = saved;
      updateShortcutUi(shortcutAccel);
      setShortcutErr("");
      toast("Updated clipboard shortcut to " + saved + ".");
    } catch (err) {
      updateShortcutUi(shortcutAccel);
      setShortcutErr(String(err));
    }
    return;
  }
  if (!shortcutEnabled) return;
  const pressed = eventToAccel(ev);
  if (pressed && pressed.toUpperCase() === shortcutAccel.toUpperCase()) {
    ev.preventDefault();
    try {
      const target = devs.find((d) => !d.gone);
      const res = await invoke("send_clipboard_to_phone", {
        id: target ? target.id : "",
        relayDecision: null,
      });
      toast(formatSendToast(target ? target.name : "phone", res));
    } catch (e) {
      const target = devs.find((d) => !d.gone);
      handleFileSendError(
        e,
        target ? target.id : "",
        target ? target.name : "your phone",
        null,
        null
      );
    }
  }
});

if ($("msg")) {
  $("msg").title = "Click to dismiss";
  $("msg").addEventListener("click", () => {
    $("msg").textContent = "";
    refreshMsg = "";
  });
}

window.vwCheckPendingSendError = function () {
  refresh();
};
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
      toast("Saved PC name. Paired devices will see the updated name.");
      refresh();
    } catch (err) {
      $("msg").textContent = String(err);
    }
  });
}
// Picking a folder saves it; a one-line note confirms it in place.
function dldirNote(text) {
  const n = $("dldir-note");
  if (n) n.textContent = text;
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
        dldirNote("Saved. New files go here.");
        shownTransfersKey = null;
        refresh();
      }
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
      dldirNote("Reset. New files go to the default folder.");
      shownTransfersKey = null;
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
  if (hint) hint.textContent = "Dark by default. System follows Windows.";
})();
