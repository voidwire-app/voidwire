// Confirm-before-open & incoming file-offer prompts. Shows host + device or
// sanitized filename + size + device only; decides by id / transferId
// (capabilities/confirm.json). No full URL or filesystem path reaches this webview.
//
// QA M1: the window never takes focus (see show_window), the list is
// updated in place (rows are never rebuilt under the pointer), and "Open" /
// "Accept" stays disabled for ARM_MS after the window appears or its content
// changes, so a click aimed at something else can't approve a new link/file.
// Layout per brand/voidwire/ui/SPEC.md 2.5 + M2.7.
"use strict";
const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);
const ARM_MS = 1000;
const POLL_MS = 700;
const rows = new Map(); // id -> { li, open, dismiss, busy }
const fileRows = new Map(); // transfer_id -> { li, acceptBtn, cancelBtn, progWrap, progFill, progText, note, busy, accepted }
const clipRows = new Map(); // id -> { li, copyBtn, saveBtn, dismissBtn, forgetBtn, busy }
let armTimer = 0;

function fmtBytes(n) {
  const b = Number(n) || 0;
  if (b < 1024) return b + " B";
  if (b < 1024 * 1024) return (b / 1024).toFixed(b < 10 * 1024 ? 1 : 0) + " KB";
  if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + " MB";
  return (b / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

function setOpenEnabled(on) {
  for (const r of rows.values()) r.open.disabled = !on || r.busy;
  for (const f of fileRows.values()) f.acceptBtn.disabled = !on || f.busy || f.accepted;
  for (const c of clipRows.values()) {
    c.copyBtn.disabled = !on || c.busy;
    if (c.saveBtn) c.saveBtn.disabled = !on || c.busy;
  }
}

// (Re)start the arming delay: every Open/Accept is disabled until ARM_MS passes
// with no change.
function rearm() {
  setOpenEnabled(false);
  clearTimeout(armTimer);
  armTimer = setTimeout(() => {
    armTimer = 0;
    setOpenEnabled(true);
  }, ARM_MS);
}

function makeRow(p) {
  const li = document.createElement("div");
  li.className = "prompt";
  li.dataset.id = String(p.id);
  const hostP = document.createElement("p");
  hostP.className = "host";
  const host = document.createElement("bdi");
  host.textContent = p.host; // the host only, never the URL (SPEC R5)
  hostP.append(host);
  const fromP = document.createElement("p");
  fromP.className = "from t-body-medium muted";
  const from = document.createElement("b");
  const fromName = document.createElement("bdi");
  fromName.textContent = p.from;
  from.append(fromName);
  const fromT = document.createElement("span");
  fromT.append("from ", from);
  fromP.append(vwIcon("phone"), fromT);
  const note = document.createElement("p");
  note.className = "t-body-small muted file-note";
  note.textContent = "Only the site is shown here. The full link opens in your default browser if you click Open.";
  const open = document.createElement("button");
  open.type = "button";
  open.className = "btn btn-primary vw-cut vw-cut-md vw-cut-frame";
  open.append(vwIcon("link"), "Open");
  open.disabled = true;
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.className = "btn btn-outline";
  dismiss.textContent = "Dismiss";
  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(dismiss, open);
  const row = { li, open, dismiss, busy: false };
  const decide = async (ev, yes) => {
    if (!ev.isTrusted || row.busy || (yes && open.disabled)) return;
    row.busy = true;
    open.disabled = dismiss.disabled = true;
    try {
      await invoke("pending_decide", { id: p.id, open: yes });
    } catch (e) {
      $("msg").textContent = String(e);
    }
    refresh();
  };
  open.addEventListener("click", (ev) => decide(ev, true));
  dismiss.addEventListener("click", (ev) => decide(ev, false));
  li.append(hostP, fromP, note, actions);
  return row;
}

function makeFileRow(f) {
  const li = document.createElement("div");
  li.className = "prompt file-prompt";
  li.dataset.transferId = f.transfer_id;

  const hostP = document.createElement("p");
  hostP.className = "host file-title-row";
  const fn = document.createElement("bdi");
  fn.className = "file-name";
  fn.textContent = f.filename;
  const sz = document.createElement("span");
  sz.className = "file-size";
  sz.textContent = fmtBytes(f.size);
  hostP.append(vwIcon("file"), fn, sz);

  const fromP = document.createElement("p");
  fromP.className = "from t-body-medium muted";
  const from = document.createElement("b");
  const fromName = document.createElement("bdi");
  fromName.textContent = f.sender_name || f.from;
  from.append(fromName);
  const fromT = document.createElement("span");
  fromT.append("from ", from);
  fromP.append(vwIcon("phone"), fromT);

  li.append(hostP, fromP);

  if (f.is_executable) {
    const warn = document.createElement("div");
    warn.className = "chip err vw-cut-all vw-cut-sm";
    warn.append(vwIcon("warn"), document.createTextNode("Executable file — save only, verify before running"));
    li.append(warn);
  }

  const progWrap = document.createElement("div");
  progWrap.className = "fprog hidden";
  const progTrack = document.createElement("div");
  progTrack.className = "fprog-track";
  const progFill = document.createElement("div");
  progFill.className = "fprog-fill";
  progTrack.append(progFill);
  const progText = document.createElement("p");
  progText.className = "t-code-small muted";
  progWrap.append(progTrack, progText);

  const note = document.createElement("p");
  note.className = "t-body-small muted";

  const acceptBtn = document.createElement("button");
  acceptBtn.type = "button";
  acceptBtn.className = "btn btn-primary vw-cut vw-cut-md vw-cut-frame";
  acceptBtn.append(vwIcon("check"), "Accept");
  acceptBtn.disabled = true;

  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "btn btn-outline";
  cancelBtn.textContent = "Decline";

  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(cancelBtn, acceptBtn);

  const entry = {
    li,
    acceptBtn,
    cancelBtn,
    progWrap,
    progFill,
    progText,
    note,
    busy: false,
    accepted: !!f.accepted,
  };

  const decideFile = async (ev, accept) => {
    if (!ev.isTrusted || entry.busy || (accept && acceptBtn.disabled)) return;
    entry.busy = true;
    acceptBtn.disabled = cancelBtn.disabled = true;
    try {
      await invoke(accept ? "accept_file" : "cancel_file", { transferId: f.transfer_id });
    } catch (e) {
      $("msg").textContent = String(e);
    } finally {
      entry.busy = false;
      cancelBtn.disabled = false;
    }
    refresh();
  };
  acceptBtn.addEventListener("click", (ev) => decideFile(ev, true));
  cancelBtn.addEventListener("click", (ev) => decideFile(ev, false));

  li.append(progWrap, note, actions);
  updateFileRow(entry, f);
  return entry;
}

function updateFileRow(entry, f) {
  entry.accepted = !!f.accepted;
  const dir = f.download_dir || "Downloads/Voidwire";
  const pct = f.size > 0 ? Math.min(100, Math.floor((f.bytes_received / f.size) * 100)) : 100;
  if (f.accepted) {
    entry.progWrap.classList.remove("hidden");
    entry.progFill.style.width = pct + "%";
    entry.progText.textContent = fmtBytes(f.bytes_received) + " / " + fmtBytes(f.size) + " (" + pct + "%)";
    entry.note.textContent = "Receiving encrypted file into " + dir + "…";
    entry.cancelBtn.textContent = "Cancel";
    entry.acceptBtn.classList.add("hidden");
  } else {
    entry.progWrap.classList.add("hidden");
    entry.note.textContent = f.is_executable
      ? "Executable file — will only be saved to " + dir + ", never opened."
      : "Will be saved to " + dir + " if you click Accept.";
    entry.cancelBtn.textContent = "Decline";
    entry.acceptBtn.classList.remove("hidden");
  }
}

function makeClipRow(c) {
  const li = document.createElement("div");
  li.className = "prompt clip-prompt";
  li.dataset.clipId = String(c.id);

  const hostP = document.createElement("p");
  hostP.className = "host file-title-row";
  const titleSpan = document.createElement("bdi");
  titleSpan.className = "file-name";
  titleSpan.textContent = "Clipboard text from " + c.from;
  const sz = document.createElement("span");
  sz.className = "file-size";
  sz.textContent = fmtBytes(c.byte_len);
  hostP.append(vwIcon("copy"), titleSpan, sz);
  li.append(hostP);

  if (c.sensitive) {
    const warn = document.createElement("div");
    warn.className = "chip err vw-cut-all vw-cut-sm";
    warn.append(vwIcon("warn"), document.createTextNode("Looks like a secret — preview masked by default"));
    li.append(warn);
  }

  const prevWrap = document.createElement("div");
  prevWrap.className = "clip-preview-wrap";
  const prevBox = document.createElement("pre");
  prevBox.className = "clip-preview";
  const previewText = c.text.length > 280 ? c.text.slice(0, 280) + "…" : c.text;
  let revealed = !c.sensitive;
  const renderPreview = () => {
    prevBox.textContent = revealed ? previewText : "••••••••••••••••••••••••";
  };
  renderPreview();
  prevWrap.append(prevBox);

  if (c.sensitive) {
    const revBtn = document.createElement("button");
    revBtn.type = "button";
    revBtn.className = "btn btn-outline clip-reveal-btn";
    revBtn.textContent = "Reveal";
    revBtn.addEventListener("click", (ev) => {
      if (!ev.isTrusted) return;
      revealed = !revealed;
      revBtn.textContent = revealed ? "Hide" : "Reveal";
      renderPreview();
    });
    prevWrap.append(revBtn);
  }
  li.append(prevWrap);

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "btn btn-primary vw-cut vw-cut-md vw-cut-frame";
  copyBtn.append(vwIcon("copy"), "Copy to clipboard");
  copyBtn.disabled = true;

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "btn btn-outline";
  saveBtn.textContent = "Save as .txt";
  saveBtn.disabled = true;

  const dismissBtn = document.createElement("button");
  dismissBtn.type = "button";
  dismissBtn.className = "btn btn-outline";
  dismissBtn.textContent = "Dismiss";

  const forgetBtn = document.createElement("button");
  forgetBtn.type = "button";
  forgetBtn.className = "btn btn-outline";
  forgetBtn.textContent = "Forget device";

  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(forgetBtn, dismissBtn, saveBtn, copyBtn);
  li.append(actions);

  const entry = { li, copyBtn, saveBtn, dismissBtn, forgetBtn, busy: false };
  const decideClip = async (ev, action) => {
    if (
      !ev.isTrusted ||
      entry.busy ||
      (action === "copy" && copyBtn.disabled) ||
      (action === "save_txt" && saveBtn.disabled)
    )
      return;
    entry.busy = true;
    copyBtn.disabled = saveBtn.disabled = dismissBtn.disabled = forgetBtn.disabled = true;
    try {
      if (action === "forget") {
        await invoke("pending_clipboard_decide", { id: c.id, action: "dismiss" });
        await invoke("device_forget", { id: c.sender_id });
      } else {
        await invoke("pending_clipboard_decide", { id: c.id, action });
      }
    } catch (e) {
      $("msg").textContent = String(e);
    } finally {
      entry.busy = false;
    }
    refresh();
  };
  copyBtn.addEventListener("click", (ev) => decideClip(ev, "copy"));
  saveBtn.addEventListener("click", (ev) => decideClip(ev, "save_txt"));
  dismissBtn.addEventListener("click", (ev) => decideClip(ev, "dismiss"));
  forgetBtn.addEventListener("click", (ev) => decideClip(ev, "forget"));
  return entry;
}

async function refresh() {
  let items;
  let files;
  let clips;
  try {
    [items, files, clips] = await Promise.all([
      invoke("pending_list"),
      invoke("incoming_files_list").catch(() => []),
      invoke("pending_clipboards_list").catch(() => []),
    ]);
  } catch (e) {
    $("msg").textContent = String(e);
    return;
  }
  const list = $("list");
  const live = new Set(items.map((p) => p.id));
  let changed = false;
  for (const [id, r] of rows) {
    if (!live.has(id)) {
      r.li.remove();
      rows.delete(id);
      changed = true;
    }
  }
  for (const p of items) {
    if (rows.has(p.id)) continue;
    const r = makeRow(p);
    rows.set(p.id, r);
    list.append(r.li);
    changed = true;
  }

  const liveFiles = new Set(files.map((f) => f.transfer_id));
  for (const [tid, entry] of fileRows) {
    if (!liveFiles.has(tid)) {
      entry.li.remove();
      fileRows.delete(tid);
      changed = true;
    }
  }
  for (const f of files) {
    const existing = fileRows.get(f.transfer_id);
    if (!existing) {
      const entry = makeFileRow(f);
      fileRows.set(f.transfer_id, entry);
      list.append(entry.li);
      changed = true;
    } else {
      updateFileRow(existing, f);
    }
  }

  const liveClips = new Set(clips.map((c) => c.id));
  for (const [cid, entry] of clipRows) {
    if (!liveClips.has(cid)) {
      entry.li.remove();
      clipRows.delete(cid);
      changed = true;
    }
  }
  for (const c of clips) {
    if (clipRows.has(c.id)) continue;
    const entry = makeClipRow(c);
    clipRows.set(c.id, entry);
    list.append(entry.li);
    changed = true;
  }

  const totalCount = rows.size + fileRows.size + clipRows.size;
  const many = totalCount > 1;
  list.classList.toggle("many", many);
  const allEntries = [...rows.values(), ...fileRows.values(), ...clipRows.values()];
  for (const r of allEntries) r.li.classList.toggle("card", many);
  for (const c of ["vw-cut", "vw-cut-lg", "vw-cut-frame"]) {
    for (const r of allEntries) r.li.classList.toggle(c, many);
  }
  $("count").textContent = many ? "· " + totalCount : "";
  const mainEl = document.querySelector("main");
  if (mainEl) mainEl.classList.toggle("many-items", many);
  const eyebrowTxt = $("eyebrow-txt");
  if (eyebrowTxt) {
    if (clipRows.size > 0 && rows.size === 0 && fileRows.size === 0) {
      eyebrowTxt.textContent = "Incoming clipboard text";
      document.title = "Voidwire – Incoming clipboard";
    } else if (fileRows.size > 0 && rows.size === 0 && clipRows.size === 0) {
      eyebrowTxt.textContent = "Incoming file";
      document.title = "Voidwire – Incoming file";
    } else if (totalCount > rows.size) {
      eyebrowTxt.textContent = "Incoming item";
      document.title = "Voidwire – Incoming item";
    } else {
      eyebrowTxt.textContent = "Incoming link";
      document.title = "Voidwire – Open link?";
    }
  }
  if (changed) rearm();
}

window.vwClear = function () {
  rows.clear();
  fileRows.clear();
  clipRows.clear();
  const list = $("list");
  if (list) list.replaceChildren();
};

// Window shown again (it is hidden, not closed, when the list empties).
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    rearm();
    refresh();
  }
});

rearm();
refresh();
setInterval(refresh, POLL_MS);
