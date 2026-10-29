"use strict";

const extApi = typeof browser !== "undefined" ? browser : chrome;
const $ = (id) => document.getElementById(id);

let activeTabUrl = null;
let pairedPhones = [];
let pendingRelayRequest = null;

function sendHostOp(payload) {
  return new Promise((resolve) => {
    try {
      extApi.runtime.sendMessage(payload, (resp) => {
        const lastErr = extApi.runtime.lastError;
        if (lastErr) {
          resolve({ ok: false, running: false, error: lastErr.message });
          return;
        }
        resolve(resp || { ok: false, error: "No response from Voidwire host." });
      });
    } catch (e) {
      resolve({ ok: false, running: false, error: String(e) });
    }
  });
}

function queryActiveTabUrl() {
  return new Promise((resolve) => {
    try {
      extApi.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const t = tabs && tabs[0];
        const url = t && typeof t.url === "string" ? t.url.trim() : "";
        if (/^https?:\/\//i.test(url)) {
          resolve(url);
        } else {
          resolve(null);
        }
      });
    } catch (_) {
      resolve(null);
    }
  });
}

function selectedPhoneId() {
  const sel = $("phone-select");
  if (sel && sel.value) return sel.value;
  if (pairedPhones.length > 0) return pairedPhones[0].id;
  return null;
}

function showFeedback(text, isOk) {
  const el = $("feedback");
  if (!text) {
    el.textContent = "";
    el.className = "feedback hidden";
    return;
  }
  el.textContent = text;
  el.className = "feedback " + (isOk ? "ok" : "err");
}

async function refreshStatus() {
  showFeedback("", true);
  $("relay-card").classList.add("hidden");
  activeTabUrl = await queryActiveTabUrl();
  const urlEl = $("tab-url");
  const sendTabBtn = $("send-tab-btn");
  if (activeTabUrl) {
    urlEl.textContent = activeTabUrl;
    urlEl.title = activeTabUrl;
    sendTabBtn.disabled = false;
  } else {
    urlEl.textContent = "Active tab is not an http:// or https:// page.";
    urlEl.title = "";
    sendTabBtn.disabled = true;
  }

  const status = await sendHostOp({ op: "status" });
  const chip = $("status-chip");
  if (!status || !status.ok) {
    chip.textContent = "Offline";
    chip.className = "chip err";
    $("main-panel").classList.add("hidden");
    $("offline-card").classList.remove("hidden");
    $("offline-title").textContent = "Voidwire desktop app is not running";
    $("offline-sub").textContent =
      (status && status.error) ||
      "Start Voidwire from your system tray or Start menu, then click Retry.";
    return;
  }

  pairedPhones = Array.isArray(status.phones) ? status.phones : [];
  if (pairedPhones.length === 0) {
    chip.textContent = "No phone";
    chip.className = "chip err";
    $("main-panel").classList.add("hidden");
    $("offline-card").classList.remove("hidden");
    $("offline-title").textContent = "No phone paired yet";
    $("offline-sub").textContent =
      "Open Voidwire from your system tray and pair your phone first.";
    return;
  }

  $("offline-card").classList.add("hidden");
  $("main-panel").classList.remove("hidden");
  chip.textContent =
    pairedPhones.length === 1
      ? pairedPhones[0].label
      : pairedPhones.length + " phones";
  chip.className = "chip ok";

  const pickerRow = $("phone-picker-row");
  const sel = $("phone-select");
  sel.replaceChildren();
  for (const p of pairedPhones) {
    const opt = document.createElement("option");
    opt.value = p.id;
    opt.textContent = p.label;
    sel.append(opt);
  }
  pickerRow.classList.toggle("hidden", pairedPhones.length <= 1);
}

async function executeSend(req, busyBtn) {
  showFeedback("", true);
  $("relay-card").classList.add("hidden");
  if (busyBtn) busyBtn.disabled = true;
  try {
    const resp = await sendHostOp(req);
    if (resp && resp.ok) {
      const target = resp.sent_to || "phone";
      const via = resp.path === "device_inbox" ? " (queued in blind inbox)" : "";
      showFeedback("Sent to " + target + via + ".", true);
      return true;
    }
    if (resp && resp.relay_prompt) {
      pendingRelayRequest = Object.assign({}, req, { allow_relay: true });
      $("relay-card").classList.remove("hidden");
      return false;
    }
    showFeedback((resp && resp.error) || "Send failed.", false);
    return false;
  } finally {
    if (busyBtn) {
      if (busyBtn.id === "send-tab-btn") {
        busyBtn.disabled = !activeTabUrl;
      } else {
        busyBtn.disabled = false;
      }
    }
  }
}

$("retry-btn").addEventListener("click", () => {
  refreshStatus();
});

$("send-tab-btn").addEventListener("click", async () => {
  if (!activeTabUrl) return;
  await executeSend(
    {
      op: "send_url",
      url: activeTabUrl,
      phone_id: selectedPhoneId(),
    },
    $("send-tab-btn")
  );
});

$("send-custom-btn").addEventListener("click", async () => {
  const val = ($("custom-input").value || "").trim();
  if (!val) return;
  const ok = await executeSend(
    {
      op: "send_text",
      text: val,
      phone_id: selectedPhoneId(),
    },
    $("send-custom-btn")
  );
  if (ok) $("custom-input").value = "";
});

$("custom-input").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") {
    ev.preventDefault();
    $("send-custom-btn").click();
  }
});

$("send-clip-btn").addEventListener("click", async () => {
  await executeSend(
    {
      op: "send_clipboard",
      phone_id: selectedPhoneId(),
    },
    $("send-clip-btn")
  );
});

$("relay-cancel-btn").addEventListener("click", () => {
  pendingRelayRequest = null;
  $("relay-card").classList.add("hidden");
});

$("relay-confirm-btn").addEventListener("click", async () => {
  if (!pendingRelayRequest) return;
  const req = pendingRelayRequest;
  pendingRelayRequest = null;
  await executeSend(req, $("relay-confirm-btn"));
});

refreshStatus();
