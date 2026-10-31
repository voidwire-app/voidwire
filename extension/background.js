"use strict";

const NATIVE_HOST = "app.voidwire.native_host";
const MENU_LINK = "voidwire-send-link";
const MENU_SELECTION = "voidwire-send-selection";
const MENU_PAGE = "voidwire-send-page";

const extApi = typeof browser !== "undefined" ? browser : chrome;

function sendToNativeHost(payload) {
  return new Promise((resolve) => {
    try {
      if (typeof browser !== "undefined" && browser.runtime && browser.runtime.sendNativeMessage) {
        browser.runtime
          .sendNativeMessage(NATIVE_HOST, payload)
          .then((resp) => resolve(resp || { ok: false, error: "Empty response from Voidwire host." }))
          .catch((err) =>
            resolve({
              ok: false,
              running: false,
              error: err && err.message ? err.message : String(err),
            })
          );
        return;
      }
      chrome.runtime.sendNativeMessage(NATIVE_HOST, payload, (resp) => {
        const lastErr = chrome.runtime.lastError;
        if (lastErr) {
          resolve({
            ok: false,
            running: false,
            error: lastErr.message || "Could not connect to Voidwire desktop app.",
          });
          return;
        }
        resolve(resp || { ok: false, error: "Empty response from Voidwire host." });
      });
    } catch (e) {
      resolve({
        ok: false,
        running: false,
        error: e && e.message ? e.message : String(e),
      });
    }
  });
}

let badgeTimer = null;
function flashBadge(ok) {
  if (!extApi.action || !extApi.action.setBadgeText) return;
  if (badgeTimer) clearTimeout(badgeTimer);
  // Desktop design tokens (desktop/ui/tokens.css, dark): success / error.
  extApi.action.setBadgeBackgroundColor({ color: ok ? "#3DDC97" : "#FF6B6B" });
  if (extApi.action.setBadgeTextColor) {
    extApi.action.setBadgeTextColor({ color: ok ? "#00210F" : "#2D0003" });
  }
  extApi.action.setBadgeText({ text: ok ? "OK" : "!" });
  badgeTimer = setTimeout(() => {
    extApi.action.setBadgeText({ text: "" });
  }, 2500);
}

// M3.2.1 / M4.5: right-click menus. One paired device keeps the flat items;
// with 2+ devices (PCs and phones) each item becomes a parent with one child
// per device, so a send always carries an explicit device_id (the desktop
// refuses an id-less send then). With 2+ phones an "All phones" child sends
// to each phone (never to a PC). Device ids and names stay in memory only;
// nothing is written to storage.
const PHONE_NOT_PAIRED_ERR = "Selected device is no longer paired.";
const ALL_PHONES = "all_phones";
const MENU_KINDS = [
  { id: MENU_LINK, title: "Send link to Voidwire", contexts: ["link"] },
  { id: MENU_SELECTION, title: "Send selection to Voidwire", contexts: ["selection"] },
  { id: MENU_PAGE, title: "Send page to Voidwire", contexts: ["page"] },
];
const CHILD_SEP = "::";

let menuPhones = [];
// False until the menus were built from a live `status` answer in this worker.
let menusSynced = false;
let menuBuild = Promise.resolve();

const IS_PROMISE_API = typeof browser !== "undefined";

// Firefox treats "&" in a menu title as an access-key marker; show it literally.
function menuLabel(label) {
  return IS_PROMISE_API ? String(label).replace(/&/g, "&&") : String(label);
}

function removeAllMenus() {
  return new Promise((resolve) => {
    try {
      if (IS_PROMISE_API) {
        extApi.contextMenus.removeAll().then(resolve, resolve);
      } else {
        extApi.contextMenus.removeAll(() => {
          void chrome.runtime.lastError;
          resolve();
        });
      }
    } catch (_) {
      resolve();
    }
  });
}

function createMenu(props) {
  return new Promise((resolve) => {
    try {
      // create() takes a callback in both Chromium and Firefox (it returns the id).
      extApi.contextMenus.create(props, () => {
        void (extApi.runtime && extApi.runtime.lastError);
        resolve();
      });
    } catch (_) {
      resolve();
    }
  });
}

function samePhones(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i].id !== b[i].id || a[i].label !== b[i].label || a[i].mobile !== b[i].mobile) return false;
  }
  return true;
}

// A `status` answer's devices.
function normalizePhones(status) {
  const list = status && (Array.isArray(status.devices) ? status.devices : null);
  if (!Array.isArray(list)) return [];
  return list
    .filter((p) => p && typeof p.id === "string" && p.id)
    .map((p) => ({
      id: p.id,
      label: typeof p.label === "string" && p.label ? p.label : "Device",
      mobile: p.mobile === true,
    }));
}

function buildContextMenus(phones) {
  if (!extApi.contextMenus) return Promise.resolve();
  menuPhones = phones;
  return removeAllMenus().then(async () => {
    for (const kind of MENU_KINDS) {
      await createMenu({ id: kind.id, title: kind.title, contexts: kind.contexts });
      if (phones.length < 2) continue;
      for (const p of phones) {
        await createMenu({
          id: kind.id + CHILD_SEP + p.id,
          parentId: kind.id,
          title: menuLabel(p.label),
          contexts: kind.contexts,
        });
      }
      if (phones.filter((p) => p.mobile).length >= 2) {
        await createMenu({
          id: kind.id + CHILD_SEP + ALL_PHONES,
          parentId: kind.id,
          title: "All phones",
          contexts: kind.contexts,
        });
      }
    }
  });
}

// Ask the desktop app for the paired phones and rebuild the menus if they changed.
// When the app is not running, keep whatever menus exist; `ensure` (install /
// browser start) makes sure the flat items exist at all.
function refreshContextMenus(ensure) {
  menuBuild = menuBuild.then(async () => {
    const status = await sendToNativeHost({ op: "status" });
    if (status && status.ok) {
      await applyPhones(normalizePhones(status));
    } else if (ensure) {
      await buildContextMenus(menuPhones);
    }
  });
  return menuBuild;
}

async function applyPhones(phones) {
  if (menusSynced && samePhones(phones, menuPhones)) return;
  await buildContextMenus(phones);
  menusSynced = true;
}

extApi.runtime.onInstalled.addListener(() => {
  refreshContextMenus(true);
});

if (extApi.runtime.onStartup) {
  extApi.runtime.onStartup.addListener(() => {
    refreshContextMenus(true);
  });
}

function parseMenuId(menuItemId) {
  const raw = String(menuItemId || "");
  const at = raw.indexOf(CHILD_SEP);
  if (at < 0) return { kind: raw, phoneId: null };
  return { kind: raw.slice(0, at), phoneId: raw.slice(at + CHILD_SEP.length) || null };
}

extApi.contextMenus.onClicked.addListener(async (info, tab) => {
  const { kind, phoneId } = parseMenuId(info.menuItemId);
  // A flat item with 2+ devices only exists for a moment between a pairing
  // change and the rebuild; fall back to the only device we know about.
  const targetId = phoneId || (menuPhones.length === 1 ? menuPhones[0].id : null);
  let req = null;
  if (kind === MENU_LINK && info.linkUrl) {
    req = { op: "send_url", url: String(info.linkUrl).trim() };
  } else if (kind === MENU_SELECTION && info.selectionText) {
    req = { op: "send_text", text: String(info.selectionText) };
  } else if (kind === MENU_PAGE) {
    const pageUrl = (info.pageUrl || (tab && tab.url) || "").trim();
    if (pageUrl) req = { op: "send_url", url: pageUrl };
  }
  if (!req) return;
  req.pop_ui_on_error = true;
  if (targetId) req.device_id = targetId;
  const resp = await sendToNativeHost(req);
  flashBadge(Boolean(resp && resp.ok));
  if (!resp || !resp.ok) {
    // Pairings may have changed (device removed / added); rebuild the submenus.
    if (resp && resp.error === PHONE_NOT_PAIRED_ERR) menusSynced = false;
    refreshContextMenus(false);
  }
});

extApi.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg !== "object" || !msg.op) {
    sendResponse({ ok: false, error: "Invalid request." });
    return false;
  }
  sendToNativeHost(msg).then((resp) => {
    if (msg.op === "status" && resp && resp.ok) {
      // Popup open: reuse its status answer to resync the menus.
      const phones = normalizePhones(resp);
      menuBuild = menuBuild.then(() => applyPhones(phones));
    } else if (resp && resp.error === PHONE_NOT_PAIRED_ERR) {
      menusSynced = false;
      refreshContextMenus(false);
    }
    sendResponse(resp);
  });
  return true;
});

// Service worker (re)start: Chromium keeps the menus across worker restarts but
// the in-memory phone list is gone; resync it (rebuilds once per worker).
refreshContextMenus(false);
