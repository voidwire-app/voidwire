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
  extApi.action.setBadgeBackgroundColor({ color: ok ? "#3FB97A" : "#E5534B" });
  extApi.action.setBadgeText({ text: ok ? "OK" : "!" });
  badgeTimer = setTimeout(() => {
    extApi.action.setBadgeText({ text: "" });
  }, 2500);
}

function registerContextMenus() {
  if (!extApi.contextMenus) return;
  extApi.contextMenus.removeAll(() => {
    extApi.contextMenus.create({
      id: MENU_LINK,
      title: "Send link to Voidwire",
      contexts: ["link"],
    });
    extApi.contextMenus.create({
      id: MENU_SELECTION,
      title: "Send selection to Voidwire",
      contexts: ["selection"],
    });
    extApi.contextMenus.create({
      id: MENU_PAGE,
      title: "Send page to Voidwire",
      contexts: ["page"],
    });
  });
}

extApi.runtime.onInstalled.addListener(() => {
  registerContextMenus();
});

if (extApi.runtime.onStartup) {
  extApi.runtime.onStartup.addListener(() => {
    registerContextMenus();
  });
}

extApi.contextMenus.onClicked.addListener(async (info, tab) => {
  let req = null;
  if (info.menuItemId === MENU_LINK && info.linkUrl) {
    req = {
      op: "send_url",
      url: String(info.linkUrl).trim(),
      pop_ui_on_error: true,
    };
  } else if (info.menuItemId === MENU_SELECTION && info.selectionText) {
    req = {
      op: "send_text",
      text: String(info.selectionText),
      pop_ui_on_error: true,
    };
  } else if (info.menuItemId === MENU_PAGE) {
    const pageUrl = (info.pageUrl || (tab && tab.url) || "").trim();
    if (pageUrl) {
      req = {
        op: "send_url",
        url: pageUrl,
        pop_ui_on_error: true,
      };
    }
  }
  if (!req) return;
  const resp = await sendToNativeHost(req);
  flashBadge(Boolean(resp && resp.ok));
});

extApi.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg !== "object" || !msg.op) {
    sendResponse({ ok: false, error: "Invalid request." });
    return false;
  }
  sendToNativeHost(msg).then((resp) => sendResponse(resp));
  return true;
});
