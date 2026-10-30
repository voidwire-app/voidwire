// Layout test stub: a fake core with worst-case (longest) content.
"use strict";
(function () {
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 85 85"><rect width="85" height="85" fill="#000"/></svg>';
  const LONG = "Workshop laptop with a long name";
  const state = new URLSearchParams(location.search).get("state");
  const never = new Promise(() => {});
  window.__TAURI__ = { core: { invoke: async (cmd) => {
    switch (cmd) {
      case "pair2_relays": return [
        { url: "https://relay.voidwire.app", nickname: "relay.voidwire.app", home: true },
        { url: "https://relay2.example.org", nickname: "my second relay at home", home: false },
      ];
      // 26 + 2 characters, as the core formats them.
      case "pair2_show": return { code: "VW-ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345", svg, expires_at_ms: Date.now() + 300000, ttl_ms: 300000 };
      case "pair2_status": return state === "verify" ? { state: "awaiting_code", device_name: LONG } : { state: "waiting" };
      case "pair2_open_code": return state === "addrelay"
        ? { relay_state: "ask", relay_host: "relay-with-a-long-name.example.org", inviter_name: LONG }
        : { relay_state: "ok", inviter_name: LONG };
      case "pair2_join": return "123456";
      case "pair2_join_wait": return never;
      default: return null;
    }
  } } };
  window.VW_LONG = LONG;
})();
