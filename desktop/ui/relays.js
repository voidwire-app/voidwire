// M4.4 relays: Settings → Relays (saved list, home, status, links) and
// moving one pairing to another relay. A move needs both devices: this PC
// asks, the other device's user allows it, and both sign the change.
// Nothing here polls the network; the lists are local reads that ride on
// the window's existing refresh.
"use strict";
(function () {
  const call = window.__TAURI__.core.invoke;
  const el = (id) => document.getElementById(id);
  let relays = [];
  let byPeer = new Map(); // peerId -> { url, host }
  let mine = new Map(); // peerId -> { host, state }
  let shownKey = null;
  let asking = null; // peerId of the request on screen

  function say(text) {
    if (typeof toast === "function") toast(text);
  }
  function fail(e) {
    const m = el("msg");
    if (m) m.textContent = String(e);
  }
  function fmtSince(ms) {
    if (!ms) return "";
    const d = new Date(ms);
    return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function button(text, cls, onClick) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "btn " + (cls || "btn-outline") + " s-btn";
    b.textContent = text;
    b.addEventListener("click", async (ev) => {
      if (!ev.isTrusted || b.disabled) return;
      b.disabled = true;
      try {
        await onClick();
      } catch (e) {
        fail(e);
      } finally {
        b.disabled = false;
      }
    });
    return b;
  }
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      say("Copied the relay link. Paste it into Settings → Relays on another device.");
    } catch (_) {
      fail("Couldn't copy. Relay link: " + text);
    }
  }

  function statusChip(r) {
    const c = document.createElement("span");
    const led = document.createElement("span");
    led.className = "led";
    const t = document.createElement("span");
    if (r.status === "unreachable") {
      c.className = "chip err vw-cut-all vw-cut-sm";
      t.textContent = "Can't reach" + (r.downSinceMs ? " since " + fmtSince(r.downSinceMs) : "");
    } else if (r.status === "connected") {
      c.className = "chip ok vw-cut-all vw-cut-sm";
      t.textContent = "Connected";
    } else {
      c.className = "chip vw-cut-all vw-cut-sm";
      t.textContent = r.usedBy > 0 || r.home ? "Idle" : "Not in use";
    }
    c.append(led, t);
    return c;
  }

  function relayRow(r) {
    const row = document.createElement("div");
    row.className = "relay-row";
    row.dataset.url = r.url;
    const meta = document.createElement("div");
    meta.className = "meta";
    const name = document.createElement("p");
    name.className = "t-title-small name2";
    const bdi = document.createElement("bdi");
    bdi.textContent = r.nickname || r.host;
    name.append(bdi);
    if (r.home) {
      const h = document.createElement("span");
      h.className = "chip home-chip vw-cut-all vw-cut-sm";
      h.textContent = "Home";
      h.title = "New pairings use this relay";
      name.append(" ", h);
    }
    row.classList.toggle("home", !!r.home);
    const sub = document.createElement("p");
    sub.className = "t-code-small muted";
    const bits = [r.host];
    if (r.builtin) bits.push("public");
    bits.push(r.usedBy === 1 ? "1 pairing" : r.usedBy + " pairings");
    sub.textContent = bits.join(" · ");
    meta.append(name, sub, statusChip(r));
    const act = document.createElement("div");
    act.className = "s-actions relay-act";
    act.append(button("Copy link", "", () => copyText(r.link)));
    if (r.status === "unreachable") {
      act.append(
        button("Retry", "", async () => {
          await call("relays_retry", { url: r.url });
          say("Trying " + r.host + " again.");
          refreshRelays(true);
        })
      );
    }
    if (!r.home) {
      act.append(
        button("Make home", "", async () => {
          await call("relays_set_home", { url: r.url });
          say("Home relay is now " + r.host + ". New pairings use it; existing pairings keep their relay.");
          refreshRelays(true);
        })
      );
    }
    act.append(
      button("Rename", "", async () => {
        const inp = document.createElement("input");
        inp.className = "s-input";
        inp.maxLength = 40;
        inp.value = r.nickname || r.host;
        inp.setAttribute("aria-label", "Name for " + r.host);
        const save = async () => {
          try {
            await call("relays_rename", { url: r.url, nickname: inp.value.trim() });
          } catch (e) {
            fail(e);
          }
          refreshRelays(true);
        };
        inp.addEventListener("keydown", (ev) => {
          if (ev.key === "Enter") save();
          if (ev.key === "Escape") refreshRelays(true);
        });
        inp.addEventListener("blur", save);
        name.replaceChildren(inp);
        inp.focus();
        inp.select();
      })
    );
    if (!r.builtin && !r.home && r.usedBy === 0) {
      act.append(
        button("Remove", "btn-danger", async () => {
          await call("relays_remove", { url: r.url });
          say("Removed " + r.host + ".");
          refreshRelays(true);
        })
      );
    }
    row.append(meta, act);
    return row;
  }

  function renderRelays() {
    const list = el("relays-list");
    if (!list) return;
    const k = JSON.stringify(relays);
    if (k === shownKey) return;
    shownKey = k;
    list.replaceChildren(...relays.map(relayRow));
    const text = relays.length + " / 8 saved";
    ["relays-count", "relays-saved"].forEach((id) => {
      const c = el(id);
      if (c) c.textContent = text;
    });
  }

  // "via <host>" and the pairing's move state on each device row.
  function decorateRows() {
    document.querySelectorAll("#list [data-device-id]").forEach((row) => {
      const id = row.dataset.deviceId;
      const via = row.querySelector(".relay-via");
      if (!via) return;
      const p = byPeer.get(id);
      const m = mine.get(id);
      let text = p && p.host ? "via " + p.host : "";
      if (m) {
        if (m.state === "waiting") text += " · moving to " + m.host + ": waiting for the other device to allow it";
        else if (m.state === "declined") text += " · move to " + m.host + " was declined";
        else if (m.state === "no_room") text += " · the other device has no room for " + m.host;
        else if (m.state === "done") text += " · moved";
      }
      via.textContent = text;
    });
  }

  async function refreshRelays(force) {
    try {
      const [r, p, ch] = await Promise.all([
        call("relays_list"),
        call("pairing_relays"),
        call("relay_changes"),
      ]);
      relays = r;
      if (force) shownKey = null;
      byPeer = new Map(p.map((x) => [x.peerId, x]));
      mine = new Map(ch.mine.map((x) => [x.peerId, x]));
      renderRelays();
      decorateRows();
      showRequest(ch.requests);
    } catch (_) {
      /* network service not up yet */
    }
  }

  // ---- the other device asks to move a pairing ----
  function showRequest(reqs) {
    const modal = el("relaychg-ask");
    if (!modal) return;
    const r = reqs.find((x) => x.peerId === asking) || reqs[0];
    if (!r) {
      asking = null;
      modal.classList.add("hidden");
      return;
    }
    if (asking === r.peerId && !modal.classList.contains("hidden")) return;
    asking = r.peerId;
    el("relaychg-ask-title").textContent = r.peerName + " wants to move your pairing to " + r.host;
    el("relaychg-ask-body").textContent =
      (r.newRelay ? r.host + " isn't in your saved relays yet; allowing saves it. " : "") +
      "Only this pairing moves. Links and files keep their end-to-end encryption; the relay only sees encrypted traffic. Decline to keep the current relay.";
    modal.classList.remove("hidden");
  }
  async function answer(allow) {
    const peerId = asking;
    if (!peerId) return;
    el("relaychg-allow").disabled = true;
    el("relaychg-decline").disabled = true;
    try {
      await call("relay_change_answer", { peerId, allow });
      say(allow ? "Moved the pairing. Both devices now use the new relay." : "Declined. The pairing keeps its relay.");
      el("relaychg-ask").classList.add("hidden");
      asking = null;
    } catch (e) {
      el("relaychg-ask-body").textContent = String(e);
    } finally {
      el("relaychg-allow").disabled = false;
      el("relaychg-decline").disabled = false;
      refreshRelays(true);
    }
  }

  // ---- this PC asks to move a pairing ----
  let moving = null;
  function openMove(d) {
    const modal = el("relaychg-pick");
    const sel = el("relaychg-select");
    if (!modal || !sel) return;
    moving = d;
    const cur = byPeer.get(d.id);
    const opts = relays.filter((r) => !cur || r.url !== (cur.url || ""));
    sel.replaceChildren(
      ...opts.map((r) => {
        const o = document.createElement("option");
        o.value = r.url;
        o.textContent = (r.nickname || r.host) + (r.nickname && r.nickname !== r.host ? " (" + r.host + ")" : "");
        return o;
      })
    );
    // With nowhere to move to, the dialog only says so (no empty picker).
    const none = opts.length === 0;
    el("relaychg-pick-title").textContent = none ? "" : "Move " + d.name + " to another relay";
    el("relaychg-pick-title").classList.toggle("hidden", none);
    sel.classList.toggle("hidden", none);
    el("relaychg-go").classList.toggle("hidden", none);
    el("relaychg-go").disabled = none;
    el("relaychg-cancel").textContent = none ? "Close" : "Cancel";
    el("relaychg-pick-body").textContent = none
      ? "Add another relay in Settings → Relays first."
      : "Both devices must be online. " + d.name + " has to allow it before anything moves.";
    modal.classList.remove("hidden");
  }
  async function propose() {
    const d = moving;
    const url = el("relaychg-select").value;
    if (!d || !url) return;
    el("relaychg-go").disabled = true;
    el("relaychg-pick-body").textContent = "Asking " + d.name + "…";
    try {
      await call("relay_change_propose", { peerId: d.id, url });
      el("relaychg-pick").classList.add("hidden");
      say("Asked " + d.name + ". The pairing moves once it allows the change.");
    } catch (e) {
      el("relaychg-pick-body").textContent = String(e);
    } finally {
      el("relaychg-go").disabled = false;
      refreshRelays(true);
    }
  }

  // A device row's ⋯ menu (Change relay… lives there, not on the row).
  let openMenu = null;
  function closeMenu() {
    if (!openMenu) return;
    openMenu.list.classList.add("hidden");
    openMenu.btn.setAttribute("aria-expanded", "false");
    openMenu = null;
  }
  if (document.addEventListener) {
    document.addEventListener("click", (ev) => {
      if (openMenu && !openMenu.wrap.contains(ev.target)) closeMenu();
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") closeMenu();
    });
  }
  function rowMenu(d, items) {
    const wrap = document.createElement("div");
    wrap.className = "rowmenu";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn btn-outline rowmenu-btn";
    btn.textContent = "⋯";
    btn.title = "More";
    btn.setAttribute("aria-label", "More for " + d.name);
    btn.setAttribute("aria-haspopup", "menu");
    btn.setAttribute("aria-expanded", "false");
    const list = document.createElement("div");
    list.className = "rowmenu-list card vw-cut vw-cut-md vw-cut-frame";
    list.classList.add("hidden");
    list.setAttribute("role", "menu");
    items.forEach(([text, run]) => {
      const it = document.createElement("button");
      it.type = "button";
      it.className = "rowmenu-item";
      it.setAttribute("role", "menuitem");
      it.textContent = text;
      it.addEventListener("click", (ev) => {
        if (!ev.isTrusted) return;
        closeMenu();
        run();
      });
      list.append(it);
    });
    btn.addEventListener("click", (ev) => {
      if (!ev.isTrusted) return;
      const was = openMenu && openMenu.btn === btn;
      closeMenu();
      if (was) return;
      list.classList.remove("hidden");
      btn.setAttribute("aria-expanded", "true");
      openMenu = { wrap, btn, list };
    });
    wrap.append(btn, list);
    return wrap;
  }

  // Called by devices.js for each device row it builds: "via <host>" under
  // the name, and the ⋯ menu before `before` (Forget) in the row's head.
  window.vwRelayRow = function (d, meta, head, before) {
    const via = document.createElement("p");
    via.className = "t-code-small muted relay-via";
    meta.append(via);
    head.insertBefore(rowMenu(d, [["Change relay…", () => openMove(d)]]), before);
    setTimeout(decorateRows, 0);
  };
  window.vwRelaysRefresh = () => refreshRelays(false);
  window.vwRelayChanges = () => refreshRelays(true);

  function wire() {
    const add = el("relay-add");
    if (add) {
      add.addEventListener("click", async (ev) => {
        if (!ev.isTrusted || add.disabled) return;
        const linkOrUrl = (el("relay-add-input").value || "").trim();
        const mailboxId = (el("relay-add-mailbox").value || "").trim();
        if (!linkOrUrl) return;
        add.disabled = true;
        try {
          await call("relays_add", { linkOrUrl, mailboxId, nickname: "" });
          el("relay-add-input").value = "";
          el("relay-add-mailbox").value = "";
          say("Saved the relay. Use Change relay… on a device to move a pairing to it.");
          refreshRelays(true);
        } catch (e) {
          fail(e);
        } finally {
          add.disabled = false;
        }
      });
    }
    const on = (id, f) => {
      const x = el(id);
      if (x) x.addEventListener("click", (ev) => ev.isTrusted && f());
    };
    on("relaychg-allow", () => answer(true));
    on("relaychg-decline", () => answer(false));
    on("relaychg-go", propose);
    on("relaychg-cancel", () => el("relaychg-pick").classList.add("hidden"));
    refreshRelays(true);
  }
  wire();
})();
