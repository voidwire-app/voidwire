// U1: Settings → Updates and the update banner (docs/UPDATES.md). Core
// checks, verifies and installs; this page only shows the state and sends
// clicks. It re-reads the state when the app says something changed
// (window.vwUpdate, called from update.rs); it never polls.
"use strict";
(function () {
  const call = window.__TAURI__.core.invoke;
  const el = (id) => document.getElementById(id);
  let st = null;

  function fmtSize(n) {
    const b = Number(n) || 0;
    if (b < 1024 * 1024) return Math.max(1, Math.round(b / 1024)) + " KB";
    return (b / (1024 * 1024)).toFixed(1) + " MB";
  }
  function show(id, on) {
    const e = el(id);
    if (e) e.classList.toggle("hidden", !on);
  }
  function text(id, t) {
    const e = el(id);
    if (e) e.textContent = t;
  }

  function render() {
    if (!st || !st.available_in_build) {
      show("upd-section", false);
      show("upd-banner", false);
      return;
    }
    show("upd-section", true);
    el("upd-checks").checked = st.checks_on;
    el("upd-test").checked = st.test_builds;
    const auto = st.kind === "windows" || st.kind === "appimage";
    show("upd-auto-row", auto);
    el("upd-auto").checked = st.auto_install;
    text(
      "upd-auto-hint",
      st.kind === "windows"
        ? "Downloads and checks new versions, then installs them when you quit Voidwire. Windows asks for permission each time."
        : "Downloads and checks new versions, then uses them the next time Voidwire starts."
    );
    text("upd-version", "Version " + st.version);
    let status = "";
    if (st.status === "checking") status = "Checking…";
    else if (st.status === "uptodate") status = "You're up to date (Voidwire " + st.version + ").";
    else if (st.status === "failed") status = "Couldn't check for updates. Try again later.";
    else if (!st.checks_on) status = "Update checks are off.";
    text("upd-status", status);
    el("upd-check").disabled = st.status === "checking";

    // Banner: an offer not put off with "Not now" / "Later" (a running
    // download always shows).
    const running = st.phase === "downloading" || st.phase === "verifying";
    const on = !!st.offer_version && (running || !st.dismissed);
    show("upd-banner", on);
    if (!on) return;
    const pageOnly = st.kind === "deb" || st.kind === "macos";
    let body = "Voidwire " + st.offer_version + " is ready to download (" + fmtSize(st.offer_size) + ").";
    let go = pageOnly ? "Download" : "Update";
    let later = "Not now";
    if (st.phase === "downloading") body = "Downloading… " + st.percent + "%";
    else if (st.phase === "verifying") body = "Checking the download…";
    else if (st.phase === "ready" && st.auto_install) {
      body = "Update ready. It will install when you quit Voidwire.";
      go = "Install now";
      later = "";
    } else if (st.phase === "ready") {
      body = "Ready to install. Voidwire will close and start again.";
      go = "Install now";
      later = "Later";
    } else if (st.phase === "installed") {
      body = "Update installed. Restart Voidwire to use it.";
      go = "Restart now";
      later = "";
    }
    text("upd-body", body);
    text("upd-go", go);
    text("upd-later", later);
    show("upd-go", st.phase === "" || st.phase === "ready" || st.phase === "installed");
    show("upd-later", later !== "");
    show("upd-notes", st.phase === "");
    text("upd-err", st.error || "");
    show("upd-err", !!st.error);
  }

  async function load() {
    try {
      st = await call("update_state");
    } catch (_) {
      st = null;
    }
    render();
  }
  window.vwUpdate = load;

  function on(id, ev, fn) {
    const e = el(id);
    if (!e) return;
    e.addEventListener(ev, async (x) => {
      if (!x.isTrusted) return;
      try {
        await fn(x);
      } catch (err) {
        const m = el("msg");
        if (m) m.textContent = String(err);
      }
      await load();
    });
  }
  on("upd-checks", "change", (e) => call("update_set_checks", { on: e.target.checked }));
  on("upd-test", "change", (e) => call("update_set_test_builds", { on: e.target.checked }));
  on("upd-auto", "change", (e) => call("update_set_auto_install", { on: e.target.checked }));
  on("upd-check", "click", () => call("update_check_now"));
  on("upd-notes", "click", () => call("update_whats_new"));
  on("upd-later", "click", () => call("update_not_now"));
  on("upd-go", "click", () =>
    st && (st.phase === "ready" || st.phase === "installed") ? call("update_install_now") : call("update_start")
  );
  load();
})();
