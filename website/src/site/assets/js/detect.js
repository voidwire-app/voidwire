/* Optional progressive enhancement for download.html. Without it every platform is listed and the page works the same.
   Reads the platform locally; nothing is stored or sent anywhere. */
(function () {
  // User-agent string first (it is what the page is actually told), platform hints as a fallback.
  var ua = (navigator.userAgent || "").toLowerCase();
  var hint = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "").toLowerCase();
  function pick(s) {
    return /android/.test(s) ? "android" : /iphone|ipad|ipod/.test(s) ? "ios" : /windows|win32|win64/.test(s) ? "windows"
      : /mac os|macintosh|macos/.test(s) ? "macos" : /linux|x11|cros/.test(s) ? "linux" : "";
  }
  var id = pick(ua) || pick(hint);
  var card = id && document.getElementById(id);
  if (!card) return;
  card.classList.add("is-detected");
  document.documentElement.classList.add("has-detect");
  var out = document.getElementById("det-name");
  if (out) out.textContent = card.getAttribute("data-name");
  var link = document.getElementById("det-link");
  if (link) link.setAttribute("href", "#" + id);
})();
