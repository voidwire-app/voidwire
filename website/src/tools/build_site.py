#!/usr/bin/env python3
"""Builds the static voidwire.app prototype into ../site/*.html (+ site/.well-known/security.txt).
Shared header/footer + per-page bodies live here so the pages stay consistent.
Output is plain HTML/CSS; only download.html loads one small optional script (assets/js/detect.js).
Launch framing: the site is written as if the stable release is out. Values not known yet are
[PLACEHOLDERS] (blue dashed, .ph) and unconfirmed claims are [VERIFY: ...] (amber dashed, .verify).
Both must be gone before anything is published: website/build.py fails a stable build while
any V() call is left, so a claim is fixed in the text here, never just hidden.
Run: python3 tools/build_site.py"""
import pathlib, re, html

ROOT = pathlib.Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
GH = "https://github.com/voidwire-app/voidwire"
REL = f"{GH}/releases/download/[TAG]"   # [TAG] = git tag (v1.2.3) for the URL path; [VERSION] = 1.2.3 in file names
SECURITY = "security@voidwire.app"
SALES = "sales@voidwire.app"   # FILL-IN §1; mail for voidwire.app must be live before launch
APK_CERT = "5C:ED:BE:22:A9:52:C2:38:B0:7B:E9:CF:46:16:9A:06:66:DB:6C:C6:20:F5:AB:E3:77:3B:7F:99:7E:E2:78:6E"   # FILL-IN VERIFY 3
CF_PRIVACY = "https://www.cloudflare.com/privacypolicy/"   # checked: resolves (200), Nov 2, 2026

def V(text):
    """A claim nobody has confirmed. Visible in the prototype on purpose; collected in COPY.md / QUESTIONS.md."""
    return f'<span class="verify">[VERIFY: {html.escape(text)}]</span>'

def P(name):
    """A value that doesn't exist yet (price, version, endpoint). Visible on purpose; listed in COPY.md."""
    return f'<span class="ph">[{html.escape(name)}]</span>'

VER = P("VERSION")
# Release file names (scripts/release_assets.py): Voidwire_<version>_<platform>.
FILES = {
    "win": "Voidwire_[VERSION]_x64-setup.exe",
    "apk": "Voidwire_[VERSION]_android.apk",
    "crx": "Voidwire_[VERSION]_extension-chromium.zip",
    "xpi": "Voidwire_[VERSION]_extension-firefox.zip",
    "deb": "Voidwire_[VERSION]_amd64.deb",
    "appimage": "Voidwire_[VERSION]_amd64.AppImage",
    "dmg": "Voidwire_[VERSION]_universal.dmg",
}
def fname_html(f):
    return html.escape(f).replace("[VERSION]", VER)

# ---------- brand mark (C2 Relay), vendored in tools/ so this folder builds on its own ----------
def mark_svg():
    src = (ROOT / "tools/voidwire-mark.svg").read_text()
    src = src.replace('fill="#C9D1DB"', 'class="mark-node"').replace('fill="#3D8BFF"', 'class="mark-wire"').replace('fill="#F2C94C"', 'class="mark-relay"')
    src = re.sub(r'<svg [^>]*>', '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" aria-hidden="true" focusable="false">', src, count=1)
    return src
MARK = mark_svg()

# macOS (beta) is listed only when the release has a disk image
# (website/build.py leaves "dmg" out of FILES for older releases).
MAC = "dmg" in FILES
MAC_JUMP = '\n          <a class="vw-cut vw-cut-frame" href="#macos">macOS <small>beta</small></a>' if MAC else ""
MAC_LIST = ", macOS (beta)" if MAC else ""

# ---------- icons (24px line icons) ----------
ICONS = {
 "link": '<path d="M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1"/><path d="M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1"/>',
 "text": '<path d="M4 6h16M4 11h16M4 16h10"/>',
 "file": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
 "browser": '<rect x="3" y="4" width="18" height="16" rx="1"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01"/>',
 "folder": '<path d="M3 7a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><path d="M12 11v5M9.5 13.5 12 16l2.5-2.5"/>',
 "lock": '<rect x="5" y="11" width="14" height="10" rx="1"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
 "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 13-6.2"/><path d="m17 17 4 4m0-4-4 4"/>',
 "eye": '<path d="M3 3l18 18"/><path d="M10.6 6.1A10 10 0 0 1 12 6c5 0 8.5 4 9.5 6a12 12 0 0 1-2.6 3.4M6.3 7.6A12 12 0 0 0 2.5 12c1 2 4.5 6 9.5 6a9.6 9.6 0 0 0 4-.9"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
 "history": '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/>',
 "server": '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><path d="M7 7.5h.01M7 16.5h.01"/>',
 "code": '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14"/>',
 "radio": '<circle cx="12" cy="12" r="2"/><path d="M8.5 15.5a5 5 0 0 1 0-7M15.5 8.5a5 5 0 0 1 0 7M5.6 18.4a9 9 0 0 1 0-12.8M18.4 5.6a9 9 0 0 1 0 12.8"/>',
 "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
 "managed": '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><path d="M7 7.5h.01M7 16.5h.01M14 7.5h4M14 16.5h4"/>',
 "check": '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
 "alert": '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>',
}
def icon(name, cls=""):
    return f'<span class="icon-well{(" " + cls) if cls else ""}" aria-hidden="true"><svg viewBox="0 0 24 24">{ICONS[name]}</svg></span>'

# Main nav. Download is the outlined button at the end; managed relays and pricing are first-class now.
NAV = [("index.html", "Home"), ("download.html", "Download"), ("managed-relays.html", "Managed relays"), ("pricing.html", "Pricing"),
       ("self-host.html", "Self-host"), ("privacy.html", "Privacy & security"), ("faq.html", "FAQ")]

def header(active):
    def cur(h): return ' aria-current="page"' if h == active else ""
    desk = "\n        ".join(f'<a href="{h}"{cur(h)}>{l}</a>' for h, l in NAV if h not in ("index.html", "download.html"))
    mob = "\n          ".join(f'<a href="{h}"{cur(h)}>{l}</a>' for h, l in NAV)
    return f'''<a class="skip" href="#main">Skip to content</a>
  <div class="band" aria-hidden="true"></div>
  <header class="site-header">
    <div class="wrap">
      <a class="brand" href="index.html" aria-label="Voidwire home">{MARK}<span>Voidwire</span></a>
      <nav class="nav" aria-label="Main">
        {desk}
        <a class="ext" href="{GH}">Source</a>
        <a class="btn btn-secondary btn-sm vw-cut vw-cut-frame nav-dl" href="download.html"{cur("download.html")}>Download</a>
      </nav>
      <details class="menu">
        <summary>Menu</summary>
        <nav class="menu-panel" aria-label="Main">
          {mob}
          <a class="ext" href="{GH}">Source on GitHub</a>
        </nav>
      </details>
    </div>
  </header>'''

FOOTER = f'''<footer class="site-footer">
    <div class="wrap">
      <div class="foot-grid">
        <div class="foot-brand">
          <a class="brand" href="index.html" aria-label="Voidwire home">{MARK}<span>Voidwire</span></a>
          <p>Encrypted sending of links, text and files between your own devices. Open source, CC0 with an MIT fallback.</p>
          <p class="foot-sec"><span>Security issues</span><a href="mailto:{SECURITY}">{SECURITY}</a></p>
        </div>
        <nav aria-labelledby="f-product"><h2 id="f-product">Product</h2><ul>
          <li><a href="index.html#how">How it works</a></li>
          <li><a href="download.html">Download</a></li>
          <li><a href="download.html#verify">Verify a download</a></li>
          <li><a href="managed-relays.html">Managed relays</a></li>
          <li><a href="pricing.html">Pricing</a></li>
          <li><a href="faq.html">FAQ</a></li>
        </ul></nav>
        <nav aria-labelledby="f-trust"><h2 id="f-trust">Trust</h2><ul>
          <li><a href="privacy.html">Privacy &amp; security</a></li>
          <li><a href="privacy.html#threats">Threat model</a></li>
          <li><a href="privacy.html#report">Report a security issue</a></li>
          <li><a href="self-host.html">Self-host a relay</a></li>
          <li><a href="public-relay.html">Public relay rules</a></li>
        </ul></nav>
        <nav aria-labelledby="f-proj"><h2 id="f-proj">Project</h2><ul>
          <li><a class="ext" href="{GH}">Source on GitHub</a></li>
          <li><a class="ext" href="{GH}/releases">Releases</a></li>
          <li><a class="ext" href="{GH}/blob/master/LICENSE">License</a></li>
          <li><a class="ext" href="{GH}/blob/master/docs/THREAT-MODEL.md">THREAT-MODEL.md</a></li>
          <li><a href="terms.html">Terms for paid services</a></li>
        </ul></nav>
      </div>
      <p class="no-track"><span><b>●</b> This site has no trackers, analytics or cookies, and loads nothing from other servers. Fonts are self-hosted. <a href="privacy.html#website">Details</a></span><span>voidwire.app</span></p>
    </div>
  </footer>'''

CSP_BASE = "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; script-src 'self'; base-uri 'none'"

def page(fname, title, desc, body, active=None, extra_head="", scripts="", noindex=False, form_action="'none'"):
    robots = '\n  <meta name="robots" content="noindex">' if noindex else ""
    doc = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <meta name="description" content="{html.escape(desc)}">{robots}
  <meta name="color-scheme" content="dark light">
  <meta name="theme-color" content="#070B14" media="(prefers-color-scheme: dark)">
  <meta name="theme-color" content="#F4F6F9" media="(prefers-color-scheme: light)">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="{CSP_BASE}; form-action {form_action}">
  <link rel="icon" href="assets/img/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="assets/css/site.css">{extra_head}
</head>
<body>
  {header(active or fname)}
  <main id="main" tabindex="-1">
{body}
  </main>
  {FOOTER}{scripts}
</body>
</html>
'''
    (SITE / fname).write_text(doc)

# ======================================================================
# HOME
# ======================================================================
DIAGRAM = '''<figure class="diagram vw-cut vw-cut-frame" aria-labelledby="dg-cap">
          <svg viewBox="0 0 480 300" role="img" aria-labelledby="dg-title dg-desc">
            <title id="dg-title">How a send travels</title>
            <desc id="dg-desc">A phone and a laptop. On the same network they connect directly. Away from home, the encrypted data passes through a relay that cannot read it.</desc>
            <!-- phone -->
            <rect class="d-node" x="18" y="40" width="70" height="124" rx="10"/>
            <rect class="d-screen" x="27" y="54" width="52" height="88" rx="3"/>
            <rect class="d-pkt" x="35" y="64" width="36" height="5"/><rect class="d-screen" x="35" y="76" width="28" height="4"/><rect class="d-screen" x="35" y="86" width="32" height="4"/>
            <text class="t-strong" x="53" y="190" text-anchor="middle">Phone</text>
            <!-- laptop -->
            <rect class="d-node" x="356" y="58" width="108" height="76" rx="4"/>
            <rect class="d-screen" x="365" y="66" width="90" height="60" rx="2"/>
            <path class="d-node" d="M342 140h136l-10 12H352z"/>
            <rect class="d-pkt" x="374" y="76" width="44" height="5"/><rect class="d-screen" x="374" y="88" width="62" height="4"/>
            <text class="t-strong" x="410" y="190" text-anchor="middle">Laptop</text>
            <!-- direct wire -->
            <path class="d-wire" d="M96 100H340"/>
            <rect class="d-pkt" x="150" y="95" width="16" height="10"/><rect class="d-pkt" x="196" y="95" width="16" height="10"/><rect class="d-pkt" x="242" y="95" width="16" height="10"/>
            <text class="t-wire" x="218" y="82" text-anchor="middle">SAME NETWORK · DIRECT</text>
            <!-- relay path -->
            <path class="d-wire-alt" d="M53 206v44h130M297 250h113v-44"/>
            <polygon class="d-relay" points="191,226 297,226 297,266 289,274 183,274 183,234"/>
            <rect class="d-relay-core" x="221" y="246" width="46" height="8" rx="2"/>
            <text x="240" y="296" text-anchor="middle">AWAY · VIA A RELAY · CIPHERTEXT ONLY</text>
            <!-- locks -->
            <g transform="translate(110 116)"><rect class="d-lock" x="0" y="6" width="14" height="11" rx="1"/><path class="d-lock" d="M3 6V3.5a4 4 0 0 1 8 0V6"/></g>
            <g transform="translate(316 116)"><rect class="d-lock" x="0" y="6" width="14" height="11" rx="1"/><path class="d-lock" d="M3 6V3.5a4 4 0 0 1 8 0V6"/></g>
          </svg>
          <figcaption id="dg-cap">// Encrypted on the sending device, decrypted only on the receiving one. Locks mark the two ends that hold keys.</figcaption>
        </figure>'''

home = f'''    <section class="hero" aria-labelledby="hero-title">
      <div class="wrap">
        <div>
          <p class="eyebrow">// Your devices, one private wire</p>
          <h1 id="hero-title">Send links, text and files to your own devices.</h1>
          <p class="lede">Share from your phone and it opens on your PC. Send from your PC and it lands on your phone. Everything is encrypted end to end. No account, no cloud sign-in, no phone number.</p>
          <div class="btn-row">
            <a class="btn btn-primary vw-cut vw-cut-frame" href="download.html">Download <span class="arrow" aria-hidden="true">→</span></a>
            <a class="btn btn-secondary vw-cut vw-cut-frame" href="#how">How it works</a>
          </div>
          <p class="hero-meta"><span class="ok">Windows</span><span class="ok">Linux</span>{'<span class="ok">macOS (beta)</span>' if MAC else ""}<span class="ok">Android</span><span class="ok">Browser extension</span><span>Free and open source</span></p>
        </div>
        {DIAGRAM}
      </div>
    </section>

    <section class="section" aria-labelledby="send-title">
      <div class="wrap">
        <div class="section-head">
          <p class="eyebrow">// What you can send</p>
          <h2 id="send-title">The things you'd otherwise email yourself.</h2>
        </div>
        <div class="grid g5">
          <div class="card card-tight vw-cut vw-cut-frame">{icon("link")}<h3>Links</h3><p>Share a page from your phone and it opens in your PC's browser.</p></div>
          <div class="card card-tight vw-cut vw-cut-frame">{icon("text")}<h3>Text and clipboard</h3><p>Send a note, a code or your PC's clipboard text.</p></div>
          <div class="card card-tight vw-cut vw-cut-frame">{icon("file")}<h3>Files and photos</h3><p>The receiving device asks before it saves anything.</p></div>
          <div class="card card-tight vw-cut vw-cut-frame">{icon("browser")}<h3>From your browser</h3><p>An extension for Chrome, Edge, Brave and Firefox sends the tab, a link or a selection.</p></div>
          <div class="card card-tight vw-cut vw-cut-frame">{icon("folder")}<h3>From your file manager</h3><p>Right-click a file in Explorer, or in Nautilus, Dolphin or Nemo on Linux, and choose <strong>Send with Voidwire</strong>.</p></div>
        </div>
      </div>
    </section>

    <section class="section" id="how" aria-labelledby="how-title">
      <div class="wrap">
        <div class="section-head">
          <p class="eyebrow">// How it works</p>
          <h2 id="how-title">Pair once. Then just share.</h2>
        </div>
        <ol class="reset-list grid g3 steps" role="list">
          <li class="card step vw-cut vw-cut-frame">
            <span class="step-num"><b>01</b>PAIR</span>
            <h3>Pair two devices</h3>
            <p>Scan a QR code, or type a short code that starts with <code>VW-</code>. Both screens then show the same 6-digit number. Check that it matches.</p>
            <span class="code-sample vw-cut vw-cut-frame" aria-label="Example confirmation code 482 913">482 913</span>
          </li>
          <li class="card step vw-cut vw-cut-frame">
            <span class="step-num"><b>02</b>SHARE</span>
            <h3>Share as usual</h3>
            <p>Use the Android share sheet, the browser extension, or right-click a file in your file manager. Pick the device, for example <strong>Laptop</strong> or <strong>Office PC</strong>.</p>
          </li>
          <li class="card step vw-cut vw-cut-frame">
            <span class="step-num"><b>03</b>ARRIVE</span>
            <h3>It arrives</h3>
            <p>On the same network, devices connect directly. Away from home, the encrypted data goes through a relay. Links open in your browser; files wait until you accept them.</p>
          </li>
        </ol>
      </div>
    </section>

    <section class="section" aria-labelledby="promise-title">
      <div class="wrap">
        <div class="section-head">
          <p class="eyebrow">// Privacy promises</p>
          <h2 id="promise-title">Built so there's little to leak.</h2>
          <p class="lede">These are design rules in the code, not settings you have to find. The <a href="privacy.html">privacy &amp; security page</a> lists what each part can and can't see, and what Voidwire doesn't protect against.</p>
        </div>
        <div class="promises">
          <div class="promise">{icon("user")}<h3>No accounts</h3><p>No sign-up, email or phone number in the apps. Devices trust each other because you paired them.</p></div>
          <div class="promise">{icon("lock")}<h3>End-to-end encrypted</h3><p>Only the paired device you send to can decrypt. The relay forwards data it can't read.</p></div>
          <div class="promise">{icon("eye")}<h3>No telemetry</h3><p>The apps don't report usage or crashes anywhere. The shipped relay configs keep no logs.</p></div>
          <div class="promise">{icon("history")}<h3>No history unless you ask</h3><p>Recent sends, file history and diagnostics are off by default. Turn one off and its data is deleted.</p></div>
          <div class="promise">{icon("server")}<h3>Your choice of relay</h3><p>Use the free public relay, run your own, or have one run for you. The apps work the same with all three.</p></div>
          <div class="promise">{icon("code")}<h3>Open source</h3><p>Every app and the relay mailbox are public on GitHub, including the threat model and its known weak points.</p></div>
        </div>
      </div>
    </section>

    <section class="section" id="relays" aria-labelledby="relays-title">
      <div class="wrap">
        <div class="section-head">
          <p class="eyebrow">// Away from home</p>
          <h2 id="relays-title">Three ways to relay. Two are free.</h2>
          <p class="lede">When your devices can't reach each other directly, they talk through a relay. It only ever forwards encrypted data. Pick who runs it.</p>
        </div>
        <div class="grid g3 relay-options">
          <div class="card vw-cut vw-cut-frame">{icon("globe")}<h3>Public relay <span class="chip chip-ok vw-cut vw-cut-frame">Free</span></h3>
            <p>The default. Run by the Voidwire project and free while costs allow. Nothing to set up.</p>
            <p class="card-foot small"><a href="privacy.html#relay">What a relay can see <span aria-hidden="true">→</span></a></p></div>
          <div class="card vw-cut vw-cut-frame">{icon("server")}<h3>Your own relay <span class="chip chip-ok vw-cut vw-cut-frame">Free</span></h3>
            <p>Run the relay and mailbox with Docker on a Linux host. IP addresses and timing stay with you.</p>
            <p class="card-foot small"><a href="self-host.html">Self-host guide <span aria-hidden="true">→</span></a></p></div>
          <div class="card card-feature vw-cut vw-cut-frame">{icon("managed")}<h3>Managed relay <span class="chip chip-info vw-cut vw-cut-frame">Paid</span></h3>
            <p>A private relay we run for your devices only, so you get your own relay without a server to look after. From $79 a month.</p>
            <p class="card-foot small"><a href="managed-relays.html">Managed relays <span aria-hidden="true">→</span></a><span class="sep" aria-hidden="true">·</span><a href="pricing.html">Pricing</a></p></div>
        </div>
        <p class="mt-20 small muted">Same apps, same encryption, whichever you choose. Paying doesn't unlock anything in the apps.</p>
      </div>
    </section>

    <section class="section" aria-labelledby="status-title">
      <div class="wrap">
        <div class="status vw-cut vw-cut-frame">
          <div><p class="eyebrow">// Before you install</p><h2 id="status-title">The facts, plainly</h2></div>
          <ul>
            <li><span class="chip chip-info vw-cut vw-cut-frame">Release</span><span>Version {VER}, released {P("RELEASE DATE")}. <a class="ext" href="{GH}/releases">Release notes</a></span></li>
            <li><span class="chip vw-cut vw-cut-frame">Review</span><span>Voidwire hasn't been independently audited yet. The protocol spec and threat model are public, including their known weak points, so anyone can review them.</span></li>
            <li><span class="chip vw-cut vw-cut-frame">Checksums</span><span>Every download has a published SHA-256 checksum. The Windows installer isn't code-signed, so <a href="download.html#verify">check the checksum</a> before you install. Updates inside the apps are signed, and the apps reject any update that doesn't match.</span></li>
          </ul>
        </div>
      </div>
    </section>

    <section class="section" aria-labelledby="cta-title">
      <div class="wrap">
        <div class="cta-band vw-cut vw-cut-frame">
          <div>
            <h2 id="cta-title">Get Voidwire for Windows, Android{MAC_LIST} and Linux.</h2>
            <p class="muted">Version {VER}. Free, open source, and each download has a published SHA-256 checksum.</p>
          </div>
          <a class="btn btn-secondary vw-cut vw-cut-frame" href="download.html">Go to downloads <span class="arrow" aria-hidden="true">→</span></a>
        </div>
      </div>
    </section>'''
page("index.html", "Voidwire: send links, text and files between your own devices",
     "Free, open-source, end-to-end encrypted sending of links, text, clipboard and files between your own devices. No account.", home)

# ======================================================================
# DOWNLOAD
# ======================================================================
def artifact(key, label, note=""):
    f = FILES[key]
    return f'''<div class="artifact">
              <div class="row"><span class="file">{fname_html(f)}</span><a class="btn btn-secondary btn-sm vw-cut vw-cut-frame" href="{REL}/{html.escape(f)}" aria-label="Download {label}, {html.escape(f)}">Download</a></div>
              <dl><dt>SHA-256</dt><dd><span class="hash">{P("SHA256")}</span></dd>{note}</dl>
            </div>'''

if MAC:
    MAC_CARD = f'''<article class="card platform vw-cut vw-cut-frame" id="macos" data-name="macOS" aria-labelledby="mac-h">
            <div class="platform-head"><div><h3 id="mac-h">macOS (beta)</h3><p class="req">macOS 13 Ventura or later · Apple silicon and Intel · .dmg</p></div>
              <div><span class="chip chip-info vw-cut vw-cut-frame detected">Detected</span> <span class="chip chip-test vw-cut vw-cut-frame">Beta</span></div></div>
            <p>A menu bar app, like the tray app on Windows. Needed for the browser extension.</p>
            <p class="small muted">macOS is in beta: it has had less testing than Windows and Android, so expect rough edges. Please report problems on <a class="ext" href="{GH}/issues">GitHub</a>.</p>
            {artifact("dmg", "the macOS disk image")}
            <p class="small muted">Voidwire isn't notarized by Apple, so macOS blocks it the first time you open it. To allow it:</p>
            <ol class="small muted">
              <li>Open the .dmg and drag <strong>Voidwire</strong> to <strong>Applications</strong>.</li>
              <li>Open Voidwire from Applications. macOS says it can't verify the app. Close the message; don't choose <strong>Move to Trash</strong>.</li>
              <li>Open <strong>System Settings</strong> › <strong>Privacy &amp; Security</strong> and scroll down to <strong>Security</strong>. Click <strong>Open Anyway</strong> next to the message about Voidwire. The button is there for about an hour after you tried to open the app.</li>
              <li>Enter your login password. When the message comes back, click <strong>Open</strong>.</li>
            </ol>
            <p class="small muted">After that it opens normally. You may need to do this again after downloading a new version.</p>
          </article>'''
else:
    MAC_CARD = '''<article class="card platform is-soon vw-cut vw-cut-frame" id="macos" data-name="macOS" aria-labelledby="mac-h">
            <div class="platform-head"><div><h3 id="mac-h">macOS</h3></div>
              <div><span class="chip chip-info vw-cut vw-cut-frame detected">Detected</span> <span class="chip chip-soon vw-cut vw-cut-frame">Coming soon</span></div></div>
            <p class="placeholder">macOS is coming soon. Until then you can still use Voidwire between your other devices.</p>
          </article>'''

download = f'''    <section class="page-head" aria-labelledby="dl-title">
      <div class="wrap">
        <p class="eyebrow">// Download</p>
        <h1 id="dl-title">Download Voidwire</h1>
        <p class="lede">Install it on two devices and pair them. It's free, with no account to create.</p>
        <p class="release-strip"><span class="chip chip-info vw-cut vw-cut-frame">Current release</span><span class="rs-ver">Version {VER}</span><span>Released {P("RELEASE DATE")}</span><a class="ext" href="{GH}/releases">Release notes</a></p>
        <p class="det-wrap det-banner notice vw-cut vw-cut-frame" role="status">Looks like you're on <strong class="inl" id="det-name">your platform</strong>. <a class="ml-6" id="det-link" href="#platforms">Jump to it</a></p>
        <nav class="jump" aria-label="Platforms">
          <a class="vw-cut vw-cut-frame" href="#windows">Windows</a>
          <a class="vw-cut vw-cut-frame" href="#android">Android</a>
          <a class="vw-cut vw-cut-frame" href="#extension">Browser extension</a>
          <a class="vw-cut vw-cut-frame" href="#linux">Linux</a>{MAC_JUMP}
          <a class="vw-cut vw-cut-frame" href="self-host.html">Relay <small>self-host</small></a>
        </nav>
      </div>
    </section>

    <section class="sec-first section" id="platforms" aria-labelledby="pl-title">
      <div class="wrap">
        <h2 id="pl-title" class="sr-only">Platforms</h2>
        <div class="platforms">
          <article class="card platform vw-cut vw-cut-frame" id="windows" data-name="Windows" aria-labelledby="win-h">
            <div class="platform-head"><div><h3 id="win-h">Windows</h3><p class="req">Windows 10 or 11 · 64-bit (x64)</p></div>
              <span class="chip chip-info vw-cut vw-cut-frame detected">Detected</span></div>
            <p>Tray app with the Explorer <strong>Send with Voidwire</strong> right-click entry. Needed for the browser extension.</p>
            {artifact("win", "the Windows installer")}
            <p class="small muted">If Windows SmartScreen warns about the installer, check the checksum first, then choose <strong>More info</strong> and <strong>Run anyway</strong>. The installer isn't code-signed, so Windows doesn't recognise the publisher.</p>
          </article>

          <article class="card platform vw-cut vw-cut-frame" id="android" data-name="Android" aria-labelledby="and-h">
            <div class="platform-head"><div><h3 id="and-h">Android</h3><p class="req">Android 8.0 or later · APK</p></div>
              <span class="chip chip-info vw-cut vw-cut-frame detected">Detected</span></div>
            <p>Share from any app's share sheet, scan pairing codes, and receive links, text and files.</p>
            {artifact("apk", "the Android APK", '<dt>Signer</dt><dd><span class="hash">' + APK_CERT + '</span></dd>')}
            <p class="small muted">Voidwire isn't on Google Play or F-Droid. Allow your browser or file manager to install unknown apps, then open the APK. After that, the app checks for signed updates itself.</p>
          </article>

          <article class="card platform vw-cut vw-cut-frame" id="extension" data-name="the browser extension" aria-labelledby="ext-h">
            <div class="platform-head"><div><h3 id="ext-h">Browser extension</h3><p class="req">Chrome, Edge, Brave · Firefox</p></div></div>
            <p>Send the current tab, a link, selected text or your clipboard to your phone. It talks only to the Voidwire app on the same PC, so install that first.</p>
            <p><a class="ext" href="https://microsoftedge.microsoft.com/addons/detail/gdcjokipaeghnjfcbnjeofbealnkdgbh">Get it for Edge</a> from Microsoft Edge Add-ons.</p>
            {artifact("crx", "the Chromium extension")}
            {artifact("xpi", "the Firefox extension")}
            <p class="small muted">It isn't in the Chrome Web Store or Firefox Add-ons yet. Chrome, Brave and other Chromium browsers: unzip, open the extensions page, turn on Developer mode, <strong>Load unpacked</strong>. Firefox: load it as a temporary add-on; it is removed when Firefox restarts.</p>
          </article>

          <article class="card platform vw-cut vw-cut-frame" id="linux" data-name="Linux" aria-labelledby="lin-h">
            <div class="platform-head"><div><h3 id="lin-h">Linux</h3><p class="req">x86_64 · .deb (Ubuntu 22.04+, Debian 12+) or AppImage</p></div>
              <div><span class="chip chip-info vw-cut vw-cut-frame detected">Detected</span></div></div>
            <p>The same tray app as on Windows, with <strong>Send with Voidwire</strong> in Nautilus, Dolphin and Nemo (turn it on in Settings). The send-clipboard shortcut is Ctrl+Shift+Alt+V unless you pick other keys. On Wayland your desktop asks which keys to use; on GNOME without that, Settings adds the shortcut to GNOME's keyboard settings for you. It can also start when you sign in (off until you turn it on).</p>
            {artifact("deb", "the Linux .deb package")}
            {artifact("appimage", "the Linux AppImage")}
          </article>

          {MAC_CARD}

          <article class="card platform is-soon vw-cut vw-cut-frame" id="ios" data-name="iOS" aria-labelledby="ios-h">
            <div class="platform-head"><div><h3 id="ios-h">iPhone and iPad</h3></div>
              <div><span class="chip chip-info vw-cut vw-cut-frame detected">Detected</span> <span class="chip chip-soon vw-cut vw-cut-frame">Not available</span></div></div>
            <p class="placeholder">There's no iOS app. You can still use Voidwire between your other devices.</p>
          </article>
        </div>
      </div>
    </section>

    <section class="section" id="verify" aria-labelledby="vf-title">
      <div class="wrap with-toc">
        <div>
          <p class="eyebrow">// Verify</p>
          <h2 id="vf-title">Check your download</h2>
        </div>
        <div class="prose">
          <p class="mt-0 lede">Every release has a <code>SHA256SUMS</code> file listing the SHA-256 checksum of each file. CI writes it after the published files pass the release checks. Compare your file's checksum with the one listed.</p>
          <ol class="num">
            <li><h3>Windows (PowerShell)</h3>
              <figure class="code vw-cut vw-cut-frame"><figcaption class="code-label"><span>PowerShell</span><span>in your Downloads folder</span></figcaption>
<pre><span class="p">&gt; </span><span class="cmd">Get-FileHash .\\Voidwire_{VER}_x64-setup.exe -Algorithm SHA256</span></pre></figure>
              <p>The <strong>Hash</strong> it prints must match the line for that file in <code>SHA256SUMS</code> (case doesn't matter).</p></li>
            <li><h3>Linux or macOS</h3>
              <figure class="code vw-cut vw-cut-frame"><figcaption class="code-label"><span>Terminal</span><span>same folder as SHA256SUMS</span></figcaption>
<pre><span class="p">$ </span><span class="cmd">sha256sum -c SHA256SUMS --ignore-missing</span>        <span class="c"># Linux</span>
<span class="p">$ </span><span class="cmd">shasum -a 256 -c SHA256SUMS --ignore-missing</span>    <span class="c"># macOS</span>
Voidwire_{VER}_x64-setup.exe: OK</pre></figure></li>
            <li><h3>Android: check who signed the APK</h3>
              <figure class="code vw-cut vw-cut-frame"><figcaption class="code-label"><span>Terminal</span><span>Android SDK build-tools</span></figcaption>
<pre><span class="p">$ </span><span class="cmd">apksigner verify --print-certs Voidwire_{VER}_android.apk</span></pre></figure>
              <p>The <strong>certificate SHA-256 digest</strong> it prints must match this one (case and colons don't matter):</p>
              <p class="hash">{APK_CERT}</p>
              <p>The certificate's name reads <code>Voidwire dev release (not for store)</code>. That's the name the key was created with; the digest is what counts. Android also refuses an update signed with a different key.</p></li>
          </ol>
          <div class="notice notice-warn vw-cut vw-cut-frame"><strong>What a checksum does and doesn't prove</strong>
            A matching checksum shows your file is the one on the GitHub release page: nothing broke or changed it on the way. On its own it doesn't prove the release page itself is genuine: neither <code>SHA256SUMS</code> nor the Windows installer is signed. Updates installed through the apps are different: they're signed, with keys pinned in the app.</div>
          <p class="small muted">Downloads are served by GitHub, which sees your IP address like any download host. voidwire.app doesn't mirror them.</p>
        </div>
      </div>
    </section>'''
page("download.html", "Download Voidwire", f"Download Voidwire for Windows, Android, Linux{MAC_LIST} and the browser extension, with checksums to verify them.", download,
     scripts='\n  <script src="assets/js/detect.js" defer></script>')

# ======================================================================
# SELF-HOST
# ======================================================================
selfhost = f'''    <section class="page-head" aria-labelledby="sh-title">
      <div class="wrap">
        <p class="eyebrow">// Self-host a relay</p>
        <h1 id="sh-title">Run your own relay</h1>
        <p class="lede">When your devices can't reach each other directly, they talk through a relay. It only ever forwards encrypted data. Running your own decides who sees the metadata: IP addresses, timing, sizes and device public keys.</p>
        <p class="mt-16 small muted">Rather not run a server? Use the free public relay (see its <a href="public-relay.html">rules</a>), or have a <a href="managed-relays.html">managed relay</a> run for you. Want a hand running your own? See <a href="pricing.html#help">setup help</a>.</p>
      </div>
    </section>

    <section class="sec-first section" aria-labelledby="what-title">
      <div class="wrap">
        <div class="section-head"><p class="eyebrow">// What you run</p><h2 id="what-title">Two small programs on one Linux host</h2></div>
        <div class="grid g2">
          <div class="card vw-cut vw-cut-frame">{icon("radio")}<h3>iroh-relay</h3><p>From the iroh project. Forwards encrypted traffic between devices that can't connect directly.</p><p class="small muted">Inbound TCP 443. UDP 7842 optional.</p></div>
          <div class="card vw-cut vw-cut-frame">{icon("server")}<h3>voidwire-mailbox</h3><p>Holds short-lived encrypted items for devices that are offline. It has no keys to decrypt them, keeps them in RAM only, and drops them after 60 minutes by default.</p><p class="small muted">Outbound only. No open ports.</p></div>
        </div>
        <div class="mt-20 grid g4">
          <div class="card card-tight vw-cut vw-cut-frame"><h4>Linux, always on</h4><p class="small">x86_64 or arm64. A small machine is enough.</p></div>
          <div class="card card-tight vw-cut vw-cut-frame"><h4>A public address</h4><p class="small">Not behind carrier-grade NAT, or use a tunnel you control.</p></div>
          <div class="card card-tight vw-cut vw-cut-frame"><h4>A DNS name</h4><p class="small">Such as <code>relay.example.com</code>. Dynamic DNS is fine.</p></div>
          <div class="card card-tight vw-cut vw-cut-frame"><h4>Port 443 forwarded</h4><p class="small">TCP 443 to the host. UDP 7842 helps direct connections.</p></div>
        </div>
      </div>
    </section>

    <section class="section" id="quick-start" aria-labelledby="qs-title">
      <div class="wrap with-toc">
        <div><p class="eyebrow">// Quick start</p><h2 id="qs-title">Docker in five steps</h2><p class="mt-12 small muted">No copy of the repository needed. Images come from the release.</p></div>
        <ol class="num">
          <li><h3>Get the release bundle</h3>
            <figure class="code vw-cut vw-cut-frame"><figcaption class="code-label"><span>bash</span><span>replace TAG with {P("TAG")}</span></figcaption>
<pre><span class="p">$ </span><span class="cmd">curl -fsSL {GH}/releases/download/TAG/voidwire-relay-docker.tar.gz | tar -xz</span>
<span class="p">$ </span><span class="cmd">cd voidwire-relay</span></pre></figure></li>
          <li><h3>Fill in your settings</h3>
            <figure class="code vw-cut vw-cut-frame"><figcaption class="code-label"><span>bash</span><span>.env holds no secrets</span></figcaption>
<pre><span class="p">$ </span><span class="cmd">cp .env.example .env</span>
<span class="c"># then set these three in .env</span>
VOIDWIRE_RELAY_HOSTNAME=relay.example.com
VOIDWIRE_RELAY_CONTACT=you@example.com
VOIDWIRE_RELAY_UDP=true</pre></figure>
            <p>The contact address is only given to Let&rsquo;s Encrypt. Set <code>UDP=false</code> if you can&rsquo;t forward UDP 7842. The defaults keep it private: token access, and the relay gets its own Let&rsquo;s Encrypt certificate on port 443. The guide covers running it behind your own HTTPS proxy instead.</p></li>
          <li><h3>Start it</h3>
            <figure class="code vw-cut vw-cut-frame"><figcaption class="code-label"><span>bash</span></figcaption>
<pre><span class="p">$ </span><span class="cmd">docker compose up -d</span></pre></figure></li>
          <li><h3>Copy the relay link</h3>
            <figure class="code vw-cut vw-cut-frame"><figcaption class="code-label"><span>bash</span><span>rewritten on every start</span></figcaption>
<pre><span class="p">$ </span><span class="cmd">sudo cat config/relay-link.txt</span>
voidwire:relay?r=https%3A%2F%2Frelay.example.com&amp;m=…</pre></figure>
            <p>The link includes your relay's access token. Treat it like a password.</p></li>
          <li><h3>Add it in the apps</h3>
            <p><strong>PC:</strong> Devices → Relays, paste the link, <strong>Add</strong>. <strong>Android:</strong> Settings → Relays → <strong>Add relay</strong>. Then choose <strong>Make home</strong>. New pairings use your relay; move an existing pairing with <strong>Change relay…</strong> and confirm on both devices.</p></li>
        </ol>
      </div>
    </section>

    <section class="section" aria-labelledby="acc-title">
      <div class="wrap">
        <div class="section-head"><p class="eyebrow">// Defaults</p><h2 id="acc-title">Private by default</h2></div>
        <div class="grid g3">
          <div class="card vw-cut vw-cut-frame"><h3>Token access</h3><p>By default only devices that have your relay link can use the relay. You can open it to everyone, or keep it on your LAN or VPN.</p></div>
          <div class="card vw-cut vw-cut-frame"><h3>No logs</h3><p>The shipped configs log nothing: Docker's log driver is off and the services run with <code>RUST_LOG=off</code>. Turn off access logs on any proxy you put in front.</p></div>
          <div class="card vw-cut vw-cut-frame"><h3>Limits you set</h3><p>Files up to 25 MB go through the relay by default (up to 1 TB if you allow it), at 1 MB/s per device. Devices on the same network don't use the relay at all.</p></div>
        </div>
      </div>
    </section>

    <section class="section" id="updates" aria-labelledby="up-title">
      <div class="wrap with-toc">
        <div><p class="eyebrow">// Updates</p><h2 id="up-title">Updating, and Watchtower</h2></div>
        <div class="prose">
          <p>To update by hand, unpack the new release's <code>compose.yml</code> and templates over the old ones, then <code>docker compose pull &amp;&amp; docker compose up -d</code>. Your <code>.env</code>, token and data are kept. Back up <code>data/mailbox/identity.key</code>: it is your relay's mailbox ID, and losing it means re-adding the link on every device.</p>
          <div class="notice vw-cut vw-cut-frame"><strong>Automatic updates with Watchtower (optional)</strong>
            Use the maintained fork, <code>ghcr.io/nicholas-fedor/watchtower</code>; the original <code>containrrr/watchtower</code> is archived. Label only the <strong>mailbox</strong> container. The relay image is pinned by digest on purpose, and a release that needs a newer relay ships a new <code>compose.yml</code>. Watchtower only updates the <code>latest</code> tag, and <code>latest</code> moves only on stable releases. Watchtower needs the Docker socket, which is root-level access to the host.</div>
        </div>
      </div>
    </section>

    <section class="section" id="cloudflare" aria-labelledby="cf-title">
      <div class="wrap with-toc">
        <div><p class="eyebrow">// Why not Cloudflare Tunnel</p><h2 id="cf-title">Keep TLS on your relay</h2></div>
        <div class="prose">
          <p class="mt-0 lede">A Cloudflare Tunnel or proxied (orange-cloud) DNS record is the easy way to expose a home server. For a Voidwire relay it works against the reason you're self-hosting.</p>
          <ul class="ticks no">
            <li><strong>A third party sits in the path.</strong> Cloudflare terminates TLS, so it sees who connects to whom, when and how much, and it sees your relay's access token. Content stays end-to-end encrypted, but the metadata you meant to keep is now with Cloudflare.</li>
            <li><strong>No UDP.</strong> Tunnels and the proxy don't carry UDP 7842, so devices lose address discovery and fewer connections go direct.</li>
            <li><strong>Terms of service.</strong> Cloudflare's self-serve terms restrict serving large non-HTML files through its proxy or Tunnel, so big transfers can put your account at risk.</li>
          </ul>
          <p><strong>What works:</strong> a DNS-only (grey-cloud) record pointing at your public IP, with the relay keeping its own TLS on TCP 443. Using Cloudflare for DNS only is fine. Behind CGNAT, use a tunnel or reverse proxy on a host <em>you</em> control.</p>
          <p class="small"><a class="ext" href="{GH}/blob/master/docs/self-host-relay.md">Full guide: plain binaries, TLS behind a proxy, access control, Portainer, troubleshooting</a></p>
        </div>
      </div>
    </section>'''
page("self-host.html", "Self-host a Voidwire relay", "Run your own Voidwire relay and mailbox with Docker, keep TLS on your relay, and why not to use Cloudflare Tunnel.", selfhost)

# ======================================================================
# PRIVACY & SECURITY
# ======================================================================
privacy = f'''    <section class="page-head" aria-labelledby="pv-title">
      <div class="wrap">
        <p class="eyebrow">// Privacy &amp; security</p>
        <h1 id="pv-title">What's stored, who sees what, and the limits</h1>
        <p class="lede">The short version: what you send is encrypted on your device and decrypted only on the paired device you chose. Servers in between see that traffic happened, not what it was. Below is the long version, including what Voidwire doesn't protect against.</p>
      </div>
    </section>

    <div class="sec-first section">
      <div class="wrap with-toc">
        <nav class="toc" aria-labelledby="toc-h"><p id="toc-h">On this page</p><ol>
          <li><a href="#stored">What's stored where</a></li>
          <li><a href="#extension">Browser extension</a></li>
          <li><a href="#relay">What the relay sees</a></li>
          <li><a href="#encryption">Encryption</a></li>
          <li><a href="#threats">Threat model</a></li>
          <li><a href="#website">This website</a></li>
          <li><a href="#requests">Requests and billing</a></li>
          <li><a href="#report">Reporting a security issue</a></li>
        </ol></nav>
        <div class="prose">
          <h2 id="stored">What's stored where</h2>
          <p>Nothing is kept as history unless you turn it on. Every file the apps write is listed in the <a class="ext" href="{GH}/blob/master/docs/THREAT-MODEL.md#7-data-inventory-m11-privacy-first-rule-of-10-11-2026">data inventory</a>, and CI fails if a new one appears.</p>
          <div class="grid g3">
            <div class="card vw-cut vw-cut-frame"><h3>On your PC</h3>
              <ul class="ticks"><li>Device keys, paired devices and settings. On Windows: sealed with Windows DPAPI. On Linux: stored in your home folder, readable only by your user account (not encrypted).</li><li>A replay list of message IDs, kept about 20 minutes. No links, no hosts.</li></ul>
              <p class="small muted card-foot">Only if you turn it on: a diagnostics log that never contains links.</p></div>
            <div class="card vw-cut vw-cut-frame"><h3>On your phone</h3>
              <ul class="ticks"><li>Device keys, paired devices and settings, encrypted with a key in the Android Keystore</li><li>Excluded from cloud backup</li></ul>
              <p class="small muted card-foot">Only if you turn it on: the last 20 sends (host only, never the full link) and the last device you sent to.</p></div>
            <div class="card vw-cut vw-cut-frame"><h3>On the relay</h3>
              <ul class="ticks"><li>The relay software writes nothing about you to disk</li><li>Encrypted items for an offline device, in RAM, deleted when fetched or after 60 minutes by default</li></ul>
              <p class="small muted card-foot">The public relay, <code>relay.voidwire.app</code>, is run by the Voidwire project with the same relay and mailbox software we publish for self-hosting. To keep the free relay affordable, its offline inbox may be smaller than the default. Its <a href="public-relay.html">rules</a> are short.</p></div>
          </div>
          <p class="small muted">Not stored anywhere: an account (there isn't one), the links you open, or Windows notifications. The desktop app shows none, because Windows keeps notification text in a database on disk.</p>
          <div class="notice vw-cut vw-cut-frame" id="updates"><strong>What the apps fetch on their own: update checks</strong>
            At most once a day, each app downloads a small signed file from GitHub Pages to see if there's a new version. It sends no device ID or anything about your devices; GitHub sees your IP address and the time. Turn it off in <strong>Settings → Updates</strong>.</div>

          <h2 id="extension">The browser extension</h2>
          <p>The extension for Chrome, Edge, Brave and Firefox talks only to the Voidwire desktop app on the same computer, through the browser's native messaging. It makes no network requests of its own, can't read the pages you visit, and stores nothing. When you click a send action, it hands the desktop app exactly what you chose: the current tab's address, a link or selected text, or a request to send your PC clipboard. The desktop app encrypts it end to end to the device you picked. To list your devices, the extension asks the desktop app for their names and keeps them in memory only. Neither the extension nor the Voidwire project receives what you send.</p>
          <h2 id="relay">What the relay can and can't see</h2>
          <p>This applies to the public relay, a managed relay and any relay you run. Choosing one changes <em>who</em> holds the left column, not what's in it. With a managed relay, that's the Voidwire project, the same as the public relay.</p>
          <div class="seeing vw-cut vw-cut-frame" role="group" aria-label="What a relay can and cannot see">
            <div class="can"><h3><span class="mk" aria-hidden="true">+</span>Can see</h3><ul>
              <li>IP addresses of devices that connect through it</li>
              <li>Device public keys, and which of them are talking</li>
              <li>When traffic happens and roughly how much (messages are padded to fixed sizes, but a large file still means a lot of traffic)</li>
              <li>Opaque mailbox IDs, and which IPs read or write them</li>
              <li>Your access token, if it's your own relay with one</li>
            </ul></div>
            <div class="cannot"><h3><span class="mk" aria-hidden="true">–</span>Can't see</h3><ul>
              <li>Links, text, clipboard contents or files</li>
              <li>File names, types and exact sizes</li>
              <li>Device names, like "Laptop" or "Office PC"</li>
              <li>Pairing codes or keys</li>
              <li>Anything sent directly on your local network: that never touches a relay</li>
            </ul></div>
          </div>

          <h2 id="encryption">Encryption, in plain words</h2>
          <p>When you pair, both devices create keys and show the same 6-digit number, tied to that exact connection. If the numbers match, nobody sat in between. After that, every message is encrypted to the receiving device's key, signed by the sender, and checked before anything happens. Your PC only opens a link that came from a device you paired, passed every check, and is a normal web address.</p>
          <details class="tech vw-cut vw-cut-frame"><summary>The technical version</summary><div>
            <ul class="ticks">
              <li><strong>Transport:</strong> QUIC with TLS 1.3 (iroh), dialled by device key. Direct on the LAN first, relay otherwise.</li>
              <li><strong>Messages:</strong> HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, padded to fixed buckets. Signed with Ed25519 (<code>verify_strict</code>).</li>
              <li><strong>Files:</strong> XChaCha20-Poly1305 in 256 KiB chunks, then a BLAKE3 check of the whole file. Partial files are deleted if a transfer fails.</li>
              <li><strong>Pairing:</strong> single-use QR or <code>VW-</code> code that expires after 5 minutes, plus a 6-digit short authentication string bound to the TLS handshake.</li>
              <li><strong>Replays:</strong> ±10 minute timestamp window and a saved list of seen message IDs.</li>
            </ul>
            <p class="mt-12 small">Spec: <a class="ext" href="{GH}/blob/master/docs/PROTOCOL.md">PROTOCOL.md</a>. Voidwire hasn't been independently audited yet.</p>
          </div></details>

          <h2 id="threats">Threat model</h2>
          <div class="grid g2">
            <div class="card vw-cut vw-cut-frame"><h3>Voidwire protects against</h3><ul class="ticks">
              <li>People on the same Wi-Fi or network reading what you send</li>
              <li>The relay operator, including us, reading what you send</li>
              <li>Strangers sending links to your PC: only paired devices are accepted</li>
              <li>Someone in the middle during pairing, if you compare the 6-digit number</li>
              <li>Old messages replayed later</li>
              <li>Links to <code>file:</code>, scripts or other odd schemes: only http and https open</li>
            </ul></div>
            <div class="card vw-cut vw-cut-frame"><h3>It does not protect against</h3><ul class="ticks no">
              <li><strong>A paired device that's compromised</strong>, or stolen and unlocked. It's trusted: by default it can open any web page on your PC. Turn on <strong>Ask before opening</strong>, and <strong>Forget</strong> a lost device.</li>
              <li><strong>Malware on your PC or phone.</strong> It can read the app's data or act as you.</li>
              <li><strong>Metadata.</strong> Relays and networks see IP addresses and timing. People on your LAN can see that a Voidwire PC is there.</li>
              <li><strong>Links into your home network.</strong> A paired device can open a router or NAS page (home addresses are allowed).</li>
              <li><strong>Look-alike devices.</strong> If you pair with a hostile PC that copies your PC's name, you'll see two with that name.</li>
              <li><strong>A compromised release page.</strong> A checksum shows your file matches the release page, not that the page is genuine. Neither the installer nor <code>SHA256SUMS</code> is signed yet; updates installed through the apps are signed with keys pinned in the app.</li>
            </ul></div>
          </div>
          <p class="small muted">The full list, with residual risks and tests: <a class="ext" href="{GH}/blob/master/docs/THREAT-MODEL.md">THREAT-MODEL.md</a>.</p>

          <h2 id="website">This website</h2>
          <ul class="ticks">
            <li>This site sets no cookies and has no analytics, trackers or ads. Cloudflare (below) may set its own security cookie, but only if it has to check a request it finds suspicious.</li>
            <li>Nothing loads from other servers: fonts, styles and images are served from voidwire.app. The download page has one small script that reads your platform on your device to highlight the right download; it stores and sends nothing, and the page works without it.</li>
            <li>The site's web server is set to keep no access logs.</li>
            <li>Requests pass through Cloudflare, which handles the connection, so it sees your IP address and the pages you ask for, and processes them under <a class="ext" href="{CF_PRIVACY}">Cloudflare's own privacy policy</a>.</li>
            <li>Download links point to GitHub, which sees your IP address when you download.</li>
          </ul>
          <p class="small muted">Why Cloudflare here, when the <a href="self-host.html#cloudflare">self-host guide</a> advises against it for relays? This site is public pages anyone can read. A relay carries your devices' metadata and its access token, so it should keep its own TLS.</p>

          <h2 id="requests">Requests and billing</h2>
          <p>To ask about a managed relay or self-host help, you email <a href="mailto:{SALES}">{SALES}</a>. There's no form on this site. We get what you send: your email address, your name if you give it, and whatever you tell us about your devices and plans. We use it only to reply. No newsletter, no mailing list, and it isn't shared or sold.</p>
          <ul class="ticks">
            <li><strong>Where it's kept.</strong> Your emails arrive in a Proton Mail mailbox for voidwire.app, which stores mail encrypted. Only the person who runs the Voidwire project can read it.</li>
            <li><strong>How long.</strong> We haven't set a fixed retention period yet; we plan to publish one here. Until then, if you ask, we'll delete your emails, except invoices and payment records we have to keep for tax.</li>
            <li><strong>Billing.</strong> If you become a customer, payments go through Stripe, which handles your card and billing details under its own privacy policy. We never see or store your full card number. We keep invoices (your name or company, billing address, what you bought and what you paid) for as long as tax law requires. Invoices are issued under the legal name of the person who runs the Voidwire project.</li>
            <li>The apps themselves still have no account, and your relay never learns who paid for it. See the <a href="terms.html">terms</a> for paid services.</li>
          </ul>

          <h2 id="report">Reporting a security issue</h2>
          <p>Found a security problem in Voidwire, a relay or this site? Email <a href="mailto:{SECURITY}">{SECURITY}</a>. Please report it privately first, and give us a chance to fix it before you publish.</p>
          <p class="small muted">The same contact is in <a href=".well-known/security.txt"><code>/.well-known/security.txt</code></a> (RFC 9116).</p>
        </div>
      </div>
    </div>'''
page("privacy.html", "Privacy & security · Voidwire", "What Voidwire stores, what a relay can and can't see, how it's encrypted, what it doesn't protect against, and how to report a security issue.", privacy)

# ======================================================================
# FAQ
# ======================================================================
def qa(q, a, open_=False):
    return f'<details class="qa"{" open" if open_ else ""}><summary>{q}</summary><div>{a}</div></details>'

faq_groups = [
 ("Basics", [
  qa("Do I need an account?", "<p>No. There's no sign-up, email or phone number. Two devices trust each other because you paired them with a QR or <code>VW-</code> code and checked the 6-digit number.</p>", True),
  qa("Which devices does it run on?", (f"<p>Windows, Android, Linux and macOS (beta), plus a browser extension for Chrome, Edge, Brave and Firefox. On Linux there's a <code>.deb</code> for Ubuntu 22.04+ and Debian 12+, and an AppImage. The Mac app runs on macOS 13 or later, Apple silicon and Intel. macOS has had less testing than Windows, Android and Linux, so it's marked beta. There's no iOS app. You can pair any two: PC with phone, PC with PC, or phone with phone.</p>" if MAC else f"<p>Windows, Android and Linux, plus a browser extension for Chrome, Edge, Brave and Firefox. On Linux there's a <code>.deb</code> for Ubuntu 22.04+ and Debian 12+, and an AppImage. There's no macOS or iOS app. You can pair any two: PC with phone, PC with PC, or phone with phone.</p>")),
  qa("What can I send?", "<p>Web links, text, your PC's clipboard text, and files or photos. Links open in your PC's default browser. Files are only saved after you accept them on the receiving device, and programs are never run automatically.</p>"),
  qa("Does it cost anything?", "<p>No. The apps are free and open source, and so is running your own relay. The public relay is run by the Voidwire project and is free while costs allow, under a few <a href=\"public-relay.html\">rules</a>.</p><p>Managed relays are an optional paid service for people who want a private relay without running a server. You never need one. See <a href=\"pricing.html\">pricing</a>.</p>"),
 ]),
 ("Relays", [
  qa("Does it work when I'm away from home?", "<p>Yes. On the same network, devices connect directly. Otherwise they go through a relay, still encrypted end to end. By default files up to 25 MB go through the relay, and the app asks before sending anything over 256 KB that way.</p>"),
  qa("What if the other device is off or asleep?", "<p>Links and text wait for it on the relay, encrypted and in RAM only, for up to 60 minutes by default, and arrive when it next connects. Files need both devices online.</p>"),
  qa("What's a managed relay?", "<p>A relay and mailbox that the Voidwire project runs for your devices only, with token access, so you get your own relay without running a server. You add it in the apps with a relay link, the same way as a self-hosted one.</p><p>Like any relay it can't read what you send, but it sees IP addresses and timing. If you want that metadata to stay with you, run your own. Plans start at $79 a month. <a href=\"managed-relays.html\">More about managed relays</a>.</p>"),
  qa("Can I run my own relay?", "<p>Yes, for free, with Docker or plain binaries on a Linux host. See <a href=\"self-host.html\">Self-host a relay</a>. You can use more than one relay, and each pairing can sit on a different one.</p>"),
  qa("Can I put my relay behind Cloudflare Tunnel?", "<p>We don't recommend it. Cloudflare would terminate TLS and see who connects to whom, when, how much, and your access token. It also doesn't carry UDP. A DNS-only record is fine. <a href=\"self-host.html#cloudflare\">Why</a>.</p>"),
 ]),
 ("Privacy & safety", [
  qa("Why did a link open on my PC by itself?", "<p>That's the default: links from your paired devices open right away. If you'd rather approve each one, turn on <strong>Ask before opening</strong> in the desktop app's settings. It shows the website and the sending device first.</p>"),
  qa("Why doesn't Voidwire show Windows notifications?", "<p>Windows stores notification text in a database on disk. A notification like \"Opened example.com from Phone\" would leave a record of what you opened, so the desktop app shows none.</p>"),
  qa("Does Voidwire keep a history?", "<p>Not unless you ask. Recent sends, the last device you used, file history and the diagnostics log are all off by default. Turn one off and its data is deleted.</p>"),
  qa("I lost my phone. What do I do?", "<p>On your PC, open Devices and choose <strong>Forget</strong> on that phone. Your PC refuses it from then on. Anyone holding the unlocked phone could otherwise keep sending to your PC.</p>"),
  qa("Has it been audited?", "<p>Not yet. Voidwire hasn't been independently audited. The protocol spec, the threat model with its known weak points, and all the code are public on GitHub. If an audit happens, we'll publish the report and link it here.</p>"),
  qa("Does the app contact anything on its own?", "<p>Only to check for updates. At most once a day, each app downloads a small signed file from GitHub Pages to see if there's a new version. It sends no device ID or anything about your devices; GitHub sees your IP address and the time. Turn it off in <strong>Settings → Updates</strong>. <a href=\"privacy.html#updates\">More</a>.</p>"),
  qa("How do I report a security issue?", f"<p>Email <a href=\"mailto:{SECURITY}\">{SECURITY}</a>, privately first. See <a href=\"privacy.html#report\">reporting a security issue</a>.</p>"),
 ]),
 ("Installing", [
  qa("Why does Windows say it protected my PC?", f"<p>SmartScreen can warn about apps that few people have downloaded. Check the checksum on the <a href=\"download.html#verify\">download page</a>, then choose <strong>More info → Run anyway</strong>. The installer isn't code-signed, which is why the warning names no publisher.</p>"),
  qa("How do I install the browser extension?", f"<p>Download it from the <a href=\"download.html#extension\">download page</a> and load it as the page explains. On Edge, get it from <a class=\"ext\" href=\"https://microsoftedge.microsoft.com/addons/detail/gdcjokipaeghnjfcbnjeofbealnkdgbh\">Microsoft Edge Add-ons</a>; it isn't in the Chrome Web Store or Firefox Add-ons yet. It needs the desktop app on the same PC.</p>"),
  qa("Where are the release notes and older versions?", f"<p>On the <a class=\"ext\" href=\"{GH}/releases\">GitHub releases page</a>. The current release is {VER}.</p>"),
 ]),
]
faq_body = "\n".join(f'<div class="faq-group"><h2>{g}</h2>{"".join(items)}</div>' for g, items in faq_groups)
faq = f'''    <section class="page-head" aria-labelledby="faq-title">
      <div class="wrap">
        <p class="eyebrow">// FAQ</p>
        <h1 id="faq-title">Questions</h1>
        <p class="lede">Short answers. For the details, see <a href="privacy.html">privacy &amp; security</a> or the <a class="ext" href="{GH}">source</a>.</p>
      </div>
    </section>
    <div class="sec-first section">
      <div class="narrow-900 wrap">
        {faq_body}
      </div>
    </div>'''
page("faq.html", "FAQ · Voidwire", "Answers about Voidwire: accounts, platforms, relays, managed relays, privacy and installing.", faq)

# ======================================================================
# MANAGED RELAYS (product page; in the main nav, indexed)
# ======================================================================
def mailto(subject):
    return f"mailto:{SALES}?subject=" + subject.replace(" ", "%20").replace(":", "%3A")

managed = f'''    <section class="page-head" aria-labelledby="mr-title">
      <div class="wrap">
        <p class="eyebrow">// Managed relays</p>
        <h1 id="mr-title">Your own relay, without the server.</h1>
        <p class="lede">We run a private relay and mailbox for your devices only. You paste one link into the apps, and everything stays end-to-end encrypted. It's optional: the public relay and self-hosting stay free.</p>
        <div class="btn-row mt-24">
          <a class="btn btn-primary vw-cut vw-cut-frame" href="{mailto('Managed relay request')}">Request a managed relay <span class="arrow" aria-hidden="true">→</span></a>
          <a class="btn btn-secondary vw-cut vw-cut-frame" href="pricing.html">See pricing</a>
        </div>
        <p class="mt-16 small muted">From $79 a month. Requests go by email to <a href="mailto:{SALES}">{SALES}</a>.</p>
      </div>
    </section>

    <section class="sec-first section" aria-labelledby="mr-get">
      <div class="wrap">
        <div class="section-head"><p class="eyebrow">// What you get</p><h2 id="mr-get">A relay that only your devices use</h2></div>
        <div class="grid g3">
          <div class="card vw-cut vw-cut-frame">{icon("lock")}<h3>Private to you</h3><p>Token access: only devices that have your relay link can use it. Nobody else's traffic shares it.</p></div>
          <div class="card vw-cut vw-cut-frame">{icon("eye")}<h3>Can't read your data</h3><p>It forwards end-to-end encrypted data and holds no keys. The relay and mailbox run with logging off, as in the self-hosted setup, and keep offline items in RAM only. Our server setup keeps the system journal in memory and turns off the service that would copy it to log files on disk.</p></div>
          <div class="card vw-cut vw-cut-frame">{icon("managed")}<h3>Nothing to run</h3><p>No Linux host, DNS name or port forwarding. We keep the relay updated and its certificate renewed. It's best effort, with no uptime guarantee.</p></div>
        </div>
      </div>
    </section>

    <section class="section" aria-labelledby="mr-how">
      <div class="wrap with-toc">
        <div><p class="eyebrow">// How it works</p><h2 id="mr-how">Three steps</h2></div>
        <ol class="num">
          <li><h3>Request one</h3><p>Email <a href="{mailto('Managed relay request')}">{SALES}</a> with the plan you want, roughly how many devices you have and how you'll use it. We reply by email.</p></li>
          <li><h3>Get your relay link</h3><p>Once it's set up, we send your relay link in an encrypted message that expires after 7 days, and give you its password separately by phone or text. We never send the link in a plain email. It includes your relay's access token, so treat it like a password. If it leaks, ask us and we'll replace it.</p></li>
          <li><h3>Add it in the apps</h3><p><strong>PC:</strong> Devices → Relays, paste the link, <strong>Add</strong>. <strong>Android:</strong> Settings → Relays → <strong>Add relay</strong>. Then choose <strong>Make home</strong>. Move an existing pairing with <strong>Change relay…</strong> and confirm on both devices.</p></li>
        </ol>
      </div>
    </section>

    <section class="section" id="compare" aria-labelledby="mr-cmp">
      <div class="wrap">
        <div class="section-head"><p class="eyebrow">// Compare</p><h2 id="mr-cmp">Which relay is right for you</h2>
          <p class="lede">No relay can read what you send. The difference is who runs it, who sees the metadata, and what it costs.</p></div>
        <div class="table-wrap cmp vw-cut vw-cut-frame" role="region" aria-labelledby="mr-cmp" tabindex="0">
          <table>
            <thead><tr><th scope="col"><span class="sr-only">Question</span></th><th scope="col">Public relay</th><th scope="col" class="hl">Managed relay</th><th scope="col">Your own relay</th></tr></thead>
            <tbody>
              <tr><th scope="row">Who runs it</th><td>The Voidwire project</td><td class="hl">The Voidwire project, for your devices only</td><td>You</td></tr>
              <tr><th scope="row">Cost</th><td>Free, while costs allow</td><td class="hl">From $79/month</td><td>Free, plus your own hosting</td></tr>
              <tr><th scope="row">Who can use it</th><td>Anyone using the default</td><td class="hl">Devices with your relay link</td><td>Whoever you allow</td></tr>
              <tr><th scope="row">Sees IP addresses and timing</th><td>The Voidwire project and its hosting provider</td><td class="hl">The Voidwire project and its host (DigitalOcean)</td><td>You and your host</td></tr>
              <tr><th scope="row">Can read what you send</th><td>No</td><td class="hl">No</td><td>No</td></tr>
              <tr><th scope="row">Rules</th><td><a href="public-relay.html">Public relay rules</a></td><td class="hl"><a href="terms.html">Terms for paid services</a></td><td>Yours</td></tr>
              <tr><th scope="row">Uptime</th><td>Best effort</td><td class="hl">Best effort, no guarantee</td><td>Up to you</td></tr>
              <tr><th scope="row">Setup</th><td>None</td><td class="hl">Paste one link</td><td>A Linux host, a DNS name, port 443</td></tr>
            </tbody>
          </table>
        </div>
        <p class="mt-20 small muted">If you want the metadata to stay with you, <a href="self-host.html">run your own relay</a>. That's free and fully supported, and there's paid <a href="pricing.html#help">setup help</a> if you want it.</p>
      </div>
    </section>

    <section class="section" aria-labelledby="mr-keep">
      <div class="wrap with-toc">
        <div><p class="eyebrow">// Our promises</p><h2 id="mr-keep">What paying doesn't change</h2></div>
        <ul class="ticks">
          <li>The apps stay free, open source, and work without an account.</li>
          <li>Paying doesn't unlock anything in the apps. A managed relay is just a relay.</li>
          <li>Self-hosting stays free and documented.</li>
          <li>The public relay stays free while costs allow, under its <a href="public-relay.html">rules</a>. Managed relays help pay for it.</li>
          <li>Your relay never learns who paid for it.</li>
        </ul>
      </div>
    </section>

    <section class="section" aria-labelledby="mr-cta">
      <div class="wrap">
        <div class="cta-band vw-cut vw-cut-frame">
          <div>
            <h2 id="mr-cta">Two plans: Team and Business.</h2>
            <p class="muted">From $79 a month, or pay yearly for the price of 10 months.</p>
          </div>
          <a class="btn btn-secondary vw-cut vw-cut-frame" href="pricing.html">See pricing <span class="arrow" aria-hidden="true">→</span></a>
        </div>
      </div>
    </section>'''
page("managed-relays.html", "Managed relays · Voidwire", "A private Voidwire relay run for your devices, from $79 a month. Optional: the public relay and self-hosting stay free.", managed)

# ======================================================================
# PRICING. Live: mailto only. Later state (_later-*): the same page with the request form.
# ======================================================================
def feat(items):
    return '<ul class="ticks">' + "".join(f"<li>{i}</li>" for i in items) + "</ul>"

FORM_ENDPOINT = "/request"   # FILL-IN §1; the handler isn't built, so the form is a later state

def request_form(state="empty"):
    """state: 'empty' or 'error' (what /request sends back after a failed server-side check). Later state only."""
    err = state == "error"
    summary = '''<div class="form-summary" role="alert" tabindex="-1" id="form-errors">
              <strong>Check 2 fields</strong>
              <ul><li><a href="#rq-email">Enter an email address, like name@example.com</a></li><li><a href="#rq-usage">Tell us roughly how many devices you have</a></li></ul>
            </div>''' if err else ""
    def field(fid, label, control, hint="", error="", optional=False):
        inv = err and error
        opt = ' <span class="opt">(optional)</span>' if optional else ''
        described = " ".join(x for x in [f"{fid}-hint" if hint else "", f"{fid}-err" if inv else ""] if x)
        control = control.replace("ARIA", (f' aria-describedby="{described}"' if described else "") + (' aria-invalid="true"' if inv else ""))
        return f'''<div class="field{" is-invalid" if inv else ""}">
              <label for="{fid}">{label}{opt}</label>
              {f'<p class="hint" id="{fid}-hint">{hint}</p>' if hint else ""}
              {f'<p class="field-error" id="{fid}-err"><span aria-hidden="true">!</span> {error}</p>' if inv else ""}
              {control}
            </div>'''
    email_val = ' value="name@example"' if err else ""
    msg_val = "Two phones and a laptop for a small team." if err else ""
    return f'''<form class="req-form vw-cut vw-cut-frame" action="{FORM_ENDPOINT}" method="post" aria-labelledby="rq-title">
            <h3 id="rq-title" class="form-title">Request a managed relay</h3>
            {summary}
            {field("rq-name", "Name", '<input id="rq-name" name="name" type="text" autocomplete="name" maxlength="120"ARIA>', optional=True)}
            {field("rq-email", "Email", f'<input id="rq-email" name="email" type="email" autocomplete="email" required maxlength="254"{email_val}ARIA>', hint="We reply to this address. Nothing else.", error="Enter an email address, like name@example.com")}
            {field("rq-usage", "Expected devices and usage", '<input id="rq-usage" name="usage" type="text" required maxlength="300"ARIA>', hint="For example: 4 devices, a phone and three PCs, mostly links.", error="Tell us roughly how many devices you have")}
            {field("rq-msg", "Message", f'<textarea id="rq-msg" name="message" rows="4" maxlength="2000"ARIA>{msg_val}</textarea>', optional=True)}
            <div class="form-actions">
              <button class="btn btn-primary vw-cut vw-cut-frame" type="submit">Send request</button>
              <p class="small muted">Not live: this form is a design for later. Requests come by email only. Used only to reply. <a href="privacy.html#requests">What we keep</a></p>
            </div>
          </form>'''

def plan(pid, kind, price, per, sub, items, cta_label, cta_href, managed=False):
    per_html = f'<span class="plan-per">{per}</span>' if per else ""
    return f'''<article class="card plan{" plan-managed" if managed else ""} vw-cut vw-cut-frame" aria-labelledby="{pid}-k {pid}">
            <p class="plan-kind" id="{pid}-k">{kind}</p>
            <h3 id="{pid}" class="plan-price">{price}{per_html}</h3>
            <p class="plan-sub">{sub}</p>
            {feat(items)}
            <a class="btn btn-secondary vw-cut vw-cut-frame plan-cta" href="{cta_href}">{cta_label}</a>
          </article>'''

def request_section(state):
    """state: 'live' (mailto only), 'empty' or 'error' (later state with the form)."""
    if state == "live":
        right = f'''<div class="req-mail card vw-cut vw-cut-frame">
            <h3 class="form-title">Email us</h3>
            <p><a class="req-addr" href="mailto:{SALES}">{SALES}</a></p>
            <p class="small muted">Include:</p>
            {feat(["The plan: Team, Business, setup help or a support plan", "Roughly how many devices, and what kinds", "How you'll use it, for example mostly links or large files"])}
            <a class="btn btn-primary vw-cut vw-cut-frame" href="{mailto('Managed relay request')}">Write an email <span class="arrow" aria-hidden="true">→</span></a>
            <p class="small muted">Opens your email app. We use what you send only to reply. <a href="privacy.html#requests">What we keep</a></p>
          </div>'''
        side = f'''<li>We reply by email.</li>
            <li>No form and no scripts: nothing is stored in your browser.</li>
            <li>If you become a customer, our <a href="terms.html">terms for paid services</a> apply.</li>'''
        notice = ""
    else:
        right = request_form(state)
        side = f'''<li>We use what you send only to reply. No newsletter, no mailing list. <a href="privacy.html#requests">Details</a></li>
            <li>Nothing is stored in your browser, and the form loads no scripts.</li>
            <li>If you become a customer, our <a href="terms.html">terms for paid services</a> apply.</li>'''
        notice = f'<div class="notice mt-24 vw-cut vw-cut-frame"><strong>Prefer email?</strong>Write to <a href="{mailto("Managed relay request")}">{SALES}</a> with the same details.</div>'
    return f'''    <section class="section" id="request" aria-labelledby="rq-head">
      <div class="wrap request">
        <div>
          <p class="eyebrow">// Request</p>
          <h2 id="rq-head">Get a managed relay or setup help</h2>
          <p class="mt-16 lede">Tell us which plan you want, roughly how many devices you have and how you'll use them.</p>
          <ul class="ticks mt-24">
            {side}
          </ul>
          {notice}
        </div>
        {right}
      </div>
    </section>'''

def pricing_body(state="live"):
    def managed_items(traffic, files, speed):
        return ["Private: only devices with your relay link", traffic, files, speed, "Updates and certificates handled for you", "Can't read what you send"]
    return f'''    <section class="page-head" aria-labelledby="pr-title">
      <div class="wrap">
        <p class="eyebrow">// Pricing</p>
        <h1 id="pr-title">Voidwire is free. Managed relays are optional.</h1>
        <p class="lede">The apps, the public relay and self-hosting cost nothing. Pay only if you want a private relay that we run for you, or a hand running your own. Every option has the same apps and the same end-to-end encryption.</p>
      </div>
    </section>

    <section class="sec-first section" aria-labelledby="free-title">
      <div class="wrap">
        <div class="section-head"><p class="eyebrow">// Free for everyone</p><h2 id="free-title">Free</h2></div>
        <div class="plans plans-2">
          {plan("pl-public", "Public relay", "Free", "", "while costs allow", ["Used by default. Nothing to set up.", "Run by the Voidwire project", "Shared with everyone on the default relay", "Can't read what you send"], "Download", "download.html")}
          {plan("pl-self", "Your own relay", "Free", "", "on your own server", ["Relay and mailbox in Docker on a Linux host", "IP addresses and timing stay with you", "You keep it running and updated", "Can't read what you send"], "Self-host guide", "self-host.html")}
        </div>
      </div>
    </section>

    <section class="section" id="managed" aria-labelledby="mg-title">
      <div class="wrap">
        <div class="section-head"><p class="eyebrow">// Managed relays</p><h2 id="mg-title">A private relay, run for you</h2>
          <p class="lede">A dedicated relay and mailbox on its own server, used only by your devices. <a href="managed-relays.html">How managed relays work</a>.</p></div>
        <div class="plans plans-2">
          {plan("pl-team", "Managed relay · Team", "$79", " / month", "or $790 a year. Monthly plans have a one-time $99 setup fee.", managed_items("2 TB of relayed traffic a month included", "Files up to 1 TB device-to-device; relay file-size limit depends on your plan", "10 MB/s per device"), "Request Team", mailto("Managed relay: Team"), managed=True)}
          {plan("pl-business", "Managed relay · Business", "$109", " / month", "or $1,090 a year. Monthly plans have a one-time $99 setup fee.", managed_items("4 TB of relayed traffic a month included", "Files up to 1 TB device-to-device; relay file-size limit depends on your plan", "No speed cap"), "Request Business", mailto("Managed relay: Business"), managed=True)}
        </div>
        <p class="mt-20 small muted plan-note">Prices are in US dollars. Pay monthly, or yearly for the price of 10 months. Monthly plans have a one-time $99 setup fee, which yearly plans don't. Any sales tax or VAT that applies is shown on your invoice before you pay. Extra traffic beyond your plan is $20 per TB; we tell you before it's billed. Best effort, with no uptime guarantee. See the <a href="terms.html">terms</a> and <a href="managed-relays.html#compare">compare the three kinds of relay</a>.</p>
      </div>
    </section>

    <section class="section" id="help" aria-labelledby="help-title">
      <div class="wrap">
        <div class="section-head"><p class="eyebrow">// Help running your own relay</p><h2 id="help-title">Self-host, with a hand</h2>
          <p class="lede">The self-host guide is free. If you'd like help, we work with you on a call or by email. You keep the keys.</p></div>
        <div class="plans plans-2">
          {plan("pl-setup", "Setup help", "$199", " one-time", "for your own server", ["We help you install the relay on your server", "We review your settings", "We check that your devices connect", "If we can't get it working, you get a full refund"], "Request setup help", mailto("Self-host setup help"))}
          {plan("pl-support", "Support plan", "$1,000", " / year", "setup help included", ["Setup help", "Email support for your self-hosted relay", "Notes ahead of each relay release", "One config review a year"], "Request a support plan", mailto("Self-host support plan"))}
        </div>
      </div>
    </section>

{request_section(state)}

    <section class="section" aria-labelledby="pr-faq">
      <div class="wrap"><div class="narrow-900">
        <h2 id="pr-faq" class="faq-h">Questions about paying</h2>
        {qa("Do I need a managed relay?", "<p>No. Voidwire works fully with the free public relay or a relay you run yourself. A managed relay is for people who want a private relay without running a server.</p>", True)}
        {qa("Does paying unlock anything in the apps?", "<p>No. The apps are the same for everyone. A managed relay is only a relay.</p>")}
        {qa("What's the difference between Team and Business?", "<p>Both are a dedicated relay on its own server. Files up to 1 TB go device-to-device; how large a file the relay carries depends on your plan. Team includes 2 TB of relayed traffic a month and caps each device at 10 MB/s. Business runs on a larger server, includes 4 TB a month and has no speed cap. Devices on the same network connect directly and don't use the relay at all.</p>")}
        {qa("How do I pay, and can I cancel?", "<p>We send invoices through Stripe, monthly or yearly. Cancel anytime by emailing " + SALES + "; service continues until the end of the period you've paid for. A new managed relay can be refunded in full within 14 days. The <a href='terms.html'>terms</a> have the details.</p>")}
        {qa("Can I switch relays later?", "<p>Yes. Add the new relay in the apps, choose <strong>Make home</strong>, and move each pairing with <strong>Change relay…</strong>, confirming on both devices.</p>")}
        {qa("Do I need an account?", "<p>Not in the apps. To set up a managed relay we need an email address to reply to and, once you pay, billing details. <a href='privacy.html#requests'>What we keep</a>.</p>")}
      </div></div>
    </section>'''

page("pricing.html", "Pricing · Voidwire", "Voidwire is free. Managed relays from $79 a month, and paid help running your own relay. The public relay and self-hosting cost nothing.", pricing_body("live"))
# LATER STATE, not part of the live site: the request form, used once the /request handler exists. Files starting with _later are never deployed.
page("_later-pricing-form.html", "Pricing · Voidwire", "Later state: request form.", pricing_body("empty"), active="pricing.html", noindex=True, form_action="'self'")
page("_later-pricing-form-error.html", "Pricing · Voidwire", "Later state: request form error.", pricing_body("error"), active="pricing.html", noindex=True, form_action="'self'")

def result_page(kind):
    ok = kind == "sent"
    title = "Request sent" if ok else "Your request didn't send"
    body = (f'''<p class="lede">Thanks. We'll reply to the email address you gave. If you don't hear back, write to <a href="mailto:{SALES}">{SALES}</a>.</p>
          <p class="small muted mt-16">We use your request only to reply. <a href="privacy.html#requests">What we keep</a>. If you become a customer, our <a href="terms.html">terms</a> apply.</p>
          <div class="btn-row mt-24"><a class="btn btn-secondary vw-cut vw-cut-frame" href="managed-relays.html">About managed relays</a><a class="btn btn-secondary vw-cut vw-cut-frame" href="index.html">Home</a></div>'''
            if ok else
            f'''<p class="lede">Something went wrong on our side, and nothing was sent. Go back to try again; your browser usually keeps what you typed.</p>
          <div class="notice mt-24 vw-cut vw-cut-frame"><strong>Or email us</strong>Write to <a href="{mailto('Managed relay request')}">{SALES}</a> with the same details.</div>
          <div class="btn-row mt-24"><a class="btn btn-primary vw-cut vw-cut-frame" href="_later-pricing-form.html#request">Back to the form</a></div>''')
    html_ = f'''    <section class="page-head result" aria-labelledby="res-title">
      <div class="narrow-820 wrap">
        <div class="result-head">{icon("check" if ok else "alert", "is-ok" if ok else "is-err")}<p class="eyebrow">// {"Sent" if ok else "Not sent"}</p></div>
        <h1 id="res-title">{title}</h1>
        <div class="mt-20">{body}</div>
      </div>
    </section>'''
    page(f"_later-request-{kind}.html", f"{title} · Voidwire", title, html_, active="pricing.html", noindex=True)
result_page("sent"); result_page("error")

# ======================================================================
# TERMS (paid services only).
# ======================================================================
def tsec(tid, h, inner):
    return f'          <h2 id="{tid}">{h}</h2>\n          {inner}\n'
terms = f'''    <section class="page-head" aria-labelledby="tm-title">
      <div class="wrap">
        <p class="eyebrow">// Terms</p>
        <h1 id="tm-title">Terms for managed relays and self-host help</h1>
        <p class="lede">These cover only paid services. The Voidwire apps are free, open-source software under their own license, and you don't need to agree to anything to use them.</p>
        <p class="mt-16 small muted">Effective {P("EFFECTIVE DATE")}</p>
      </div>
    </section>

    <div class="sec-first section">
      <div class="wrap with-toc">
        <nav class="toc" aria-labelledby="toc-t"><p id="toc-t">On this page</p><ol>
          <li><a href="#who">Who we are</a></li>
          <li><a href="#buying">What you're buying</a></li>
          <li><a href="#uptime">No uptime guarantee</a></li>
          <li><a href="#seeing">What we can see</a></li>
          <li><a href="#payment">Payment and cancelling</a></li>
          <li><a href="#refunds">Refunds</a></li>
          <li><a href="#use">Acceptable use</a></li>
          <li><a href="#yours">Your responsibilities</a></li>
          <li><a href="#warranty">No warranty</a></li>
          <li><a href="#liability">Liability</a></li>
          <li><a href="#changes">Changes</a></li>
          <li><a href="#law">Governing law</a></li>
          <li><a href="#contact">Contact</a></li>
        </ol></nav>
        <div class="prose terms">
{tsec("who", "Who we are", '<p>"We" means the Voidwire project. These paid services are provided by the individual who runs the project, and that person\'s legal name appears on your invoice. These terms cover only paid services: managed relays, setup help and support plans.</p>')}
{tsec("buying", "What you're buying", '<ul class="ticks"><li><strong>Managed relay:</strong> a Voidwire relay and mailbox on a server we rent, used only by devices that have your relay link, with the limits of your plan. We keep its software updated and its certificate renewed.</li><li><strong>Setup help:</strong> we help you install and configure a relay on your own server, by call or email.</li><li><strong>Support plan:</strong> setup help, email support for your self-hosted relay, and notes ahead of relay releases, for one year.</li></ul>')}
{tsec("uptime", "Best effort, no uptime guarantee", "<p>We work to keep your relay running and to fix problems quickly, but we don't promise any level of uptime and there are no service credits. Relays can go down for maintenance, hosting provider outages, network problems or attacks. When a relay is unreachable, devices on the same network still connect directly. Don't rely on a managed relay for anything where an outage could cause harm.</p>")}
{tsec("seeing", "What we can and can't see", '<p>Your relay can\'t read what you send: links, text and files are end-to-end encrypted between your devices, and we hold no keys to them. Like any relay, it does handle metadata: the IP addresses of your devices, their public keys and which of them talk to each other, when traffic happens and roughly how much, and opaque mailbox IDs. The relay software is set to write no logs and keeps offline items in memory only. Our server setup keeps the system journal in memory and turns off the service that would copy it to log files on disk. We look at the server\'s health (is it up, how much traffic in total) to run the service and to bill extra traffic. Our hosting provider (DigitalOcean) can see network traffic to and from the server. For billing we keep your contact email, invoices and payment records, and Stripe processes payments. See the <a href="privacy.html#requests">privacy page</a> for details.</p>')}
{tsec("payment", "Payment, renewal and cancellation", f'<ul class="ticks"><li>Plans are billed monthly or yearly in advance, in US dollars, through Stripe. Monthly plans have a one-time setup fee. Extra traffic beyond your plan is billed at the listed rate, and we\'ll tell you before it\'s charged.</li><li>Plans renew until you cancel. Cancel anytime by emailing <a href="mailto:{SALES}">{SALES}</a>. Service continues until the end of the period you\'ve paid for.</li><li>When service ends, we delete the server and its access token within 7 days. We keep only invoices and payment records, for as long as tax law requires.</li><li>If you don\'t pay within 14 days of an invoice\'s due date, we may suspend the relay, and delete it after a further 14 days.</li></ul>')}
{tsec("refunds", "Refunds", "<ul class=\"ticks\"><li><strong>First 14 days:</strong> if a new managed relay doesn't work for you, tell us within 14 days of setup for a full refund, including the setup fee.</li><li><strong>After that:</strong> monthly plans aren't refunded for partial months. If you cancel a yearly plan, we refund the unused whole months.</li><li><strong>Setup help:</strong> if we can't get your relay working, we refund you in full.</li><li><strong>Support plan:</strong> if you cancel, we refund the unused whole months.</li><li>If we end a service ourselves for any reason other than a breach of these terms, we refund any unused prepaid time.</li></ul>")}
{tsec("use", "Acceptable use", "<p>Use the relay only with Voidwire apps on your own or your organization's devices. Don't use it to break the law, to send malware or abuse, to attack other systems, or to resell relay access without our agreement. Because the relay can't see content, our only tools are replacing your token or ending the service. We'll do that, with notice where we reasonably can, if we see abuse (for example traffic that harms the server or other customers) or receive a valid legal order. Keep your relay link private: anyone who has it can use your relay. If it leaks, ask us and we'll issue a new one.</p>")}
{tsec("yours", "Your responsibilities", "<p>Keep your devices and relay link secure, and keep your own copies of anything important; a relay isn't storage. For self-host help, you remain in control of, and responsible for, your own server.</p>")}
{tsec("warranty", "No warranty", '<p>Services are provided "as is" and "as available". To the extent the law allows, we disclaim all warranties, including merchantability, fitness for a particular purpose and non-infringement. The Voidwire apps and relay software are open source and come with their own license terms.</p>')}
{tsec("liability", "Limitation of liability", "<p>To the extent the law allows, we aren't liable for indirect, incidental, special or consequential damages, or for lost data, profits or business. Our total liability for any claim about these services is limited to what you paid us for them in the 12 months before the claim.</p>")}
{tsec("changes", "Changes", "<p>We may change these terms or our prices. We'll email you at least 30 days before a change affects you, and you can cancel before it takes effect.</p>")}
{tsec("law", "Governing law", f"<p>These terms are governed by the laws of Texas, USA. Disputes go to the courts there, unless the law where you live gives you other rights.</p>")}
{tsec("contact", "Contact", f'<p>Billing and service: <a href="mailto:{SALES}">{SALES}</a>. Security issues: <a href="mailto:{SECURITY}">{SECURITY}</a>.</p>')}
        </div>
      </div>
    </div>'''
page("terms.html", "Terms for paid services · Voidwire", "Terms for Voidwire managed relays, setup help and support plans. The apps themselves are free and need no agreement.", terms)

# ======================================================================
# PUBLIC RELAY RULES (free relay acceptable use).
# ======================================================================
relay_rules = f'''    <section class="page-head" aria-labelledby="pr-title">
      <div class="wrap">
        <p class="eyebrow">// Public relay</p>
        <h1 id="pr-title">Public relay rules</h1>
        <p class="lede">The public relay, <code>relay.voidwire.app</code>, is free and shared by everyone who uses Voidwire. These short rules keep it usable. They cover only the public relay; managed relays have their own <a href="terms.html">terms</a>.</p>
      </div>
    </section>

    <div class="sec-first section">
      <div class="wrap with-toc">
        <nav class="toc" aria-labelledby="toc-pr"><p id="toc-pr">On this page</p><ol>
          <li><a href="#use">Acceptable use</a></li>
          <li><a href="#enforce">What we can see and do</a></li>
          <li><a href="#effort">Free and best effort</a></li>
          <li><a href="#report">Report abuse</a></li>
        </ol></nav>
        <div class="prose terms">
{tsec("use", "Acceptable use", "<p>Use the public relay only with Voidwire apps on your own devices. Don't use it to break the law, to send malware or abuse, or to attack other systems. Don't flood it: no scripts or bots that send traffic in bulk, open connection after connection, or try to get around its limits.</p>")}
{tsec("enforce", "What we can see and do", "<p>The relay can't read what you send: links, text and files are end-to-end encrypted between your devices, and we hold no keys to them. So we don't scan content, and we can't. Like any relay, it handles metadata: IP addresses, device public keys, when traffic happens and roughly how much. It writes no logs, so we act on traffic patterns as they happen (for example a flood of connections or uploads) and on reports. If we see abuse, we may rate-limit or block the IP addresses or devices involved. The relay has no way to contact you, so this can happen without notice.</p>")}
{tsec("effort", "Free and best effort", "<p>The public relay is free and run on a best-effort basis. We don't promise any level of uptime. It can go down for maintenance, hosting provider outages, network problems or attacks. When it's unreachable, devices on the same network still connect directly. We may change its limits, or end it. If you need more, <a href=\"self-host.html\">run your own relay</a> or use a <a href=\"managed-relays.html\">managed relay</a>.</p>")}
{tsec("report", "Report abuse", f'<p>Email <a href="mailto:{SECURITY}">{SECURITY}</a> with what happened, when (with your time zone) and any IP addresses involved. Please don\'t send us material you think is illegal; we can\'t see what passes through the relay and don\'t need it to act.</p>')}
        </div>
      </div>
    </div>'''
page("public-relay.html", "Public relay rules · Voidwire", "Acceptable use for the free Voidwire public relay: what's not allowed, what we can see, and how to report abuse.", relay_rules)

# ======================================================================
# /.well-known/security.txt (RFC 9116)
# ======================================================================
(SITE / ".well-known").mkdir(exist_ok=True)
(SITE / ".well-known/security.txt").write_text(f"""Contact: mailto:{SECURITY}
Expires: 2027-11-01T06:00:00.000Z
Preferred-Languages: en
Canonical: https://voidwire.app/.well-known/security.txt
Policy: https://voidwire.app/privacy#report
""")
print("built", sorted(p.name for p in SITE.glob("*.html")), "+ .well-known/security.txt")
