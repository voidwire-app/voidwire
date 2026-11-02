#!/usr/bin/env python3
"""Build the deployable voidwire.app site into dist/site/.

    python3 build.py                 # latest stable GitHub release (preview fallback)
    python3 build.py --tag v1.0.0    # a specific release
    python3 build.py --keep-verify   # keep the amber [VERIFY] chips visible
    python3 build.py --assume-stable # launch look from a pre-release (local testing only)

Steps:
 1. Pick the release of voidwire-app/voidwire (GitHub API, no login needed;
    set GITHUB_TOKEN to raise the rate limit):
      - the newest non-draft release GitHub does not mark as pre-release;
      - else the newest release whose tag is plain vX.Y.Z but is marked
        pre-release (the release workflow publishes plain tags as full
        releases, so this only happens if someone ticked the box by hand),
        with a warning;
      - else PREVIEW: the newest pre-release. Every page then gets a visible
        "preview build" banner and noindex, and the [VERIFY] chips stay.
 2. Read its SHA256SUMS asset and find each download by the same rules the
    release scripts use (scripts/release_assets.py): *-setup.exe, *.apk, *.deb,
    *.AppImage, *extension-chromium.zip, *extension-firefox.zip. Releases use
    Voidwire_<version>_<platform> names; older releases (up to v0.9.8-m5.1,
    voidwire-android-m1.apk) still match. Exactly one of each, or the build fails.
 3. Run src/tools/build_site.py (the design's generator, vendored) in a temp
    dir with [TAG], [VERSION], [RELEASE DATE], [SHA256] and [EFFECTIVE DATE]
    filled. [GOVERNING STATE] stays as a visible [TODO: GOVERNING STATE].
 4. security.txt: Expires = build time + 364 days (RFC 9116: under a year).
 5. Copy pages + assets to dist/site/, leaving out _later-*, _preview* and any
    other file starting with "_".
 6. Checks (fail the build): no unfilled placeholder except the listed TODOs,
    no external resource loads, external links only to the allowlist below,
    no internal link to a missing file, no personal details.
 7. Writes dist/BUILD-REPORT.md (not served) and dist/release.json.

Only the Python standard library is used."""
import argparse, datetime as dt, html, json, os, pathlib, re, shutil, subprocess, sys, tempfile, urllib.request

HERE = pathlib.Path(__file__).resolve().parent   # website/
SRC = HERE / "src"
DIST = HERE / "dist"
OUT = DIST / "site"
REPO = os.environ.get("VOIDWIRE_REPO", "voidwire-app/voidwire")
API = f"https://api.github.com/repos/{REPO}"
TZ = os.environ.get("SITE_TZ", "America/Chicago")   # dates shown on the site

# How each download is recognised in SHA256SUMS (same rules as release_assets.py).
KINDS = {
    "win": lambda n: n.endswith("-setup.exe"),
    "apk": lambda n: n.endswith(".apk"),
    "deb": lambda n: n.endswith(".deb"),
    "appimage": lambda n: n.endswith(".AppImage"),
    "crx": lambda n: n.endswith("extension-chromium.zip"),
    "xpi": lambda n: n.endswith("extension-firefox.zip"),
}
# Hyperlinks (not loads) allowed to leave the site.
LINK_ALLOW = [
    re.compile(r"^https://github\.com/voidwire-app/voidwire(/.*)?$"),
    re.compile(r"^https://www\.cloudflare\.com/privacypolicy/$"),
]
ALLOWED_EMAILS = {"security@voidwire.app", "sales@voidwire.app"}
# Personal details must never ship. The generic patterns live here; the
# owner's own names, domains and hostnames come from REPO_DENYLIST (comma-
# separated, case-insensitive regexes; the same GitHub Actions secret as
# scripts/leak-guard.py) so they are not in the repo. A hit never prints the
# denylisted pattern.
GENERIC = [r"fill-in\.md", r"\bfill-in\b"]
DENY = [x.strip() for x in os.environ.get("REPO_DENYLIST", "").split(",") if x.strip()]
TODO_OK = {"GOVERNING STATE"}


def gh(url, raw=False):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "voidwire-website-build"})
    if os.environ.get("GITHUB_TOKEN"):
        req.add_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    if raw:
        req.add_header("Accept", "application/octet-stream")
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    return data if raw else json.loads(data)


def pick_release(tag):
    if tag:
        r = gh(f"{API}/releases/tags/{tag}")
        stable = not r["prerelease"] or bool(re.fullmatch(r"v\d+\.\d+\.\d+", r["tag_name"]))
        return r, ("stable" if stable else "preview"), []
    rels = [r for r in gh(f"{API}/releases?per_page=100") if not r["draft"]]
    rels.sort(key=lambda r: r["published_at"] or "", reverse=True)
    warn = []
    for r in rels:
        if not r["prerelease"]:
            return r, "stable", warn
    for r in rels:
        if re.fullmatch(r"v\d+\.\d+\.\d+", r["tag_name"]):
            warn.append(f"{r['tag_name']} is a plain vX.Y.Z tag but GitHub marks it pre-release "
                        "(the release workflow publishes plain tags as full releases, so it was changed "
                        "by hand or published before that fix). Used as stable; untick 'Set as a "
                        "pre-release' on the release page so it is the official latest.")
            return r, "stable", warn
    if not rels:
        sys.exit("no releases found")
    warn.append(f"No stable release exists. PREVIEW build from pre-release {rels[0]['tag_name']}: do not publish.")
    return rels[0], "preview", warn


def tzinfo():
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(TZ)
    except Exception:
        return dt.timezone.utc


def fmt_date(d):
    return f"{d:%B} {d.day}, {d.year}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tag", help="use this release tag instead of the latest")
    ap.add_argument("--assume-stable", action="store_true",
                    help="local preview of the launch look from a pre-release: no banner, chips removed. "
                         "release.json says mode=assumed-stable and the workflow never publishes it")
    ap.add_argument("--keep-verify", action="store_true", help="keep [VERIFY] chips visible (always on for preview)")
    a = ap.parse_args()

    rel, mode, warnings = pick_release(a.tag)
    if a.assume_stable and mode == "preview":
        mode = "assumed-stable"
        warnings = [f"--assume-stable: {rel['tag_name']} is a pre-release built with the launch look. Local testing only."]
    tag = rel["tag_name"]
    version = tag[1:] if tag.startswith("v") else tag
    assets = {x["name"]: x for x in rel["assets"]}
    if "SHA256SUMS" not in assets:
        sys.exit(f"{tag}: no SHA256SUMS asset")
    sums = {}
    for line in gh(assets["SHA256SUMS"]["url"], raw=True).decode().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(\S.*)", line.strip())
        if m:
            sums[m.group(2)] = m.group(1)
    files = {}
    for key, match in KINDS.items():
        found = [n for n in sums if match(n)]
        if len(found) != 1:
            sys.exit(f"{tag}: expected one {key} file in SHA256SUMS, found {found}")
        if found[0] not in assets:
            sys.exit(f"{tag}: {found[0]} is in SHA256SUMS but not attached to the release")
        files[key] = found[0]

    tz = tzinfo()
    now = dt.datetime.now(dt.timezone.utc)
    published = dt.datetime.fromisoformat(rel["published_at"].replace("Z", "+00:00")).astimezone(tz)
    expires = (now + dt.timedelta(days=364)).replace(hour=0, minute=0, second=0, microsecond=0)
    preview = mode == "preview"
    strip_verify = not (preview or a.keep_verify)
    cfg = {
        "tag": tag, "files": files, "strip_verify": strip_verify,
        "values": {"TAG": tag, "VERSION": version, "RELEASE DATE": fmt_date(published),
                   "EFFECTIVE DATE": fmt_date(now.astimezone(tz))},
    }

    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        shutil.copytree(SRC / "site" / "assets", tmp / "site" / "assets")
        (tmp / "tools").mkdir()
        shutil.copy(SRC / "tools" / "voidwire-mark.svg", tmp / "tools")
        code = (SRC / "tools" / "build_site.py").read_text()
        anchor = re.search(r"def fname_html\(f\):\n    return [^\n]*\n", code)
        if not anchor:
            sys.exit("build_site.py changed: fname_html anchor not found; update build.py")
        code = code[:anchor.end()] + OVERRIDE + code[anchor.end():] + EPILOGUE
        (tmp / "tools" / "build_site.py").write_text(code)
        (tmp / "cfg.json").write_text(json.dumps(cfg))
        subprocess.run([sys.executable, str(tmp / "tools" / "build_site.py")], check=True,
                       env={**os.environ, "VW_DEPLOY_CFG": str(tmp / "cfg.json"), "PYTHONDONTWRITEBYTECODE": "1"})
        meta = json.loads((tmp / "meta.json").read_text())

        if OUT.exists():
            shutil.rmtree(OUT)
        OUT.mkdir(parents=True)
        site = tmp / "site"
        for p in sorted(site.rglob("*")):
            rel_p = p.relative_to(site)
            if any(part.startswith("_") or part.startswith("preview") for part in rel_p.parts):
                continue
            dest = OUT / rel_p
            if p.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dest)

    # Post-process pages.
    for page in OUT.glob("*.html"):
        s = page.read_text()
        # One SHA-256 per artifact block, taken from the file its Download button links to.
        def fill(m):
            block = m.group(0)
            name = re.search(r'href="[^"]*/releases/download/[^/"]+/([^"]+)"', block).group(1)
            name = urllib.request.unquote(html.unescape(name))
            assert block.count("@@SHA256@@") == 1, block
            return block.replace("@@SHA256@@", sums[name])
        s = re.sub(r'<div class="artifact">.*?</dl>', fill, s, flags=re.S)
        # Example commands spell the standard names (Voidwire_<version>_...);
        # point them at the release's real files (older releases differ).
        for key, suffix in [("win", "x64-setup.exe"), ("apk", "android.apk"),
                            ("crx", "extension-chromium.zip"), ("xpi", "extension-firefox.zip"),
                            ("deb", "amd64.deb"), ("appimage", "amd64.AppImage")]:
            s = s.replace(f"Voidwire_{version}_{suffix}", files[key])
        s = s.replace("/releases/download/TAG/", f"/releases/download/{tag}/")
        s = s.replace(f"replace TAG with {tag}", f"release {tag}")
        if preview:
            s = s.replace("<head>\n", '<head>\n  <meta name="robots" content="noindex">\n', 1) if 'name="robots"' not in s else s
            s = s.replace('<main id="main" tabindex="-1">',
                          '<main id="main" tabindex="-1">\n    <div class="wrap"><p class="verify">PREVIEW BUILD from pre-release '
                          f'{html.escape(tag)}. Not a stable release. Do not publish.</p></div>', 1)
        if page.name == "404.html":
            # Served at any depth, so every local URL must be root-relative.
            s = re.sub(r'(href|src)="(?!https?:|mailto:|#|/)', r'\1="/', s)
        page.write_text(s)

    sec = OUT / ".well-known" / "security.txt"
    t = sec.read_text()
    t = "\n".join(l for l in t.splitlines() if not l.startswith("# [VERIFY]")) + "\n"
    t = re.sub(r"^Expires: .*$", f"Expires: {expires:%Y-%m-%dT%H:%M:%S.000Z}", t, flags=re.M)
    sec.write_text(t)

    if not DENY:
        warnings.append("REPO_DENYLIST is not set: only generic personal-detail checks ran.")
    problems = check(preview or a.keep_verify)
    report(rel, mode, warnings, files, sums, meta, expires, problems, strip_verify)
    (DIST / "release.json").write_text(json.dumps({"tag": tag, "version": version, "mode": mode,
        "published_at": rel["published_at"], "files": files, "built_at": now.isoformat()}, indent=2) + "\n")
    for w in warnings:
        print("WARNING:", w, file=sys.stderr)
    if problems:
        print("\n".join("FAIL: " + p for p in problems), file=sys.stderr)
        sys.exit(1)
    print(f"built dist/site from {tag} ({mode}); report: dist/BUILD-REPORT.md")


def check(allow_verify):
    problems = []
    files = [p for p in OUT.rglob("*") if p.is_file()]
    names = {p.relative_to(OUT).as_posix() for p in files}
    for p in files:
        rel = p.relative_to(OUT).as_posix()
        if p.suffix == ".woff2":
            continue
        s = p.read_text(errors="replace")
        low = s.lower()
        for pat in GENERIC:
            if re.search(pat, low):
                problems.append(f"{rel}: personal detail /{pat}/")
        for i, pat in enumerate(DENY):
            try:
                found = re.search(pat, s, re.I)
            except re.error:
                problems.append(f"REPO_DENYLIST entry #{i + 1} is not a valid regex")
                continue
            for n, line in enumerate(s.splitlines(), 1) if found else ():
                if re.search(pat, line, re.I):
                    problems.append(f"{rel}:{n}: denylisted text (pattern not shown)")
        for ip in re.findall(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])", s):
            problems.append(f"{rel}: IP-like string {ip}")
        for em in set(re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", s)):
            if em.lower() not in ALLOWED_EMAILS and not re.search(r"@example\.(com|org|net)$", em.lower()) and not em.lower().endswith(".woff2"):
                problems.append(f"{rel}: unexpected email {em}")
        if p.suffix not in (".html", ".css", ".js", ".txt", ".svg"):
            continue
        if p.suffix in (".html", ".css", ".js", ".svg"):
            for u in re.findall(r"""(?:src|srcset|action|poster|data)\s*=\s*["']\s*((?:https?:)?//[^"']+)""", s):
                problems.append(f"{rel}: external load {u}")
            for u in re.findall(r"""url\(\s*["']?((?:https?:)?//[^)"']+)""", s) + re.findall(r"""@import\s+["']((?:https?:)?//[^"']+)""", s):
                problems.append(f"{rel}: external load {u}")
            for u in re.findall(r'<link[^>]+href="((?:https?:)?//[^"]+)"', s):
                problems.append(f"{rel}: external <link> {u}")
        if p.suffix == ".html":
            if "@@SHA256@@" in s:
                problems.append(f"{rel}: SHA256 not filled")
            for ph in re.findall(r'class="ph">\[([^\]]+)\]', s):
                if ph.replace("TODO: ", "") not in TODO_OK:
                    problems.append(f"{rel}: placeholder [{ph}] left")
            if re.search(r"\[(TAG|VERSION|RELEASE DATE|SHA256|EFFECTIVE DATE)\]", s):
                problems.append(f"{rel}: raw placeholder left")
            if not allow_verify and 'class="verify"' in s:
                problems.append(f"{rel}: [VERIFY] chip left")
            for href in re.findall(r'href="([^"]+)"', s):
                href = html.unescape(href)
                if href.startswith(("mailto:", "#")):
                    if href.startswith("mailto:") and href[7:].split("?")[0].lower() not in ALLOWED_EMAILS:
                        problems.append(f"{rel}: mailto to {href}")
                    continue
                if re.match(r"^(https?:)?//", href):
                    if not any(r.match(href.split("#")[0]) for r in LINK_ALLOW):
                        problems.append(f"{rel}: external link not allowed {href}")
                    continue
                target = href.split("#")[0].split("?")[0]
                if not target:
                    continue
                path = (OUT / target.lstrip("/")).resolve() if target.startswith("/") else (p.parent / target).resolve()
                try:
                    tr = path.relative_to(OUT.resolve()).as_posix()
                except ValueError:
                    problems.append(f"{rel}: link escapes site {href}"); continue
                if tr == "." or tr == "":
                    tr = "index.html"
                if tr not in names and f"{tr}.html" not in names and f"{tr}/index.html" not in names:
                    problems.append(f"{rel}: broken internal link {href}")
    return problems


def report(rel, mode, warnings, files, sums, meta, expires, problems, strip_verify):
    L = [f"# Build report ({dt.datetime.now(tzinfo()):%Y-%m-%d %H:%M %Z})", "",
         f"- Release: `{rel['tag_name']}` ({mode}), published {rel['published_at']}",
         f"- Page: {rel['html_url']}",
         f"- security.txt Expires: {expires:%Y-%m-%dT%H:%M:%SZ} (renew before then: rebuild and redeploy)", ""]
    if warnings:
        L += ["## Warnings", ""] + [f"- {w}" for w in warnings] + [""]
    L += ["## Downloads", "", "| kind | file | SHA-256 |", "|---|---|---|"]
    L += [f"| {k} | `{n}` | `{sums[n]}` |" for k, n in files.items()]
    L += ["", "## Left visible (TODO before publishing)", ""]
    L += [f"- [TODO: {n}]" for n in sorted(set(meta["left"]))] or ["- none"]
    L += ["", "## [VERIFY] claims " + ("removed from the pages; confirm each is true before launch" if strip_verify else "kept visible on the pages"), ""]
    L += [f"- {v}" for v in dict.fromkeys(meta["verifies"])] or ["- none"]
    L += ["", "## Checks", ""] + ([f"- FAIL: {p}" for p in problems] or ["- all passed"])
    (DIST / "BUILD-REPORT.md").write_text("\n".join(L) + "\n")


# Injected into build_site.py after fname_html(): real values instead of placeholders.
OVERRIDE = r'''
# ---- voidwire-website-deploy overrides ----
import json as _json, os as _os
_CFG = _json.loads(open(_os.environ["VW_DEPLOY_CFG"]).read())
REL = f"{GH}/releases/download/{_CFG['tag']}"
_LEFT, _VERIFIES = [], []
def P(name):
    if name == "SHA256":
        return "@@SHA256@@"
    if name in _CFG["values"]:
        return html.escape(_CFG["values"][name])
    _LEFT.append(name)
    return f'<span class="ph">[TODO: {html.escape(name)}]</span>'
def V(text):
    _VERIFIES.append(text)
    return "" if _CFG["strip_verify"] else f'<span class="verify">[VERIFY: {html.escape(text)}]</span>'
VER = P("VERSION")
FILES = dict(_CFG["files"])
def fname_html(f):
    return html.escape(f)
# ---- end overrides ----
'''

EPILOGUE = r'''
# ---- voidwire-website-deploy: 404 page + metadata ----
page("404.html", "Page not found · Voidwire", "This page doesn't exist.", """    <section class="page-head" aria-labelledby="nf-title">
      <div class="wrap">
        <p class="eyebrow">// 404</p>
        <h1 id="nf-title">Page not found</h1>
        <p class="lede">There's nothing at this address. It may have moved, or the link may be mistyped.</p>
        <div class="btn-row mt-24"><a class="btn btn-primary vw-cut vw-cut-frame" href="/">Go to the home page</a> <a class="btn btn-secondary vw-cut vw-cut-frame" href="/download.html">Download Voidwire</a></div>
      </div>
    </section>""", noindex=True)
(ROOT / "meta.json").write_text(_json.dumps({"left": _LEFT, "verifies": _VERIFIES}))
'''

if __name__ == "__main__":
    main()
