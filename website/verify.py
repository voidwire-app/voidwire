#!/usr/bin/env python3
"""Check a running voidwire.app container from the outside.

    python3 verify.py http://127.0.0.1:8080 [--container NAME] [--downloads]

- every page in dist/site (and its clean URL) returns 200; / and security.txt too
- the security headers are exact, and no response has Set-Cookie
- unknown paths, _later-* and dotfiles return the 404 page; POST returns 405
- caching: pages revalidate, assets are cacheable
- every internal link and asset on every page resolves (200)
- external URLs in served pages: only GitHub (voidwire-app/voidwire) and the
  Cloudflare privacy policy; no external loads at all
- --downloads: every GitHub release download link answers (redirect or 200)
- stable builds (dist/release.json mode "stable"): no page carries a
  [VERIFY] chip or marker
- --container: `docker logs` of the container is empty after all requests
  (no access log, no error output)
Exit 1 on any failure. Standard library only."""
import argparse, html, json, pathlib, re, subprocess, sys, urllib.error, urllib.parse, urllib.request

HERE = pathlib.Path(__file__).resolve().parent
SITE = HERE / "dist" / "site"
CSP = ("default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; script-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
HEADERS = {
    "content-security-policy": CSP,
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
}
EXT_ALLOW = [re.compile(r"^https://github\.com/voidwire-app/voidwire(/.*)?$"),
             re.compile(r"^https://www\.cloudflare\.com/privacypolicy/$")]

fails, checks = [], 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


opener = urllib.request.build_opener(NoRedirect)


def req(url, method="GET"):
    r = urllib.request.Request(url, method=method, headers={"User-Agent": "voidwire-verify"})
    try:
        resp = opener.open(r, timeout=20)
    except urllib.error.HTTPError as e:
        resp = e
    body = resp.read() if method != "HEAD" else b""
    return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.headers.get_all("Set-Cookie") or [], body


def ok(cond, msg):
    global checks
    checks += 1
    if not cond:
        fails.append(msg)


def get(base, path, want=200, method="GET"):
    st, h, cookies, body = req(base + path, method)
    ok(st == want, f"{method} {path}: {st}, want {want}")
    ok(not cookies, f"{path}: Set-Cookie {cookies}")
    for k, v in HEADERS.items():
        ok(h.get(k) == v, f"{path}: header {k} = {h.get(k)!r}")
    ok("permissions-policy" in h and "camera=()" in h["permissions-policy"], f"{path}: Permissions-Policy missing")
    ok("server" not in h or "/" not in h["server"], f"{path}: Server header shows a version: {h.get('server')}")
    return st, h, body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--container")
    ap.add_argument("--downloads", action="store_true")
    a = ap.parse_args()
    base = a.base.rstrip("/")

    stable = json.loads((HERE / "dist" / "release.json").read_text()).get("mode") == "stable"
    pages = sorted(p.name for p in SITE.glob("*.html") if p.name != "404.html")
    ok(len(pages) >= 8, f"only {len(pages)} pages in dist/site")
    seen_ext, links = set(), set()
    for name in pages:
        st, h, body = get(base, "/" + name)
        ok(h.get("cache-control") == "no-cache", f"/{name}: Cache-Control {h.get('cache-control')!r}")
        ok(h.get("content-type", "").startswith("text/html"), f"/{name}: Content-Type {h.get('content-type')}")
        if name != "index.html":
            get(base, "/" + name[:-5])
        s = body.decode()
        ok(not re.search(r"\[(TAG|VERSION|RELEASE DATE|SHA256|EFFECTIVE DATE)\]", s), f"/{name}: unfilled placeholder")
        if stable:
            ok('class="verify"' not in s and "[VERIFY" not in s.upper(), f"/{name}: [VERIFY] chip or marker in a stable build")
        for attr, u in re.findall(r'\b(href|src|srcset|action)="([^"]+)"', s):
            u = html.unescape(u)
            if re.match(r"^(https?:)?//", u):
                ok(attr == "href", f"/{name}: external load {attr}={u}")
                ok(any(r.match(u.split("#")[0]) for r in EXT_ALLOW), f"/{name}: external URL not allowed {u}")
                seen_ext.add(u)
            elif not u.startswith(("mailto:", "#", "data:")):
                links.add(urllib.parse.urljoin("/" + name, u).split("#")[0])
        for u in re.findall(r"https?://[^\s\"'<>)]+", re.sub(r'xmlns="http://www\.w3\.org/2000/svg"', "", s)):
            ok(any(r.match(u.rstrip(".,")) for r in EXT_ALLOW) or u.startswith("https://voidwire.app"),
               f"/{name}: external URL in text {u}")
    for css in SITE.glob("assets/**/*.css"):
        ok(not re.search(r"url\(\s*['\"]?(https?:)?//|@import\s+['\"]?(https?:)?//", css.read_text()), f"{css.name}: external load")

    get(base, "/")
    st, h, body = get(base, "/.well-known/security.txt")
    t = body.decode()
    ok(h.get("content-type", "").startswith("text/plain"), f"security.txt Content-Type {h.get('content-type')}")
    ok("Contact: mailto:security@voidwire.app" in t and re.search(r"^Expires: \d{4}-\d\d-\d\dT", t, re.M) and "VERIFY" not in t,
       "security.txt content")
    for path in sorted(links):
        st, h, _ = get(base, path)
        if path.startswith("/assets/"):
            ok(h.get("cache-control", "").startswith("public, max-age="), f"{path}: Cache-Control {h.get('cache-control')!r}")
    for path in ["/nope", "/nope/deeper/x.html", "/_later-pricing-form.html", "/_later-request-sent", "/.git/config",
                 "/.env", "/BUILD-REPORT.md", "/FILL-IN.md"]:
        st, h, body = get(base, path, 404)
        ok(b"Page not found" in body and b'href="/assets/css/site.css"' in body, f"{path}: not the 404 page")
    get(base, "/index.html", 405, "POST")
    get(base, "/index.html", 200, "HEAD")

    if a.downloads:
        for u in sorted(x for x in seen_ext if "/releases/download/" in x):
            st, _, _, _ = req(u, "HEAD")
            ok(st in (200, 302), f"download {u}: {st}")

    if a.container:
        out = subprocess.run(["docker", "logs", a.container], capture_output=True, text=True)
        ok(out.returncode == 0, f"docker logs failed: {out.stderr}")
        ok(out.stdout == "" and out.stderr == "", f"container logged output:\n{out.stdout}{out.stderr}")

    print(f"{checks} checks, {len(fails)} failed; {len(pages)} pages, {len(links)} internal URLs, "
          f"{len(seen_ext)} external links ({sum('/releases/download/' in x for x in seen_ext)} downloads)")
    for f in fails:
        print("FAIL:", f)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
