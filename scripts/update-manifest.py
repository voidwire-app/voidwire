#!/usr/bin/env python3
"""Write the update channel manifest for a release (U1, docs/UPDATES.md).

    scripts/update-manifest.py --channel test --tag v0.9.8-m4.7 \
        --dist dist --repo voidwire-app/voidwire --out site/update/v1/test.json

Takes the version and build number (versionCode) from
android/app/build.gradle.kts, the hashes from dist/SHA256SUMS (the same file
published with the release) and the sizes from dist/. `seq` is the current
Unix time, so it only grows. The output is signed separately
(`voidwire-sign sign`); nothing here holds a key.

`--self-test` checks the file matching and the output shape."""
import argparse, json, pathlib, re, sys, time, urllib.parse

KINDS = [
    ("windows-x86_64-nsis", lambda n: n.endswith("-setup.exe")),
    ("android-apk", lambda n: n.endswith(".apk")),
    ("linux-x86_64-appimage", lambda n: n.endswith(".AppImage")),
    ("linux-x86_64-deb", lambda n: n.endswith(".deb")),
]


def gradle_identity(path):
    text = pathlib.Path(path).read_text()
    code = re.search(r"^\s*versionCode = (\d+)\s*$", text, re.M)
    name = re.search(r'^\s*versionName = "([^"]+)"\s*$', text, re.M)
    if not code or not name:
        sys.exit(f"{path}: versionCode/versionName not found")
    return name.group(1), int(code.group(1))


def sums(dist):
    out = {}
    for line in (pathlib.Path(dist) / "SHA256SUMS").read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(.+)", line.strip())
        if m:
            out[m.group(2)] = m.group(1)
    return out


def build(channel, tag, version, build_no, dist, repo, seq, released):
    if channel not in ("test", "stable"):
        sys.exit(f"unknown channel {channel}")
    if channel == "stable" and "-" in version:
        sys.exit(f"{version} is a pre-release; it can't go on the stable channel")
    if tag != f"v{version}":
        sys.exit(f"tag {tag} does not match versionName {version}")
    hashes = sums(dist)
    files = {}
    for key, match in KINDS:
        names = sorted(n for n in hashes if match(n))
        if len(names) != 1:
            sys.exit(f"{key}: expected one file in SHA256SUMS, found {names}")
        name = names[0]
        size = (pathlib.Path(dist) / name).stat().st_size
        url = f"https://github.com/{repo}/releases/download/{urllib.parse.quote(tag)}/{urllib.parse.quote(name)}"
        files[key] = {"url": url, "sha256": hashes[name], "size": size}
    return {
        "schema": 1,
        "channel": channel,
        "seq": seq,
        "version": version,
        "build": build_no,
        "released": released,
        "notes_url": f"https://github.com/{repo}/releases/tag/{urllib.parse.quote(tag)}",
        "files": files,
    }


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d)
        names = ["Voidwire_1.0.0_x64-setup.exe", "voidwire-1.0.0.apk", "Voidwire_1.0.0_amd64.AppImage",
                 "voidwire_1.0.0_amd64.deb", "THIRD-PARTY-LICENSES.txt"]
        lines = []
        for i, n in enumerate(names):
            (p / n).write_bytes(b"x" * (i + 1))
            lines.append(f"{str(i) * 64}  {n}")
        (p / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        m = build("stable", "v1.0.0", "1.0.0", 40, d, "o/r", 5, "2026-11-02")
        assert m["files"]["android-apk"] == {
            "url": "https://github.com/o/r/releases/download/v1.0.0/voidwire-1.0.0.apk",
            "sha256": "1" * 64, "size": 2}, m
        assert set(m["files"]) == {k for k, _ in KINDS}
        assert m["notes_url"] == "https://github.com/o/r/releases/tag/v1.0.0"
        for bad in [("stable", "v1.0.0-rc1", "1.0.0-rc1"), ("test", "v1.0.1", "1.0.0")]:
            try:
                build(bad[0], bad[1], bad[2], 40, d, "o/r", 5, "x")
            except SystemExit:
                continue
            raise AssertionError(f"accepted {bad}")
        (p / "two.apk").write_bytes(b"y")
        (p / "SHA256SUMS").write_text("\n".join(lines + [f"{'f' * 64}  two.apk"]) + "\n")
        try:
            build("test", "v1.0.0", "1.0.0", 40, d, "o/r", 5, "x")
            raise AssertionError("accepted two APKs")
        except SystemExit:
            pass
    print("update-manifest self-test: ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    ap = argparse.ArgumentParser()
    ap.add_argument("--channel", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--gradle", default="android/app/build.gradle.kts")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    version, build_no = gradle_identity(a.gradle)
    m = build(a.channel, a.tag, version, build_no, a.dist, a.repo, int(time.time()),
              time.strftime("%Y-%m-%d", time.gmtime()))
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(m, indent=2) + "\n")
    print(f"wrote {out}: {a.channel} {version} build {build_no} seq {m['seq']}")


if __name__ == "__main__":
    main()
