#!/usr/bin/env python3
"""Write the update channel manifest for a release (U1, docs/UPDATES.md).

    scripts/update-manifest.py --channel test --tag v0.9.8-m4.7 \
        --dist dist --repo voidwire-app/voidwire --out site/update/v1/test.json

Takes the version and build number (versionCode) from
android/app/build.gradle.kts, the hashes from dist/SHA256SUMS (the same file
published with the release) and the sizes from dist/. Each entry points at the
exact file name from scripts/release_assets.py (Voidwire_<version>_...), so a
renamed or missing download fails here instead of shipping a broken link. `seq` is the current
Unix time, so it only grows. The output is signed separately
(`voidwire-sign sign`); nothing here holds a key.

`--self-test` checks the file matching and the output shape."""
import argparse, json, pathlib, re, sys, time, urllib.parse

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from release_assets import gradle_identity, names as asset_names  # noqa: E402

# The platforms the updater installs (core/src/update/manifest.rs).
# "macos" points at the disk image: the app opens the release page for it
# (docs/UPDATES.md); an in-app swap is M5.3.
KINDS = ["windows-x86_64-nsis", "android-apk", "linux-x86_64-appimage", "linux-x86_64-deb", "macos"]


def sums(dist):
    out = {}
    for line in (pathlib.Path(dist) / "SHA256SUMS").read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(.+)", line.strip())
        if m:
            out[m.group(2)] = m.group(1)
    return out


def build(channel, tag, version, build_no, dist, repo, seq, released, app=None):
    if channel not in ("test", "stable"):
        sys.exit(f"unknown channel {channel}")
    if channel == "stable" and "-" in version:
        sys.exit(f"{version} is a pre-release; it can't go on the stable channel")
    if tag != f"v{version}":
        sys.exit(f"tag {tag} does not match versionName {version}")
    hashes = sums(dist)
    want = asset_names(version, app)
    files = {}
    for key in KINDS:
        name = want[key]
        if name not in hashes:
            sys.exit(f"{key}: {name} is not in SHA256SUMS")
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
        names = ["Voidwire_1.0.0_x64-setup.exe", "Voidwire_1.0.0_android.apk", "Voidwire_1.0.0_amd64.AppImage",
                 "Voidwire_1.0.0_amd64.deb", "THIRD-PARTY-LICENSES.txt", "Voidwire_1.0.0_universal.dmg"]
        lines = []
        for i, n in enumerate(names):
            (p / n).write_bytes(b"x" * (i + 1))
            lines.append(f"{str(i) * 64}  {n}")
        (p / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        m = build("stable", "v1.0.0", "1.0.0", 40, d, "o/r", 5, "2026-11-02", "Voidwire")
        assert m["files"]["android-apk"] == {
            "url": "https://github.com/o/r/releases/download/v1.0.0/Voidwire_1.0.0_android.apk",
            "sha256": "1" * 64, "size": 2}, m
        assert set(m["files"]) == set(KINDS)
        assert m["notes_url"] == "https://github.com/o/r/releases/tag/v1.0.0"
        for bad in [("stable", "v1.0.0-rc1", "1.0.0-rc1"), ("test", "v1.0.1", "1.0.0")]:
            try:
                build(bad[0], bad[1], bad[2], 40, d, "o/r", 5, "x", "Voidwire")
            except SystemExit:
                continue
            raise AssertionError(f"accepted {bad}")
        # an old-style name (the APK as voidwire-android-m1.apk) is refused
        (p / "SHA256SUMS").write_text("\n".join(lines[:1] + [f"{'1' * 64}  voidwire-android-m1.apk"] + lines[2:]) + "\n")
        try:
            build("test", "v1.0.0", "1.0.0", 40, d, "o/r", 5, "x", "Voidwire")
            raise AssertionError("accepted an unversioned APK name")
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
