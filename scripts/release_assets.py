#!/usr/bin/env python3
"""Release file names: one pattern for every user-facing download.

    scripts/release_assets.py rename [--dist dist]   # in the prerelease workflow
    scripts/release_assets.py names VERSION          # print the names
    scripts/release_assets.py name android-apk       # one name, this checkout's version
    scripts/release_assets.py --self-test

Every download a person installs is named `<APP_NAME>_<version>_<platform>`,
where <version> is the release's versionName (android/app/build.gradle.kts,
the tag without the leading "v": 0.9.8-m5.1, 1.0.0):

    Voidwire_<version>_x64-setup.exe          Windows installer
    Voidwire_<version>_amd64.deb              Linux deb
    Voidwire_<version>_amd64.AppImage         Linux AppImage
    Voidwire_<version>_android.apk            Android APK
    Voidwire_<version>_extension-chromium.zip Browser extension (Chrome, Edge, Brave)
    Voidwire_<version>_extension-firefox.zip  Browser extension (Firefox)

Operator tools keep fixed names, because docs and scripts fetch them as
releases/download/<tag>/<name> (the tag already carries the version):
voidwire-relay-docker.tar.gz, voidwire-relay-selfhost.tar.gz,
voidwire-mailbox-linux-x86_64, voidwire-sign-*, THIRD-PARTY-LICENSES.txt.

`rename` takes the files the ci run built (Tauri names the desktop bundles
after the Cargo version, which has no "-m" suffix), checks there is exactly
one of each, and renames them. update-manifest.py uses `names()` too, so the
update manifest always points at these exact files."""
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# key -> (how the ci artifact is recognised, name template)
ASSETS = {
    "windows-x86_64-nsis": (lambda n: n.endswith("-setup.exe"), "{app}_{v}_x64-setup.exe"),
    "linux-x86_64-deb": (lambda n: n.endswith(".deb"), "{app}_{v}_amd64.deb"),
    "linux-x86_64-appimage": (lambda n: n.endswith(".AppImage"), "{app}_{v}_amd64.AppImage"),
    "android-apk": (lambda n: n.endswith(".apk"), "{app}_{v}_android.apk"),
    "extension-chromium": (lambda n: n.endswith("extension-chromium.zip"), "{app}_{v}_extension-chromium.zip"),
    "extension-firefox": (lambda n: n.endswith("extension-firefox.zip"), "{app}_{v}_extension-firefox.zip"),
}
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?")


def app_name(root=ROOT):
    for line in (root / "branding.properties").read_text(encoding="utf-8").splitlines():
        k, _, v = line.partition("=")
        if k.strip() == "APP_NAME":
            return v.strip()
    sys.exit("branding.properties: APP_NAME not found")


def gradle_identity(path=ROOT / "android/app/build.gradle.kts"):
    text = pathlib.Path(path).read_text()
    code = re.search(r"^\s*versionCode = (\d+)\s*$", text, re.M)
    name = re.search(r'^\s*versionName = "([^"]+)"\s*$', text, re.M)
    if not code or not name:
        sys.exit(f"{path}: versionCode/versionName not found")
    return name.group(1), int(code.group(1))


def names(version, app=None):
    if not VERSION_RE.fullmatch(version):
        sys.exit(f"bad version {version!r}")
    app = app or app_name()
    return {k: tpl.format(app=app, v=version) for k, (_, tpl) in ASSETS.items()}


def rename(dist, version, app=None):
    dist = pathlib.Path(dist)
    want = names(version, app)
    present = sorted(p.name for p in dist.iterdir() if p.is_file())
    plan = []
    for key, (match, _) in ASSETS.items():
        found = [n for n in present if match(n)]
        if len(found) != 1:
            sys.exit(f"{key}: expected one file in {dist}, found {found}")
        plan.append((found[0], want[key]))
    for old, new in plan:
        if old != new:
            (dist / old).rename(dist / new)
        print(f"{old} -> {new}")
    return want


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d)
        for n in ["Voidwire_1.0.0_x64-setup.exe", "Voidwire_1.0.0_amd64.deb", "Voidwire_1.0.0_amd64.AppImage",
                  "voidwire-android-m1.apk", "voidwire-extension-chromium.zip", "voidwire-extension-firefox.zip",
                  "voidwire-relay-docker.tar.gz", "voidwire-sign-linux-x86_64"]:
            (p / n).write_bytes(b"x")
        rename(d, "1.0.1-rc1", "Voidwire")
        got = sorted(x.name for x in p.iterdir())
        assert got == sorted(["Voidwire_1.0.1-rc1_x64-setup.exe", "Voidwire_1.0.1-rc1_amd64.deb",
                              "Voidwire_1.0.1-rc1_amd64.AppImage", "Voidwire_1.0.1-rc1_android.apk",
                              "Voidwire_1.0.1-rc1_extension-chromium.zip", "Voidwire_1.0.1-rc1_extension-firefox.zip",
                              "voidwire-relay-docker.tar.gz", "voidwire-sign-linux-x86_64"]), got
        rename(d, "1.0.1-rc1", "Voidwire")  # idempotent
        (p / "second.apk").write_bytes(b"y")
        try:
            rename(d, "1.0.1-rc1", "Voidwire")
            raise AssertionError("accepted two APKs")
        except SystemExit:
            pass
    for bad in ["v1.0.0", "1.0", "1.0.0/../x", "1.0.0 rc"]:
        try:
            names(bad, "Voidwire")
            raise AssertionError(f"accepted {bad}")
        except SystemExit:
            pass
    assert names("0.9.8-m5.1", "Voidwire")["android-apk"] == "Voidwire_0.9.8-m5.1_android.apk"
    print("release-assets self-test: ok")


def main():
    a = sys.argv[1:]
    if a == ["--self-test"]:
        return self_test()
    if a[:1] == ["names"] and len(a) == 2:
        for n in names(a[1]).values():
            print(n)
        return
    if a[:1] == ["name"] and len(a) == 2 and a[1] in ASSETS:
        print(names(gradle_identity()[0])[a[1]])
        return
    if a[:1] == ["rename"]:
        dist = a[a.index("--dist") + 1] if "--dist" in a else "dist"
        version, _ = gradle_identity()
        rename(dist, version)
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main()
