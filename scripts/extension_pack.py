#!/usr/bin/env python3
"""Package the Voidwire browser extension, byte-for-byte reproducibly.

    python3 scripts/extension_pack.py release OUT_DIR
        voidwire-extension-chromium.zip  (keeps "key": sideload ID matches the desktop host)
        voidwire-extension-firefox.zip
    python3 scripts/extension_pack.py stores OUT_DIR
        voidwire-extension-<v>-chromium-store.zip  Chrome Web Store and Edge Add-ons ("key" removed:
                                                   a new store item may not carry one)
        voidwire-extension-<v>-firefox-amo.zip     addons.mozilla.org (same bytes as the release zip)
        voidwire-extension-<v>-amo-source.zip      source for AMO review (see extension/STORE-BUILD.md)
        SHA256SUMS

Zips are reproducible: fixed file order, fixed timestamps (1980-01-01), fixed
permissions, deflate level 9. Python 3 standard library only; no Node or npm.
"""
import hashlib
import json
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT = "extension"
PERMISSIONS = ["nativeMessaging", "contextMenus", "activeTab"]
FIXED_TIME = (1980, 1, 1, 0, 0, 0)

COMMON = [
    "background.js",
    "popup.html",
    "popup.css",
    "popup.js",
    "tokens.css",
    "fonts.css",
    "shapes.css",
    "fonts/web/SpaceGrotesk-Variable.latin.woff2",
    "fonts/web/JetBrainsMono-Variable.latin.woff2",
    "fonts/OFL-SpaceGrotesk.txt",
    "fonts/OFL-JetBrainsMono.txt",
    "README.md",
    "icons/icon-16.png",
    "icons/icon-32.png",
    "icons/icon-48.png",
    "icons/icon-128.png",
    "toolbar/toolbar-dark-16.png",
    "toolbar/toolbar-dark-32.png",
    "toolbar/toolbar-light-16.png",
    "toolbar/toolbar-light-32.png",
]

# What a reviewer needs to rebuild the extension, including the generated CSS.
SOURCE_DIRS = ["extension", "brand/voidwire/ui"]
SOURCE_FILES = ["scripts/extension_pack.py", "scripts/build-extension.sh", "LICENSE"]
SOURCE_SKIP_DIRS = {"tests", "__pycache__", "node_modules"}


def read(rel):
    with open(os.path.join(ROOT, rel), "rb") as f:
        return f.read()


def manifest(name, strip_key=False):
    data = json.loads(read(f"{EXT}/{name}"))
    if data.get("manifest_version") != 3:
        raise SystemExit(f"FATAL: {name} must be MV3")
    if data.get("permissions") != PERMISSIONS:
        raise SystemExit(f"FATAL: {name}: unexpected permissions {data.get('permissions')}")
    if strip_key:
        data.pop("key", None)
        return (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode()
    return read(f"{EXT}/{name}")


def write_zip(path, entries):
    """entries: list of (arcname, bytes), written in the given order."""
    if os.path.exists(path):
        os.remove(path)
    with zipfile.ZipFile(path, "w") as zf:
        for arc, data in entries:
            info = zipfile.ZipInfo(arc, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            zf.writestr(info, data, compresslevel=9)


def ext_entries(manifest_bytes):
    for rel in COMMON:
        if not os.path.isfile(os.path.join(ROOT, EXT, rel)):
            raise SystemExit(f"FATAL: missing extension file {EXT}/{rel}")
    return [("manifest.json", manifest_bytes)] + [(rel, read(f"{EXT}/{rel}")) for rel in COMMON]


def source_entries():
    files = set(SOURCE_FILES)
    for d in SOURCE_DIRS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, d)):
            dirnames[:] = [x for x in dirnames if x not in SOURCE_SKIP_DIRS]
            for fn in filenames:
                files.add(os.path.relpath(os.path.join(dirpath, fn), ROOT).replace(os.sep, "/"))
    entries = [("README.md", read(f"{EXT}/STORE-BUILD.md"))]
    return entries + [(rel, read(rel)) for rel in sorted(files)]


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("release", "stores"):
        raise SystemExit(__doc__)
    mode, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    firefox = ext_entries(manifest("manifest.firefox.json"))
    if mode == "release":
        outs = {"voidwire-extension-chromium.zip": ext_entries(manifest("manifest.json")),
                "voidwire-extension-firefox.zip": firefox}
    else:
        v = json.loads(read(f"{EXT}/manifest.json"))["version"]
        if json.loads(read(f"{EXT}/manifest.firefox.json"))["version"] != v:
            raise SystemExit("FATAL: manifest.json and manifest.firefox.json versions differ")
        outs = {f"voidwire-extension-{v}-chromium-store.zip": ext_entries(manifest("manifest.json", strip_key=True)),
                f"voidwire-extension-{v}-firefox-amo.zip": firefox,
                f"voidwire-extension-{v}-amo-source.zip": source_entries()}
    for name, entries in outs.items():
        write_zip(os.path.join(out, name), entries)
    if mode == "stores":
        with open(os.path.join(out, "SHA256SUMS"), "w") as f:
            for name in outs:
                f.write(f"{sha256(os.path.join(out, name))}  {name}\n")
    print("Built " + ", ".join(os.path.join(out, n) for n in outs))


if __name__ == "__main__":
    main()
