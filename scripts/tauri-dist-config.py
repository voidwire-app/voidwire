#!/usr/bin/env python3
"""Write the Tauri --config overlay used for every shipped desktop bundle.

    scripts/tauri-dist-config.py build/tauri-dist.json

Branding (D9: productName, identifier, mainBinaryName, publisher, homepage from
branding.properties) plus license files (D8):
  * all bundles: LICENSE + THIRD-PARTY-LICENSES.txt as Tauri resources
    (NSIS: install dir; deb/AppImage: /usr/lib/<product>/)
  * deb: /usr/share/doc/<package>/copyright (LICENSE) + THIRD-PARTY-LICENSES.txt
  * macOS (M5.2): build/Info.plist merged into the app's (menu bar only, the
    Finder service, the local network prompt), macOS 13+, and a full ad-hoc
    signature ("-": no Apple account; users allow it once in Privacy &
    Security)
Regenerates build/licenses/desktop/THIRD-PARTY-LICENSES.txt first. Paths in
the overlay are relative to desktop/ (where tauri.conf.json lives).
"""
import json
import os
import plistlib
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def hicolor_files():
    """The hand-tuned freedesktop icons (desktop/icons/linux/hicolor/**) for the .deb and
    the AppImage (built from the deb tree); the .desktop file says Icon=<mainBinaryName>
    = voidwire. Tauri itself installs 32x32 and 128x128 from bundle.icon (same files), so
    those two are left to it."""
    base = os.path.join(ROOT, "desktop", "icons", "linux", "hicolor")
    out = {}
    for d, _, files in sorted(os.walk(base)):
        rel = os.path.relpath(d, base)
        if rel.split(os.sep)[0] in ("32x32", "128x128"):
            continue
        for f in sorted(files):
            out[f"/usr/share/icons/hicolor/{rel}/{f}"] = f"icons/linux/hicolor/{rel}/{f}"
    if not out:
        sys.exit("desktop/icons/linux/hicolor is empty")
    return out


def mac_info_plist(app_name):
    """Keys merged into the bundle's Info.plist (M5.2: M1, M2, M4)."""
    return {
        # M1: menu bar only, no Dock icon.
        "LSUIElement": True,
        # M4: the prompt macOS 15+ shows before the first LAN connection.
        "NSLocalNetworkUsageDescription": f"{app_name} connects directly to your paired devices on this network.",
        # M2: Finder's "Send with <app>" (desktop/os-theme/src/mac.rs answers
        # the sendWithVoidwire message).
        "NSServices": [{
            "NSMenuItem": {"default": f"Send with {app_name}"},
            "NSMessage": "sendWithVoidwire",
            "NSPortName": app_name,
            "NSRequiredContext": {},
            "NSSendFileTypes": ["public.item"],
        }],
    }


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = os.path.abspath(sys.argv[1])
    b = {}
    for line in open(os.path.join(ROOT, "branding.properties"), encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            b[k.strip()] = v.strip()
    third_rel = "build/licenses/desktop/THIRD-PARTY-LICENSES.txt"
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts/gen-third-party.py"), "desktop",
                    os.path.join(ROOT, third_rel)], check=True)
    pkg = re.sub(r"[^a-z0-9]+", "-", b["APP_NAME"].lower()).strip("-")  # Tauri: kebab(productName)
    third = "../" + third_rel
    cfg = {
        "productName": b["APP_NAME"],
        "identifier": b["BUNDLE_ID"],
        "mainBinaryName": b["BINARY_NAME"],
        "bundle": {
            "publisher": b["PUBLISHER"],
            "homepage": b["REPO_URL"],
            "resources": {"../LICENSE": "LICENSE", third: "THIRD-PARTY-LICENSES.txt"},
            "linux": {"deb": {"files": {
                f"/usr/share/doc/{pkg}/copyright": "../LICENSE",
                f"/usr/share/doc/{pkg}/THIRD-PARTY-LICENSES.txt": third,
                **hicolor_files(),
            }}},
        },
    }
    # NSIS hooks with the branding filled in (see desktop/installer-hooks.nsh).
    hooks_src = open(os.path.join(ROOT, "desktop", "installer-hooks.nsh"), encoding="utf-8").read()
    hooks = (hooks_src.replace("@APP_NAME@", b["APP_NAME"])
             .replace("@BINARY_NAME@", b["BINARY_NAME"]).replace("@BUNDLE_ID@", b["BUNDLE_ID"]))
    if "@" in re.sub(r";.*", "", hooks):
        sys.exit("installer-hooks.nsh: unfilled @...@ placeholder")
    hooks_out = os.path.join(os.path.dirname(out), "installer-hooks.nsh")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(hooks_out, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(hooks)
    cfg["bundle"]["windows"] = {"nsis": {"installMode": "perMachine",
                                         "installerHooks": os.path.relpath(hooks_out, os.path.join(ROOT, "desktop"))}}
    plist_out = os.path.join(os.path.dirname(out), "Info.plist")
    with open(plist_out, "wb") as f:
        plistlib.dump(mac_info_plist(b["APP_NAME"]), f)
    cfg["bundle"]["macOS"] = {
        "minimumSystemVersion": "13.0",
        "signingIdentity": "-",
        "infoPlist": os.path.relpath(plist_out, os.path.join(ROOT, "desktop")),
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=1)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
