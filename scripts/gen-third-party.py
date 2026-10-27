#!/usr/bin/env python3
"""Generate THIRD-PARTY-LICENSES.txt for one artifact family (D8).

    scripts/gen-third-party.py desktop build/licenses/desktop/THIRD-PARTY-LICENSES.txt
    scripts/gen-third-party.py android build/licenses/android/THIRD-PARTY-LICENSES.txt

desktop: Rust crates linked into the desktop app (Linux, Windows, macOS
         targets), from cargo-about.
android: Rust crates in libvoidwire_core.so (Android targets, features
         ffi) from cargo-about, plus the Java/Kotlin runtime
         libraries from the Gradle dependency-license report
         (android/app/build/reports/dependency-license/licenses.csv, produced
         by `./gradlew generateLicenseReport`; run it first).

Output is deterministic (no timestamps) so it can be diffed between builds.
Fails if cargo-about fails or a crate's license can't be identified.
"""
import csv
import json
import os
import subprocess
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESKTOP_TARGETS = ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
                   "aarch64-apple-darwin", "x86_64-apple-darwin"]
ANDROID_TARGETS = ["aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android"]
GRADLE_CSV = os.path.join(ROOT, "android/app/build/reports/dependency-license/licenses.csv")
# License election (D12): JNA is used under Apache-2.0 (dual LGPL-2.1+/Apache-2.0).
GRADLE_ELECTIONS = {"net.java.dev.jna:jna": ("Apache-2.0",
    "dual-licensed LGPL-2.1-or-later OR Apache-2.0; distributed here under Apache-2.0")}


def branding():
    out = {}
    with open(os.path.join(ROOT, "branding.properties"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def cargo_about(manifest, targets, features=None):
    cmd = ["cargo", "about", "generate", "--format", "json", "--locked", "--fail",
           "-m", os.path.join(ROOT, manifest), "-c", os.path.join(ROOT, "about.toml")]
    for t in targets:
        cmd += ["--target", t]
    if features:
        cmd += ["--features", " ".join(features)]
    # encoding: Windows runners default to cp1252, which cannot decode
    # license texts (run 38121408989, desktop bundle (windows-latest)).
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    if res.returncode != 0:
        sys.exit(f"cargo about failed:\n{res.stderr[-3000:]}")
    return json.loads(res.stdout)


PLACEHOLDERS = ("<year>", "<owner>", "<copyright holders>", "[yyyy]", "[name of copyright owner]")


def notice_for(crate):
    """Copyright notice for a crate whose license text is the generic SPDX
    template (it shipped no license file): its declared authors plus any
    COPYING/NOTICE/COPYRIGHT file from the package."""
    parts = []
    if crate.get("authors"):
        parts.append("Copyright (c) the " + crate["name"] + " authors: " + ", ".join(crate["authors"]))
    pkg = os.path.dirname(crate.get("manifest_path") or "")
    for fn in ("COPYING", "NOTICE", "COPYRIGHT", "AUTHORS"):
        path = os.path.join(pkg, fn)
        if pkg and os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                parts.append(f"[{crate['name']} {fn}]\n" + f.read().strip())
    return "\n".join(parts)


def render_rust(data, lines):
    # One section per distinct license text, listing the crates that use it.
    sections = []
    for lic in data["licenses"]:
        crates = sorted({(u["crate"]["name"], u["crate"]["version"], u["crate"].get("repository") or "")
                         for u in lic["used_by"]})
        text = lic["text"].strip("\n")
        if any(p in text for p in PLACEHOLDERS):
            notices = [notice_for(u["crate"]) for u in lic["used_by"]]
            text = ("Generic license text (the package ships no license file); copyright notice:\n"
                    + "\n".join(n for n in notices if n) + "\n\n" + text)
        sections.append((lic["id"], lic["name"], text, crates))
    sections.sort(key=lambda s: (s[0], s[3]))
    count = defaultdict(set)
    for lid, _, _, crates in sections:
        for c in crates:
            count[lid].add(c[:2])
    lines.append("Summary (Rust crates by license):")
    for lid in sorted(count):
        lines.append(f"  {lid}: {len(count[lid])}")
    lines.append("")
    if "MPL-2.0" in count:
        lines.append("MPL-2.0 components are used unmodified. Their source code is available from")
        lines.append("crates.io (https://crates.io/crates/<name>/<version>) and the repositories listed below.")
        lines.append("")
    for lid, name, text, crates in sections:
        lines.append("=" * 78)
        lines.append(f"{name} ({lid})")
        lines.append("Used by:")
        for n, v, repo in crates:
            lines.append(f"  - {n} {v}" + (f"  <{repo}>" if repo else ""))
        lines.append("-" * 78)
        lines.append(text)
        lines.append("")
    return {s[0]: s[2] for s in sections}


def render_gradle(lines, texts_by_id):
    if not os.path.exists(GRADLE_CSV):
        sys.exit(f"missing {GRADLE_CSV}: run `./gradlew generateLicenseReport` in android/ first")
    rows = list(csv.DictReader(open(GRADLE_CSV, encoding="utf-8")))
    if not rows:
        sys.exit("Gradle license report is empty")
    lines.append("=" * 78)
    lines.append("Android / Java / Kotlin libraries (Gradle releaseRuntimeClasspath)")
    lines.append("-" * 78)
    for r in sorted(rows, key=lambda r: r["artifact"]):
        group_name = r["artifact"].rsplit(":", 1)[0]
        lic = r["moduleLicense"]
        if group_name in GRADLE_ELECTIONS:
            lic = f"{GRADLE_ELECTIONS[group_name][0]} ({GRADLE_ELECTIONS[group_name][1]})"
        elif "Apache" in lic and "2.0" in lic:
            lic = "Apache-2.0"
        url = r.get("moduleUrl") or ""
        lines.append(f"  - {r['artifact']}: {lic}" + (f"  <{url}>" if url else ""))
    lines.append("")
    # Canonical text (the Rust crates in this artifact may all have elected MIT).
    with open(os.path.join(ROOT, "licenses/Apache-2.0.txt"), encoding="utf-8") as f:
        apache = f.read().strip("\n")
    lines.append("The full Apache License 2.0 text that applies to the libraries above:")
    lines.append("-" * 78)
    lines.append(apache)
    lines.append("")


# Fonts bundled in both apps (M1.1 design kit): SIL OFL 1.1, the licence text
# must ship with them. Source of truth: brand/voidwire/ui/fonts/.
FONTS = [
    ("Space Grotesk", "https://github.com/floriankarsten/space-grotesk",
     "brand/voidwire/ui/fonts/OFL-SpaceGrotesk.txt"),
    ("JetBrains Mono", "https://github.com/JetBrains/JetBrainsMono",
     "brand/voidwire/ui/fonts/OFL-JetBrainsMono.txt"),
]


def render_fonts(lines):
    for name, url, path in FONTS:
        with open(os.path.join(ROOT, path), encoding="utf-8") as f:
            text = f.read().strip()
        lines.append("=" * 78)
        lines.append(f"Font: {name} (OFL-1.1), bundled unmodified except for subsetting  <{url}>")
        lines.append("-" * 78)
        lines.append(text)
        lines.append("")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("desktop", "android"):
        sys.exit(__doc__)
    kind, out = sys.argv[1], sys.argv[2]
    b = branding()
    lines = [
        "THIRD-PARTY SOFTWARE NOTICES AND LICENSES",
        f"{b['APP_NAME']} ({kind}). Generated by scripts/gen-third-party.py; do not edit.",
        "",
        f"{b['APP_NAME']}'s own code is licensed under the terms in the accompanying LICENSE",
        "file (CC0 1.0 Universal, with an MIT License fallback).",
        "This file lists the third-party components included in this build and their licenses.",
        "",
    ]
    if kind == "desktop":
        texts = render_rust(cargo_about("desktop/Cargo.toml", DESKTOP_TARGETS), lines)
    else:
        texts = render_rust(cargo_about("core/Cargo.toml", ANDROID_TARGETS, ["ffi"]), lines)
        render_gradle(lines, texts)
    render_fonts(lines)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
