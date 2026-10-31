#!/usr/bin/env python3
"""Gate: no polling in the Android app (owner rule: no timers, no polling,
no keep-alive, never hurt phone battery). Fails on any Thread.sleep in app
sources, and on any `while` loop whose body waits (delay/sleep) and so wakes
on a timer. The app refreshes on core change events (IncomingEvents.kt).
A loop may be allowed only with `// polling-allowed: <reason>` on its line."""
import pathlib, re, sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "android/app/src/main")
bad = []
for f in sorted(root.rglob("*.kt")):
    if "uniffi" in f.parts:
        continue
    src = f.read_text()
    lines = src.split("\n")
    for n, line in enumerate(lines, 1):
        code = line.split("//", 1)[0]
        if re.search(r"\bThread\.sleep\s*\(", code):
            bad.append(f"{f}:{n}: Thread.sleep")
    for m in re.finditer(r"\bwhile\s*\(", src):
        ln = src.count("\n", 0, m.start()) + 1
        if "polling-allowed:" in lines[ln - 1]:
            continue
        # body: from the first '{' after the condition to its matching '}'
        i, depth = m.end(), 1
        while i < len(src) and depth:
            depth += {"(": 1, ")": -1}.get(src[i], 0)
            i += 1
        j = i
        while j < len(src) and src[j] in " \t\r\n":
            j += 1
        if j >= len(src) or src[j] != "{":
            continue
        k, depth = j + 1, 1
        while k < len(src) and depth:
            depth += {"{": 1, "}": -1}.get(src[k], 0)
            k += 1
        body = "\n".join(l.split("//", 1)[0] for l in src[j:k].split("\n"))
        if re.search(r"\b(delay|sleep|awaitNanos|postDelayed)\s*\(", body):
            bad.append(f"{f}:{ln}: while loop waits on a timer (polling)")
for b in bad:
    print("      " + b)
sys.exit(1 if bad else 0)
