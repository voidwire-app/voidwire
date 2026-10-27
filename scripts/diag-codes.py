# Classify rustc JSON diagnostics for compile-fail-probes.sh.
# argv: expected code, cargo exit status. stdin: cargo --message-format=json.
import json, sys
want, rc = sys.argv[1], int(sys.argv[2])
codes, uncoded = [], []
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("reason") != "compiler-message": continue
    d = m["message"]
    if d["level"] != "error": continue
    c = (d.get("code") or {}).get("code")
    (codes.append(c) if c else uncoded.append(d["message"]))
uncoded = [u for u in uncoded if not u.startswith("aborting due to")]
if rc == 0: print("compiled (guarantee broken)")
elif want.startswith("msg:"):
    ok = not codes and uncoded and all(want[4:] in u for u in uncoded)
    print("ok" if ok else f"wrong reason: {sorted(set(codes))} {uncoded[:2]}")
elif not codes: print("cargo failed without the expected diagnostic: " + "; ".join(uncoded)[:300])
elif set(codes) != {want} or uncoded: print(f"wrong reason: {sorted(set(codes))} {uncoded[:2]}")
else: print("ok")
