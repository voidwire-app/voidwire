#!/usr/bin/env python3
"""Android dependency license gate (D12). Fails closed.

    scripts/check-android-licenses.py android/app/build/reports/dependency-license/licenses.csv

Every runtime module in the Gradle license report (releaseRuntimeClasspath)
must declare an allow-listed license. The only exceptions are listed in
EXCEPTIONS with the exact POM license string they were reviewed against, so a
change in what a dependency declares is flagged again. GPL/AGPL/LGPL-only and
unknown/missing licenses fail. Mirrors deny.toml's Rust allow-list.
"""
import csv
import re
import sys

# Normalized POM license names -> SPDX id.
ALLOWED = {
    r"^(the )?apache( software)? license,? (version )?2\.0$": "Apache-2.0",
    r"^apache-2\.0$|^apache 2\.0$": "Apache-2.0",
    r"^(the )?mit license$|^mit$": "MIT",
    r"^(the )?bsd 2-clause license$|^bsd-2-clause$": "BSD-2-Clause",
    r"^(the )?(new )?bsd 3-clause license$|^bsd-3-clause$": "BSD-3-Clause",
    r"^isc license$|^isc$": "ISC",
}
# group:name -> (POM license string as reviewed, decision)
EXCEPTIONS = {
    "net.java.dev.jna:jna": (
        "LGPL-2.1-or-later",
        "dual-licensed LGPL-2.1-or-later OR Apache-2.0; Apache-2.0 elected (D12)",
    ),
}


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    try:
        rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8")))
    except OSError as e:
        sys.exit(f"FAIL: cannot read license report: {e}")
    if not rows or "artifact" not in rows[0] or "moduleLicense" not in rows[0]:
        sys.exit("FAIL: license report is empty or has an unexpected format")
    bad = []
    for r in rows:
        art = r["artifact"].strip()
        lic = (r["moduleLicense"] or "").strip()
        key = art.rsplit(":", 1)[0]
        if key in EXCEPTIONS:
            want, why = EXCEPTIONS[key]
            if lic != want:
                bad.append(f"{art}: declares '{lic}', exception was reviewed for '{want}'")
            else:
                print(f"exception  {art}: {why}")
            continue
        norm = re.sub(r"\s+", " ", lic.lower())
        if not any(re.match(p, norm) for p in ALLOWED):
            bad.append(f"{art}: '{lic or '<none>'}' is not allow-listed")
    for b in bad:
        print(f"FAIL  {b}")
    print(f"android licenses: {len(rows)} modules, {len(bad)} problem(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
