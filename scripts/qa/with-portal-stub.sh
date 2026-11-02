#!/usr/bin/env bash
# Run a command with scripts/qa/portal-stub.py owning the portal name on the
# current session bus (tests only; run inside dbus-run-session):
#   dbus-run-session -- bash scripts/qa/with-portal-stub.sh cargo test ...
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
log=$(mktemp)
python3 "$here/portal-stub.py" >"$log" 2>&1 &
stub=$!
for _ in $(seq 50); do grep -q "portal-stub: ready" "$log" && break; sleep 0.1; done
grep -q "portal-stub: ready" "$log" || { cat "$log"; kill "$stub" 2>/dev/null; exit 1; }
"$@"
rc=$?
kill "$stub" 2>/dev/null
exit $rc
