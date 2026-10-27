#!/usr/bin/env bash
# AUTH-12/AUTH-17: every probe in tools/probes/src/bin must FAIL to compile,
# with exactly the error code named in its `// expect: EXXXX` line and no other
# error. Fails closed: a probe that compiles, fails for another reason, or a
# cargo failure that produced no rustc diagnostics all fail this script.
# (rustdoc only checks compile_fail error codes on nightly, hence this script.)
set -euo pipefail
cd "$(dirname "$0")/../tools/probes"
cp ../../Cargo.lock Cargo.lock   # same pinned versions as the workspace
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-../../target}/probes"
fail=0
for f in src/bin/*.rs; do
  name=$(basename "$f" .rs)
  # `// expect: E0451` (error code) or `// expect-msg: <text>` (uncoded error)
  want=$(sed -n 's|^// expect: \(E[0-9]\{4\}\).*|\1|p; s|^// expect-msg: \(.*\)$|msg:\1|p' "$f" | head -1)
  [ -n "$want" ] || { echo "FAIL $name: no '// expect:' line"; fail=1; continue; }
  set +e
  out=$(cargo check --quiet --offline --bin "$name" --message-format=json 2>/dev/null)
  rc=$?
  set -e
  verdict=$(printf "%s\n" "$out" | python3 ../../scripts/diag-codes.py "$want" "$rc")
  if [ "$verdict" = ok ]; then echo "ok   $name ($want)"; else echo "FAIL $name: $verdict"; fail=1; fi
done
exit $fail
