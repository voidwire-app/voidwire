#!/usr/bin/env bash
# Source this: exports every key of branding.properties (APP_NAME, BUNDLE_ID,
# PACKAGE_ID, BINARY_NAME, ENV_PREFIX, REPO_URL, PUBLISHER) and
# TAURI_BRANDING_JSON for `cargo tauri build --config` (same values that
# desktop/build.rs injects; the CLI needs them for bundling).
_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
while IFS='=' read -r k v; do
  [[ -z "$k" || "$k" == \#* ]] && continue
  export "$k"="$v"
done < "$_root/branding.properties"
TAURI_BRANDING_JSON=$(python3 -c 'import json,os; e=os.environ; print(json.dumps({
  "productName": e["APP_NAME"], "identifier": e["BUNDLE_ID"], "mainBinaryName": e["BINARY_NAME"],
  "bundle": {"publisher": e["PUBLISHER"], "homepage": e["REPO_URL"]}}))')
export TAURI_BRANDING_JSON
