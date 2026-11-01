#!/usr/bin/env bash
# Checks the Docker relay bundle against a local mailbox image, without
# starting the relay (that needs a public name and port 443):
#   scripts/relay-docker-test.sh <image:tag>
# Unpacks the release bundle for that tag, runs the setup service and the
# mailbox's one-off commands with docker compose, and checks: configs built
# from .env (mode A/B, UDP, open), config/*.toml winning over .env, the
# token file, ownership and modes, idempotence, a custom token, rotation,
# config/relay-link.txt matching --print-relay-link after every start, the
# VOIDWIRE_RELAY_* limits (rendered, defaults, bad values refused, relay
# starts with them in mode B), and
# that the token never reaches the environment or the setup output. Needs docker with the
# compose plugin; uses sudo for reading root/10001-owned files when not root.
set -euo pipefail
image=${1:?usage: relay-docker-test.sh <image:tag>}
version=${image##*:}
repo=$(cd "$(dirname "$0")/.." && pwd)
SUDO=; [ "$(id -u)" = 0 ] || SUDO=sudo
DOCKER=${DOCKER:-docker}

work=$(mktemp -d)
cleanup() { (cd "$work/voidwire-relay" 2>/dev/null && $DOCKER compose down --remove-orphans >/dev/null 2>&1) || true; $SUDO rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

"$repo/scripts/relay-docker-bundle.sh" "$version" "$work" >/dev/null
tar -xzf "$work/voidwire-relay-docker.tar.gz" -C "$work"
cd "$work/voidwire-relay"
[ "$(grep -c "image: ${image}\$" compose.yml)" = 2 ] || fail "bundle does not use $image"
[ -f .env.example ] || fail "no .env.example"
[ ! -e config/relay.toml ] && [ ! -e config/mailbox.toml ] || fail "bundle ships active configs"
export COMPOSE_PROJECT_NAME="vwtest$$"
$DOCKER compose config --quiet
$DOCKER compose -f compose.yml -f compose.override.example.yml config --quiet

setup() { $DOCKER compose run --rm --pull never setup >/dev/null; }
link() { $DOCKER compose run --rm --pull never --no-deps mailbox --print-relay-link "$@"; }
# The link file setup writes; it must equal what --print-relay-link prints.
lf() { $SUDO cat config/relay-link.txt; }
lf_ok() { [ "$(lf)" = "$(link)" ] || fail "relay-link.txt differs from --print-relay-link ($1)"; }
mode_owner() { $SUDO stat -c '%a %u:%g' "$1"; }
relay_cfg() { $SUDO grep "$@" data/relay/relay.toml; }
mailbox_cfg() { $SUDO grep "$@" data/mailbox/mailbox.toml; }
# env_set KEY VALUE: set or add a line in .env
env_set() { if grep -q "^#\?$1=" .env; then sed -i "s|^#\?$1=.*|$1=$2|" .env; else echo "$1=$2" >>.env; fi; }

# 0. No .env and no configs: setup refuses; so does the unedited example.
if setup 2>/dev/null; then fail "setup ran without .env"; fi
cp .env.example .env
if setup 2>/dev/null; then fail "setup accepted the example host name"; fi
env_set VOIDWIRE_RELAY_HOSTNAME relay.test.invalid
if setup 2>/dev/null; then fail "setup accepted the example contact"; fi
env_set VOIDWIRE_RELAY_CONTACT ops@test.invalid
for bad in 'VOIDWIRE_RELAY_MODE x' 'VOIDWIRE_RELAY_UDP no' 'VOIDWIRE_RELAY_ACCESS all' 'VOIDWIRE_RELAY_HOSTNAME a"b'; do
  cp .env .env.good; env_set $bad
  if setup 2>/dev/null; then fail "setup accepted $bad"; fi
  mv .env.good .env
done

# 1. First start from .env (mode A): token created, configs rendered, ownership set.
setup
[ "$(mode_owner config/relay-token)" = "600 10001:10001" ] || fail "relay-token is $(mode_owner config/relay-token)"
[ "$(mode_owner config/relay-link.txt)" = "600 10001:10001" ] || fail "relay-link.txt is $(mode_owner config/relay-link.txt)"
token=$($SUDO cat config/relay-token)
out=$($DOCKER compose run --rm --pull never setup 2>&1)
[[ "$out" != *"$token"* && "$out" != *voidwire:relay* ]] || fail "setup output has the token or link"
ls -a config | grep -q '^\.relay-link\.' && fail "temp link file left in config/"
[[ "$token" =~ ^[0-9a-f]{64}$ ]] || fail "generated token has the wrong form"
[ "$(mode_owner data/relay/relay.toml)" = "600 0:0" ] || fail "relay.toml is $(mode_owner data/relay/relay.toml)"
[ "$(mode_owner data/mailbox/mailbox.toml)" = "600 10001:10001" ] || fail "mailbox.toml is $(mode_owner data/mailbox/mailbox.toml)"
[ "$(mode_owner data/relay)" = "700 0:0" ] || fail "data/relay is $(mode_owner data/relay)"
[ "$(mode_owner data/mailbox)" = "700 10001:10001" ] || fail "data/mailbox is $(mode_owner data/mailbox)"
relay_cfg -qxF "access.shared_token = [\"$token\"]" || fail "token not in relay.toml"
relay_cfg -qx 'hostname = "relay.test.invalid"' || fail "hostname not rendered"
relay_cfg -qx 'contact = "ops@test.invalid"' || fail "contact not rendered"
relay_cfg -qx 'enable_quic_addr_discovery = true' || fail "UDP not on"
! relay_cfg -q '@RELAY_TOKEN@\|example.com' || fail "placeholder left in relay.toml"
mailbox_cfg -qx 'relay_url = "https://relay.test.invalid"' || fail "relay_url not rendered"
[ ! -e config/relay.toml ] && [ ! -e config/mailbox.toml ] || fail "setup wrote into config/"
# The token is never in a container's environment.
$DOCKER compose config | grep -q "$token" && fail "token in compose config"
$DOCKER compose run --rm --pull never --no-deps --entrypoint env mailbox | grep -q "$token" && fail "token in mailbox env"
$DOCKER compose run --rm --pull never --no-deps --entrypoint env setup | grep -q "$token" && fail "token in setup env"

# 1b. Limits: empty keeps the template defaults; set values land in both
# configs; bad values stop setup with a message naming the setting.
relay_cfg -qx 'bytes_per_second = 1048576            # per client; raise for faster relayed files' || fail "default rate changed"
relay_cfg -qx 'accept_conn_limit = 50.0' || fail "default conn limit changed"
mailbox_cfg -q '^max_relay_file_bytes = 26214400 ' || fail "default file limit changed"
mailbox_cfg -qx 'inbox_max_items = 16                      # 1-256' || fail "default inbox items changed"
env_set VOIDWIRE_RELAY_FILE_LIMIT_MB 200
env_set VOIDWIRE_RELAY_DEVICE_RATE_KB 10240
env_set VOIDWIRE_RELAY_NEW_CONN_PER_SEC 20
env_set VOIDWIRE_RELAY_INBOX_ITEMS 64
env_set VOIDWIRE_RELAY_INBOX_MINUTES 1440
env_set VOIDWIRE_RELAY_INBOX_RAM_MB 128
setup
relay_cfg -qx 'bytes_per_second = 10485760' || fail "rate not rendered"
relay_cfg -qx 'max_burst_bytes = 41943040' || fail "burst not rendered"
relay_cfg -qx 'accept_conn_limit = 20.0' && relay_cfg -qx 'accept_conn_burst = 80' || fail "conn limit not rendered"
mailbox_cfg -qx 'max_relay_file_bytes = 209715200' || fail "file limit not rendered"
mailbox_cfg -qx 'inbox_max_items = 64' || fail "inbox items not rendered"
mailbox_cfg -qx 'inbox_ttl_secs = 86400' || fail "inbox minutes not rendered"
mailbox_cfg -qx 'inbox_max_total_bytes = 134217728' || fail "inbox RAM not rendered"
link >/dev/null || fail "mailbox refused the rendered limits"
env_set VOIDWIRE_RELAY_FILE_LIMIT_MB 0
env_set VOIDWIRE_RELAY_DEVICE_RATE_KB 0
setup
mailbox_cfg -qx 'max_relay_file_bytes = 0' || fail "file limit 0 not rendered"
! relay_cfg -q '^\[limits\.client\.rx\]\|^bytes_per_second\|^max_burst_bytes' || fail "rate 0 left a limit"
relay_cfg -q '^\[limits\]$' || fail "rate 0 dropped [limits]"
for bad in 'VOIDWIRE_RELAY_FILE_LIMIT_MB 2049' 'VOIDWIRE_RELAY_FILE_LIMIT_MB 25MB' 'VOIDWIRE_RELAY_DEVICE_RATE_KB -1' \
           'VOIDWIRE_RELAY_DEVICE_RATE_KB 1048576' 'VOIDWIRE_RELAY_NEW_CONN_PER_SEC 0' 'VOIDWIRE_RELAY_INBOX_ITEMS 257' \
           'VOIDWIRE_RELAY_INBOX_MINUTES 0' 'VOIDWIRE_RELAY_INBOX_RAM_MB 1.5'; do
  cp .env .env.good; env_set $bad
  if err=$($DOCKER compose run --rm --pull never setup 2>&1 >/dev/null); then fail "setup accepted $bad"; fi
  [[ "$err" == *"${bad%% *} must be a whole number from "* ]] || fail "unclear error for $bad: $err"
  mv .env.good .env
done
echo "limits error example: $err"
for k in FILE_LIMIT_MB DEVICE_RATE_KB NEW_CONN_PER_SEC INBOX_ITEMS INBOX_MINUTES INBOX_RAM_MB; do env_set "VOIDWIRE_RELAY_$k" ""; done
setup
relay_cfg -qx 'accept_conn_limit = 50.0' && relay_cfg -q '^bytes_per_second = 1048576 ' || fail "empty limits did not restore the defaults"

# 2. Relay link: mailbox ID kept in data/mailbox, token from the file.
l1=$(link)
[[ "$l1" == "voidwire:relay?r=https%3A%2F%2Frelay.test.invalid&m="*"&t=$token" ]] || fail "unexpected link: ${l1%%&t=*}&t=…"
[[ "$l1" != *"q=0"* ]] || fail "UDP off in the link with UDP on"
[ "$(mode_owner data/mailbox/identity.key)" = "600 10001:10001" ] || fail "identity.key is $(mode_owner data/mailbox/identity.key)"
[ "$(link)" = "$l1" ] || fail "link changed between runs"
[[ "$(link --no-udp)" == *q=0* ]] || fail "--no-udp not in link"
[ "$(lf)" = "$l1" ] || fail "relay-link.txt differs from --print-relay-link"
[ "$(wc -l < <(lf))" = 1 ] || fail "relay-link.txt is not one line"

# 3. Idempotent: a second start keeps the token.
setup
[ "$($SUDO cat config/relay-token)" = "$token" ] || fail "token regenerated"

# 4. No UDP from .env: relay and link both.
env_set VOIDWIRE_RELAY_UDP false
setup
relay_cfg -qx 'enable_quic_addr_discovery = false' || fail "UDP not off"
[[ "$(link)" == *q=0* ]] || fail "link without q=0 when UDP is off"
lf_ok "UDP off"
env_set VOIDWIRE_RELAY_UDP true

# 5. Your own token: edit the file, restart.
own=my-own-token-0123456789
printf '%s\n' "$own" | $SUDO tee config/relay-token >/dev/null
setup
relay_cfg -qxF "access.shared_token = [\"$own\"]" || fail "own token not used"
[[ "$(link)" == *"&t=$own" ]] || fail "own token not in link"
lf_ok "own token"
printf 'short\n' | $SUDO tee config/relay-token >/dev/null
if setup 2>/dev/null; then fail "invalid token accepted"; fi

# 6. Rotate: delete the file, restart: new token, same mailbox ID.
$SUDO rm config/relay-token
setup
new=$($SUDO cat config/relay-token)
[[ "$new" =~ ^[0-9a-f]{64}$ && "$new" != "$token" ]] || fail "rotation did not make a new token"
l2=$(link)
[ "${l2%%&t=*}" = "${l1%%&t=*}" ] || fail "mailbox ID changed on rotation"
[ "$(lf)" = "$l2" ] && [[ "$(lf)" == *"&t=$new" ]] || fail "relay-link.txt not updated on rotation"

# 7. Open relay from .env: no token anywhere.
$SUDO rm config/relay-token
env_set VOIDWIRE_RELAY_ACCESS open
setup
[ ! -e config/relay-token ] || fail "open mode created a token"
relay_cfg -qx 'access = "everyone"' || fail "open mode not rendered"
[[ "$(link)" != *"&t="* ]] || fail "open mode link has a token"
lf_ok "open"; [[ "$(lf)" != *"&t="* ]] || fail "open relay-link.txt has a token"
env_set VOIDWIRE_RELAY_ACCESS token

# 8. Mode B from .env: plain HTTP bind, no TLS section, link without UDP.
env_set VOIDWIRE_RELAY_MODE proxy
env_set VOIDWIRE_RELAY_CONTACT ""
env_set VOIDWIRE_RELAY_PROXY_BIND 192.168.1.5:3340
setup
relay_cfg -qx 'http_bind_addr = "192.168.1.5:3340"' || fail "mode B bind not rendered"
! relay_cfg -q '^\[tls\]' || fail "mode B has [tls]"
relay_cfg -q '^access.shared_token = \["[0-9a-f]\{64\}"\]$' || fail "mode B token not rendered"
[[ "$(link)" == *q=0* ]] || fail "mode B link without q=0"
lf_ok "mode B"
# Limits in mode B, and the relay itself accepts the rendered file.
env_set VOIDWIRE_RELAY_DEVICE_RATE_KB 4096
env_set VOIDWIRE_RELAY_FILE_LIMIT_MB 0
setup
relay_cfg -qx 'bytes_per_second = 4194304' && relay_cfg -qx 'max_burst_bytes = 16777216' || fail "mode B rate not rendered"
mailbox_cfg -qx 'max_relay_file_bytes = 0' || fail "mode B file limit not rendered"
relay_image=$($DOCKER compose config --images | grep iroh-relay)
relay_runs() {
  local id running
  id=$($DOCKER run -d --network host -v "$PWD/data/relay:/data" -e RUST_LOG=off "$relay_image" --config-path /data/relay.toml)
  sleep 5
  running=$($DOCKER inspect -f '{{.State.Running}}' "$id")
  $DOCKER rm -f "$id" >/dev/null
  [ "$running" = true ] || fail "iroh-relay did not start with the rendered config ($1)"
}
env_set VOIDWIRE_RELAY_PROXY_BIND 127.0.0.1:3340
setup
relay_runs "mode B, rate 4096"
env_set VOIDWIRE_RELAY_DEVICE_RATE_KB 0
setup
relay_runs "mode B, no rate limit"
env_set VOIDWIRE_RELAY_DEVICE_RATE_KB ""
env_set VOIDWIRE_RELAY_FILE_LIMIT_MB ""
env_set VOIDWIRE_RELAY_MODE tls
env_set VOIDWIRE_RELAY_CONTACT ops@test.invalid

# 9. Your own config files win over .env, each on its own.
cp config/relay.example.toml config/relay.toml
sed -i 's|^hostname = .*|hostname = "custom.test.invalid"|' config/relay.toml
setup
relay_cfg -qx 'hostname = "custom.test.invalid"' || fail "config/relay.toml not used"
relay_cfg -q '^# Generated from config/relay.toml' || fail "relay header"
mailbox_cfg -qx 'relay_url = "https://relay.test.invalid"' || fail "mailbox not from .env"
cp config/mailbox.example.toml config/mailbox.toml
sed -i 's|^relay_url = .*|relay_url = "https://custom.test.invalid"|' config/mailbox.toml
rm .env
setup
mailbox_cfg -qx 'relay_url = "https://custom.test.invalid"' || fail "config/mailbox.toml not used"
[[ "$(link)" == "voidwire:relay?r=https%3A%2F%2Fcustom.test.invalid&m="* ]] || fail "link not from config/mailbox.toml"
lf_ok "config/mailbox.toml"
# Hand-edited open relay.
$SUDO rm config/relay-token
sed -i 's|^access.shared_token = \["@RELAY_TOKEN@"\]$|access = "everyone"|' config/relay.toml
setup
[ ! -e config/relay-token ] || fail "open config created a token"
relay_cfg -qx 'access = "everyone"' || fail "open config not rendered"
[[ "$(link)" != *"&t="* ]] || fail "open config link has a token"
# Hand-edited mode B.
cp config/relay-behind-https-proxy.example.toml config/relay.toml
setup
relay_cfg -q '^access.shared_token = \["[0-9a-f]\{64\}"\]$' || fail "mode B file not rendered"

# A key outside /data: no link file (never a stale one), setup still succeeds.
sed -i 's|^key_path = .*|key_path = "/elsewhere/identity.key"|' config/mailbox.toml
setup 2>/dev/null
[ ! -e config/relay-link.txt ] || fail "relay-link.txt kept with an unmapped key_path"

# 10. Image basics.
[ "$($DOCKER run --rm --entrypoint id "$image" -u)" = 10001 ] || fail "image user is not 10001"
$DOCKER run --rm "$image" --gen-token | grep -Eq '^[0-9a-f]{64}$' || fail "--gen-token"
echo "relay-docker-test: all checks passed ($image)"
