#!/usr/bin/env bash
# Checks the Docker relay bundle against a local mailbox image, without
# starting the relay (that needs a public name and port 443):
#   scripts/relay-docker-test.sh <image:tag>
# Unpacks the release bundle for that tag, runs the setup service and the
# mailbox's one-off commands with docker compose, and checks: configs built
# from .env (mode A/B, UDP, open), config/*.toml winning over .env, the
# token file, ownership and modes, idempotence, a custom token, rotation,
# and that the token never reaches the environment. Needs docker with the
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
token=$($SUDO cat config/relay-token)
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

# 2. Relay link: mailbox ID kept in data/mailbox, token from the file.
l1=$(link)
[[ "$l1" == "voidwire:relay?r=https%3A%2F%2Frelay.test.invalid&m="*"&t=$token" ]] || fail "unexpected link: ${l1%%&t=*}&t=…"
[[ "$l1" != *"q=0"* ]] || fail "UDP off in the link with UDP on"
[ "$(mode_owner data/mailbox/identity.key)" = "600 10001:10001" ] || fail "identity.key is $(mode_owner data/mailbox/identity.key)"
[ "$(link)" = "$l1" ] || fail "link changed between runs"
[[ "$(link --no-udp)" == *q=0* ]] || fail "--no-udp not in link"

# 3. Idempotent: a second start keeps the token.
setup
[ "$($SUDO cat config/relay-token)" = "$token" ] || fail "token regenerated"

# 4. No UDP from .env: relay and link both.
env_set VOIDWIRE_RELAY_UDP false
setup
relay_cfg -qx 'enable_quic_addr_discovery = false' || fail "UDP not off"
[[ "$(link)" == *q=0* ]] || fail "link without q=0 when UDP is off"
env_set VOIDWIRE_RELAY_UDP true

# 5. Your own token: edit the file, restart.
own=my-own-token-0123456789
printf '%s\n' "$own" | $SUDO tee config/relay-token >/dev/null
setup
relay_cfg -qxF "access.shared_token = [\"$own\"]" || fail "own token not used"
[[ "$(link)" == *"&t=$own" ]] || fail "own token not in link"
printf 'short\n' | $SUDO tee config/relay-token >/dev/null
if setup 2>/dev/null; then fail "invalid token accepted"; fi

# 6. Rotate: delete the file, restart: new token, same mailbox ID.
$SUDO rm config/relay-token
setup
new=$($SUDO cat config/relay-token)
[[ "$new" =~ ^[0-9a-f]{64}$ && "$new" != "$token" ]] || fail "rotation did not make a new token"
l2=$(link)
[ "${l2%%&t=*}" = "${l1%%&t=*}" ] || fail "mailbox ID changed on rotation"

# 7. Open relay from .env: no token anywhere.
$SUDO rm config/relay-token
env_set VOIDWIRE_RELAY_ACCESS open
setup
[ ! -e config/relay-token ] || fail "open mode created a token"
relay_cfg -qx 'access = "everyone"' || fail "open mode not rendered"
[[ "$(link)" != *"&t="* ]] || fail "open mode link has a token"
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

# 10. Image basics.
[ "$($DOCKER run --rm --entrypoint id "$image" -u)" = 10001 ] || fail "image user is not 10001"
$DOCKER run --rm "$image" --gen-token | grep -Eq '^[0-9a-f]{64}$' || fail "--gen-token"
echo "relay-docker-test: all checks passed ($image)"
