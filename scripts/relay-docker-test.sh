#!/usr/bin/env bash
# Checks the Docker relay bundle against a local mailbox image, without
# starting the relay (that needs a public name and port 443):
#   scripts/relay-docker-test.sh <image:tag>
# Unpacks the release bundle for that tag, runs the setup service and the
# mailbox's one-off commands with docker compose, and checks the token file,
# the generated relay config, ownership and modes, idempotence, a custom
# token, rotation and open mode. Needs docker with the compose plugin; uses
# sudo for reading root/10001-owned files when not root.
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
export COMPOSE_PROJECT_NAME="vwtest$$"
$DOCKER compose config --quiet
$DOCKER compose -f compose.yml -f compose.override.example.yml config --quiet

setup() { $DOCKER compose run --rm --pull never setup >/dev/null; }
link() { $DOCKER compose run --rm --pull never --no-deps mailbox --print-relay-link "$@"; }
mode_owner() { $SUDO stat -c '%a %u:%g' "$1"; }

# 1. First start: token created, relay config rendered, ownership set.
setup
[ "$(mode_owner config/relay-token)" = "600 10001:10001" ] || fail "relay-token is $(mode_owner config/relay-token)"
token=$($SUDO cat config/relay-token)
[[ "$token" =~ ^[0-9a-f]{64}$ ]] || fail "generated token has the wrong form"
[ "$(mode_owner data/relay/relay.toml)" = "600 0:0" ] || fail "relay.toml is $(mode_owner data/relay/relay.toml)"
[ "$(mode_owner data/relay)" = "700 0:0" ] || fail "data/relay is $(mode_owner data/relay)"
[ "$(mode_owner data/mailbox)" = "700 10001:10001" ] || fail "data/mailbox is $(mode_owner data/mailbox)"
$SUDO grep -qxF "access.shared_token = [\"$token\"]" data/relay/relay.toml || fail "token not in relay.toml"
! $SUDO grep -q '@RELAY_TOKEN@' data/relay/relay.toml || fail "placeholder left in relay.toml"
grep -q '@RELAY_TOKEN@' config/relay.toml || fail "config/relay.toml was changed"

# 2. Relay link: mailbox ID kept in data/mailbox, token from the file.
l1=$(link)
[[ "$l1" == "voidwire:relay?r=https%3A%2F%2Frelay.example.com&m="*"&t=$token" ]] || fail "unexpected link: ${l1%%&t=*}&t=…"
[ "$(mode_owner data/mailbox/identity.key)" = "600 10001:10001" ] || fail "identity.key is $(mode_owner data/mailbox/identity.key)"
[ "$(link)" = "$l1" ] || fail "link changed between runs"
link --no-udp | grep -q '&q=0\|q=0' || fail "--no-udp not in link"

# 3. Idempotent: a second start keeps the token.
setup
[ "$($SUDO cat config/relay-token)" = "$token" ] || fail "token regenerated"

# 4. Your own token: edit the file, restart.
own=my-own-token-0123456789
printf '%s\n' "$own" | $SUDO tee config/relay-token >/dev/null
setup
$SUDO grep -qxF "access.shared_token = [\"$own\"]" data/relay/relay.toml || fail "own token not used"
[[ "$(link)" == *"&t=$own" ]] || fail "own token not in link"
printf 'short\n' | $SUDO tee config/relay-token >/dev/null
if setup 2>/dev/null; then fail "invalid token accepted"; fi

# 5. Rotate: delete the file, restart: new token, same mailbox ID.
$SUDO rm config/relay-token
setup
new=$($SUDO cat config/relay-token)
[[ "$new" =~ ^[0-9a-f]{64}$ && "$new" != "$token" ]] || fail "rotation did not make a new token"
l2=$(link)
[ "${l2%%&t=*}" = "${l1%%&t=*}" ] || fail "mailbox ID changed on rotation"

# 6. Open relay: access = "everyone", no token file.
$SUDO rm config/relay-token
sed -i 's|^access.shared_token = \["@RELAY_TOKEN@"\]$|access = "everyone"|' config/relay.toml
setup
[ ! -e config/relay-token ] || fail "open mode created a token"
$SUDO grep -qx 'access = "everyone"' data/relay/relay.toml || fail "open mode not rendered"
[[ "$(link)" != *"&t="* ]] || fail "open mode link has a token"

# 7. Mode B file renders too.
cp config/relay-behind-https-proxy.toml config/relay.toml
setup
$SUDO grep -q '^access.shared_token = \["[0-9a-f]\{64\}"\]$' data/relay/relay.toml || fail "mode B not rendered"

# 8. Image basics.
[ "$($DOCKER run --rm --entrypoint id "$image" -u)" = 10001 ] || fail "image user is not 10001"
$DOCKER run --rm "$image" --gen-token | grep -Eq '^[0-9a-f]{64}$' || fail "--gen-token"
echo "relay-docker-test: all checks passed ($image)"
