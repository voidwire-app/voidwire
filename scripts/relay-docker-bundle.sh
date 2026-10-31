#!/usr/bin/env bash
# Builds voidwire-relay-docker.tar.gz: the files a self-hoster needs to run
# the relay and mailbox from published images, with no repository checkout.
#   scripts/relay-docker-bundle.sh <version> <out-dir>
# <version> is the image tag (release tag without the leading "v").
# The archive unpacks to voidwire-relay/: compose.yml (mailbox image pinned
# to <version>), .env.example, compose.override.example.yml and config/
# with the *.example.toml files. .env is the user's copy of .env.example;
# data/ and config/relay-token are created on first start.
set -euo pipefail
version=${1:?usage: relay-docker-bundle.sh <version> <out-dir>}
out=${2:?usage: relay-docker-bundle.sh <version> <out-dir>}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "bad version: $version" >&2; exit 1; }

src=$(cd "$(dirname "$0")/../ops/relay/docker" && pwd)
image=ghcr.io/voidwire-app/voidwire-mailbox
placeholder="image: $image:unreleased"
[ "$(grep -cxF "    $placeholder" "$src/compose.yml")" = 2 ] || { echo "expected the image placeholder twice in compose.yml (setup, mailbox)" >&2; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
d="$tmp/voidwire-relay"; mkdir "$d"
sed "s|^    $placeholder\$|    image: $image:$version|" "$src/compose.yml" > "$d/compose.yml"
[ "$(grep -cxF "    image: $image:$version" "$d/compose.yml")" = 2 ]
! grep -q ':unreleased' "$d/compose.yml"
cp "$src/compose.override.example.yml" "$src/.env.example" "$d/"
mkdir "$d/config"
cp "$src/config/relay.example.toml" "$src/config/relay-behind-https-proxy.example.toml" "$src/config/mailbox.example.toml" "$d/config/"
chmod 0755 "$d" "$d/config"
find "$d" -type f -exec chmod 0644 {} +
mkdir -p "$out"
tar --owner=0 --group=0 --numeric-owner --sort=name -czf "$out/voidwire-relay-docker.tar.gz" -C "$tmp" voidwire-relay
echo "$out/voidwire-relay-docker.tar.gz ($image:$version)"
