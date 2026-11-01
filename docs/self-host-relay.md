# Run your own Voidwire relay

This guide sets up a relay and mailbox for your own devices, on a home
server or a rented one. It does not depend on any particular hosting
provider.

Voidwire encrypts everything end to end. A relay forwards ciphertext and
cannot read URLs, text, files or device names, whoever runs it. Running
your own relay controls who sees the metadata: IP addresses, timing,
sizes and device public keys.

## Contents

1. [What you run](#1-what-you-run)
2. [Before you start](#2-before-you-start)
3. [Choose how TLS works](#3-choose-how-tls-works)
4. [Choose who may use the relay](#4-choose-who-may-use-the-relay)
5. [Install with Docker](#5-install-with-docker)
6. [Install as plain binaries](#6-install-as-plain-binaries)
7. [Add the relay in the apps](#7-add-the-relay-in-the-apps)
8. [Health checks](#8-health-checks)
9. [No logs](#9-no-logs)
10. [Updates and backups](#10-updates-and-backups)
11. [Troubleshooting](#11-troubleshooting)
12. [FAQ](#12-faq)

## 1. What you run

Two programs on one Linux host:

| Program | What it does | Network |
|---|---|---|
| `iroh-relay` 1.3.x (from the iroh project) | Forwards encrypted traffic between devices that can't reach each other directly. | TCP 443 in. UDP 7842 in (optional). |
| `voidwire-mailbox` (this repo) | Holds short-lived, encrypted inbox items for devices that are offline. It has no decryption keys. Items live in RAM and expire (`inbox_ttl_secs`). | Outbound only, to your relay. No open ports. |

With Docker you need no copy of this repository: each release attaches
`voidwire-relay-docker.tar.gz` (a compose file and config templates), and
the images are pulled from registries (section 5). For plain binaries,
releases attach `voidwire-mailbox-linux-x86_64` and
`voidwire-relay-selfhost.tar.gz` (the `ops/relay/` folder). The same files
are in `ops/relay/` (systemd) and `ops/relay/docker/` (Docker).

## 2. Before you start

- **A public IPv4 or IPv6 address.** Some home connections sit behind
  carrier-grade NAT (CGNAT) and can't accept inbound connections. If the WAN
  address on your router differs from what a "what is my IP" site shows,
  you are probably behind CGNAT. In that case use a tunnel or reverse proxy
  that you control on a host with a public address (see section 3), or ask
  your ISP for a public address.
- **A DNS name** such as `relay.example.com` pointing at that address. A
  dynamic DNS name is fine. Your apps connect to this name. Certificates
  issued for it appear in public Certificate Transparency logs, so the name
  itself is not secret.
- **Port forwarding** on your router: TCP 443 to the relay host, and
  optionally UDP 7842 (see below).
- **A Linux host**, x86_64 or arm64, always on. A small machine is enough.

### Is UDP 7842 needed?

No. It is optional.

With UDP 7842 open, the relay also offers QUIC address discovery. Devices
use it to learn their public address, which helps them set up direct
connections to each other. Without it, everything still works, but more
connections stay on the relay. That means more traffic through your
upload bandwidth and somewhat slower transfers. Content is end-to-end
encrypted either way.

UDP 7842 only works when the relay keeps its own TLS (mode A below). It
has to reach the relay directly: port-forward it, don't proxy it.
If you leave it closed, set `VOIDWIRE_RELAY_UDP=false` (Docker, section 5),
or set `enable_quic_addr_discovery = false` and print the relay link with
`--no-udp` (section 7). The link then ends in
`&q=0`, and devices skip address discovery at your relay instead of
probing a port that never answers.

## 3. Choose how TLS works

### Mode A: the relay keeps its own TLS (recommended)

The relay holds its own certificate and terminates TLS itself. Anything in
front of it sees only encrypted bytes.

- **Directly:** forward TCP 443 (and UDP 7842) to the relay host. The relay
  gets a Let's Encrypt certificate by itself with TLS-ALPN-01 on port 443.
  No port 80 is needed.
- **Behind a TCP passthrough proxy** (also called SNI or layer-4
  forwarding): if 443 on your public address is shared with other
  services, have your proxy route connections for the relay's name to the
  relay host *without* terminating TLS. Because the TLS handshake passes
  through untouched, the relay's own certificate and Let's Encrypt renewal
  keep working, and the proxy never sees plaintext. Don't add PROXY
  protocol headers toward the relay; it does not expect them.

Docker: `VOIDWIRE_RELAY_MODE=tls` in `.env` (section 5), with your name
and contact. systemd: `ops/relay/relay.toml`; set `hostname` and
`contact`.

If you can't use port 443, set `https_bind_addr` to another port and use
`cert_mode = "Reloading"`: get a certificate some other way (for example
ACME DNS-01 with certbot, lego or acme.sh) and put it at
`<cert_dir>/default.crt` and `<cert_dir>/default.key`. Include the port in
the relay URL (`https://relay.example.com:8443`).

`Reloading` re-reads those two files every 24 hours, so a renewed
certificate takes effect without a restart; if a read fails, the relay
keeps the certificate it has. `Manual` reads them only at start, so with
`Manual` you must restart the relay after every renewal. Renew at least a
day before expiry (the usual 30 days is fine).

### Mode B: behind an HTTPS-terminating proxy

Use this when the only way in is a reverse proxy or tunnel that terminates
TLS itself. Use one that you control: whoever runs the proxy sees the
same metadata as the relay operator (never content).

- Docker: `VOIDWIRE_RELAY_MODE=proxy` in `.env` (section 5). For
  binaries, or full control in Docker, use
  `relay-behind-https-proxy.example.toml` (in the bundle's `config/` and in
  `ops/relay/docker/config/`). The relay then has no TLS, listens on
  `http://127.0.0.1:3340` (`VOIDWIRE_RELAY_PROXY_BIND` to change it), and
  turns off address discovery.
- Point the proxy at `http://127.0.0.1:3340` for your relay's name.
- The proxy **must allow WebSocket upgrades** (the relay uses a WebSocket
  at `/relay`). It must not put logins, browser challenges or caching in
  front of the name.
- The relay pings each connection every 15 seconds, so proxy idle timeouts
  of 60 seconds or more are fine.
- UDP 7842 isn't available in this mode. With Docker and `.env` the
  relay link already says so; otherwise print it with `--no-udp`.
- Turn off the proxy's access log for this name, or it logs device IPs.

In both modes, the apps and the mailbox use the public `https://` name.

## 4. Choose who may use the relay

| Option | Who can use it | Cost |
|---|---|---|
| Access token (recommended for a personal relay) | Only devices that added your relay link | Anyone who sees the link can use the relay until you change the token |
| Open (`access = "everyone"`) | Anyone who knows the name | Strangers can spend your bandwidth, within the per-client limits. They can't read anything. |
| LAN or VPN only | Devices on your network or VPN | Away from home, devices need the VPN on, or they fall back to direct connections only |

### Access token

The relay accepts only clients that send a shared secret. The secret
travels inside the relay link (`t=`), so adding the link on a device is
all that's needed.

**With Docker (section 5) this is the default and automatic:** on first
start the setup service creates the token in `config/relay-token`, and
the relay and mailbox both use it. Skip the steps below; viewing, setting
and rotating the token are in section 5.

**Plain binaries (section 6):**

1. Generate a token:

   ```bash
   voidwire-mailbox --gen-token
   ```

2. In the relay config, replace `access = "everyone"` with:

   ```toml
   access.shared_token = ["PASTE-TOKEN-HERE"]
   ```

3. In the mailbox config, add:

   ```toml
   relay_token = "PASTE-TOKEN-HERE"
   ```

   Or set the environment variable `VOIDWIRE_RELAY_TOKEN` instead. There is
   deliberately no command-line flag, because command lines are visible to
   other users on the host.

4. Restart both, then print the relay link (section 7). It now ends in
   `&t=…`.

Things to know:

- **Treat the relay link as a password.** Share it only with people you
  want on your relay, and don't post screenshots of it.
- **Pairing codes and QR codes don't carry the token.** Someone you pair
  with must add your relay link on their device first. Otherwise they
  can't reach your relay. Your own devices are the same.
- **To revoke access**, generate a new token, update both configs, restart,
  and re-add the new link on every device you still want (Docker: see
  "Rotate the token" in section 5). Adding a link
  for a relay you already have updates its token.
- Devices with a missing or wrong token are refused by the relay. They
  can still connect directly when they share a network with you.

Why not an allowlist of device IDs? iroh-relay supports one, but Voidwire
uses a fresh random key for each mailbox session, so the relay can't tell
your devices apart from anyone else's by key. An allowlist would block
your own offline delivery.

### Open relay

Set `access = "everyone"` in the relay config (Docker:
`VOIDWIRE_RELAY_ACCESS=open` in `.env`, section 5) and keep the
`[limits]` tables. Per-client rate
limits (`[limits.client.rx]`) cap what any one client can use. Raise
`bytes_per_second` if you want faster relayed transfers.

### LAN or VPN only

Don't forward any ports. Use a name that resolves to the relay's LAN or VPN
address, and get a certificate by some other way (`cert_mode = "Reloading"`,
section 3),
or use mode B behind a proxy on your network. Combine this with the token
if other people share your network.

## 5. Install with Docker

Requires Docker with the compose plugin on a Linux host (x86_64 or arm64).
You don't need a copy of this repository. The compose file uses host
networking so the relay sees real client addresses and UDP works.

Images:

| Service | Image |
|---|---|
| `relay` | `n0computer/iroh-relay:v1.3.0`, from the iroh project, pinned by digest |
| `mailbox` and `setup` | `ghcr.io/voidwire-app/voidwire-mailbox:<version>`, built from this repo by GitHub Actions for each release. It runs as an unprivileged user (uid 10001). |

Each release's image is tagged with its version without the `v`
(`v0.9.2` → `0.9.2`). `latest` is only moved by full releases, never by
pre-releases (versions with a `-`, such as `0.9.2-m5.0`). The compose file
in a release always names that release's exact version.

### Set up

1. Download and unpack the release bundle. Replace `VERSION` with the
   release you want, such as `v0.9.2`:

   ```bash
   curl -fsSL https://github.com/voidwire-app/voidwire/releases/download/VERSION/voidwire-relay-docker.tar.gz | tar -xz
   cd voidwire-relay
   ```

   You get:

   ```text
   voidwire-relay/
     compose.yml                  replaced on upgrade; don't edit
     .env.example                 your settings: copy to .env
     compose.override.example.yml
     config/
       relay.example.toml         full relay config, mode A (optional)
       relay-behind-https-proxy.example.toml   same, mode B (optional)
       mailbox.example.toml       full mailbox config (optional)
   ```

2. Copy the settings file and edit it:

   ```bash
   cp .env.example .env
   nano .env
   ```

   | Setting | What |
   |---|---|
   | `VOIDWIRE_RELAY_HOSTNAME` | your relay's public name, such as `relay.example.com`. The apps and the mailbox use `https://` plus this name. |
   | `VOIDWIRE_RELAY_MODE` | `tls` (mode A, the default) or `proxy` (mode B), see section 3 |
   | `VOIDWIRE_RELAY_CONTACT` | mode A: your email address for Let's Encrypt |
   | `VOIDWIRE_RELAY_UDP` | mode A: `true` (default), or `false` if you can't forward UDP 7842 (section 2) |
   | `VOIDWIRE_RELAY_ACCESS` | `token` (default: only devices with your relay link) or `open` (section 4) |
   | `VOIDWIRE_RELAY_PROXY_BIND` | mode B: where the relay listens for your proxy, default `127.0.0.1:3340` |

   Optional limits. Leave them empty (or out) for the default. Whole
   numbers; 1 MB = 1048576 bytes, 1 KB = 1024 bytes.

   | Setting | Default | What |
   |---|---|---|
   | `VOIDWIRE_RELAY_FILE_LIMIT_MB` | `25` | largest file the apps send through the relay, in MB; `0` = the 2048 MB maximum. The apps read it from the relay; devices on the same network don't use the relay. |
   | `VOIDWIRE_RELAY_DEVICE_RATE_KB` | `1024` | upload speed through the relay per device, in KB per second (bursts of 4×); `0` = no limit. 200 MB takes about 3 minutes at the default. |
   | `VOIDWIRE_RELAY_NEW_CONN_PER_SEC` | `50` | new connections per second for the whole relay (bursts of 4×), 1-10000 |
   | `VOIDWIRE_RELAY_INBOX_ITEMS` | `16` | offline inbox: items held per device, 1-256 |
   | `VOIDWIRE_RELAY_INBOX_MINUTES` | `60` | offline inbox: minutes an item is kept, 1-10080 (7 days) |
   | `VOIDWIRE_RELAY_INBOX_RAM_MB` | `32` | offline inbox: MB of RAM for all inboxes together, 1-1024; when full, the oldest items go first |

   Setup checks each value and stops with a message naming the setting
   if one is out of range. A limit in `.env` has no effect on a
   `config/relay.toml` or `config/mailbox.toml` of your own (see below).

   Docker Compose reads `.env` from the folder automatically. It holds no
   secrets: the access token is never an environment value (those show
   up in `docker inspect`); it stays in `config/relay-token`.
3. Start:

   ```bash
   docker compose up -d
   ```

4. Get the relay link and add it in the apps (section 7):

   ```bash
   sudo cat config/relay-link.txt
   ```

   Setup writes this file on every start, so it always matches the
   current token, name and UDP setting. The link includes the access
   token, so treat it like a password: the file is 0600 and owned by
   uid 10001 like `config/relay-token` (hence `sudo`), and the link is
   never logged. In mode B, or with `VOIDWIRE_RELAY_UDP=false`, the link
   already tells the apps to skip UDP 7842 (it ends in `&q=0`).
   `docker compose run --rm --no-deps mailbox --print-relay-link` prints
   the same link.

You don't edit any config file for this. To change a setting later, edit
`.env` and restart (see below).

If your router has no NAT loopback (devices inside your network can't
reach your public name), `cp compose.override.example.yml
compose.override.yml` and uncomment `extra_hosts` there to point the name
at the relay's LAN address. Split DNS on your network works too. Docker
reads `compose.override.yml` automatically, and upgrades leave it alone.

### Full control: your own config files

`.env` covers the basic settings and the common limits. For anything
else (ports, `cert_mode = "Reloading"`, per-IP mailbox quotas), copy an
example and edit it:

```bash
cp config/relay.example.toml config/relay.toml       # or relay-behind-https-proxy.example.toml
cp config/mailbox.example.toml config/mailbox.toml
```

**Which one wins:** each file on its own. If `config/relay.toml` exists,
the relay uses it as it is and ignores the relay settings in `.env`; the
same goes for `config/mailbox.toml` and the mailbox. Without the file,
the config is built from `.env`. Delete or rename the file to go back to
`.env`.

In your own files, set the public name in both (`hostname` and
`relay_url`), and in `config/mailbox.toml` set
`relay_link_no_udp = true` if UDP 7842 isn't reachable. Keep
`access.shared_token = ["@RELAY_TOKEN@"]` as it is; setup fills in the
token. For an open relay, replace that line with `access = "everyone"`
and delete `config/relay-token`.

### Where things are

Everything lives next to `compose.yml`, so it survives container
re-creation and image upgrades, and you can read, edit or back it up on
the host.

| Path | What | Owner, mode |
|---|---|---|
| `.env` | your settings | you |
| `config/relay-token` | the access token, created on first start | uid 10001 (the mailbox user), 0600 |
| `config/relay-link.txt` | the relay link for the apps, rewritten on every start. Don't edit. | uid 10001, 0600 |
| `config/relay.toml`, `config/mailbox.toml` | optional, your own full configs; win over `.env` | you; must stay readable (0644) |
| `data/mailbox/identity.key` | the mailbox ID in your relay link. Back it up. | uid 10001, 0600 |
| `data/relay/certs/` | the relay's certificates | root, 0700 |
| `data/relay/relay.toml`, `data/mailbox/mailbox.toml` | the configs in use, written on every start from `.env` or your files, with the token filled in. Don't edit. | root (relay) / uid 10001 (mailbox), 0600 |

A one-shot `setup` service runs before the relay and mailbox on every
start. It creates `data/`, sets the owners and modes above (so you don't
need to `chown` anything), builds the two configs, creates
`config/relay-token` if the relay uses a token and the file doesn't
exist, checks the token, and writes `config/relay-link.txt`. It never
replaces an existing token. It runs without network access, and the token
never appears in a log, an environment variable or a command line.

The token, link and key files belong to uid 10001, so use `sudo` on the
host to read or edit them.

### Manage the token

- **View it:** `sudo cat config/relay-token`. The relay link in
  `config/relay-link.txt` already contains it.
- **Use your own:** put 16-128 characters of `A-Z a-z 0-9 - . _ ~` in
  the file (`sudoedit config/relay-token`), then restart. Setup resets
  the file's owner and mode, and refuses an invalid token (the relay and
  mailbox then don't start).
- **Rotate (revoke all devices):** delete the file and restart. Setup
  makes a new token and a new `config/relay-link.txt`. Re-add that link
  on every device you still want. The mailbox ID stays the same.

  ```bash
  sudo rm config/relay-token
  docker compose up -d --force-recreate
  sudo cat config/relay-link.txt
  ```

- **Open relay:** set `VOIDWIRE_RELAY_ACCESS=open` in `.env`, delete
  `config/relay-token` and restart. The relay link then has no token.

**Restart** after any change in `.env` or `config/`:

```bash
docker compose up -d --force-recreate
```

(`--force-recreate` re-runs setup. A plain `docker compose restart` does
not rebuild the configs.)

### Build the image yourself (alternative)

From a copy of this repository, the compose file builds the mailbox
image instead of pulling it:

```bash
git clone https://github.com/voidwire-app/voidwire.git
cd voidwire/ops/relay/docker
cp .env.example .env    # and edit it as above
docker compose -f compose.yml -f compose.build.yml up -d --build
```

Add `-f compose.override.yml` if you have one. `.env`, `data/`,
`config/relay-token`, `config/relay.toml`, `config/mailbox.toml` and
`compose.override.yml` are ignored by git.

## 6. Install as plain binaries

```bash
# Mailbox: from a release (check SHA256SUMS), or build it
cargo build --release --locked -p voidwire-mailbox
sudo install -m 0755 target/release/voidwire-mailbox /usr/local/bin/

# Relay: iroh-relay 1.3.x
cargo install iroh-relay --version 1.3.0 --locked --features server
sudo install -m 0755 ~/.cargo/bin/iroh-relay /usr/local/bin/
```

Configs and services (from `ops/relay/`):

```bash
sudo install -d -m 0755 /etc/iroh-relay /etc/voidwire-mailbox
sudo install -m 0644 relay.toml /etc/iroh-relay/config.toml
sudo install -m 0600 mailbox.toml /etc/voidwire-mailbox/config.toml
sudo install -m 0644 iroh-relay.service voidwire-mailbox.service /etc/systemd/system/
sudo install -D -m 0644 journald-volatile.conf /etc/systemd/journald.conf.d/voidwire.conf
sudo systemctl daemon-reload
sudo systemctl enable --now iroh-relay voidwire-mailbox
```

Edit the two configs as in section 5 before starting. Use mode 0600 on
the mailbox config if it holds a token. `nftables.conf` is an example
firewall that allows TCP 443 and UDP 7842 only.

## 7. Add the relay in the apps

Get the relay link (your relay's name plus the mailbox ID, and the token
if set):

```bash
# Docker (in the folder with compose.yml): written on every start
sudo cat config/relay-link.txt
# Plain binaries:
voidwire-mailbox --config /etc/voidwire-mailbox/config.toml --print-relay-link
# add --no-udp if UDP 7842 isn't reachable
```

It looks like `voidwire:relay?r=https%3A%2F%2Frelay.example.com&m=…`.

- **PC:** Devices → Relays, paste the link, then **Add**.
- **Android:** Settings → Relays → **Add relay**, then paste the link.

Then choose **Make home** on it. New pairings use the home relay. To move
an existing pairing, use **Change relay…** in that device's ⋯ menu. Both
devices confirm.

## 8. Health checks

```bash
# Mailbox (loopback only):
curl -fsS http://127.0.0.1:48486/healthz        # -> ok

# Relay:
curl -fsS https://relay.example.com/ping         # -> 200
curl -fsS https://relay.example.com/healthz      # -> JSON status
```

Mode B on the host itself: `curl -fsS http://127.0.0.1:3340/ping`.

The apps also show each relay's status under Relays.

## 9. No logs

The shipped configs log nothing:

- Mailbox: `log = "off"`. Services and containers set `RUST_LOG=off`.
- systemd: `StandardOutput=null` and `StandardError=null`. `journald-volatile.conf` keeps
  any other logs in RAM only.
- Docker: `logging: driver: none` on every service (so `docker compose
  logs` shows nothing).
- Relay metrics are off in the Docker configs. The systemd config keeps
  aggregate counters on `127.0.0.1:9090` only. If you turn them on
  anywhere, bind them to `127.0.0.1`.
- Turn off access logs on any proxy in front of the relay.

To debug, temporarily set `RUST_LOG=info` on the relay. Turn it off
again afterwards: those logs contain client IPs and device public keys.

## 10. Updates and backups

- **Docker:** replace `compose.yml` and the example files with the ones
  from the new release, then pull and restart. Your `.env`,
  `config/relay-token`, any `config/relay.toml` or `config/mailbox.toml`,
  `data/` and `compose.override.yml` are kept. Run this in the folder that holds
  `voidwire-relay/` (replace `VERSION`):

  ```bash
  curl -fsSL https://github.com/voidwire-app/voidwire/releases/download/VERSION/voidwire-relay-docker.tar.gz | tar -xz voidwire-relay/compose.yml voidwire-relay/.env.example voidwire-relay/config
  cd voidwire-relay
  docker compose pull && docker compose up -d
  ```

  Check the release notes for changes to `.env.example` and the config
  templates. If you set up with 0.9.2-m4.6, you have your own
  `config/relay.toml` and `config/mailbox.toml`; they keep working and win
  over `.env`. To switch to `.env`, fill it in, then move those two files
  away and restart. Built from
  source: `git pull`, then
  `docker compose -f compose.yml -f compose.build.yml up -d --build`.
- **Binaries:** replace the files in `/usr/local/bin/`, then
  `sudo systemctl restart iroh-relay voidwire-mailbox`.
- Keep iroh-relay on the 1.3.x line that this release names; check the
  release notes before moving to a new minor version.
- **Back up the mailbox key** (`identity.key` in the mailbox data
  directory; Docker: `data/mailbox/identity.key`, or simply the whole
  `voidwire-relay/` folder). It is the mailbox ID in your
  relay link. If you lose it, you get a new ID and every device has to re-add
  the link. Inbox contents are temporary and don't need a backup.
- The relay's certificate directory is re-created when needed.

### Automatic mailbox updates with Watchtower (optional)

Watchtower watches running containers and replaces one when its image tag
points to a new image. The original `containrrr/watchtower` is archived
and no longer maintained
([announcement](https://github.com/containrrr/watchtower/discussions/2135)).
Use the maintained fork,
[`nicholas-fedor/watchtower`](https://github.com/nicholas-fedor/watchtower)
(image `ghcr.io/nicholas-fedor/watchtower`,
[docs](https://watchtower.nickfedor.com/)). It keeps the original labels
and `WATCHTOWER_*` settings.

What it can and can't update here:

- **Mailbox:** a version tag such as `0.9.3-m4.6` never changes, so
  Watchtower never updates it. Use the `latest` tag instead, in both
  `setup` and `mailbox`. `latest` moves only on full releases, never on
  pre-releases (versions with a `-`). Until the first full release there
  is no `latest` tag yet, so stay on a version tag and update by hand.
- **Relay:** pinned by digest (`@sha256:…`), so Watchtower can't and
  shouldn't move it. A Voidwire release that needs a newer relay bumps
  that digest in `compose.yml`; take it with the steps above (or paste
  the new `relay` image line into your Portainer stack).
- **Setup:** Watchtower replaces only the mailbox container and does not
  re-run `setup` (tested: the mailbox came back with the same mounts and
  settings, the generated configs and `config/relay-link.txt` stayed as
  they were). That's safe: setup only turns `.env` and `config/` into
  the files in `data/`, and those don't change with the image. If a
  release ever changes what setup writes, its notes say so; then run
  `docker compose up -d` (or redeploy the stack), which re-runs setup
  with the new image.

Scope Watchtower to the mailbox with a label, so it touches nothing else
on the host. In `compose.override.yml` (or the same lines in your
Portainer stack):

```yaml
services:
  setup:
    image: ghcr.io/voidwire-app/voidwire-mailbox:latest
  mailbox:
    image: ghcr.io/voidwire-app/voidwire-mailbox:latest
    labels:
      - com.centurylinklabs.watchtower.enable=true
  watchtower:
    image: ghcr.io/nicholas-fedor/watchtower:latest
    restart: unless-stopped
    environment:
      WATCHTOWER_LABEL_ENABLE: "true"   # only containers with the label above
      WATCHTOWER_CLEANUP: "true"        # remove the old image after an update
      WATCHTOWER_SCHEDULE: "0 0 4 * * *" # daily at 04:00 (container time, UTC)
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    logging:
      driver: none
```

Don't put the label on `relay` or `setup`. Watchtower needs the Docker
socket, which is root-level access to the host; if you already run
Watchtower for other stacks, add only the `image` and `labels` lines and
let your existing instance (with `WATCHTOWER_LABEL_ENABLE`) pick the
mailbox up.

## 11. Troubleshooting

| Symptom | Check |
|---|---|
| No certificate | Port 443 must reach the relay directly or via passthrough. A TLS-terminating proxy breaks TLS-ALPN-01. |
| Mailbox never comes up | Can the host reach its own public name? See NAT loopback in section 5. |
| Docker: relay and mailbox don't start, `setup` exited with an error | Logs are off, so run `docker compose run --rm setup` to see the message (no `.env`, a value in it not filled in or invalid, or an invalid `config/relay-token`). On success it says where each config came from (`.env` or your file). |
| Docker: a change in `.env` has no effect | `config/relay.toml` or `config/mailbox.toml` exists and wins over `.env` for that service. Edit that file or move it away, then restart with `--force-recreate`. |
| Docker: no `config/relay-link.txt` | Setup hasn't run yet (`docker compose up -d`), or it failed (see above), or your own `config/mailbox.toml` puts `key_path` outside `/data`. |
| Docker: `--print-relay-link` fails with a permission error | Run `docker compose up -d` once first, so setup can create `data/mailbox/`. |
| Devices show the relay as unreachable | DNS, the port forward, and, with a token, that the device added the current link. |
| Transfers are slow | Raise `[limits.client.rx] bytes_per_second`. Open UDP 7842 for more direct connections. |
| Behind CGNAT | Inbound ports don't work. Use a tunnel or proxy you control on a host with a public address (mode B, or mode A with TCP passthrough). |

## 12. FAQ

### What is Let's Encrypt for?

It gives the relay its HTTPS certificate, so the apps can trust that they
are talking to your relay's name. Your content is already end-to-end
encrypted, so TLS isn't what keeps it private. TLS stops someone from
impersonating your relay, and it hides the access token and connection
metadata on the wire.

In mode A the relay gets and renews the certificate by itself over port
443 (TLS-ALPN-01). No port 80 is needed, and it works through a TCP
passthrough proxy. The contact email only receives Let's Encrypt notices,
such as expiry warnings. It is never given to the apps.

In mode B your proxy terminates TLS instead and holds the certificate.
The tradeoff: the proxy sees the traffic (who connects, when, how much,
and the token), though never the content.

### Why do the settings live in `.env`?

The bundle's `compose.yml` is replaced on every upgrade, and `.env` is
not, so your values survive. Typing the values directly into
`compose.yml` (or into a Portainer stack) works too, with no security
difference. In that case, upgrade by changing only the image tag, not by
replacing the file.

The access token is the exception: it never goes in an environment
variable or a compose file, because those show up in `docker inspect`
and crash reports. It lives only in `config/relay-token`.

### What does `VOIDWIRE_RELAY_UDP` do?

It turns on UDP 7842, which the relay uses for QUIC address discovery.
That helps devices learn their public address so they can connect to
each other directly. Relayed data always uses TCP 443, whatever this is
set to.

With it off, the relay link ends in `&q=0` and everything still works.
Direct connections are somewhat less likely behind strict NATs, and those
transfers go through the relay instead.

### Why doesn't forwarding UDP through a tunnel or proxy help?

Address discovery tells each device the source address its packets came
from. Tunnel or reverse-proxy services such as Pangolin, frp, or a VPS
port-forward replace that address with their own, so every answer would
be wrong. Forward UDP 7842 directly, from your
router or the host's public IP, or set `VOIDWIRE_RELAY_UDP=false`. Only
turn it on through a tunnel if the tunnel keeps the clients' real source
addresses.

### Can I use Cloudflare (Tunnel or proxied, orange-cloud DNS)?

Not recommended:

1. Cloudflare's self-serve terms restrict using its CDN proxy or a Tunnel
   to serve large non-HTML files, so relaying big transfers through it
   puts your account at risk.
2. Cloudflare terminates TLS, so it sees who connects to whom, when and
   how much, and it sees your access token. Content stays end-to-end
   encrypted.
3. Tunnels and the proxy don't carry the relay's UDP.

What works: a DNS-only (grey-cloud) record pointing at your public IP,
with mode A on TCP 443. Using Cloudflare only for DNS is fine.

### How do I run it in Portainer (or another web stack editor)?

1. Paste the services from the bundle's `compose.yml` into the stack, but
   use absolute host paths. Relative `./config` and `./data` don't resolve
   to a predictable host folder in a web editor. For example, with
   everything under `/opt/voidwire-relay`, change every volume line:

   | Service | Volumes |
   |---|---|
   | `setup` | `/opt/voidwire-relay/config:/config`, `/opt/voidwire-relay/data:/data` |
   | `relay` | `/opt/voidwire-relay/data/relay:/data` |
   | `mailbox` | `/opt/voidwire-relay/config:/config:ro`, `/opt/voidwire-relay/data/mailbox:/data` |

   **Host path on the left, container path on the right.** Change only
   the left side (the folder on your host). Never change the right side
   (`/config`, `/data`): the images and the generated configs expect
   exactly those paths, and setup, the relay and the mailbox stop finding
   their files if you do.

2. Set the `VOIDWIRE_RELAY_*` values (section 5), including any limits,
   in the stack's environment variables section, or type them inline in
   the `setup` service. Never the token. Inline, the `setup` service's
   `environment:` looks like this (limits you leave out keep their
   defaults):

   ```yaml
       environment:
         VOIDWIRE_RELAY_HOSTNAME: relay.example.com
         VOIDWIRE_RELAY_MODE: proxy
         VOIDWIRE_RELAY_ACCESS: token
         VOIDWIRE_RELAY_PROXY_BIND: 127.0.0.1:3340
         VOIDWIRE_RELAY_FILE_LIMIT_MB: "0"        # up to 2048 MB through the relay
         VOIDWIRE_RELAY_DEVICE_RATE_KB: "10240"   # 10 MB/s per device
   ```

   Only `setup` reads these. After a change, update the stack, then
   restart the `relay` and `mailbox` containers so they load the configs
   setup rebuilt.
3. Deploy. `setup` showing as exited is normal: it runs once on each start.
   Logs are blank by design (section 9).
4. Get the relay link from a shell on the host:

   ```bash
   sudo cat /opt/voidwire-relay/config/relay-link.txt
   ```

   Setup rewrites it on every deploy, so after a token change just
   redeploy and read it again.

5. To upgrade, change the mailbox image tag in both places (`setup` and
   `mailbox`) and redeploy with "re-pull image" on.
