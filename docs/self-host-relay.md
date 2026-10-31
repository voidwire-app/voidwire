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

## 1. What you run

Two programs on one Linux host:

| Program | What it does | Network |
|---|---|---|
| `iroh-relay` 1.3.x (from the iroh project) | Forwards encrypted traffic between devices that can't reach each other directly. | TCP 443 in. UDP 7842 in (optional). |
| `voidwire-mailbox` (this repo) | Holds short-lived, encrypted inbox items for devices that are offline. It has no decryption keys. Items live in RAM and expire (`inbox_ttl_secs`). | Outbound only, to your relay. No open ports. |

All files referred to here are in `ops/relay/` (systemd) and
`ops/relay/docker/` (Docker). Release builds also attach
`voidwire-mailbox-linux-x86_64` and `voidwire-relay-selfhost.tar.gz`
(the `ops/relay/` folder).

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
If you leave it closed, set `enable_quic_addr_discovery = false` and print
the relay link with `--no-udp` (section 7). The link then ends in
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

Config: `ops/relay/docker/relay.toml` (Docker) or `ops/relay/relay.toml`
(systemd). Set `hostname` and `contact`.

If you can't use port 443, set `https_bind_addr` to another port and use
`cert_mode = "Manual"`: get a certificate some other way (for example
ACME DNS-01) and put it at `<cert_dir>/default.crt` and
`<cert_dir>/default.key`. Include the port in the relay URL
(`https://relay.example.com:8443`).

### Mode B: behind an HTTPS-terminating proxy

Use this when the only way in is a reverse proxy or tunnel that terminates
TLS itself. Use one that you control: whoever runs the proxy sees the
same metadata as the relay operator (never content).

- Config: `ops/relay/docker/relay-behind-https-proxy.toml`. It has no
  `[tls]` table, listens on `http://127.0.0.1:3340`, and turns off address
  discovery.
- Point the proxy at `http://127.0.0.1:3340` for your relay's name.
- The proxy **must allow WebSocket upgrades** (the relay uses a WebSocket
  at `/relay`). It must not put logins, browser challenges or caching in
  front of the name.
- The relay pings each connection every 15 seconds, so proxy idle timeouts
  of 60 seconds or more are fine.
- UDP 7842 isn't available in this mode. Print the relay link with
  `--no-udp`.
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

1. Generate a token:

   ```bash
   voidwire-mailbox --gen-token
   # Docker: docker compose run --rm mailbox --gen-token
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
  and re-add the new link on every device you still want. Adding a link
  for a relay you already have updates its token.
- Devices with a missing or wrong token are refused by the relay. They
  can still connect directly when they share a network with you.

Why not an allowlist of device IDs? iroh-relay supports one, but Voidwire
uses a fresh random key for each mailbox session, so the relay can't tell
your devices apart from anyone else's by key. An allowlist would block
your own offline delivery.

### Open relay

Keep `access = "everyone"` and the `[limits]` tables. Per-client rate
limits (`[limits.client.rx]`) cap what any one client can use. Raise
`bytes_per_second` if you want faster relayed transfers.

### LAN or VPN only

Don't forward any ports. Use a name that resolves to the relay's LAN or VPN
address, and get a certificate by some other way (`cert_mode = "Manual"`),
or use mode B behind a proxy on your network. Combine this with the token
if other people share your network.

## 5. Install with Docker

Requires Docker with the compose plugin on a Linux host. The compose file
uses host networking so the relay sees real client addresses and UDP
works.

```bash
git clone https://github.com/voidwire-app/voidwire.git
cd voidwire/ops/relay/docker
```

1. Edit `relay.toml`: set `hostname` and `contact`, and your access
   choice. For mode B, edit `relay-behind-https-proxy.toml` instead and
   change the relay's mounted file in `compose.yml`.
2. Edit `mailbox.toml`: set `relay_url` to your public `https://` name,
   and `relay_token` if you use one.
3. If your router has no NAT loopback (devices inside your network can't
   reach your public name), uncomment `extra_hosts` in `compose.yml` and
   point the name at the relay's LAN address. Split DNS on your network
   works too.
4. Start:

   ```bash
   docker compose up -d --build
   ```

The relay image is the iroh project's `n0computer/iroh-relay:v1.3.0`. The
mailbox image is built from this repo (`Dockerfile.mailbox`). It runs as
an unprivileged user and keeps its data in the `mailbox-data` volume.

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

Print the relay link (your relay's name plus the mailbox ID, and the token
if set):

```bash
voidwire-mailbox --config /etc/voidwire-mailbox/config.toml --print-relay-link
# add --no-udp if UDP 7842 isn't reachable
# Docker:
docker compose run --rm mailbox --config /config/mailbox.toml --print-relay-link
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
- Docker: `logging: driver: none` on both services.
- Relay metrics are off in the Docker configs. The systemd config keeps
  aggregate counters on `127.0.0.1:9090` only. If you turn them on
  anywhere, bind them to `127.0.0.1`.
- Turn off access logs on any proxy in front of the relay.

To debug, temporarily set `RUST_LOG=info` on the relay. Turn it off
again afterwards: those logs contain client IPs and device public keys.

## 10. Updates and backups

- **Docker:** `git pull`, then `docker compose pull && docker compose up -d --build`.
- **Binaries:** replace the files in `/usr/local/bin/`, then
  `sudo systemctl restart iroh-relay voidwire-mailbox`.
- Keep iroh-relay on the 1.3.x line that this release names; check the
  release notes before moving to a new minor version.
- **Back up the mailbox key** (`identity.key` in the mailbox data
  directory, or the `mailbox-data` volume). It is the mailbox ID in your
  relay link. If you lose it, you get a new ID and every device has to re-add
  the link. Inbox contents are temporary and don't need a backup.
- The relay's certificate directory is re-created when needed.

## 11. Troubleshooting

| Symptom | Check |
|---|---|
| No certificate | Port 443 must reach the relay directly or via passthrough. A TLS-terminating proxy breaks TLS-ALPN-01. |
| Mailbox never comes up | Can the host reach its own public name? See NAT loopback in section 5. |
| Devices show the relay as unreachable | DNS, the port forward, and, with a token, that the device added the current link. |
| Transfers are slow | Raise `[limits.client.rx] bytes_per_second`. Open UDP 7842 for more direct connections. |
| Behind CGNAT | Inbound ports don't work. Use a tunnel or proxy you control on a host with a public address (mode B, or mode A with TCP passthrough). |
