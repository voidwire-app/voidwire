# Relay and mailbox files

The setup guide is [docs/self-host-relay.md](../../docs/self-host-relay.md).

| File | Use |
|---|---|
| `relay.toml` | iroh-relay config, own TLS (systemd) |
| `mailbox.toml`, `mailbox.toml.example` | voidwire-mailbox config (systemd) |
| `iroh-relay.service`, `voidwire-mailbox.service` | hardened systemd units, no logs |
| `journald-volatile.conf` | keep any system logs in RAM only |
| `nftables.conf` | example firewall: TCP 443, UDP 7842 |
| `99-voidwire-hardening.conf`, `zram-generator.conf` | optional host tuning |
| `docker/compose.yml` | relay, setup and mailbox from published images (release bundle: `voidwire-relay-docker.tar.gz`) |
| `docker/compose.build.yml` | add-on: build the mailbox image from this repo |
| `docker/compose.override.example.yml` | template for your own compose changes |
| `docker/config/relay.toml` | relay, own TLS (mode A); token filled in by setup |
| `docker/config/relay-behind-https-proxy.toml` | relay behind an HTTPS-terminating proxy (mode B) |
| `docker/config/mailbox.toml` | mailbox in the container |
| `docker/voidwire-relay-setup` | the setup service: token, generated relay config, data folder owners |
| `docker/Dockerfile.mailbox` | builds the mailbox image (`ghcr.io/voidwire-app/voidwire-mailbox`) |
