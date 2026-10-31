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
| `docker/compose.yml` | relay and mailbox with Docker |
| `docker/relay.toml` | relay, own TLS (mode A) |
| `docker/relay-behind-https-proxy.toml` | relay behind an HTTPS-terminating proxy (mode B) |
| `docker/mailbox.toml` | mailbox in the container |
| `docker/Dockerfile.mailbox` | builds the mailbox image |
