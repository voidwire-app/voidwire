# Self-Hosting the Voidwire Relay & Blind Group-Log Mailbox

Voidwire is end-to-end encrypted (`X25519` + `ChaCha20-Poly1305` HPKE + `Ed25519` sender authentication) regardless of which relay routes the ciphertext. You can run your own `iroh-relay` and `voidwire-mailbox` on any Linux VPS and point both the Voidwire Desktop app and Android app to your custom server.

---

## 1. Architecture Overview

A Voidwire relay node runs two unprivileged `systemd` services (`DynamicUser=yes`, `StandardOutput=null`, `StandardError=null`, `RUST_LOG=off`):

1. **`iroh-relay` (v1.3.0):**
   - Terminates TLS on TCP `443` (with built-in Let's Encrypt `TLS-ALPN-01` ACME — no port 80 listener required on the public interface) and QUIC address discovery (`QAD`) on UDP `7842`.
   - Forwards end-to-end encrypted QUIC streams between paired devices when direct UDP hole-punching (`STUN`/`QAD`) cannot traverse a symmetric NAT or firewall.
   - To increase or remove per-client relay throughput limits for large files on your own server, adjust `[limits.client.rx]` (`bytes_per_second` and `max_burst_bytes`) in `/etc/iroh-relay/config.toml`.

2. **`voidwire-mailbox`:**
   - Connects **outbound only** to your local `iroh-relay` (`ip_transports = false`, zero public UDP/TCP ports).
   - Stores opaque, fixed-padded (`8,448` byte), HPKE-sealed group-log records (`PairPhone`, `RemovePhone`, `RenameDevice`, `RotateGroupKey`) keyed by an unlinkable blinded `MailboxId` (`HKDF-SHA256(k_group, "voidwire/v1/mailbox-id")`).
   - Holds **no decryption keys** and never sees device names, roster membership, URLs, or files.

---

## 2. Prerequisites & DNS

1. A Linux x86_64 server (Debian 12 / Ubuntu 24.04 recommended) with a public IPv4 (and optional IPv6) address.
2. A DNS `A` (and optional `AAAA`) record pointing your hostname (e.g., `relay.example.com`) to the server's public IP.
3. Inbound firewall allowing **TCP `443`** and **UDP `7842`** (see `nftables.conf`).

---

## 3. Installing Binaries

### 3.1 `voidwire-mailbox`
Download `voidwire-mailbox-linux-x86_64` from the Voidwire GitHub release (and verify against `SHA256SUMS`), or build from source:

```bash
cargo build --release -p voidwire-mailbox
sudo install -m 0755 target/release/voidwire-mailbox /usr/local/bin/voidwire-mailbox
```

### 3.2 `iroh-relay` (v1.3.0)
Install `iroh-relay` 1.3.0 from source:

```bash
cargo install iroh-relay --version 1.3.0 --locked
sudo install -m 0755 ~/.cargo/bin/iroh-relay /usr/local/bin/iroh-relay
```

---

## 4. Configuration & Generating Your Mailbox Endpoint ID

1. Copy the configuration templates into `/etc`:

```bash
sudo install -d -m 0755 /etc/iroh-relay /etc/voidwire-mailbox
sudo install -m 0644 relay.toml /etc/iroh-relay/config.toml
sudo install -m 0644 mailbox.toml /etc/voidwire-mailbox/config.toml
```

2. Edit `/etc/iroh-relay/config.toml`:
   - Set `hostname = "relay.example.com"` and `contact = "you@example.com"`.
   - Optionally tune `[limits.client.rx]` (`bytes_per_second` / `max_burst_bytes`) for your desired relay file transfer speed.

3. Edit `/etc/voidwire-mailbox/config.toml`:
   - Set `relay_url = "https://relay.example.com"`.
   - Set `max_relay_file_bytes` (default `26214400` = 25 MiB; set `0` for unlimited up to 2 GiB, or override via `--max-relay-file-bytes` / `VOIDWIRE_MAX_RELAY_FILE_BYTES`). `voidwire-mailbox` advertises this limit in `PULL_RESP` and `PUSH_ACK` so connected clients enforce it up front before starting a relayed file transfer.

4. Install and start the `systemd` services:

```bash
sudo install -m 0644 iroh-relay.service /etc/systemd/system/iroh-relay.service
sudo install -m 0644 voidwire-mailbox.service /etc/systemd/system/voidwire-mailbox.service
sudo systemctl daemon-reload
sudo systemctl enable --now iroh-relay.service
sudo systemctl enable --now voidwire-mailbox.service
```

5. **Read your 64-hex Mailbox Endpoint ID:**
   On first start, `voidwire-mailbox` automatically generates a fresh Ed25519 identity key at `/var/lib/private/voidwire-mailbox/identity.key` (`0600`). Print its 64-character hex `EndpointId`:

```bash
sudo /usr/local/bin/voidwire-mailbox --config /etc/voidwire-mailbox/config.toml --print-id
```

This prints a 64-character hex string (for example, `a1b2c3...`). Save this value for Step 5.

Or print a relay link (your relay URL plus this mailbox ID) to paste into **Settings → Relays** on each device:

```bash
sudo /usr/local/bin/voidwire-mailbox --config /etc/voidwire-mailbox/config.toml --print-relay-link
# -> voidwire:relay?r=https%3A%2F%2Frelay.example.org&m=a1b2c3...
```

Inbox size: the public relay keeps at most 4 items per device inbox. A self-hosted mailbox can change this with `inbox_max_items` (1–256) in the config or `--inbox-max-items`.

6. **Verify local health:**

```bash
curl -fsS http://127.0.0.1:48486/healthz
# -> ok
```

---

## 5. Configuring Voidwire Desktop & Android Clients

1. **Voidwire Desktop (`Settings` -> `File transfers & relay` -> `Relay server URL & mailbox ID`):**
   - Enter your Relay server URL: `https://relay.example.com`
   - Enter your 64-hex Mailbox Endpoint ID from Step 4.5.
   - Click **Save**. Future pairing QR codes minted by this PC will automatically include `&r=https://relay.example.com`.

2. **Voidwire Android (`Settings` -> `File transfers & relay` -> `Configure relay…`):**
   - Tap **Configure relay…**.
   - Enter `https://relay.example.com` and your 64-hex Mailbox Endpoint ID.
   - Tap **Apply**.

To revert to the official Voidwire relay and blind mailbox at any time, click **Reset** in Desktop or Android Settings.
