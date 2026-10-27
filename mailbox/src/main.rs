#![forbid(unsafe_code)]
//! `voidwire-mailbox` CLI entry point (`docs/M2-PLAN.md` §3.2).

use std::net::SocketAddr;
use std::path::PathBuf;

use voidwire_core::keys::DeviceKeypair;
use voidwire_core::mailbox::SignedConfig;
use voidwire_core::net::DEFAULT_RELAY_URL;
use voidwire_mailbox::{
    MailboxLimits, MailboxServer, MailboxServerConfig, DEFAULT_HEALTHZ_ADDR, DEFAULT_LOG_LEVEL,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
struct CliConfig {
    data_dir: PathBuf,
    key_path: PathBuf,
    relay_url: String,
    healthz_bind: Option<SocketAddr>,
    signed_config_path: Option<PathBuf>,
    limits: MailboxLimits,
    log: String,
    print_id: bool,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/voidwire-mailbox"),
            key_path: PathBuf::from("/var/lib/voidwire-mailbox/identity.key"),
            relay_url: DEFAULT_RELAY_URL.to_owned(),
            healthz_bind: Some(DEFAULT_HEALTHZ_ADDR.parse().expect("valid loopback addr")),
            signed_config_path: None,
            limits: MailboxLimits::default(),
            log: DEFAULT_LOG_LEVEL.to_owned(),
            print_id: false,
        }
    }
}

fn parse_toml_file(path: &std::path::Path, cfg: &mut CliConfig) -> Result<(), String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_toml_text(&text, cfg)
}

fn parse_u32_val(key: &str, val: &str) -> Result<u32, String> {
    val.replace('_', "")
        .parse::<u32>()
        .map_err(|e| format!("invalid {key} '{val}': {e}"))
}

fn parse_usize_val(key: &str, val: &str) -> Result<usize, String> {
    val.replace('_', "")
        .parse::<usize>()
        .map_err(|e| format!("invalid {key} '{val}': {e}"))
}

fn parse_u64_val(key: &str, val: &str) -> Result<u64, String> {
    val.replace('_', "")
        .parse::<u64>()
        .map_err(|e| format!("invalid {key} '{val}': {e}"))
}

fn parse_toml_text(text: &str, cfg: &mut CliConfig) -> Result<(), String> {
    let mut explicit_key_path = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("malformed config line: {line}"));
        };
        let key = k.trim();
        let val = v.trim().trim_matches('"').trim_matches('\'');
        match key {
            "ip_transports" => {
                if val != "false" {
                    return Err(
                        "ip_transports must be false for relay-only voidwire-mailbox".into(),
                    );
                }
            }
            "data_dir" | "store_dir" => {
                cfg.data_dir = PathBuf::from(val);
                if !explicit_key_path {
                    cfg.key_path = cfg.data_dir.join("identity.key");
                }
            }
            "key_path" => {
                cfg.key_path = PathBuf::from(val);
                explicit_key_path = true;
            }
            "relay_url" => cfg.relay_url = val.to_owned(),
            "healthz_bind" | "health_bind_addr" => {
                if val.is_empty() || val.eq_ignore_ascii_case("off") {
                    cfg.healthz_bind = None;
                } else {
                    cfg.healthz_bind = Some(
                        val.parse::<SocketAddr>()
                            .map_err(|e| format!("invalid {key} '{val}': {e}"))?,
                    );
                }
            }
            "signed_config_path" => {
                cfg.signed_config_path = if val.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(val))
                };
            }
            "max_mailbox_bytes" => cfg.limits.max_mailbox_bytes = parse_usize_val(key, val)?,
            "max_records" => cfg.limits.max_records = parse_usize_val(key, val)?,
            "max_record_bytes" => cfg.limits.max_record_bytes = parse_usize_val(key, val)?,
            "appends_per_min" => cfg.limits.appends_per_min = parse_u32_val(key, val)?,
            "append_burst" => cfg.limits.append_burst = parse_u32_val(key, val)?,
            "retention_days" => cfg.limits.retention_days = parse_u32_val(key, val)?,
            "per_ip_reads_per_min" => cfg.limits.per_ip_reads_per_min = parse_u32_val(key, val)?,
            "per_ip_appends_per_min" => {
                cfg.limits.per_ip_appends_per_min = parse_u32_val(key, val)?
            }
            "global_reads_per_min" => cfg.limits.global_reads_per_min = parse_u32_val(key, val)?,
            "global_appends_per_min" => {
                cfg.limits.global_appends_per_min = parse_u32_val(key, val)?
            }
            "max_mailboxes" => cfg.limits.max_mailboxes = parse_usize_val(key, val)?,
            "max_relay_file_bytes" => cfg.limits.max_relay_file_bytes = parse_u64_val(key, val)?,
            "log" => cfg.log = val.to_owned(),
            other => return Err(format!("unknown config key: {other}")),
        }
    }
    Ok(())
}

fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<CliConfig, String> {
    let mut cfg = CliConfig::default();
    let mut explicit_key_path = false;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => {
                let p = it.next().ok_or("--config requires a path")?;
                parse_toml_file(std::path::Path::new(&p), &mut cfg)?;
            }
            "--data-dir" | "--store-dir" => {
                let p = it.next().ok_or("--data-dir requires a path")?;
                cfg.data_dir = PathBuf::from(&p);
                if !explicit_key_path {
                    cfg.key_path = cfg.data_dir.join("identity.key");
                }
            }
            "--key-path" => {
                let p = it.next().ok_or("--key-path requires a path")?;
                cfg.key_path = PathBuf::from(p);
                explicit_key_path = true;
            }
            "--relay-url" => {
                cfg.relay_url = it.next().ok_or("--relay-url requires a URL")?;
            }
            "--healthz-bind" => {
                let v = it.next().ok_or("--healthz-bind requires an addr")?;
                if v.eq_ignore_ascii_case("off") {
                    cfg.healthz_bind = None;
                } else {
                    cfg.healthz_bind = Some(
                        v.parse()
                            .map_err(|e| format!("invalid --healthz-bind: {e}"))?,
                    );
                }
            }
            "--signed-config" => {
                cfg.signed_config_path = Some(PathBuf::from(
                    it.next().ok_or("--signed-config requires a path")?,
                ));
            }
            "--max-relay-file-bytes" => {
                let v = it
                    .next()
                    .ok_or("--max-relay-file-bytes requires a byte count")?;
                cfg.limits.max_relay_file_bytes = parse_u64_val("--max-relay-file-bytes", &v)?;
            }
            "--log" => {
                cfg.log = it.next().ok_or("--log requires a level")?;
            }
            "--print-id" => {
                cfg.print_id = true;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if let Ok(env_val) = std::env::var("VOIDWIRE_MAX_RELAY_FILE_BYTES") {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            cfg.limits.max_relay_file_bytes =
                parse_u64_val("VOIDWIRE_MAX_RELAY_FILE_BYTES", trimmed)?;
        }
    }
    Ok(cfg)
}

fn load_or_create_secret_key(path: &std::path::Path) -> Result<Zeroizing<[u8; 32]>, String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            voidwire_core::net::state::private_dir(parent)
                .map_err(|e| format!("key parent dir: {e}"))?;
        }
    }
    if path.exists() {
        let raw = Zeroizing::new(
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?,
        );
        let hex = raw.trim();
        if hex.len() != 64 {
            return Err("identity.key must be 64 hex chars".into());
        }
        let mut sk = Zeroizing::new([0u8; 32]);
        for i in 0..32 {
            sk[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| "invalid hex in identity.key".to_owned())?;
        }
        return Ok(sk);
    }
    let kp = DeviceKeypair::generate();
    let sk = kp.secret_bytes();
    let mut hex = Zeroizing::new(String::with_capacity(65));
    for b in sk.iter() {
        use std::fmt::Write;
        let _ = write!(&mut *hex, "{b:02x}");
    }
    hex.push('\n');

    let tmp_path = path.with_extension("key.tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp_path)
            .map_err(|e| format!("open {}: {e}", tmp_path.display()))?;
        f.write_all(hex.as_bytes())
            .map_err(|e| format!("write {}: {e}", tmp_path.display()))?;
        f.sync_all()
            .map_err(|e| format!("sync {}: {e}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp_path.display(), path.display()))?;
    Ok(sk)
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = parse_args(args).map_err(|e| format!("voidwire-mailbox config error: {e}"))?;

    let secret_key = load_or_create_secret_key(&cli.key_path)
        .map_err(|e| format!("voidwire-mailbox key error: {e}"))?;

    if cli.print_id {
        let kp = DeviceKeypair::from_secret_bytes(&secret_key);
        println!("{}", kp.device_id().to_hex());
        return Ok(());
    }

    let signed_config = match &cli.signed_config_path {
        Some(p) => {
            let bytes = std::fs::read(p)
                .map_err(|e| format!("voidwire-mailbox signed_config error: {e}"))?;
            let sc = SignedConfig::decode(&bytes)
                .map_err(|e| format!("voidwire-mailbox signed_config decode error: {e}"))?;
            Some(sc)
        }
        None => None,
    };

    let server = MailboxServer::start(MailboxServerConfig {
        secret_key: *secret_key,
        relay_url: cli.relay_url,
        data_dir: Some(cli.data_dir),
        healthz_addr: cli.healthz_bind,
        signed_config,
        limits: cli.limits,
        log: cli.log,
    })
    .await
    .map_err(|e| format!("voidwire-mailbox start error: {e}"))?;

    wait_for_shutdown_signal().await;
    server.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_log_level_is_off_and_cli_parses_toml() {
        let def = CliConfig::default();
        assert_eq!(def.log, "off");

        let mut cfg = CliConfig::default();
        parse_toml_text(
            r#"
            # Voidwire mailbox config
            data_dir = "/tmp/vw-mbx"
            key_path = "/tmp/vw-mbx/id.key"
            relay_url = "https://relay.voidwire.app"
            healthz_bind = "127.0.0.1:48486"
            log = "off"
            "#,
            &mut cfg,
        )
        .unwrap();
        assert_eq!(cfg.data_dir, PathBuf::from("/tmp/vw-mbx"));
        assert_eq!(cfg.key_path, PathBuf::from("/tmp/vw-mbx/id.key"));
        assert_eq!(cfg.relay_url, "https://relay.voidwire.app");
        assert_eq!(cfg.log, "off");
    }

    #[test]
    fn deploy_mailbox_toml_parses_cleanly_and_unknown_keys_error() {
        let deploy_toml = include_str!("../../ops/relay/mailbox.toml");
        let mut cfg = CliConfig::default();
        parse_toml_text(deploy_toml, &mut cfg).expect("ops/relay/mailbox.toml must parse cleanly");
        assert_eq!(
            cfg.data_dir,
            PathBuf::from("/var/lib/private/voidwire-mailbox")
        );
        assert_eq!(
            cfg.key_path,
            PathBuf::from("/var/lib/private/voidwire-mailbox/identity.key")
        );
        assert_eq!(
            cfg.healthz_bind,
            Some("127.0.0.1:48486".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(cfg.limits.max_mailbox_bytes, 1_048_576);
        assert_eq!(cfg.limits.max_records, 512);
        assert_eq!(cfg.limits.max_record_bytes, 8_448);
        assert_eq!(cfg.limits.appends_per_min, 20);
        assert_eq!(cfg.limits.append_burst, 20);
        assert_eq!(cfg.limits.retention_days, 180);
        assert_eq!(cfg.limits.per_ip_reads_per_min, 60);
        assert_eq!(cfg.limits.per_ip_appends_per_min, 30);
        assert_eq!(cfg.limits.max_mailboxes, 10_000);
        assert_eq!(cfg.log, "off");

        let mut bad = CliConfig::default();
        assert!(
            parse_toml_text("nonexistent_option = 123\n", &mut bad).is_err(),
            "unknown config key must return error"
        );
    }

    #[test]
    fn load_or_create_secret_key_writes_0600_atomically() {
        let dir = std::env::temp_dir().join(format!(
            "vw-key-test-{}",
            DeviceKeypair::generate().device_id().short()
        ));
        let key_path = dir.join("identity.key");
        let sk1 = load_or_create_secret_key(&key_path).expect("create identity.key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "identity.key must be 0600");
        }
        let sk2 = load_or_create_secret_key(&key_path).expect("reload identity.key");
        assert_eq!(*sk1, *sk2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
