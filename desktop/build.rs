//! Reads the single-source branding (../branding.properties) and injects the
//! product name, bundle identifier, binary name, publisher and homepage into
//! the Tauri config via TAURI_CONFIG, which tauri-build and
//! `tauri::generate_context!` merge over tauri.conf.json. Also exposes
//! `VOIDWIRE_BRAND_ENV_PREFIX` to the crate (env var prefix).

use std::collections::HashMap;

fn branding() -> HashMap<String, String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../branding.properties");
    println!("cargo:rerun-if-changed={path}");
    let text = std::fs::read_to_string(path).expect("read branding.properties");
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

fn main() {
    let b = branding();
    let get = |k: &str| {
        b.get(k)
            .unwrap_or_else(|| panic!("{k} missing from branding.properties"))
            .clone()
    };
    let mut cfg: serde_json::Value = std::env::var("TAURI_CONFIG")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    cfg["productName"] = get("APP_NAME").into();
    cfg["identifier"] = get("BUNDLE_ID").into();
    cfg["mainBinaryName"] = get("BINARY_NAME").into();
    if !cfg["bundle"].is_object() {
        cfg["bundle"] = serde_json::json!({});
    }
    cfg["bundle"]["publisher"] = get("PUBLISHER").into();
    cfg["bundle"]["homepage"] = get("REPO_URL").into();
    println!(
        "cargo:rustc-env=VOIDWIRE_BRAND_ENV_PREFIX={}",
        get("ENV_PREFIX")
    );
    let cfg = cfg.to_string();
    std::env::set_var("TAURI_CONFIG", &cfg);
    println!("cargo:rustc-env=TAURI_CONFIG={cfg}");
    println!("cargo:rerun-if-env-changed=TAURI_CONFIG");
    // Every app command gets allow-/deny- permissions; capabilities/*.json
    // grant each window only its own (nothing is allowed by default).
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "pair_start",
            "pair_status",
            "pair_submit_code",
            "pair_cancel",
            "pair_pause",
            "devices_list",
            "device_forget",
            "settings_get",
            "settings_set_no_prompt",
            "settings_set_diagnostics",
            "settings_set_theme",
            "open_pair_window",
            "pair2_relays",
            "pair2_show",
            "pair2_status",
            "pair2_submit_code",
            "pair2_open_code",
            "pair2_add_relay",
            "pair2_join",
            "pair2_join_wait",
            "pair2_cancel",
            "pair2_copy_code",
            "open_pair2_window",
            "pending_list",
            "pending_decide",
            "settings_set_connection_stats",
            "connection_stats_list",
            "settings_set_relay_cap",
            "settings_set_never_relay_files",
            "settings_set_file_history",
            "completed_files_clear",
            "settings_set_relay_config",
            "settings_set_pc_name",
            "settings_set_download_dir",
            "pick_download_dir",
            "incoming_files_list",
            "completed_files_list",
            "incoming_file_decide",
            "accept_file",
            "cancel_file",
            "settings_set_auto_copy_clipboard",
            "settings_set_send_clipboard_shortcut",
            "settings_set_send_clipboard_shortcut_accel",
            "set_drop_target_phone",
            "pending_clipboards_list",
            "pending_clipboard_decide",
            "send_clipboard_to_phone",
            "send_text_to_phone",
            "send_file_to_phone_pick",
            "outgoing_files_list",
            "cancel_outgoing_file",
            "settings_set_context_menu",
            "relays_list",
            "relays_add",
            "relays_remove",
            "relays_rename",
            "relays_retry",
            "relays_set_home",
            "pairing_relays",
            "relay_change_propose",
            "relay_changes",
            "relay_change_answer",
        ]),
    ))
    .expect("tauri build")
}
