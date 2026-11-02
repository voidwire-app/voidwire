//! Build-kind cfgs for the release gates (D1 / TEST-PLAN ENV-17).
//!
//! These deliberately do NOT key on `debug_assertions`, which any profile can
//! toggle (`CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true`):
//!
//! * `voidwire_release_profile`: cargo's `PROFILE` is "release", i.e. the
//!   profile is `release` or inherits from it (whatever its debug settings).
//! * `voidwire_shipping`: `VOIDWIRE_SHIPPING_BUILD=1`, set by scripts/build-*.sh
//!   and CI for every artifact handed to anyone.
//!
//! It also stamps the build identity the update check needs (U1,
//! docs/UPDATES.md): `VOIDWIRE_BUILD` (the monotonic build number, the Android
//! `versionCode`), `VOIDWIRE_VERSION_NAME` and `VOIDWIRE_UPDATE_URL` (from
//! branding.properties). A source tree without those files (the mailbox image)
//! gets build 0, which turns update checks off.
fn main() {
    build_info();
    println!("cargo::rustc-check-cfg=cfg(voidwire_release_profile)");
    println!("cargo::rustc-check-cfg=cfg(voidwire_shipping)");
    println!("cargo::rerun-if-env-changed=VOIDWIRE_SHIPPING_BUILD");
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        println!("cargo::rustc-cfg=voidwire_release_profile");
    }
    if std::env::var("VOIDWIRE_SHIPPING_BUILD").as_deref() == Ok("1") {
        println!("cargo::rustc-cfg=voidwire_shipping");
    }
}

fn build_info() {
    let dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let gradle = dir.join("../android/app/build.gradle.kts");
    let branding = dir.join("../branding.properties");
    let mut build = 0u32;
    let mut name = String::new();
    if let Ok(text) = std::fs::read_to_string(&gradle) {
        println!("cargo::rerun-if-changed={}", gradle.display());
        for line in text.lines().map(str::trim) {
            if let Some(v) = line.strip_prefix("versionCode = ") {
                build = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("versionName = ") {
                name = v.trim().trim_matches('"').to_owned();
            }
        }
    }
    let (mut url, mut repo) = (String::new(), String::new());
    if let Ok(text) = std::fs::read_to_string(&branding) {
        println!("cargo::rerun-if-changed={}", branding.display());
        for line in text.lines().map(str::trim) {
            if let Some(v) = line.strip_prefix("UPDATE_URL=") {
                url = v.trim().to_owned();
            } else if let Some(v) = line.strip_prefix("REPO_URL=") {
                repo = v.trim().to_owned();
            }
        }
    }
    if name.is_empty() {
        build = 0;
    }
    println!("cargo::rustc-env=VOIDWIRE_BUILD={build}");
    println!("cargo::rustc-env=VOIDWIRE_VERSION_NAME={name}");
    println!("cargo::rustc-env=VOIDWIRE_UPDATE_URL={url}");
    println!("cargo::rustc-env=VOIDWIRE_REPO_URL={repo}");
}
