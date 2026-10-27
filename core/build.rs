//! Build-kind cfgs for the release gates (D1 / TEST-PLAN ENV-17).
//!
//! These deliberately do NOT key on `debug_assertions`, which any profile can
//! toggle (`CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true`):
//!
//! * `voidwire_release_profile`: cargo's `PROFILE` is "release", i.e. the
//!   profile is `release` or inherits from it (whatever its debug settings).
//! * `voidwire_shipping`: `VOIDWIRE_SHIPPING_BUILD=1`, set by scripts/build-*.sh
//!   and CI for every artifact handed to anyone.
fn main() {
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
