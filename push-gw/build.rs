//! Env var prefix from the single-source branding (../branding.properties, D9).
fn main() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../branding.properties");
    println!("cargo:rerun-if-changed={path}");
    let text = std::fs::read_to_string(path).expect("read branding.properties");
    let prefix = text
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("ENV_PREFIX="))
        .expect("ENV_PREFIX in branding.properties")
        .trim();
    assert!(
        !prefix.is_empty()
            && prefix
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
        "ENV_PREFIX must be [A-Z0-9_]+"
    );
    println!("cargo:rustc-env=VOIDWIRE_BRAND_ENV_PREFIX={prefix}");
}
