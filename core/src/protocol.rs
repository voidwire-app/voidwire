#![forbid(unsafe_code)]
//! Fixed protocol identity (D9).
//!
//! The protocol name is **not branding**. It never changes when the product is
//! renamed, so builds with different product names always interoperate:
//! * the pairing QR URI scheme (`voidwire:pair?...`),
//! * every domain-separation tag (`voidwire/v1/...`, listed in [`DOMAIN_TAGS`]),
//! * the wire magic (`VW`).
//!
//! The public app name, bundle/package IDs, binary name, env-var prefix,
//! repo URL and publisher live in `branding.properties` (README "Renaming").

/// Fixed protocol name. Do not change: it is part of every signature, hash and
/// pairing URI.
pub const PROTOCOL_NAME: &str = "voidwire";

/// Pairing QR URI scheme (fixed, equal to the protocol name).
pub const PAIRING_URI_SCHEME: &str = PROTOCOL_NAME;

/// Protocol version carried in pairing URIs and the wire magic.
pub const PROTOCOL_VERSION: u8 = 1;

/// Every domain-separation tag in the protocol. Each one is
/// `<PROTOCOL_NAME>/v<PROTOCOL_VERSION>/<purpose>\0` (checked by a test).
pub const DOMAIN_TAGS: &[&[u8]] = &[
    crate::wire::DOMAIN_TAG_MESSAGE,
    crate::pairing::TAG_SECRET_ID,
    crate::pairing::TAG_PROOF,
    crate::pairing::TAG_SAS,
    crate::pairing::TAG_TRANSCRIPT,
    crate::replay::TAG_REPLAY,
    crate::keys::TAG_DEVICE_CERT,
    crate::envelope::TAG_ENVELOPE,
    crate::mailbox::TAG_MAILBOX_ENC,
    crate::mailbox::TAG_EPOCH_KEY,
    crate::mailbox::TAG_CONFIG,
    crate::file_transfer::TAG_FILE_OFFER,
    crate::file_transfer::TAG_FILE_KEY,
    crate::file_transfer::TAG_FILE_CHUNK,
    crate::mailbox::TAG_DEVICE_INBOX_INFO,
    crate::mailbox::TAG_DEVICE_INBOX_ID,
    crate::mailbox::TAG_DEVICE_INBOX_WRITE,
    crate::mailbox::TAG_DEVICE_INBOX_WRITE_VERIFIER,
    crate::mailbox::TAG_DEVICE_INBOX_READ,
    crate::mailbox::TAG_DEVICE_INBOX_READ_VERIFIER,
    crate::mailbox::TAG_DEVICE_INBOX_PUT,
    crate::mailbox::TAG_DEVICE_INBOX_PULL,
    crate::mailbox::TAG_DEVICE_INBOX_ACK,
];

/// ALPN for the pairing connection (QUIC/TLS, PROTOCOL §6).
pub const ALPN_PAIR: &[u8] = b"voidwire/v1/pair";
/// ALPN for paired-device traffic (sync + sends, PROTOCOL §5).
pub const ALPN_APP: &[u8] = b"voidwire/v1/app";
/// ALPN for the M2 blind group-log mailbox (PROTOCOL §7.1).
pub const ALPN_MAILBOX: &[u8] = b"voidwire/v1/mailbox";
/// TLS exporter label binding a pairing proof to its QUIC connection.
pub const EXPORTER_PAIR: &[u8] = b"voidwire/v1/pair-exporter";

/// Transport identifiers (not NUL-terminated: ALPNs and exporter labels are
/// length-delimited by TLS). Also fixed from now on.
pub const TRANSPORT_LABELS: &[&[u8]] = &[ALPN_PAIR, ALPN_APP, ALPN_MAILBOX, EXPORTER_PAIR];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_identity_is_fixed_and_consistent() {
        assert_eq!(PROTOCOL_NAME, "voidwire");
        assert_eq!(PAIRING_URI_SCHEME, "voidwire");
        let prefix = format!("{PROTOCOL_NAME}/v{PROTOCOL_VERSION}/");
        let mut seen = std::collections::HashSet::new();
        for t in DOMAIN_TAGS {
            assert!(
                t.starts_with(prefix.as_bytes()),
                "{:?}",
                String::from_utf8_lossy(t)
            );
            assert_eq!(t.last(), Some(&0), "NUL-terminated");
            assert!(seen.insert(*t), "tags must be distinct");
        }
    }

    /// The tag list is checked against the source, not maintained on trust:
    /// every `b"voidwire/v1/...\0"` byte-string literal in `core/src` (outside
    /// tests and the test harness) must be in `DOMAIN_TAGS`, and vice versa.
    #[test]
    fn domain_tag_list_matches_the_source() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let needle = format!("b\"{PROTOCOL_NAME}/v{PROTOCOL_VERSION}/");
        let mut found = std::collections::BTreeSet::new();
        let mut files = Vec::new();
        let mut dirs = vec![src];
        while let Some(d) = dirs.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    files.push(path);
                }
            }
        }
        for path in files {
            if path.extension().and_then(|e| e.to_str()) != Some("rs")
                || path.ends_with("test_util.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // Production code only: stop at the first test module.
            let prod = text.split("#[cfg(test)]").next().unwrap();
            let mut rest = prod;
            while let Some(i) = rest.find(&needle) {
                let lit = &rest[i + 2..];
                let end = lit.find('"').unwrap();
                found.insert(lit[..end].replace("\\0", "\0"));
                rest = &lit[end..];
            }
        }
        let listed: std::collections::BTreeSet<String> = DOMAIN_TAGS
            .iter()
            .chain(TRANSPORT_LABELS)
            .map(|t| String::from_utf8(t.to_vec()).unwrap())
            .collect();
        assert_eq!(
            found, listed,
            "core/src tag literals vs DOMAIN_TAGS + TRANSPORT_LABELS"
        );
        for l in TRANSPORT_LABELS {
            assert!(l.starts_with(&needle.as_bytes()[2..]) && l.last() != Some(&0));
        }
    }
}
