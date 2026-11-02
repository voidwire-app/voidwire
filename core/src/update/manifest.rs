//! The channel manifest (U1): parsing and the acceptance rules.
//!
//! ```json
//! { "schema": 1, "channel": "test", "seq": 1793500000, "version": "0.9.8-m4.7",
//!   "build": 34, "released": "2026-11-05",
//!   "notes_url": "https://github.com/<org>/<repo>/releases/tag/v0.9.8-m4.7",
//!   "files": { "windows-x86_64-nsis": { "url": "…", "sha256": "…", "size": 9876543 } } }
//! ```
//!
//! A manifest is accepted only if (in this order) its signature verifies
//! against a key pinned for the channel, `schema` is 1, `channel` is the one
//! asked for, `seq` is at least the highest seen for that channel, and
//! `build` is above the installed build (else "up to date"; a downgrade is
//! never offered). A platform with no entry is "up to date".

use super::policy::{Channel, UpdatePrefs};
use super::sig::{self, PublicKey};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Hard cap on an update file (a bad manifest can't fill the disk).
pub const MAX_FILE_SIZE: u64 = 200 * 1024 * 1024;
/// Cap on the manifest and signature downloads.
pub const MAX_MANIFEST_SIZE: usize = 64 * 1024;

/// Where release files may come from (and redirects may go).
pub const FILE_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

/// One installable file kind per platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    WindowsNsis,
    AndroidApk,
    LinuxAppImage,
    LinuxDeb,
    MacOs,
}

impl Platform {
    pub fn key(self) -> &'static str {
        match self {
            Platform::WindowsNsis => "windows-x86_64-nsis",
            Platform::AndroidApk => "android-apk",
            Platform::LinuxAppImage => "linux-x86_64-appimage",
            Platform::LinuxDeb => "linux-x86_64-deb",
            Platform::MacOs => "macos",
        }
    }

    /// Whether the app installs this kind itself; the others get a
    /// "Download" button that opens the release page.
    pub fn installs_in_app(self) -> bool {
        matches!(
            self,
            Platform::WindowsNsis | Platform::AndroidApk | Platform::LinuxAppImage
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    #[error("network")]
    Network,
    #[error("signature")]
    Signature,
    #[error("format")]
    Format,
    #[error("channel")]
    Channel,
    #[error("rollback")]
    Rollback,
    #[error("unavailable")]
    Unavailable,
}

impl CheckError {
    /// One word for the Diagnostics line (D8): no URL, no address.
    pub fn kind(self) -> &'static str {
        match self {
            CheckError::Network => "network",
            CheckError::Signature => "signature",
            CheckError::Format => "format",
            CheckError::Channel => "channel",
            CheckError::Rollback => "rollback",
            CheckError::Unavailable => "unavailable",
        }
    }
}

#[derive(Deserialize)]
struct RawManifest {
    schema: u32,
    channel: String,
    seq: u64,
    version: String,
    build: u32,
    #[serde(default)]
    released: String,
    notes_url: String,
    files: BTreeMap<String, RawFile>,
}

#[derive(Deserialize)]
struct RawFile {
    url: String,
    sha256: String,
    size: u64,
}

/// A verified update for this platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub channel: Channel,
    pub seq: u64,
    pub version: String,
    pub build: u32,
    pub released: String,
    pub platform: Platform,
    pub url: String,
    pub sha256: [u8; 32],
    pub size: u64,
    pub notes_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    UpToDate,
    Available(Offer),
}

/// What the acceptance rules need to know about this install.
pub struct Context<'a> {
    pub channel: Channel,
    pub keys: &'a [PublicKey],
    pub installed_build: u32,
    pub platform: Platform,
    /// Allowed hosts for file URLs ([`FILE_HOSTS`] in the app).
    pub hosts: &'a [&'a str],
    /// The project page prefix `notes_url` must start with.
    pub notes_prefix: &'a str,
    /// Tests serve files over plain http from 127.0.0.1.
    pub allow_http: bool,
}

/// Whether `url` is https (or http when allowed) on one of `hosts`.
pub(crate) fn url_allowed(url: &str, hosts: &[&str], allow_http: bool) -> bool {
    let Ok(u) = url::Url::parse(url) else {
        return false;
    };
    let scheme_ok = u.scheme() == "https" || (allow_http && u.scheme() == "http");
    let host_ok = u
        .host_str()
        .is_some_and(|h| hosts.iter().any(|a| a.eq_ignore_ascii_case(h)));
    scheme_ok && host_ok && u.username().is_empty() && u.password().is_none()
}

/// Apply the acceptance rules to a fetched manifest and its signature.
/// Updates `prefs.seen_seq` when the manifest is accepted.
pub fn evaluate(
    manifest: &[u8],
    sig_text: &str,
    ctx: &Context<'_>,
    prefs: &mut UpdatePrefs,
) -> Result<Verdict, CheckError> {
    sig::verify(ctx.keys, manifest, sig_text).map_err(|_| CheckError::Signature)?;
    let m: RawManifest = serde_json::from_slice(manifest).map_err(|_| CheckError::Format)?;
    if m.schema != 1 {
        return Err(CheckError::Format);
    }
    if m.channel != ctx.channel.name() {
        return Err(CheckError::Channel);
    }
    if m.seq < prefs.seen_seq(ctx.channel) {
        return Err(CheckError::Rollback);
    }
    prefs.note_seq(ctx.channel, m.seq);
    if m.build <= ctx.installed_build {
        return Ok(Verdict::UpToDate);
    }
    let Some(f) = m.files.get(ctx.platform.key()) else {
        return Ok(Verdict::UpToDate);
    };
    let sha256 = crate::hex::decode_array::<32>(&f.sha256).ok_or(CheckError::Format)?;
    if f.size == 0
        || f.size > MAX_FILE_SIZE
        || !url_allowed(&f.url, ctx.hosts, ctx.allow_http)
        || !m.notes_url.starts_with(ctx.notes_prefix)
        || !url_allowed(&m.notes_url, &["github.com"], false)
        || m.version.is_empty()
        || m.version.len() > 64
        || !m
            .version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+".contains(c))
    {
        return Err(CheckError::Format);
    }
    Ok(Verdict::Available(Offer {
        channel: ctx.channel,
        seq: m.seq,
        version: m.version,
        build: m.build,
        released: m.released.chars().take(32).collect(),
        platform: ctx.platform,
        url: f.url.clone(),
        sha256,
        size: f.size,
        notes_url: m.notes_url,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [3; 32];
    const OTHER_SEED: [u8; 32] = [4; 32];
    const NOTES: &str = "https://github.com/voidwire-app/voidwire/releases/";

    fn manifest(channel: &str, seq: u64, build: u32) -> Vec<u8> {
        format!(
            r#"{{"schema":1,"channel":"{channel}","seq":{seq},"version":"0.9.8-m4.7","build":{build},
"released":"2026-11-05","notes_url":"{NOTES}tag/v0.9.8-m4.7",
"files":{{"windows-x86_64-nsis":{{"url":"https://github.com/voidwire-app/voidwire/releases/download/v0.9.8-m4.7/setup.exe",
"sha256":"{}","size":1000}}}}}}"#,
            "ab".repeat(32)
        )
        .into_bytes()
    }

    fn ctx(keys: &[PublicKey]) -> Context<'_> {
        Context {
            channel: Channel::Test,
            keys,
            installed_build: 33,
            platform: Platform::WindowsNsis,
            hosts: FILE_HOSTS,
            notes_prefix: NOTES,
            allow_http: false,
        }
    }

    #[test]
    fn accepts_a_signed_newer_build() {
        let keys = [sig::public_key(&TEST_SEED)];
        let m = manifest("test", 100, 34);
        let s = sig::sign(&TEST_SEED, &m);
        let mut p = UpdatePrefs::default();
        let Ok(Verdict::Available(o)) = evaluate(&m, &s, &ctx(&keys), &mut p) else {
            panic!("not offered")
        };
        assert_eq!((o.build, o.size, o.sha256), (34, 1000, [0xab; 32]));
        assert_eq!(p.seen_seq(Channel::Test), 100);
    }

    #[test]
    fn signature_rules() {
        let keys = [sig::public_key(&TEST_SEED)];
        let m = manifest("test", 100, 34);
        let mut p = UpdatePrefs::default();
        // Wrong key, tampered bytes, no signature.
        let other = sig::sign(&OTHER_SEED, &m);
        assert_eq!(
            evaluate(&m, &other, &ctx(&keys), &mut p),
            Err(CheckError::Signature)
        );
        let s = sig::sign(&TEST_SEED, &m);
        let mut t = m.clone();
        t[20] ^= 1;
        assert_eq!(
            evaluate(&t, &s, &ctx(&keys), &mut p),
            Err(CheckError::Signature)
        );
        assert_eq!(
            evaluate(&m, "", &ctx(&keys), &mut p),
            Err(CheckError::Signature)
        );
        // No pinned key (a stable build before the stable key exists).
        assert_eq!(
            evaluate(&m, &s, &ctx(&[]), &mut p),
            Err(CheckError::Signature)
        );
        // Nothing stored from a rejected manifest.
        assert_eq!(p, UpdatePrefs::default());
        // A second pinned key also works (rotation).
        let two = [sig::public_key(&OTHER_SEED), sig::public_key(&TEST_SEED)];
        assert!(matches!(
            evaluate(&m, &s, &ctx(&two), &mut p),
            Ok(Verdict::Available(_))
        ));
    }

    #[test]
    fn rollback_rules() {
        let keys = [sig::public_key(&TEST_SEED)];
        let mut p = UpdatePrefs::default();
        p.note_seq(Channel::Test, 100);
        // Older seq: a replayed manifest is refused.
        let old = manifest("test", 99, 35);
        let s = sig::sign(&TEST_SEED, &old);
        assert_eq!(
            evaluate(&old, &s, &ctx(&keys), &mut p),
            Err(CheckError::Rollback)
        );
        // Same seq is fine.
        let same = manifest("test", 100, 34);
        let s = sig::sign(&TEST_SEED, &same);
        assert!(matches!(
            evaluate(&same, &s, &ctx(&keys), &mut p),
            Ok(Verdict::Available(_))
        ));
        // Same or lower build: up to date, never a downgrade.
        for b in [33, 20, 0] {
            let m = manifest("test", 101, b);
            let s = sig::sign(&TEST_SEED, &m);
            assert_eq!(evaluate(&m, &s, &ctx(&keys), &mut p), Ok(Verdict::UpToDate));
        }
        assert_eq!(p.seen_seq(Channel::Test), 101);
    }

    #[test]
    fn channel_must_match() {
        let keys = [sig::public_key(&TEST_SEED)];
        let m = manifest("stable", 100, 34);
        let s = sig::sign(&TEST_SEED, &m);
        let mut p = UpdatePrefs::default();
        assert_eq!(
            evaluate(&m, &s, &ctx(&keys), &mut p),
            Err(CheckError::Channel)
        );
    }

    #[test]
    fn platform_size_and_hosts() {
        let keys = [sig::public_key(&TEST_SEED)];
        let mut p = UpdatePrefs::default();
        let m = manifest("test", 1, 34);
        let s = sig::sign(&TEST_SEED, &m);
        let mut c = ctx(&keys);
        c.platform = Platform::AndroidApk;
        assert_eq!(evaluate(&m, &s, &c, &mut p), Ok(Verdict::UpToDate));
        let bad = |from: &str, to: &str| {
            let m = String::from_utf8(manifest("test", 1, 34))
                .unwrap()
                .replace(from, to);
            let s = sig::sign(&TEST_SEED, m.as_bytes());
            evaluate(m.as_bytes(), &s, &ctx(&keys), &mut UpdatePrefs::default())
        };
        assert_eq!(
            bad("\"size\":1000", "\"size\":209715201"),
            Err(CheckError::Format)
        );
        assert_eq!(bad("\"size\":1000", "\"size\":0"), Err(CheckError::Format));
        assert_eq!(
            bad(
                "https://github.com/voidwire-app/voidwire/releases/download",
                "https://evil.example/x"
            ),
            Err(CheckError::Format)
        );
        assert_eq!(
            bad(
                "https://github.com/voidwire-app/voidwire/releases/download",
                "http://github.com/x"
            ),
            Err(CheckError::Format)
        );
        assert_eq!(
            bad(
                "https://github.com/voidwire-app/voidwire/releases/download",
                "https://u:p@github.com/x"
            ),
            Err(CheckError::Format)
        );
        assert_eq!(
            bad(
                "\"notes_url\":\"https://github.com/voidwire-app/voidwire/releases/",
                "\"notes_url\":\"https://github.com/other/"
            ),
            Err(CheckError::Format)
        );
        assert_eq!(bad("\"schema\":1", "\"schema\":2"), Err(CheckError::Format));
        assert_eq!(
            bad("\"version\":\"0.9.8-m4.7\"", "\"version\":\"<b>\""),
            Err(CheckError::Format)
        );
        assert_eq!(bad(&"ab".repeat(32), "zz"), Err(CheckError::Format));
        assert!(matches!(
            bad("\"version\"", "\"extra\":true,\"version\""),
            Ok(Verdict::Available(_))
        ));
    }
}
