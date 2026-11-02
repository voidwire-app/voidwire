//! App updates (U1, docs/UPDATES.md).
//!
//! One signed manifest per channel at a fixed URL. The app fetches it with a
//! single anonymous GET, at most once a UTC day, and only on user-visible
//! events (start, window shown, "Check now"); never on a timer and never
//! from a background service. A manifest counts only if it is signed by a
//! key pinned here ([`keys`]), names the channel asked for, is not older
//! than one already seen, and offers a higher build than this one.
//! Downloads are checked against the signed size and SHA-256 and deleted on
//! a mismatch.

pub mod keys;
mod manifest;
mod policy;
pub mod sig;

#[cfg(feature = "updates")]
mod fetch;

pub use manifest::{
    evaluate, CheckError, Context, Offer, Platform, Verdict, FILE_HOSTS, MAX_FILE_SIZE,
    MAX_MANIFEST_SIZE,
};
pub use policy::{utc_day, Channel, Trigger, UpdatePrefs};

#[cfg(feature = "updates")]
pub use fetch::{check, download, verify_file, DownloadError, Outcome, Source, Verified};

const fn parse_u32(s: &str) -> u32 {
    let b = s.as_bytes();
    let mut i = 0;
    let mut n: u32 = 0;
    while i < b.len() {
        if b[i] < b'0' || b[i] > b'9' {
            return 0;
        }
        n = n * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    n
}

/// This build's number (the Android `versionCode`); 0 turns updates off.
pub const BUILD: u32 = parse_u32(env!("VOIDWIRE_BUILD"));
/// This build's version name (`0.9.7-m4.6`).
pub const VERSION_NAME: &str = env!("VOIDWIRE_VERSION_NAME");
/// Base URL of the channel manifests (`<base>/<channel>.json`).
pub const UPDATE_URL: &str = env!("VOIDWIRE_UPDATE_URL");
/// The project page (`https://github.com/<org>/<repo>`).
pub const REPO_URL: &str = env!("VOIDWIRE_REPO_URL");

/// The channel this build came from.
pub fn build_channel() -> Channel {
    Channel::of_version(VERSION_NAME)
}

/// Whether this build can check for updates at all.
pub fn enabled_in_build() -> bool {
    BUILD > 0 && UPDATE_URL.starts_with("https://") && REPO_URL.starts_with("https://")
}

/// Prefix every signed `notes_url` must start with.
pub fn notes_prefix() -> String {
    format!("{REPO_URL}/releases/")
}

/// A project page the app may open in the browser: the release notes of a
/// verified offer, or the releases list. Nothing else can be made into one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectPage(String);

impl ProjectPage {
    pub fn releases() -> ProjectPage {
        ProjectPage(format!("{REPO_URL}/releases"))
    }

    /// The offer's `notes_url` (checked against [`notes_prefix`] when the
    /// manifest was accepted).
    pub fn notes(offer: &Offer) -> ProjectPage {
        ProjectPage(offer.notes_url.clone())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn build_identity() {
        assert_eq!(super::parse_u32("33"), 33);
        assert_eq!(super::parse_u32(""), 0);
        assert_eq!(super::parse_u32("3x"), 0);
        // This source tree has the gradle file and branding.
        const { assert!(super::BUILD > 0) };
        assert!(super::enabled_in_build());
        assert!(super::ProjectPage::releases()
            .as_str()
            .starts_with("https://github.com/"));
    }
}
