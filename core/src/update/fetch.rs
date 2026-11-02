//! The network side of the update check (feature `updates`): one GET for
//! the manifest and one for its signature, and the file download.
//!
//! Requests carry nothing about the user: no query, no cookies, no
//! identifiers, `User-Agent: Voidwire`. TLS is rustls with the webpki roots;
//! redirects are followed only to allowed hosts.

use super::manifest::{evaluate, CheckError, Context, Offer, Platform, Verdict, MAX_MANIFEST_SIZE};
use super::policy::{Channel, Trigger, UpdatePrefs};
use super::sig::PublicKey;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Where manifests come from and what this install is.
#[derive(Clone, Debug)]
pub struct Source {
    base: String,
    hosts: Vec<String>,
    allow_http: bool,
    installed_build: u32,
    build_channel: Channel,
    keys: [Vec<PublicKey>; 2],
    notes_prefix: String,
}

impl Source {
    /// The real source; `None` when this build has updates off (build 0).
    pub fn official() -> Option<Source> {
        if !super::enabled_in_build() {
            return None;
        }
        let mut hosts: Vec<String> = super::FILE_HOSTS.iter().map(|h| h.to_string()).collect();
        if let Some(h) = url::Url::parse(super::UPDATE_URL)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
        {
            hosts.push(h);
        }
        Some(Source {
            base: super::UPDATE_URL.trim_end_matches('/').to_owned(),
            hosts,
            allow_http: false,
            installed_build: super::BUILD,
            build_channel: super::build_channel(),
            keys: [
                super::keys::pinned(Channel::Stable),
                super::keys::pinned(Channel::Test),
            ],
            notes_prefix: super::notes_prefix(),
        })
    }

    /// A local test server (plain http on 127.0.0.1) with test keys.
    #[cfg(feature = "test-util")]
    pub fn for_tests(
        base: &str,
        installed_build: u32,
        build_channel: Channel,
        stable_keys: Vec<PublicKey>,
        test_keys: Vec<PublicKey>,
    ) -> Source {
        Source {
            base: base.trim_end_matches('/').to_owned(),
            hosts: vec!["127.0.0.1".into()],
            allow_http: true,
            installed_build,
            build_channel,
            keys: [stable_keys, test_keys],
            notes_prefix: crate::update::notes_prefix(),
        }
    }

    pub fn build_channel(&self) -> Channel {
        self.build_channel
    }

    fn keys(&self, ch: Channel) -> &[PublicKey] {
        match ch {
            Channel::Stable => &self.keys[0],
            Channel::Test => &self.keys[1],
        }
    }

    fn allowed(&self, url: &url::Url) -> bool {
        let hosts: Vec<&str> = self.hosts.iter().map(String::as_str).collect();
        super::manifest::url_allowed(url.as_str(), &hosts, self.allow_http)
    }

    fn client(&self, read_timeout: Duration) -> Result<reqwest::Client, CheckError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| CheckError::Network)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let me = self.clone();
        let policy = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                attempt.error("too many redirects")
            } else if me.allowed(attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        });
        reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .user_agent("Voidwire")
            .redirect(policy)
            .no_proxy()
            .https_only(!self.allow_http)
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(read_timeout)
            .build()
            .map_err(|_| CheckError::Network)
    }
}

/// The result of one check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not due (already checked today, or checks are off): no request made.
    Skipped,
    UpToDate,
    Available(Offer),
    Failed(CheckError),
}

enum Got {
    Body(Vec<u8>),
    NotFound,
}

async fn get_small(client: &reqwest::Client, url: &str) -> Result<Got, CheckError> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|_| CheckError::Network)?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Got::NotFound);
    }
    if !resp.status().is_success() {
        return Err(CheckError::Network);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| CheckError::Network)? {
        if body.len() + chunk.len() > MAX_MANIFEST_SIZE {
            return Err(CheckError::Format);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Got::Body(body))
}

/// Check for an update if `trigger` is due (see [`UpdatePrefs::should_check`]).
/// `prefs` gets the new `seen_seq` and, after a completed check, today's
/// date; the caller saves it.
pub async fn check(
    src: &Source,
    prefs: &mut UpdatePrefs,
    trigger: Trigger,
    today: u32,
    platform: Platform,
) -> Outcome {
    if !prefs.should_check(trigger, today) {
        return Outcome::Skipped;
    }
    let channel = prefs.channel(src.build_channel);
    let client = match src.client(Duration::from_secs(30)) {
        Ok(c) => c,
        Err(e) => return Outcome::Failed(e),
    };
    let url = format!("{}/{}.json", src.base, channel.name());
    let manifest = match get_small(&client, &url).await {
        Ok(Got::Body(b)) => b,
        // No manifest yet on this channel (stable before its first release).
        Ok(Got::NotFound) => {
            prefs.last_check_day = today;
            return Outcome::UpToDate;
        }
        Err(e) => return Outcome::Failed(e),
    };
    let sig = match get_small(&client, &format!("{url}.sig")).await {
        Ok(Got::Body(b)) => String::from_utf8(b).unwrap_or_default(),
        Ok(Got::NotFound) => return Outcome::Failed(CheckError::Signature),
        Err(e) => return Outcome::Failed(e),
    };
    let hosts: Vec<&str> = src.hosts.iter().map(String::as_str).collect();
    let ctx = Context {
        channel,
        keys: src.keys(channel),
        installed_build: src.installed_build,
        platform,
        hosts: &hosts,
        notes_prefix: &src.notes_prefix,
        allow_http: src.allow_http,
    };
    match evaluate(&manifest, &sig, &ctx, prefs) {
        Ok(v) => {
            prefs.last_check_day = today;
            match v {
                Verdict::UpToDate => Outcome::UpToDate,
                Verdict::Available(o) => Outcome::Available(o),
            }
        }
        Err(e) => Outcome::Failed(e),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DownloadError {
    #[error("network")]
    Network,
    /// Size or SHA-256 did not match the signed manifest; the file is gone.
    #[error("security")]
    Security,
    #[error("io")]
    Io,
}

/// A downloaded file whose size and SHA-256 matched the signed offer when
/// it was last read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    path: PathBuf,
    platform: Platform,
}

impl Verified {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn platform(&self) -> Platform {
        self.platform
    }
}

/// Re-read `path` and check it against `offer` (call right before using
/// it). A mismatching file is deleted.
pub fn verify_file(path: &Path, offer: &Offer) -> Result<Verified, DownloadError> {
    let mut f = std::fs::File::open(path).map_err(|_| DownloadError::Io)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut n_total = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|_| DownloadError::Io)?;
        if n == 0 {
            break;
        }
        n_total += n as u64;
        if n_total > offer.size {
            break;
        }
        h.update(&buf[..n]);
    }
    drop(f);
    if n_total != offer.size || h.finalize().as_slice() != offer.sha256 {
        let _ = std::fs::remove_file(path);
        return Err(DownloadError::Security);
    }
    Ok(Verified {
        path: path.to_owned(),
        platform: offer.platform,
    })
}

/// Download `offer` to `dest` (through `dest.part`), reporting
/// `(bytes so far, total)`. Only a file with the signed size and SHA-256
/// ends up at `dest`; anything else is deleted.
pub async fn download(
    src: &Source,
    offer: &Offer,
    dest: &Path,
    progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<Verified, DownloadError> {
    let part = dest.with_extension("part");
    // Never leave an older download where the new one goes.
    let _ = std::fs::remove_file(dest);
    if let Err(e) = download_to(src, offer, &part, progress).await {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, dest).map_err(|_| {
        let _ = std::fs::remove_file(&part);
        DownloadError::Io
    })?;
    verify_file(dest, offer)
}

async fn download_to(
    src: &Source,
    offer: &Offer,
    part: &Path,
    progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<(), DownloadError> {
    let hosts: Vec<&str> = src.hosts.iter().map(String::as_str).collect();
    if !super::manifest::url_allowed(&offer.url, &hosts, src.allow_http) {
        return Err(DownloadError::Security);
    }
    let client = src
        .client(Duration::from_secs(60))
        .map_err(|_| DownloadError::Network)?;
    let mut resp = client
        .get(&offer.url)
        .send()
        .await
        .map_err(|_| DownloadError::Network)?;
    if !resp.status().is_success() {
        return Err(DownloadError::Network);
    }
    if resp.content_length().is_some_and(|n| n != offer.size) {
        return Err(DownloadError::Security);
    }
    let _ = std::fs::remove_file(part);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(part)
        .map_err(|_| DownloadError::Io)?;
    let mut h = Sha256::new();
    let mut got = 0u64;
    progress(0, offer.size);
    while let Some(chunk) = resp.chunk().await.map_err(|_| DownloadError::Network)? {
        got += chunk.len() as u64;
        if got > offer.size {
            return Err(DownloadError::Security);
        }
        h.update(&chunk);
        f.write_all(&chunk).map_err(|_| DownloadError::Io)?;
        progress(got, offer.size);
    }
    f.sync_all().map_err(|_| DownloadError::Io)?;
    if got != offer.size || h.finalize().as_slice() != offer.sha256 {
        return Err(DownloadError::Security);
    }
    Ok(())
}
