//! The only door to the OS URL opener (decisions: docs/PROTOCOL.md §9).
//!
//! * [`UrlOpener::open`] takes an [`OpenApproval`] by value. An approval can
//!   only be minted here, by [`deliver`] (no-prompt mode) or by
//!   [`PendingOpen::confirm`] (the user clicked "Open"), so an opener cannot be
//!   driven with a bare [`VerifiedUrl`], a `String`, or a URL that skipped the
//!   mode/membership checks (D2 / TEST-PLAN AUTH-17).
//! * Both minting paths take the app's [`Inbox`] and refuse a `VerifiedUrl`
//!   minted by any other inbox (`ForeignInbox`), then re-check the sender's
//!   is still that inbox's peer immediately before the open (REV-04).
//! * [`OpenMode::OpenImmediately`] (no-prompt) is the **default** (REV-06
//!   residual risk documented in
//!   THREAT-MODEL §3). [`OpenMode::ConfirmBeforeOpen`] is the desktop setting
//!   "Ask before opening". In both modes the approval is minted only after
//!   full verification (a [`VerifiedUrl`] exists only from `Inbox::receive`)
//!   and after the peer re-check right before the open.
//! * The system opener does **not** use the `open` crate (banned in deny.toml
//!   and CI). Windows: one `ShellExecuteW(NULL, "open", canon, NULL, NULL,
//!   SW_SHOWNORMAL)`. Linux: exec `/usr/bin/xdg-open canon` (no shell, one argv
//!   element, no fallback chain). macOS: exec `/usr/bin/open canon`.

#![deny(unsafe_code)]

use crate::ids::DeviceId;
use crate::reject::RejectReason;
use crate::verify::MemberStatus;
use crate::verify::{Inbox, VerifiedUrl};
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("url refused at open time: {0}")]
    Policy(#[from] RejectReason),
    /// OS error text only; never the URL.
    #[error("the OS refused to open the link: {0}")]
    Os(String),
}

/// Permission to open exactly one verified URL, exactly once.
///
/// * Private fields, no public constructor.
/// * No `Clone`, `Copy`, `Default`, `From`, `FromStr` or serde impls.
/// * Minted only by [`deliver`] (`OpenImmediately`) and [`PendingOpen::confirm`].
pub struct OpenApproval {
    url: VerifiedUrl,
}

impl OpenApproval {
    /// The canonical URL to open (re-checked by the system opener).
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }
    pub fn host_for_display(&self) -> &str {
        self.url.host_for_display()
    }
    pub fn sender(&self) -> DeviceId {
        self.url.sender()
    }
}

impl fmt::Debug for OpenApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenApproval")
            .field("url", &self.url)
            .finish()
    }
}

/// Anything that opens URLs (real OS opener, or `SpyOpener` in tests).
/// Implementable anywhere, but only callable with an [`OpenApproval`].
pub trait UrlOpener {
    fn open(&self, approval: OpenApproval) -> Result<(), OpenError>;
}

/// Whether an inbound link opens immediately or waits for the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpenMode {
    /// "Ask before opening" (desktop setting, off by default): show
    /// "Open <host> from <device>?" and open only on the user's click.
    ConfirmBeforeOpen,
    /// The default: open right away, through
    /// [`deliver`], after verification and the peer re-check.
    #[default]
    OpenImmediately,
}

/// A verified link waiting for the user's click.
pub struct PendingOpen {
    url: VerifiedUrl,
}

impl fmt::Debug for PendingOpen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingOpen")
            .field("url", &self.url)
            .finish()
    }
}

impl PendingOpen {
    pub fn host_for_display(&self) -> &str {
        self.url.host_for_display()
    }
    pub fn sender(&self) -> DeviceId {
        self.url.sender()
    }
    /// The inbox the link was verified in.
    pub(crate) fn inbox_tag(&self) -> crate::verify::InboxTag {
        self.url.inbox_tag()
    }
    /// User clicked "Open". Re-checks that the link came from this inbox and
    /// that the sender is still a member (it may have been forgotten while the
    /// prompt was up), then mints the approval.
    pub fn confirm(self, inbox: &Inbox, opener: &dyn UrlOpener) -> Result<(), OpenError> {
        recheck(inbox, &self.url)?;
        opener.open(OpenApproval { url: self.url })
    }
}

#[derive(Debug)]
pub enum Delivery {
    Opened,
    NeedsConfirmation(PendingOpen),
}

fn recheck(inbox: &Inbox, url: &VerifiedUrl) -> Result<(), OpenError> {
    if url.inbox_tag() != inbox.tag() {
        return Err(OpenError::Policy(RejectReason::ForeignInbox));
    }
    match inbox.member_status(&url.sender()) {
        MemberStatus::Active => Ok(()),
        MemberStatus::Unknown => Err(OpenError::Policy(RejectReason::NotPaired)),
    }
}

/// Hand a verified URL to the opener according to `mode`.
pub fn deliver(
    inbox: &Inbox,
    url: VerifiedUrl,
    mode: OpenMode,
    opener: &dyn UrlOpener,
) -> Result<Delivery, OpenError> {
    recheck(inbox, &url)?;
    match mode {
        OpenMode::ConfirmBeforeOpen => Ok(Delivery::NeedsConfirmation(PendingOpen { url })),
        OpenMode::OpenImmediately => opener.open(OpenApproval { url }).map(|()| Delivery::Opened),
    }
}

/// The real OS opener.
#[cfg(feature = "system-opener")]
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemOpener;

#[cfg(feature = "system-opener")]
impl UrlOpener for SystemOpener {
    fn open(&self, approval: OpenApproval) -> Result<(), OpenError> {
        let url = approval;
        // Defense in depth: the canonical string must still pass and be a fixed point.
        let canon = crate::url_policy::check_url(url.as_str())?;
        if canon.as_str() != url.as_str() {
            return Err(OpenError::Policy(RejectReason::UrlBadChars));
        }
        platform::open_one(canon.as_str())
    }
}

#[cfg(all(feature = "system-opener", windows))]
mod platform {
    #![allow(unsafe_code)] // the one FFI call, audited below
    use super::OpenError;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn open_one(canon: &str) -> Result<(), OpenError> {
        let verb = wide("open");
        let file = wide(canon);
        // SAFETY: both buffers are NUL-terminated UTF-16 and outlive the call;
        // all other pointer arguments are NULL as documented for ShellExecuteW.
        // lpParameters is NULL: the URL is the only argument.
        let r = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        let code = r as isize;
        if code > 32 {
            Ok(())
        } else {
            Err(OpenError::Os(format!(
                "ShellExecuteW failed with code {code}"
            )))
        }
    }
}

#[cfg(all(feature = "system-opener", unix))]
mod platform {
    use super::OpenError;
    use std::process::{Command, Stdio};

    #[cfg(target_os = "macos")]
    const LAUNCHER: &str = "/usr/bin/open";
    #[cfg(not(target_os = "macos"))]
    const LAUNCHER: &str = "/usr/bin/xdg-open";

    #[allow(clippy::disallowed_methods)] // the single sanctioned spawn
    pub(super) fn open_one(canon: &str) -> Result<(), OpenError> {
        // canon starts with "http://" or "https://", so it can't be read as an option.
        debug_assert!(canon.starts_with("http://") || canon.starts_with("https://"));
        let mut child = Command::new(LAUNCHER)
            .arg(canon)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| OpenError::Os(format!("{LAUNCHER}: {}", e.kind())))?;
        // Reap in the background; no retry, no fallback launcher.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}
