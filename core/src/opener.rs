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

/// U1: open a project page in the browser (the release notes of a signed
/// update, or the releases list). [`crate::update::ProjectPage`] can only
/// be made from those, and the page must still be under the project's
/// `/releases`.
#[cfg(feature = "system-opener")]
pub fn open_project_page(page: &crate::update::ProjectPage) -> Result<(), OpenError> {
    let canon = crate::url_policy::check_url(page.as_str())?;
    let prefix = format!("{}/releases", crate::update::REPO_URL);
    if !crate::update::REPO_URL.starts_with("https://") || !canon.as_str().starts_with(&prefix) {
        return Err(OpenError::Policy(RejectReason::UrlBadChars));
    }
    platform::open_one(canon.as_str())
}

/// Which desktop's keyboard-shortcut settings to open.
#[cfg(all(feature = "system-opener", target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortcutSettings {
    /// GNOME Settings › Keyboard.
    Gnome,
    /// KDE System Settings › Shortcuts.
    Kde,
}

/// Open the desktop's own keyboard-shortcut settings, where the user
/// changes the keys of the command shortcut the app added. Only on a click
/// (never on its own). Fixed programs, no arguments from outside.
#[cfg(all(feature = "system-opener", target_os = "linux"))]
pub fn open_shortcut_settings(which: ShortcutSettings) -> Result<(), OpenError> {
    let tries: &[&[&str]] = match which {
        ShortcutSettings::Gnome => &[&["gnome-control-center", "keyboard"]],
        ShortcutSettings::Kde => &[
            &["systemsettings", "kcm_keys"],
            &["systemsettings5", "kcm_keys"],
            &["kcmshell5", "kcm_keys"],
        ],
    };
    let mut last = OpenError::Os("no settings program".into());
    for t in tries {
        match platform::spawn_settings(t[0], &t[1..]) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Why an update could not be started.
#[cfg(all(feature = "system-opener", feature = "updates"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartUpdateError {
    /// The user said no to the Windows permission prompt.
    Cancelled,
    /// The OS could not start it (or this platform installs another way).
    Failed,
}

/// U1: start a verified update. Windows: run the downloaded installer
/// (`/P /UPDATE`, plus `/R` to start Voidwire again), which brings up the
/// UAC prompt; the app then quits. Linux AppImage: start the replaced
/// AppImage (the app quits right after). Call [`crate::update::verify_file`]
/// right before this.
#[cfg(all(feature = "system-opener", feature = "updates"))]
pub fn start_update(
    update: &crate::update::Verified,
    restart: bool,
) -> Result<(), StartUpdateError> {
    #[cfg(any(windows, all(unix, not(target_os = "macos"))))]
    use crate::update::Platform;
    match update.platform() {
        #[cfg(windows)]
        Platform::WindowsNsis => platform::run_installer(update.path(), restart),
        #[cfg(all(unix, not(target_os = "macos")))]
        Platform::LinuxAppImage => {
            let _ = restart;
            platform::start_appimage(update.path())
        }
        _ => {
            let _ = restart;
            Err(StartUpdateError::Failed)
        }
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

    /// U1: the verified installer, by full path, with fixed arguments. The
    /// installer asks for elevation itself (per-machine install), so this
    /// goes through ShellExecuteW, not CreateProcess (error 740).
    #[cfg(feature = "updates")]
    pub(super) fn run_installer(
        path: &std::path::Path,
        restart: bool,
    ) -> Result<(), super::StartUpdateError> {
        use std::os::windows::ffi::OsStrExt;
        let verb = wide("open");
        let file: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let params = wide(if restart {
            "/P /R /UPDATE"
        } else {
            "/P /UPDATE"
        });
        // SAFETY: all buffers are NUL-terminated UTF-16 and outlive the call;
        // the window handle and directory are NULL as documented.
        let r = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        match r as isize {
            c if c > 32 => Ok(()),
            // SE_ERR_ACCESSDENIED: the UAC prompt was declined.
            5 => Err(super::StartUpdateError::Cancelled),
            _ => Err(super::StartUpdateError::Failed),
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
        let mut cmd = Command::new(LAUNCHER);
        super::host_env(&mut cmd);
        let mut child = cmd
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

    /// A desktop settings program from [`super::open_shortcut_settings`]'s
    /// fixed list (looked up on `PATH`).
    #[cfg(target_os = "linux")]
    #[allow(clippy::disallowed_methods)] // fixed settings programs only
    pub(super) fn spawn_settings(prog: &str, args: &[&str]) -> Result<(), OpenError> {
        let mut cmd = Command::new(prog);
        super::host_env(&mut cmd);
        let mut child = cmd
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| OpenError::Os(format!("{prog}: {}", e.kind())))?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }

    /// U1: start the verified, replaced AppImage (no arguments). The
    /// caller exits right after.
    #[cfg(all(feature = "updates", not(target_os = "macos")))]
    #[allow(clippy::disallowed_methods)] // the sanctioned update restart
    pub(super) fn start_appimage(path: &std::path::Path) -> Result<(), super::StartUpdateError> {
        let mut cmd = Command::new(path);
        super::host_env(&mut cmd);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(drop)
            .map_err(|_| super::StartUpdateError::Failed)
    }
}

/// Inside an AppImage, AppRun points `LD_LIBRARY_PATH`, `PATH`, the GTK and
/// GIO module paths and more into the image. A host program started with
/// them loads the image's libraries: `/usr/bin/env` in the next AppRun
/// fails on the bundled libsystemd, and the browser can pick up the bundled
/// GTK. Give spawned programs the desktop's own environment back.
#[cfg(all(feature = "system-opener", unix, not(target_os = "macos")))]
fn host_env(cmd: &mut std::process::Command) {
    let Some(appdir) = std::env::var("APPDIR").ok() else {
        return;
    };
    let inside = std::env::current_exe().is_ok_and(|e| e.starts_with(&appdir));
    if !inside {
        return;
    }
    let vars = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
    // AppRun runs us inside the image (`$APPDIR/usr`); a child left there
    // keeps the old image mounted and breaks once it is gone.
    let start_dir = [std::env::var_os("OWD"), std::env::var_os("HOME")]
        .into_iter()
        .flatten()
        .map(std::path::PathBuf::from)
        .find(|d| d.is_absolute() && !d.starts_with(&appdir) && d.is_dir())
        .unwrap_or_else(|| "/".into());
    cmd.current_dir(start_dir);
    for (key, value) in appimage_env_fixes(&appdir, vars) {
        match value {
            Some(v) => cmd.env(key, v),
            None => cmd.env_remove(key),
        };
    }
}

#[cfg(all(feature = "system-opener", target_os = "macos"))]
fn host_env(_: &mut std::process::Command) {}

/// What to change in an environment set up by AppRun for `appdir`: list
/// entries inside the image are dropped (the variable too when nothing is
/// left), and the variables only AppRun sets are removed.
#[cfg_attr(
    not(all(feature = "system-opener", unix, not(target_os = "macos"))),
    allow(dead_code)
)]
fn appimage_env_fixes(
    appdir: &str,
    vars: impl Iterator<Item = (String, String)>,
) -> Vec<(String, Option<String>)> {
    const APPRUN_ONLY: &[&str] = &[
        "APPDIR",
        "APPIMAGE",
        "ARGV0",
        "OWD",
        "GTK_THEME",
        "PYTHONDONTWRITEBYTECODE",
    ];
    let appdir = appdir.trim_end_matches('/');
    if !appdir.starts_with('/') || appdir.len() < 2 {
        return Vec::new();
    }
    let in_image = |p: &str| p == appdir || p.starts_with(&format!("{appdir}/"));
    let mut out = Vec::new();
    for (key, value) in vars {
        if APPRUN_ONLY.contains(&key.as_str()) {
            out.push((key, None));
            continue;
        }
        if !value.split(':').any(in_image) {
            continue;
        }
        let kept: Vec<&str> = value
            .split(':')
            .filter(|p| !p.is_empty() && !in_image(p))
            .collect();
        out.push((key, (!kept.is_empty()).then(|| kept.join(":"))));
    }
    out
}

#[cfg(test)]
mod host_env_tests {
    use super::appimage_env_fixes;

    fn fixes(vars: &[(&str, &str)]) -> Vec<(String, Option<String>)> {
        let mut v = appimage_env_fixes(
            "/tmp/.mount_VoidwiX",
            vars.iter().map(|(k, v)| (k.to_string(), v.to_string())),
        );
        v.sort();
        v
    }

    #[test]
    fn apprun_paths_are_taken_out_and_the_desktops_own_kept() {
        let got = fixes(&[
            (
                "LD_LIBRARY_PATH",
                "/tmp/.mount_VoidwiX/usr/lib/:/tmp/.mount_VoidwiX/lib/:",
            ),
            (
                "PATH",
                "/tmp/.mount_VoidwiX/usr/bin/:/usr/local/bin:/usr/bin",
            ),
            (
                "XDG_DATA_DIRS",
                "/tmp/.mount_VoidwiX/usr/share/:/usr/share:",
            ),
            (
                "GDK_PIXBUF_MODULE_FILE",
                "/tmp/.mount_VoidwiX//usr/lib/loaders.cache",
            ),
            ("GTK_THEME", "Adwaita:light"),
            ("APPIMAGE", "/opt/apps/Voidwire.AppImage"),
            ("HOME", "/srv/u"),
            ("OTHER", "/tmp/.mount_VoidwiXY/usr/lib"),
        ]);
        assert_eq!(
            got,
            vec![
                ("APPIMAGE".into(), None),
                ("GDK_PIXBUF_MODULE_FILE".into(), None),
                ("GTK_THEME".into(), None),
                ("LD_LIBRARY_PATH".into(), None),
                ("PATH".into(), Some("/usr/local/bin:/usr/bin".into())),
                ("XDG_DATA_DIRS".into(), Some("/usr/share".into())),
            ]
        );
    }

    #[test]
    fn a_bad_appdir_changes_nothing() {
        for dir in ["", "/", "relative/dir"] {
            let got = appimage_env_fixes(
                dir,
                [("PATH".to_string(), "/usr/bin".to_string())].into_iter(),
            );
            assert!(got.is_empty());
        }
    }
}
