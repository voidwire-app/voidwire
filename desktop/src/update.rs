//! U1: the update check, download and install on the desktop
//! (docs/UPDATES.md). Core does the network, the signature and the hashes;
//! this module holds the in-memory state for the Settings page and the
//! banner, and starts the install the platform allows:
//!
//! * Windows: download to `<local app data>\update\`, then run the verified
//!   NSIS installer (`/P /R /UPDATE`, UAC prompt) and quit. With "Install
//!   updates automatically" on, the download happens during the check and
//!   the install starts on tray → Quit.
//! * Linux AppImage: download next to `$APPIMAGE`, then `rename()` it in
//!   place (to the new version's file name when the old one had the
//!   release's name); "Restart now" starts the new file as this one exits.
//! * Linux deb, macOS: "Download" opens the release page.
//!
//! Checks run only on events: at start and when the Devices window is
//! shown, at most once a UTC day, on "Check now", and once when the
//! "Test builds" switch is flipped. No timers.

use crate::node;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{AppHandle, Manager};
use voidwire_core::time::Clock as _;
use voidwire_core::update::{self, Offer, Outcome, Platform, Trigger, Verified};

/// What the Updates section and the banner show.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Idle,
    Checking,
    Downloading(u8),
    Verifying,
    /// Windows: the verified installer is on disk.
    Ready(Verified),
    /// AppImage: the new file replaced the old one.
    Installed(Verified),
}

#[derive(Default)]
struct State {
    /// Last check result for the status line: "", "uptodate", "failed".
    status: &'static str,
    offer: Option<Offer>,
    phase: Phase,
    /// One error line for the banner (design §8), cleared by the next action.
    error: Option<&'static str>,
    /// "Not now": hides the banner until the app quits (memory only).
    dismissed: bool,
    /// AppImage: start the replaced file as this process exits.
    restart_on_exit: bool,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(State::default))
}

const ERR_SECURITY: &str = "The download didn't pass the security check and was deleted.";
const ERR_DOWNLOAD: &str = "Download failed. Try again later.";
const ERR_START: &str = "Couldn't start the installer.";
const ERR_CANCELLED: &str = "The installer was cancelled.";

/// How this install updates itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Windows,
    AppImage,
    Deb,
    MacOs,
}

fn kind() -> Kind {
    if cfg!(windows) {
        Kind::Windows
    } else if cfg!(target_os = "macos") {
        Kind::MacOs
    } else if appimage_path().is_some() {
        Kind::AppImage
    } else {
        Kind::Deb
    }
}

fn platform() -> Platform {
    match kind() {
        Kind::Windows => Platform::WindowsNsis,
        Kind::AppImage => Platform::LinuxAppImage,
        Kind::Deb => Platform::LinuxDeb,
        Kind::MacOs => Platform::MacOs,
    }
}

/// The running AppImage (set by the AppImage runtime), if this is one.
fn appimage_path() -> Option<PathBuf> {
    if !cfg!(all(unix, not(target_os = "macos"))) {
        return None;
    }
    let p = PathBuf::from(std::env::var_os("APPIMAGE")?);
    (p.is_absolute() && p.is_file()).then_some(p)
}

/// Windows: where the installer is downloaded (removed at every start).
fn update_dir(app: &AppHandle) -> Option<PathBuf> {
    app.path()
        .app_local_data_dir()
        .ok()
        .map(|d| d.join("update"))
}

/// Ask the Devices window to re-read the update state (event-driven).
fn refresh(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(crate::DEVICES_WINDOW) {
        let _ = w.eval("window.vwUpdate&&window.vwUpdate()");
    }
    crate::refresh_tray(app);
}

/// Whether the tray shows "Update available…".
pub fn tray_offer() -> bool {
    with(|s| s.offer.is_some())
}

/// At start: remove what an earlier update left behind, then check if due.
pub fn on_start(app: &AppHandle) {
    if kind() == Kind::Windows {
        if let Some(d) = update_dir(app) {
            let _ = std::fs::remove_dir_all(d);
        }
    }
    if let Some(dir) = appimage_path().as_deref().and_then(|p| p.parent()) {
        let _ = std::fs::remove_file(dir.join(APPIMAGE_TMP));
        let _ = std::fs::remove_file(dir.join(APPIMAGE_TMP).with_extension("part"));
    }
    check(app, Trigger::AppStart);
}

/// The Devices window was shown.
pub fn on_window_opened(app: &AppHandle) {
    check(app, Trigger::WindowOpened);
}

const APPIMAGE_TMP: &str = ".voidwire-update.AppImage";

fn check(app: &AppHandle, trigger: Trigger) {
    let Some(src) = update::Source::official() else {
        return;
    };
    let Some(n) = node::get(app) else {
        return;
    };
    let mut prefs = n.update_prefs();
    let today = update::utc_day(voidwire_core::time::SystemClock.now().wall);
    if !prefs.should_check(trigger, today) {
        return;
    }
    let busy = with(|s| {
        let busy = !matches!(s.phase, Phase::Idle);
        if !busy {
            s.phase = Phase::Checking;
            s.error = None;
        }
        busy
    });
    if busy {
        return;
    }
    refresh(app);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let before = prefs.clone();
        let out = update::check(&src, &mut prefs, trigger, today, platform()).await;
        if prefs != before && prefs.checks_on {
            let _ = n.set_update_prefs(&prefs);
        }
        let auto = prefs.auto_install;
        let mut start_download = false;
        with(|s| {
            s.phase = Phase::Idle;
            match &out {
                Outcome::Skipped => {}
                Outcome::UpToDate => {
                    s.status = "uptodate";
                    s.offer = None;
                }
                Outcome::Available(o) => {
                    s.status = "";
                    if s.offer.as_ref().map(|x| x.build) != Some(o.build) {
                        s.dismissed = false;
                    }
                    s.offer = Some(o.clone());
                    start_download = auto && matches!(kind(), Kind::Windows | Kind::AppImage);
                }
                Outcome::Failed(_) => s.status = "failed",
            }
        });
        // D8: one line, only with Diagnostics on (node::log writes nothing
        // otherwise); never the URL or an address.
        if let Outcome::Failed(e) = &out {
            node::log(&format!("update check failed: {}", e.kind()));
        }
        refresh(&app);
        if start_download {
            download(&app).await;
        }
    });
}

/// Download and verify the held offer; then Ready (Windows) or replace
/// the AppImage (Installed).
async fn download(app: &AppHandle) {
    let Some(src) = update::Source::official() else {
        return;
    };
    let Some(offer) = with(|s| {
        if matches!(s.phase, Phase::Idle) {
            s.phase = Phase::Downloading(0);
            s.error = None;
            s.offer.clone()
        } else {
            None
        }
    }) else {
        return;
    };
    refresh(app);
    let k = kind();
    let dest = match k {
        Kind::Windows => update_dir(app).map(|d| d.join("voidwire-setup.exe")),
        Kind::AppImage => appimage_path()
            .as_deref()
            .and_then(|p| p.parent())
            .map(|d| d.join(APPIMAGE_TMP)),
        _ => None,
    };
    let Some(dest) = dest else {
        return fail(app, ERR_DOWNLOAD);
    };
    if let Some(d) = dest.parent() {
        if std::fs::create_dir_all(d).is_err() {
            return fail(app, ERR_DOWNLOAD);
        }
    }
    let h = app.clone();
    let mut last = 0u8;
    let mut progress = move |done: u64, total: u64| {
        let pct = (done.saturating_mul(100) / total.max(1)).min(100) as u8;
        if pct != last {
            last = pct;
            with(|s| s.phase = Phase::Downloading(pct));
            if let Some(w) = h.get_webview_window(crate::DEVICES_WINDOW) {
                let _ = w.eval("window.vwUpdate&&window.vwUpdate()");
            }
        }
    };
    let res = update::download(&src, &offer, &dest, &mut progress).await;
    with(|s| s.phase = Phase::Verifying);
    refresh(app);
    let verified = match res {
        Ok(v) => v,
        Err(update::DownloadError::Security) => return fail(app, ERR_SECURITY),
        Err(update::DownloadError::Io) if k == Kind::AppImage => {
            // The AppImage's folder isn't writable: fall back to the page.
            with(|s| s.phase = Phase::Idle);
            let _ = voidwire_core::opener::open_project_page(&update::ProjectPage::notes(&offer));
            return refresh(app);
        }
        Err(_) => return fail(app, ERR_DOWNLOAD),
    };
    match k {
        Kind::AppImage => match replace_appimage(app, &verified, &offer) {
            Some(v) => with(|s| s.phase = Phase::Installed(v)),
            None => return fail(app, ERR_DOWNLOAD),
        },
        _ => with(|s| s.phase = Phase::Ready(verified)),
    }
    refresh(app);
}

/// Make the verified download executable and put it in place of
/// `$APPIMAGE`: under the new version's name when the old file still has
/// the release's own name (`Voidwire_1.1.0_amd64.AppImage`), else under the
/// user's own name. The sign-in entry and the command shortcut follow.
fn replace_appimage(app: &AppHandle, v: &Verified, offer: &Offer) -> Option<Verified> {
    let target = appimage_path()?;
    let name = app.package_info().name.clone();
    let dest = renamed_appimage(&target, &name, &offer.version)
        .filter(|p| !p.exists())
        .unwrap_or_else(|| target.clone());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(v.path(), std::fs::Permissions::from_mode(0o755)).ok()?;
    }
    if std::fs::rename(v.path(), &dest).is_err() {
        let _ = std::fs::remove_file(v.path());
        return None;
    }
    if dest != target {
        // The running copy keeps its mount of the old file until it exits.
        let _ = std::fs::remove_file(&target);
        voidwire_os_theme::app_moved_to(&name, &app.config().identifier, &dest);
    }
    update::verify_file(&dest, offer).ok()
}

/// A version as it may appear in a file name (`1.1.0-m5.4`).
fn file_safe_version(v: &str) -> bool {
    v.starts_with(|c: char| c.is_ascii_digit())
        && v.len() <= 64
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '~'))
}

/// The AppImage's new path for `version`, when its file name is the
/// release's own pattern `<App>_<version>_<arch>.AppImage` in any letter
/// case (`voidwire_1.0.1_amd64.AppImage` too). The new name is always
/// `<App>_<version>_<arch>.AppImage`. `None` for a name the user chose
/// (kept as it is).
pub(crate) fn renamed_appimage(path: &Path, app: &str, version: &str) -> Option<PathBuf> {
    // ASCII lowercasing keeps every byte where it was.
    let file = path.file_name()?.to_str()?.to_ascii_lowercase();
    let rest = file
        .strip_prefix(&app.to_ascii_lowercase())?
        .strip_prefix('_')?
        .strip_suffix(".appimage")?;
    let (old, arch) = ["amd64", "x86_64", "aarch64", "arm64"]
        .into_iter()
        .find_map(|a| Some((rest.strip_suffix(a)?.strip_suffix('_')?, a)))?;
    if !(file_safe_version(old) && file_safe_version(version)) {
        return None;
    }
    Some(path.with_file_name(format!("{app}_{version}_{arch}.AppImage")))
}

fn fail(app: &AppHandle, msg: &'static str) {
    with(|s| {
        s.phase = Phase::Idle;
        s.error = Some(msg);
    });
    refresh(app);
}

/// Windows: run the verified installer and quit. `restart`: the installer
/// starts Voidwire again (not when quitting).
fn install(app: &AppHandle, restart: bool) -> Result<(), &'static str> {
    let (v, offer) = with(|s| match (&s.phase, &s.offer) {
        (Phase::Ready(v), Some(o)) => Some((v.clone(), o.clone())),
        _ => None,
    })
    .ok_or(ERR_START)?;
    // Re-read the file right before running it.
    let v = update::verify_file(v.path(), &offer).map_err(|_| {
        with(|s| s.phase = Phase::Idle);
        ERR_SECURITY
    })?;
    match voidwire_core::opener::start_update(&v, restart) {
        Ok(()) => {
            node::shutdown(app);
            app.exit(0);
            Ok(())
        }
        Err(voidwire_core::opener::StartUpdateError::Cancelled) => Err(ERR_CANCELLED),
        Err(voidwire_core::opener::StartUpdateError::Failed) => Err(ERR_START),
    }
}

/// Tray → Quit. Returns true when the quit was handed to the installer
/// (automatic mode with a ready update); the caller exits otherwise.
pub fn on_quit(app: &AppHandle) -> bool {
    let ready = with(|s| matches!(s.phase, Phase::Ready(_)));
    let auto = node::get(app).is_some_and(|n| n.update_prefs().auto_install);
    ready && auto && install(app, false).is_ok()
}

/// RunEvent::Exit: AppImage "Restart now" starts the new file. The
/// single-instance name and the instance lock are released first so the
/// new copy doesn't hand over to this one.
pub fn on_exit(app: &AppHandle) {
    let v = with(|s| match (&s.phase, s.restart_on_exit) {
        (Phase::Installed(v), true) => Some(v.clone()),
        _ => None,
    });
    if let Some(v) = v {
        tauri_plugin_single_instance::destroy(app);
        node::release_instance_lock();
        let _ = voidwire_core::opener::start_update(&v, true);
    }
}

// ---- commands (Devices window) ----

#[derive(Serialize)]
pub struct UpdateOut {
    /// False in builds without updates (build number 0).
    available_in_build: bool,
    version: &'static str,
    /// "windows", "appimage", "deb", "macos".
    kind: &'static str,
    checks_on: bool,
    test_builds: bool,
    auto_install: bool,
    /// "", "checking", "uptodate", "failed".
    status: &'static str,
    offer_version: Option<String>,
    offer_size: Option<u64>,
    /// "", "downloading", "verifying", "ready", "installed".
    phase: &'static str,
    percent: u8,
    error: Option<&'static str>,
    dismissed: bool,
}

#[tauri::command]
pub fn update_state(app: AppHandle) -> UpdateOut {
    let prefs = node::get(&app)
        .map(|n| n.update_prefs())
        .unwrap_or_default();
    with(|s| UpdateOut {
        available_in_build: update::enabled_in_build(),
        version: update::VERSION_NAME,
        kind: match kind() {
            Kind::Windows => "windows",
            Kind::AppImage => "appimage",
            Kind::Deb => "deb",
            Kind::MacOs => "macos",
        },
        checks_on: prefs.checks_on,
        test_builds: prefs.channel(update::build_channel()) == update::Channel::Test,
        auto_install: prefs.auto_install,
        status: if s.phase == Phase::Checking {
            "checking"
        } else {
            s.status
        },
        offer_version: s.offer.as_ref().map(|o| o.version.clone()),
        offer_size: s.offer.as_ref().map(|o| o.size),
        phase: match s.phase {
            Phase::Idle | Phase::Checking => "",
            Phase::Downloading(_) => "downloading",
            Phase::Verifying => "verifying",
            Phase::Ready(_) => "ready",
            Phase::Installed(_) => "installed",
        },
        percent: match s.phase {
            Phase::Downloading(p) => p,
            _ => 0,
        },
        error: s.error,
        dismissed: s.dismissed,
    })
}

fn save(app: &AppHandle, f: impl FnOnce(&mut update::UpdatePrefs)) -> Result<(), String> {
    let n = crate::commands::node(app)?;
    let mut p = n.update_prefs();
    f(&mut p);
    n.set_update_prefs(&p).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn update_set_checks(app: AppHandle, on: bool) -> Result<(), String> {
    save(&app, |p| p.checks_on = on)?;
    if !on {
        with(|s| {
            if matches!(s.phase, Phase::Idle) {
                s.offer = None;
            }
            s.status = "";
        });
    }
    refresh(&app);
    Ok(())
}

#[tauri::command]
pub fn update_set_test_builds(app: AppHandle, on: bool) -> Result<(), String> {
    save(&app, |p| {
        p.test_builds = Some(on);
        p.last_check_day = 0;
    })?;
    with(|s| {
        if matches!(s.phase, Phase::Idle) {
            s.offer = None;
        }
        s.status = "";
        s.dismissed = false;
    });
    refresh(&app);
    // One check on the new channel now (not a timer); skipped while
    // update checks are off.
    check(&app, Trigger::ChannelChanged);
    Ok(())
}

#[tauri::command]
pub fn update_set_auto_install(app: AppHandle, on: bool) -> Result<(), String> {
    save(&app, |p| p.auto_install = on)
}

#[tauri::command]
pub fn update_check_now(app: AppHandle) {
    // Brings back a banner put off with "Not now".
    with(|s| s.dismissed = false);
    refresh(&app);
    check(&app, Trigger::CheckNow);
}

/// "Update" / "Download" on the banner.
#[tauri::command]
pub fn update_start(app: AppHandle) -> Result<(), String> {
    let Some(offer) = with(|s| s.offer.clone()) else {
        return Ok(());
    };
    match kind() {
        Kind::Windows | Kind::AppImage => {
            let h = app.clone();
            tauri::async_runtime::spawn(async move { download(&h).await });
            Ok(())
        }
        Kind::Deb | Kind::MacOs => {
            voidwire_core::opener::open_project_page(&update::ProjectPage::notes(&offer))
                .map_err(|_| "Couldn't open the browser.".to_owned())
        }
    }
}

/// "Install now" (Windows) / "Restart now" (AppImage).
#[tauri::command]
pub fn update_install_now(app: AppHandle) {
    let installed = with(|s| {
        let i = matches!(s.phase, Phase::Installed(_));
        s.restart_on_exit = i;
        i
    });
    if installed {
        node::shutdown(&app);
        app.exit(0);
        return;
    }
    if let Err(msg) = install(&app, true) {
        with(|s| s.error = Some(msg));
        refresh(&app);
    }
}

#[tauri::command]
pub fn update_not_now(app: AppHandle) {
    with(|s| s.dismissed = true);
    refresh(&app);
}

#[tauri::command]
pub fn update_whats_new() -> Result<(), String> {
    let page = with(|s| s.offer.as_ref().map(update::ProjectPage::notes))
        .unwrap_or_else(update::ProjectPage::releases);
    voidwire_core::opener::open_project_page(&page)
        .map_err(|_| "Couldn't open the browser.".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appimage_takes_the_new_versioned_name() {
        let p = Path::new("/home/u/Apps/Voidwire_1.1.0-m5.3_amd64.AppImage");
        assert_eq!(
            renamed_appimage(p, "Voidwire", "1.1.0-m5.4"),
            Some(PathBuf::from(
                "/home/u/Apps/Voidwire_1.1.0-m5.4_amd64.AppImage"
            ))
        );
        assert_eq!(
            renamed_appimage(
                Path::new("/a/Voidwire_1.0.1_x86_64.AppImage"),
                "Voidwire",
                "1.1.0"
            ),
            Some(PathBuf::from("/a/Voidwire_1.1.0_x86_64.AppImage"))
        );
    }

    #[test]
    fn letter_case_of_the_release_name_does_not_matter() {
        for (from, to) in [
            (
                "/h/voidwire_1.0.1_amd64.AppImage",
                "/h/Voidwire_1.1.0-m5.5_amd64.AppImage",
            ),
            (
                "/h/VOIDWIRE_1.0.1_AMD64.APPIMAGE",
                "/h/Voidwire_1.1.0-m5.5_amd64.AppImage",
            ),
            (
                "/h/Voidwire_1.1.0-m5.3_x86_64.appimage",
                "/h/Voidwire_1.1.0-m5.5_x86_64.AppImage",
            ),
            (
                "/h/voidwire_1.1.0-rc.1+b2_aarch64.AppImage",
                "/h/Voidwire_1.1.0-m5.5_aarch64.AppImage",
            ),
        ] {
            assert_eq!(
                renamed_appimage(Path::new(from), "Voidwire", "1.1.0-m5.5"),
                Some(PathBuf::from(to)),
                "{from}"
            );
        }
    }

    #[test]
    fn a_name_the_user_chose_is_kept() {
        for f in [
            "/a/Voidwire.AppImage",
            "/a/voidwire.AppImage",
            "/a/Voidwire_amd64.AppImage",
            "/a/voidwire_1.1.0_amd64 (copy).AppImage",
            "/a/Voidwire-1.1.0-amd64.AppImage",
            "/a/Voidwire_latest_amd64.AppImage",
            "/a/Voidwire_1.1.0_amd64.AppImage.bak",
            "/a/Voidwire_1.1.0_sparc.AppImage",
            "/a/MyVoidwire_1.1.0_amd64.AppImage",
        ] {
            assert_eq!(
                renamed_appimage(Path::new(f), "Voidwire", "1.2.0"),
                None,
                "{f}"
            );
        }
        let p = Path::new("/a/Voidwire_1.1.0_amd64.AppImage");
        assert_eq!(
            renamed_appimage(p, "Voidwire", "../x"),
            None,
            "unsafe version"
        );
        assert_eq!(renamed_appimage(p, "Voidwire", ""), None);
    }
}
