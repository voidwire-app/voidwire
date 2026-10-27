//! Tray glyph for the OS theme (C2 Relay icon set, `icons/tray/`).
//!
//! * Windows: `SystemUsesLightTheme` picks `tray-light-*` (light taskbar) or
//!   `tray-dark-*`; the frame follows the system DPI (16/20/24/32/40/48). A
//!   watcher thread swaps the icon when the setting changes.
//! * Linux (AppIndicator): `tray-dark-24`/`tray-light-24` from the desktop's
//!   theme; GNOME Shell's top bar is dark in both styles, so GNOME always gets
//!   the dark-panel glyph. Follows GTK theme / colour-scheme changes.
//! * macOS: `trayTemplate@2x.png` as a template image (the menu bar recolours it).
//!
//! The pixel frames are hand-drawn: never resample them (desktop/icons-src/README.md).

use tauri::image::Image;
use tauri::AppHandle;

pub const TRAY_ID: &str = "main";

/// The colour of the panel/taskbar the icon sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Panel {
    Dark,
    Light,
}

macro_rules! frames {
    ($kind:literal) => {
        [
            (
                16,
                include_bytes!(concat!("../icons/tray/tray-", $kind, "-16.png")) as &[u8],
            ),
            (
                20,
                include_bytes!(concat!("../icons/tray/tray-", $kind, "-20.png")) as &[u8],
            ),
            (
                24,
                include_bytes!(concat!("../icons/tray/tray-", $kind, "-24.png")) as &[u8],
            ),
            (
                32,
                include_bytes!(concat!("../icons/tray/tray-", $kind, "-32.png")) as &[u8],
            ),
            (
                40,
                include_bytes!(concat!("../icons/tray/tray-", $kind, "-40.png")) as &[u8],
            ),
            (
                48,
                include_bytes!(concat!("../icons/tray/tray-", $kind, "-48.png")) as &[u8],
            ),
        ]
    };
}
const DARK_PANEL: [(u32, &[u8]); 6] = frames!("dark");
const LIGHT_PANEL: [(u32, &[u8]); 6] = frames!("light");
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MAC_TEMPLATE: &[u8] = include_bytes!("../icons/tray/trayTemplate@2x.png");

/// PNG bytes of the glyph for `panel` at `size` px (nearest shipped frame).
pub fn png(panel: Panel, size: u32) -> &'static [u8] {
    let set = match panel {
        Panel::Dark => &DARK_PANEL,
        Panel::Light => &LIGHT_PANEL,
    };
    // Exact frame, else the nearest one (never resampled here).
    set.iter()
        .min_by_key(|(s, _)| s.abs_diff(size))
        .map(|(_, b)| *b)
        .unwrap_or(set[2].1)
}

fn image(bytes: &'static [u8]) -> tauri::Result<Image<'static>> {
    Image::from_bytes(bytes)
}

/// Linux: decide the panel colour from what the desktop tells us.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn linux_panel(
    current_desktop: &str,
    gtk_theme_env: Option<&str>,
    prefer_dark: bool,
    gtk_theme_name: Option<&str>,
    color_scheme: Option<&str>,
) -> Panel {
    let dark_name = |s: &str| s.to_ascii_lowercase().contains("dark");
    if current_desktop
        .split(':')
        .any(|d| d.eq_ignore_ascii_case("GNOME"))
    {
        return Panel::Dark; // GNOME Shell's top bar is dark in light and dark style
    }
    if gtk_theme_env.is_some_and(dark_name) || prefer_dark || gtk_theme_name.is_some_and(dark_name)
    {
        return Panel::Dark;
    }
    match color_scheme {
        Some("prefer-dark") => Panel::Dark,
        Some(_) => Panel::Light,
        // A GTK theme we can read and that isn't dark: light panel.
        None if gtk_theme_name.is_some() || gtk_theme_env.is_some() => Panel::Light,
        // Nothing detectable: the usual dark panel.
        None => Panel::Dark,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{linux_panel, Panel};
    use gtk::prelude::*;

    fn color_scheme_settings() -> Option<gio::Settings> {
        let src = gio::SettingsSchemaSource::default()?;
        let schema = src.lookup("org.gnome.desktop.interface", true)?;
        schema
            .has_key("color-scheme")
            .then(|| gio::Settings::new("org.gnome.desktop.interface"))
    }

    pub fn color_scheme() -> Option<String> {
        color_scheme_settings().map(|g| g.string("color-scheme").to_string())
    }

    pub fn panel() -> Panel {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        let env_theme = std::env::var("GTK_THEME").ok();
        let (prefer_dark, theme) = match gtk::Settings::default() {
            Some(s) => (
                s.is_gtk_application_prefer_dark_theme(),
                s.gtk_theme_name().map(|n| n.to_string()),
            ),
            None => (false, None),
        };
        let scheme = color_scheme_settings().map(|g| g.string("color-scheme").to_string());
        linux_panel(
            &desktop,
            env_theme.as_deref(),
            prefer_dark,
            theme.as_deref(),
            scheme.as_deref(),
        )
    }

    /// Call `f` whenever the GTK theme or the GNOME colour scheme changes.
    pub fn watch(f: impl Fn() + Clone + 'static) {
        if let Some(s) = gtk::Settings::default() {
            let g = f.clone();
            s.connect_gtk_theme_name_notify(move |_| g());
            let g = f.clone();
            s.connect_gtk_application_prefer_dark_theme_notify(move |_| g());
        }
        if let Some(cs) = color_scheme_settings() {
            cs.connect_changed(Some("color-scheme"), move |_, _| f());
            // Keep the GSettings object (and its signal) alive for the process.
            std::mem::forget(cs);
        }
    }
}

/// App window theme (M1.1): dark unless the OS explicitly says light.
/// * Windows: `AppsUseLightTheme` = 1 → light; 0 or missing → dark.
/// * Linux: GNOME `color-scheme` = `prefer-light` → light; anything else
///   (`default`, `prefer-dark`, unreadable) → dark.
/// * Others: dark.
///
/// `VOIDWIRE_THEME=light|dark` overrides it (QA screenshots).
pub fn app_is_light() -> bool {
    let env = std::env::var(concat!(env!("VOIDWIRE_BRAND_ENV_PREFIX"), "_THEME")).ok();
    app_is_light_from(env.as_deref(), crate::diag::theme(), os_app_light())
}

/// Pure rule behind `app_is_light` (unit-tested). Order: the QA env
/// override, then the in-app Theme setting (`setting`: None = System), then
/// the OS. System means dark unless the OS explicitly says light.
pub fn app_is_light_from(env: Option<&str>, setting: Option<bool>, os: Option<bool>) -> bool {
    match env {
        Some("light") => true,
        Some("dark") => false,
        _ => setting.unwrap_or(os == Some(true)),
    }
}

fn os_app_light() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        linux::color_scheme().map(|c| c == "prefer-light")
    }
    #[cfg(not(target_os = "linux"))]
    {
        voidwire_os_theme::apps_are_light()
    }
}

/// The page script that applies the theme (`<html data-theme=...>`), run
/// before any page script (initialization script) and on theme changes.
pub fn theme_script(light: bool) -> String {
    let t = if light { "light" } else { "dark" };
    format!(
        "(function(){{var t='{t}';var a=function(){{var e=document.documentElement;if(e){{e.dataset.theme=t;return true}}return false}};if(!a()){{new MutationObserver(function(m,o){{if(a())o.disconnect()}}).observe(document,{{childList:true,subtree:true}})}}}})();"
    )
}

/// Initialization script: like `theme_script`, but a `vwtheme` / `vwtab`
/// query (set by a Linux reopen, which reloads a hidden window) wins.
pub fn theme_script_url(light: bool) -> String {
    let t = if light { "light" } else { "dark" };
    format!(
        "(function(){{var q=new URLSearchParams(location.search),t=q.get('vwtheme');if(t!=='light'&&t!=='dark')t='{t}';var b=q.get('vwtab');if(b)window.__VW_TAB=b;var a=function(){{var e=document.documentElement;if(e){{e.dataset.theme=t;return true}}return false}};if(!a()){{new MutationObserver(function(m,o){{if(a())o.disconnect()}}).observe(document,{{childList:true,subtree:true}})}}}})();"
    )
}

/// Window background behind the webview (no white flash before first paint):
/// the tokens' background colour.
pub fn window_bg(light: bool) -> tauri::window::Color {
    if light {
        tauri::window::Color(0xf4, 0xf6, 0xf9, 0xff)
    } else {
        tauri::window::Color(0x07, 0x0b, 0x14, 0xff)
    }
}

pub fn tauri_theme(light: bool) -> tauri::Theme {
    if light {
        tauri::Theme::Light
    } else {
        tauri::Theme::Dark
    }
}

/// Push the current app theme into every open window (OS change or the
/// in-app Theme setting): native caption + <html data-theme>.
///
/// A call that races one in progress is not dropped (QA 10-13): it leaves a
/// flag, and the running call re-reads the theme once it is done and applies
/// again if the theme changed meanwhile.
pub fn apply_windows(app: &AppHandle) {
    use std::sync::atomic::Ordering::SeqCst;
    use tauri::Manager;
    // Linux: set_theme writes GTK's prefer-dark setting, which fires our own
    // GTK theme watcher synchronously; without this guard the watcher
    // re-applies forever and the UI thread spins (found by the M1.1
    // Theme-setting screenshots).
    loop {
        if APPLYING.swap(true, SeqCst) {
            // Another call is applying: it picks this one up when done.
            APPLY_AGAIN.store(true, SeqCst);
            return;
        }
        APPLY_AGAIN.store(false, SeqCst);
        let light = app_is_light();
        for w in app.webview_windows().values() {
            let _ = w.set_theme(Some(tauri_theme(light)));
            let _ = w.set_background_color(Some(window_bg(light)));
            let _ = w.eval(theme_script(light));
        }
        APPLYING.store(false, SeqCst);
        // Re-run only for a real change that arrived meanwhile (an echo of
        // our own set_theme reads the same value), so this can't spin.
        if !APPLY_AGAIN.swap(false, SeqCst) || app_is_light() == light {
            return;
        }
    }
}

static APPLYING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Set by a call that arrived while another was applying.
static APPLY_AGAIN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True while `apply_windows` runs (the Linux GTK watcher ignores its own echo).
#[cfg(target_os = "linux")]
fn applying() -> bool {
    APPLYING.load(std::sync::atomic::Ordering::SeqCst)
}

/// The current panel colour (Windows, Linux); macOS/others: dark.
pub fn current_panel() -> Panel {
    #[cfg(target_os = "linux")]
    {
        linux::panel()
    }
    #[cfg(not(target_os = "linux"))]
    {
        match voidwire_os_theme::taskbar_is_light() {
            Some(true) => Panel::Light,
            _ => Panel::Dark,
        }
    }
}

/// The tray image for right now, and whether it is a macOS template image.
pub fn initial() -> tauri::Result<(Image<'static>, bool)> {
    if cfg!(target_os = "macos") {
        return Ok((image(MAC_TEMPLATE)?, true));
    }
    Ok((image(png(current_panel(), tray_size()))?, false))
}

fn tray_size() -> u32 {
    if cfg!(target_os = "linux") {
        return 24; // AppIndicator panels: 22-24 px
    }
    let dpi = voidwire_os_theme::system_dpi().unwrap_or(96);
    voidwire_os_theme::tray_frame_for_dpi(dpi)
}

fn apply(app: &AppHandle, panel: Panel) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        if let Ok(img) = image(png(panel, tray_size())) {
            let _ = tray.set_icon(Some(img));
            crate::node::log(&format!("tray icon: {panel:?} panel"));
        }
    }
}

/// Swap the icon when the theme changes (Windows: registry watcher thread;
/// Linux: GTK/GSettings signals on the main thread; macOS: nothing to do).
pub fn follow_theme(app: &AppHandle) {
    let start = current_panel();
    #[cfg(target_os = "linux")]
    {
        let app = app.clone();
        let last = std::rc::Rc::new(std::cell::Cell::new(start));
        let last_light = std::rc::Rc::new(std::cell::Cell::new(app_is_light()));
        linux::watch(move || {
            if applying() {
                return; // our own set_theme echoing back
            }
            let l = app_is_light();
            if l != last_light.get() {
                last_light.set(l);
                apply_windows(&app);
            }
            let p = current_panel();
            if p != last.get() {
                last.set(p);
                apply(&app, p);
            }
        });
    }
    #[cfg(windows)]
    {
        let app = app.clone();
        std::thread::Builder::new()
            .name("tray-theme".into())
            .spawn(move || {
                let mut last = start;
                while voidwire_os_theme::wait_for_theme_change() {
                    apply_windows(&app);
                    let p = current_panel();
                    if p != last {
                        last = p;
                        apply(&app, p);
                    }
                }
            })
            .ok();
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (app, start);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frame_is_a_png_of_its_size() {
        for (set, _) in [(&DARK_PANEL, "dark"), (&LIGHT_PANEL, "light")] {
            for (size, bytes) in set.iter() {
                let img = Image::from_bytes(bytes).expect("decodes");
                assert_eq!((img.width(), img.height()), (*size, *size));
            }
        }
        let t = Image::from_bytes(MAC_TEMPLATE).unwrap();
        assert_eq!((t.width(), t.height()), (32, 32));
    }

    #[test]
    fn png_picks_the_exact_frame() {
        for s in [16, 20, 24, 32, 40, 48] {
            let b = png(Panel::Light, s);
            assert_eq!(Image::from_bytes(b).unwrap().width(), s);
        }
        assert_ne!(png(Panel::Light, 24), png(Panel::Dark, 24));
    }

    #[test]
    fn app_theme_is_dark_unless_the_os_explicitly_says_light() {
        assert!(!app_is_light_from(None, None, None), "unknown: dark");
        assert!(!app_is_light_from(None, None, Some(false)));
        assert!(app_is_light_from(None, None, Some(true)));
        assert!(!app_is_light_from(Some("dark"), None, Some(true)));
        assert!(app_is_light_from(Some("light"), None, None));
        assert!(!app_is_light_from(Some("auto"), None, None));
        // In-app Theme setting (SPEC 2.6) beats the OS; System (None) follows it.
        assert!(
            app_is_light_from(None, Some(true), Some(false)),
            "Light on a dark OS"
        );
        assert!(
            !app_is_light_from(None, Some(false), Some(true)),
            "Dark on a light OS"
        );
        assert!(
            !app_is_light_from(None, None, None),
            "System, OS silent: dark"
        );
        assert!(theme_script(false).contains("'dark'"));
        assert!(theme_script(true).contains("'light'"));
    }

    #[test]
    fn linux_panel_rules() {
        // GNOME: top bar is always dark.
        assert_eq!(
            linux_panel("ubuntu:GNOME", None, false, Some("Yaru"), Some("default")),
            Panel::Dark
        );
        // KDE/XFCE etc. follow the theme.
        assert_eq!(
            linux_panel("XFCE", None, false, Some("Adwaita"), None),
            Panel::Light
        );
        assert_eq!(
            linux_panel("XFCE", None, false, Some("Adwaita-dark"), None),
            Panel::Dark
        );
        assert_eq!(
            linux_panel("KDE", None, true, Some("Breeze"), None),
            Panel::Dark
        );
        assert_eq!(
            linux_panel("", Some("Adwaita:dark"), false, Some("Adwaita"), None),
            Panel::Dark
        );
        assert_eq!(
            linux_panel("", None, false, Some("Adwaita"), Some("prefer-dark")),
            Panel::Dark
        );
        assert_eq!(
            linux_panel("", None, false, Some("Adwaita"), Some("prefer-light")),
            Panel::Light
        );
        // Nothing known: dark (the usual panel).
        assert_eq!(linux_panel("", None, false, None, None), Panel::Dark);
    }
}
