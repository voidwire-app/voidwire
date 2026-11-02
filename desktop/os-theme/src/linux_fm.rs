//! Linux file managers: "Send with Voidwire" (M5.1, L2). Written and removed
//! by the opt-in right-click setting; each entry runs the existing
//! `--send-file <path>` CLI. Nothing outside these three per-user files is
//! touched (Thunar keeps its actions in the user's own `uca.xml`, so it is
//! not supported).
//!
//! - Nautilus: `nautilus/scripts/Send with Voidwire` (right-click › Scripts).
//! - Dolphin: `kio/servicemenus/voidwire-send.desktop` (top level).
//! - Nemo: `nemo/actions/voidwire-send.nemo_action` (top level).

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// Every file we write carries this line, so removal never takes a
/// same-named file the user made.
const MARK: &str = "Voidwire right-click entry";

pub(crate) const NAUTILUS: &str = "nautilus/scripts/Send with Voidwire";
pub(crate) const DOLPHIN: &str = "kio/servicemenus/voidwire-send.desktop";
pub(crate) const NEMO: &str = "nemo/actions/voidwire-send.nemo_action";

/// `$XDG_DATA_HOME`, else `~/.local/share`.
pub(crate) fn data_home() -> Option<PathBuf> {
    match std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        Some(p) if p.is_absolute() => Some(p),
        _ => std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")),
    }
}

/// POSIX shell single quotes.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A quoted argument for a desktop-entry `Exec=` line (Desktop Entry spec:
/// double quotes, with `"` `` ` `` `$` `\` backslash-escaped, and `%` doubled;
/// the key-file layer then needs each backslash doubled again).
fn exec_quote(s: &str) -> String {
    let mut q = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '`' | '$' | '\\' => {
                q.push_str(r"\\");
                q.push(c);
            }
            '%' => q.push_str("%%"),
            '\n' | '\r' => {}
            _ => q.push(c),
        }
    }
    q.push('"');
    q
}

pub(crate) fn render_nautilus(exe: &str) -> String {
    format!(
        "#!/bin/sh\n# {MARK}. Turn it off in Voidwire's settings.\nfor f in \"$@\"; do\n  {} --send-file \"$f\"\ndone\n",
        sh_quote(exe)
    )
}

pub(crate) fn render_dolphin(exe: &str) -> String {
    format!(
        "# {MARK}. Turn it off in Voidwire's settings.\n[Desktop Entry]\nType=Service\nMimeType=all/allfiles;\nX-KDE-ServiceTypes=KonqPopupMenu/Plugin\nX-KDE-Priority=TopLevel\nActions=sendWithVoidwire;\n\n[Desktop Action sendWithVoidwire]\nName=Send with Voidwire\nIcon=voidwire\nExec={} --send-file %f\n",
        exec_quote(exe)
    )
}

pub(crate) fn render_nemo(exe: &str) -> String {
    format!(
        "# {MARK}. Turn it off in Voidwire's settings.\n[Nemo Action]\nName=Send with Voidwire\nComment=Send this file to a paired device\nExec={} --send-file %F\nSelection=s\nExtensions=nodirs;\nQuote=double\nIcon-Name=voidwire\n",
        exec_quote(exe)
    )
}

fn write_entry(path: &Path, body: &str, mode: u32) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Leave a same-named file the user made alone.
    if path.exists() && !is_ours(path) {
        return Ok(());
    }
    let tmp = path.with_extension("voidwire-tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(body.as_bytes())?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path)
}

fn is_ours(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|s| s.lines().take(3).any(|l| l.contains(MARK)))
}

fn remove_entry(path: &Path) {
    if is_ours(path) {
        let _ = std::fs::remove_file(path);
    }
}

/// Write the three entries pointing at `exe`, or remove ours (`None`).
/// The scripts and the Dolphin menu must be executable (Plasma 6 skips
/// service menus that aren't); the Nemo action is plain data.
pub(crate) fn sync(data_home: &Path, exe: Option<&Path>) -> std::io::Result<()> {
    let entries = [(NAUTILUS, 0o700), (DOLPHIN, 0o700), (NEMO, 0o600)];
    let Some(exe) = exe else {
        for (rel, _) in entries {
            remove_entry(&data_home.join(rel));
        }
        return Ok(());
    };
    let exe = exe.to_string_lossy();
    let mut first_err = None;
    for (rel, mode) in entries {
        let body = match rel {
            NAUTILUS => render_nautilus(&exe),
            DOLPHIN => render_dolphin(&exe),
            _ => render_nemo(&exe),
        };
        if let Err(e) = write_entry(&data_home.join(rel), &body, mode) {
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vw-linux-fm-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn quoting_survives_odd_paths() {
        assert_eq!(sh_quote("/opt/it's here/vw"), r"'/opt/it'\''s here/vw'");
        assert_eq!(exec_quote("/a b/100%/$x\"y"), r#""/a b/100%%/\\$x\\"y""#);
    }

    #[test]
    fn entries_point_at_the_app_and_have_the_right_modes() {
        let d = tmp("write");
        let exe = Path::new("/home/u/Apps/Voidwire.AppImage");
        sync(&d, Some(exe)).unwrap();
        let n = std::fs::read_to_string(d.join(NAUTILUS)).unwrap();
        assert!(n.starts_with("#!/bin/sh\n"));
        assert!(n.contains("'/home/u/Apps/Voidwire.AppImage' --send-file \"$f\""));
        let k = std::fs::read_to_string(d.join(DOLPHIN)).unwrap();
        assert!(k.contains("Exec=\"/home/u/Apps/Voidwire.AppImage\" --send-file %f\n"));
        assert!(k.contains("X-KDE-Priority=TopLevel"));
        let m = std::fs::read_to_string(d.join(NEMO)).unwrap();
        assert!(m.contains("Exec=\"/home/u/Apps/Voidwire.AppImage\" --send-file %F\n"));
        assert!(m.contains("Selection=s\n"));
        let mode = |p: &str| std::fs::metadata(d.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(NAUTILUS), 0o700);
        assert_eq!(mode(DOLPHIN), 0o700);
        assert_eq!(mode(NEMO), 0o600);
        // A rewrite (new AppImage path) replaces ours.
        sync(&d, Some(Path::new("/usr/bin/voidwire"))).unwrap();
        assert!(std::fs::read_to_string(d.join(NEMO))
            .unwrap()
            .contains("\"/usr/bin/voidwire\""));
        sync(&d, None).unwrap();
        for p in [NAUTILUS, DOLPHIN, NEMO] {
            assert!(!d.join(p).exists(), "{p}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_users_own_file_with_our_name_is_left_alone() {
        let d = tmp("theirs");
        std::fs::create_dir_all(d.join("nautilus/scripts")).unwrap();
        std::fs::write(d.join(NAUTILUS), "#!/bin/sh\necho mine\n").unwrap();
        sync(&d, Some(Path::new("/usr/bin/voidwire"))).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.join(NAUTILUS)).unwrap(),
            "#!/bin/sh\necho mine\n"
        );
        sync(&d, None).unwrap();
        assert!(d.join(NAUTILUS).exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
