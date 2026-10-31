//! OS file drops on the Devices window. The native drop handler gets them
//! (the page sees no drag events for OS files), so it hands the pointer
//! position to the page, which hit-tests its device rows: the row under the
//! pointer is the target, anywhere else asks which device. Never a default.

/// Script for the drag pointer (physical pixels in the webview), or `None`
/// when the drag left the window: highlights the row under it.
pub fn drag_over_js(at: Option<(f64, f64)>) -> String {
    match at {
        Some((x, y)) => format!(
            "window.vwDragOver&&window.vwDragOver({},{})",
            num(x),
            num(y)
        ),
        None => "window.vwDragOver&&window.vwDragOver(null,null)".to_owned(),
    }
}

/// Script for a drop of `paths` at a pointer position (physical pixels).
pub fn drop_js(x: f64, y: f64, paths: &[std::path::PathBuf]) -> String {
    let list: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
    // JSON is a valid JS literal; escape `<` and the JS-only line breaks too.
    let json = serde_json::to_string(&list)
        .unwrap_or_else(|_| "[]".to_owned())
        .replace('<', "\\u003c")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    format!(
        "window.vwDropAt&&window.vwDropAt({},{},{json})",
        num(x),
        num(y)
    )
}

fn num(v: f64) -> String {
    if v.is_finite() {
        format!("{}", v.round() as i64)
    } else {
        "0".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn drop_passes_the_pointer_and_every_path() {
        let js = drop_js(
            120.4,
            388.6,
            &[
                PathBuf::from(r"C:\a b\x.pdf"),
                PathBuf::from(r#"C:\q"</script>.txt"#),
            ],
        );
        assert_eq!(
            js,
            r#"window.vwDropAt&&window.vwDropAt(120,389,["C:\\a b\\x.pdf","C:\\q\"\u003c/script>.txt"])"#
        );
    }

    #[test]
    fn drag_over_and_leave() {
        assert_eq!(
            drag_over_js(Some((10.0, 20.6))),
            "window.vwDragOver&&window.vwDragOver(10,21)"
        );
        assert_eq!(
            drag_over_js(None),
            "window.vwDragOver&&window.vwDragOver(null,null)"
        );
        assert_eq!(
            drag_over_js(Some((f64::NAN, 1.0))),
            "window.vwDragOver&&window.vwDragOver(0,1)"
        );
    }
}
