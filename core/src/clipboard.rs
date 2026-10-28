#![forbid(unsafe_code)]
//! First-class clipboard text sharing and URL vs. text classification (`M3-PLAN.md` §2).

use crate::limits::{MAX_INLINE_CLIPBOARD_BYTES, MAX_STREAMED_CLIPBOARD_BYTES};
use crate::reject::RejectReason;
use crate::url_policy::check_url;

/// Bit 0 in `MessageKind::ClipboardText { flags }`: sender-side heuristic
/// detected that the clipboard text looks like a single-line secret/token/key.
pub const FLAG_SENSITIVE_HINT: u8 = 0x01;

/// Synthetic MIME type used when streaming oversized clipboard text (`> 7,680 B`)
/// over the chunked file transfer channel (`M3-PLAN.md` §2.5).
pub const CLIPBOARD_STREAM_MIME: &str = "text/x-voidwire-clipboard;charset=utf-8";

/// Classified outbound payload when sharing text or clipboard contents (`M3-PLAN.md` §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedContentKind {
    /// Trimmed text is a single valid `http`/`https` URL passing `validate_url`.
    Url { url: String },
    /// UTF-8 text `<= 7,680` bytes sent inside a single `BUCKET_LARGE` (`8,448 B`) HPKE envelope.
    InlineClipboard { text: String, sensitive_hint: bool },
    /// UTF-8 text `> 7,680` bytes (up to `10 MiB`) streamed over `FILE_OFFER` + `FILE_CHUNK`.
    StreamedClipboard { text: String, sensitive_hint: bool },
}

fn shannon_entropy_bits_per_byte(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Heuristic for whether clipboard text looks like a sensitive token, API key,
/// private key, or password so the receiving UI defaults the preview to masked (`••••••`).
pub fn looks_sensitive_clipboard(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains("-----BEGIN ") && trimmed.contains("PRIVATE KEY-----") {
        return true;
    }
    if text.contains('\n') || text.contains('\r') {
        return false;
    }
    let char_count = trimmed.chars().count();
    if !(8..=512).contains(&char_count) {
        return false;
    }
    for prefix in [
        "sk-",
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "ghp_",
        "gho_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "ASIA",
        "AIza",
        "eyJ",
        "AGE-SECRET-KEY-",
    ] {
        if trimmed.starts_with(prefix) {
            return true;
        }
    }
    if trimmed.to_ascii_lowercase().starts_with("bearer ") {
        return true;
    }
    if !trimmed.chars().any(char::is_whitespace) && trimmed.len() >= 16 {
        let has_upper = trimmed.bytes().any(|b| b.is_ascii_uppercase());
        let has_lower = trimmed.bytes().any(|b| b.is_ascii_lowercase());
        let has_digit = trimmed.bytes().any(|b| b.is_ascii_digit());
        let has_sym = trimmed
            .bytes()
            .any(|b| b.is_ascii_punctuation() && b != b'.' && b != b'/');
        let classes = (has_upper as u8) + (has_lower as u8) + (has_digit as u8) + (has_sym as u8);
        if classes >= 3 && shannon_entropy_bits_per_byte(trimmed.as_bytes()) >= 3.8 {
            return true;
        }
        // Hex or base64-like secret of >= 32 chars with high entropy
        if trimmed.len() >= 32
            && classes >= 2
            && shannon_entropy_bits_per_byte(trimmed.as_bytes()) >= 3.7
        {
            return true;
        }
    }
    false
}

/// Deterministically classify shared text or clipboard text (`M3-PLAN.md` §2.1):
/// 1. Empty or whitespace-only -> `Err(RejectReason::MalformedFrame)`
/// 2. Contains NUL (`\0`) -> `Err(RejectReason::MalformedFrame)`
/// 3. Exceeds `MAX_STREAMED_CLIPBOARD_BYTES` (10 MiB) -> `Err(RejectReason::UrlTooLong)`
/// 4. Single line (no internal whitespace) starting with `http://` or `https://`:
///    validated via `check_url(trimmed)` -> `Ok(SharedContentKind::Url { url })`
///    (Note: if `validate_url` rejects a dangerous URL such as loopback/RFC1918/userinfo,
///    that policy rejection is returned rather than silently downgrading a blocked URL to text!
///    Only non-URL text or strings that fail generic URL syntax parsing become `ClipboardText`.)
/// 5. Otherwise -> `InlineClipboard` (`<= 7,680 B`) or `StreamedClipboard` (`> 7,680 B`).
pub fn classify_shared_text(raw: &str) -> Result<SharedContentKind, RejectReason> {
    if raw.as_bytes().contains(&0) {
        return Err(RejectReason::MalformedFrame);
    }
    let trimmed = raw.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if trimmed.is_empty() {
        return Err(RejectReason::MalformedFrame);
    }
    if raw.len() > MAX_STREAMED_CLIPBOARD_BYTES {
        return Err(RejectReason::UrlTooLong);
    }

    if !trimmed.chars().any(char::is_whitespace) && trimmed.len() <= crate::limits::MAX_URL_BYTES {
        let lower_prefix = trimmed.get(..8).unwrap_or(trimmed).to_ascii_lowercase();
        if lower_prefix.starts_with("http://") || lower_prefix.starts_with("https://") {
            match check_url(trimmed) {
                Ok(valid) => {
                    return Ok(SharedContentKind::Url {
                        url: valid.as_str().to_owned(),
                    });
                }
                Err(reason) => match reason {
                    // Syntax error in something starting with http(s):// (e.g. "http:// no host")
                    // falls through to clipboard text; explicit security policy blocks (loopback,
                    // userinfo, link-local, etc.) propagate as errors if it's a single token URL.
                    RejectReason::UrlParseError
                    | RejectReason::SchemeNotAllowed
                    | RejectReason::UrlMissingHost => {}
                    other => return Err(other),
                },
            }
        }
    }

    let sensitive_hint = looks_sensitive_clipboard(raw);
    if raw.len() <= MAX_INLINE_CLIPBOARD_BYTES {
        Ok(SharedContentKind::InlineClipboard {
            text: raw.to_owned(),
            sensitive_hint,
        })
    } else {
        Ok(SharedContentKind::StreamedClipboard {
            text: raw.to_owned(),
            sensitive_hint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_url_vs_clipboard_text() {
        assert_eq!(
            classify_shared_text("  https://example.com/path?q=1  ").unwrap(),
            SharedContentKind::Url {
                url: "https://example.com/path?q=1".into(),
            }
        );

        // Multi-line text with a URL inside is classified as ClipboardText
        let multi = "Check this out:\nhttps://example.com/path";
        assert_eq!(
            classify_shared_text(multi).unwrap(),
            SharedContentKind::InlineClipboard {
                text: multi.into(),
                sensitive_hint: false,
            }
        );

        // Plain note -> InlineClipboard
        assert_eq!(
            classify_shared_text("meeting at 3pm in room 4B").unwrap(),
            SharedContentKind::InlineClipboard {
                text: "meeting at 3pm in room 4B".into(),
                sensitive_hint: false,
            }
        );

        // Secret token -> InlineClipboard with sensitive_hint = true
        let secret = "ghp_1234567890abcdefghijklmnopqrstuvwx";
        assert_eq!(
            classify_shared_text(secret).unwrap(),
            SharedContentKind::InlineClipboard {
                text: secret.into(),
                sensitive_hint: true,
            }
        );

        // > 7,680 bytes -> StreamedClipboard
        let big = "a".repeat(MAX_INLINE_CLIPBOARD_BYTES + 10);
        assert_eq!(
            classify_shared_text(&big).unwrap(),
            SharedContentKind::StreamedClipboard {
                text: big,
                sensitive_hint: false,
            }
        );

        // Empty or whitespace-only -> Err
        assert!(classify_shared_text("   \n\t  ").is_err());
        // NUL byte -> Err
        assert!(classify_shared_text("hello\0world").is_err());
    }
}
