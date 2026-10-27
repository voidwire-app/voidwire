#![forbid(unsafe_code)]
//! The URL allow-list (TEST-PLAN §4 pipeline). Applied on receive (in
//! `verify`), again inside the system opener (defense in depth), and on send.
//!
//! 1. Reject raw input containing whitespace, C0/C1 controls, DEL, U+2028/2029,
//!    bidi/format controls or BOM. Nothing is stripped first.
//! 2. Parse with the WHATWG parser (`url` crate).
//! 3. Scheme must be `http`/`https` (parser lowercases), host non-empty.
//! 4. No username/password. Host policy (OQ-8, docs/PROTOCOL.md §6.1): RFC 1918
//!    and IPv6 ULA allowed; loopback, link-local and unspecified rejected,
//!    including IPv4-mapped/compatible/NAT64 IPv6 forms. Odd IPv4 spellings
//!    (`2130706433`, `0x7f.1`, `0177.0.0.1`, `127.1`) are normalized by the
//!    WHATWG parser before this check, so they hit the same rule.
//! 5. Re-serialize to `canon`; percent-encode any byte outside the RFC 3986
//!    character set (e.g. `|`, `^`, `{`, `}`), then require that re-parsing
//!    `canon` is idempotent.
//! 6. `canon.len() <= cap` (cap applied to `canon`, not the raw input).
//!
//! Callers must use `canon` (via `Url::as_str()`), never the raw input.

use crate::limits::{MAX_PUSH_URL_BYTES, MAX_URL_BYTES};
use crate::reject::RejectReason;
use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

fn forbidden_char(c: char) -> bool {
    c.is_whitespace()
        || c.is_control()
        || matches!(c,
            '\u{200B}'..='\u{200F}'   // zero-width, LRM/RLM
            | '\u{202A}'..='\u{202E}' // bidi embeddings/overrides
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{2028}' | '\u{2029}'
            | '\u{FEFF}')
}

fn rfc3986_allowed(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&b)
}

fn check_ipv4(a: Ipv4Addr) -> Result<(), RejectReason> {
    let o = a.octets();
    if o[0] == 0 {
        Err(RejectReason::HostUnspecified)
    } else if a.is_loopback() {
        Err(RejectReason::HostLoopback)
    } else if a.is_link_local() {
        Err(RejectReason::HostLinkLocal)
    } else if a.is_broadcast() {
        Err(RejectReason::HostBroadcast)
    } else if a.is_multicast() {
        Err(RejectReason::HostMulticast)
    } else {
        Ok(())
    }
}

/// RFC 6052 IPv4-embedded IPv6: the IPv4 address for prefix length `plen`
/// (32/40/48/56/64/96). Bits 64..72 (the "u" octet) are skipped.
fn rfc6052_embedded(a: Ipv6Addr, plen: usize) -> Ipv4Addr {
    let o = a.octets();
    let idx: [usize; 4] = match plen {
        32 => [4, 5, 6, 7],
        40 => [5, 6, 7, 9],
        48 => [6, 7, 9, 10],
        56 => [7, 9, 10, 11],
        64 => [9, 10, 11, 12],
        _ => [12, 13, 14, 15],
    };
    Ipv4Addr::new(o[idx[0]], o[idx[1]], o[idx[2]], o[idx[3]])
}

fn check_ipv6(a: Ipv6Addr) -> Result<(), RejectReason> {
    if a.is_unspecified() {
        return Err(RejectReason::HostUnspecified);
    }
    if a.is_loopback() {
        return Err(RejectReason::HostLoopback);
    }
    let seg = a.segments();
    if seg[0] & 0xffc0 == 0xfe80 {
        return Err(RejectReason::HostLinkLocal);
    }
    // N1: deprecated site-local fec0::/10, multicast ff00::/8.
    if seg[0] & 0xffc0 == 0xfec0 {
        return Err(RejectReason::HostSiteLocal);
    }
    if seg[0] & 0xff00 == 0xff00 {
        return Err(RejectReason::HostMulticast);
    }
    let embedded =
        |s: &[u16]| Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    // ::ffff:a.b.c.d (mapped), ::a.b.c.d (deprecated compatible),
    // ::ffff:0:a.b.c.d (N1: IPv4-translated, RFC 2765), 64:ff9b::a.b.c.d (NAT64)
    if seg[..5] == [0; 5] && (seg[5] == 0xffff || seg[5] == 0)
        || seg[..4] == [0; 4] && seg[4] == 0xffff && seg[5] == 0
        || seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
    {
        return check_ipv4(embedded(&seg));
    }
    // N1: local-use NAT64 64:ff9b:1::/48 (RFC 8215). The operator picks the
    // prefix length, so every RFC 6052 placement must be clean.
    // Loopback/link-local in any placement is rejected; the /96 placement
    // also gets the multicast/broadcast rules, and an all-zero suffix is
    // unspecified (zero padding in the other placements is normal).
    if seg[..3] == [0x64, 0xff9b, 0x1] {
        for plen in [96, 48, 56, 64] {
            if let Err(e @ (RejectReason::HostLoopback | RejectReason::HostLinkLocal)) =
                check_ipv4(rfc6052_embedded(a, plen))
            {
                return Err(e);
            }
        }
        if a.octets()[6..].iter().all(|&b| b == 0) {
            return Err(RejectReason::HostUnspecified);
        }
        let v96 = rfc6052_embedded(a, 96);
        if v96.octets()[0] != 0 {
            check_ipv4(v96)?;
        }
    }
    // N1: 6to4 2002:a.b.c.d::/48 (RFC 3056).
    if seg[0] == 0x2002 {
        check_ipv4(Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        ))?;
    }
    Ok(())
}

fn check_host(url: &Url) -> Result<(), RejectReason> {
    match url.host() {
        None => Err(RejectReason::UrlMissingHost),
        Some(Host::Domain("")) => Err(RejectReason::UrlMissingHost),
        Some(Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            // N1: also the common /etc/hosts loopback aliases.
            if d == "localhost"
                || d.ends_with(".localhost")
                || d == "localhost.localdomain"
                || d == "ip6-localhost"
                || d == "ip6-loopback"
            {
                Err(RejectReason::HostLoopback)
            } else {
                Ok(())
            }
        }
        Some(Host::Ipv4(a)) => check_ipv4(a),
        Some(Host::Ipv6(a)) => check_ipv6(a),
    }
}

/// Percent-encode every byte outside the RFC 3986 set, and every `%` that
/// does not start a valid `%XX` escape (D6 / URL-22: `https://x/%zz` becomes
/// `https://x/%25zz`). Valid escapes are kept as-is so `canon` is a fixed point.
fn rfc3986_canon(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut canon = String::with_capacity(s.len());
    for (i, &b) in bytes.iter().enumerate() {
        let valid_escape = b == b'%'
            && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit);
        if rfc3986_allowed(b) && (b != b'%' || valid_escape) {
            canon.push(b as char);
        } else {
            canon.push_str(&format!("%{b:02X}"));
        }
    }
    canon
}

/// `https://:@host` parses to an *empty* userinfo that the serializer drops;
/// refuse any `@` in the raw authority anyway (URL-06), so what the sender
/// typed and what we open never disagree about credentials.
fn raw_authority_has_at(raw: &str) -> bool {
    let Some((_, rest)) = raw.split_once(':') else {
        return false;
    };
    let rest = rest.trim_start_matches(['/', '\\']);
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    rest[..end].contains('@')
}

/// Check a URL for the LAN/relay path (cap [`MAX_URL_BYTES`]).
pub fn check_url(raw: &str) -> Result<Url, RejectReason> {
    check_url_with_cap(raw, MAX_URL_BYTES)
}

/// Check a URL for the push path (cap [`MAX_PUSH_URL_BYTES`]).
pub fn check_push_url(raw: &str) -> Result<Url, RejectReason> {
    check_url_with_cap(raw, MAX_PUSH_URL_BYTES)
}

pub fn check_url_with_cap(raw: &str, cap: usize) -> Result<Url, RejectReason> {
    if raw.is_empty() {
        return Err(RejectReason::UrlParseError);
    }
    if raw.len() > cap {
        return Err(RejectReason::UrlTooLong);
    }
    if raw.chars().any(forbidden_char) {
        return Err(RejectReason::UrlBadChars);
    }
    let url = Url::parse(raw).map_err(|_| RejectReason::UrlParseError)?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(RejectReason::SchemeNotAllowed),
    }
    if !url.username().is_empty() || url.password().is_some() || raw_authority_has_at(raw) {
        return Err(RejectReason::UrlHasUserinfo);
    }
    check_host(&url)?;
    let canon = rfc3986_canon(url.as_str());
    if canon.len() > cap {
        return Err(RejectReason::UrlTooLong);
    }
    let reparsed = Url::parse(&canon).map_err(|_| RejectReason::UrlBadChars)?;
    if reparsed.as_str() != canon
        || reparsed.scheme() != url.scheme()
        || reparsed.host_str() != url.host_str()
    {
        return Err(RejectReason::UrlBadChars);
    }
    Ok(reparsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        check_url(s).unwrap().as_str().to_owned()
    }

    #[test]
    fn accepts_http_and_https() {
        assert_eq!(
            canon("https://example.com/a?b=c#d"),
            "https://example.com/a?b=c#d"
        );
        assert_eq!(canon("http://example.com"), "http://example.com/");
        assert!(check_url("http://192.168.1.10:8080/").is_ok());
        assert_eq!(canon("HtTpS://EXAMPLE.com"), "https://example.com/");
        assert_eq!(
            check_url("https://bücher.example/").unwrap().host_str(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            check_url("https://аpple.com/").unwrap().host_str(),
            Some("xn--pple-43d.com")
        );
    }

    #[test]
    fn rejects_other_schemes() {
        for u in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "file:///etc/passwd",
            "file:///C:/Windows/System32/calc.exe",
            "file://host/share",
            "data:text/html,<script>alert(1)</script>",
            "Data:text/plain,x",
            "intent://scan/#Intent;scheme=zxing;end",
            "ftp://example.com/",
            "ms-msdt:/id",
            "ms-settings:",
            "search-ms:query=x",
            "ms-officecmd:x",
            "smb://host/share",
            "vbscript:msgbox",
            "chrome://settings",
            "edge://settings",
            "about:blank",
            "blob:https://x/uuid",
            "mailto:a@example.com",
            "tel:123",
            "sms:123",
            "market://details",
            "ws://example.com/",
            "wss://example.com/",
            "view-source:https://x",
            "microsoft-edge:https://x",
            "voidwire:pair?v=1",
            "shell:startup",
            "jar:file:x!/",
            "x-callback-url://x",
            "steam://run/1",
            "zoommtg://x",
        ] {
            assert!(
                matches!(check_url(u), Err(RejectReason::SchemeNotAllowed)),
                "{u}"
            );
        }
    }

    #[test]
    fn rejects_controls_without_stripping() {
        for u in [
            " https://example.com",
            "https://example.com ",
            "https://example.com/\r\nHost: y",
            "https://exa\tmple.com",
            "java\nscript:alert(1)",
            "java\tscript:alert(1)",
            "https://x/\0",
            "https://x/\x0b",
            "https://x/\x7f",
            "https://x/\u{a0}",
            "https://x/\u{2028}",
            "\u{feff}https://x/",
            "https://evil.com/\u{202e}gpj.exe",
            "https://x/\u{2066}",
            "https://x/\u{200e}",
        ] {
            assert_eq!(check_url(u), Err(RejectReason::UrlBadChars), "{u:?}");
        }
    }

    #[test]
    fn userinfo_and_structure() {
        for u in [
            "https://user:pw@example.com/",
            "https://good.com@evil.com",
            "https://:@x",
            "https://@x/x",
        ] {
            let r = check_url(u);
            assert!(
                matches!(
                    r,
                    Err(RejectReason::UrlHasUserinfo) | Err(RejectReason::UrlParseError)
                ),
                "{u}: {r:?}"
            );
        }
        assert_eq!(
            check_url("https://user@example.com/"),
            Err(RejectReason::UrlHasUserinfo)
        );
        for u in [
            "example.com",
            "//evil.com",
            "%68ttps://x",
            "https%3A%2F%2Fx",
            "\\\\evil.com\\share",
            "",
        ] {
            assert!(check_url(u).is_err(), "{u}");
        }
        assert!(matches!(
            check_url("javascript%3Aalert(1)"),
            Err(RejectReason::UrlParseError)
        ));
        // Backslashes normalize per WHATWG.
        assert_eq!(canon("https:\\\\evil.com\\"), "https://evil.com/");
    }

    #[test]
    fn injection_chars_are_encoded_in_canon() {
        for u in [
            "https://x/%22%20--single-argument",
            "https://x/&calc",
            "https://x/|calc",
            "https://x/^calc",
            "https://x/'$(id)'",
            "https://x/;id",
            "https://x/{a}",
            "https://x/?q=\"a\"",
            "https://x/#`id`",
            "https://x/?a=<b>",
        ] {
            let c = canon(u);
            assert!(c.bytes().all(rfc3986_allowed), "{u} -> {c}");
            assert!(
                !c.contains('"') && !c.contains('`') && !c.contains(' '),
                "{c}"
            );
            assert_eq!(canon(&c), c, "idempotent");
        }
        assert_eq!(canon("https://x/|calc"), "https://x/%7Ccalc");
    }

    #[test]
    fn host_policy_oq8() {
        use RejectReason::*;
        let cases: &[(&str, Result<&str, RejectReason>)] = &[
            // allowed: RFC 1918, ULA, public, odd spellings of private addresses normalize
            ("http://10.0.0.1/", Ok("http://10.0.0.1/")),
            ("http://172.16.5.4:8080/", Ok("http://172.16.5.4:8080/")),
            ("http://192.168.1.10/", Ok("http://192.168.1.10/")),
            ("http://0xa.1/", Ok("http://10.0.0.1/")),
            ("http://3232235777/", Ok("http://192.168.1.1/")),
            ("http://[fd12:3456::1]/", Ok("http://[fd12:3456::1]/")),
            ("http://[fc00::1]/", Ok("http://[fc00::1]/")),
            ("https://8.8.8.8/", Ok("https://8.8.8.8/")),
            ("https://[2001:db8::1]/", Ok("https://[2001:db8::1]/")),
            (
                "https://[::ffff:192.168.0.1]/",
                Ok("https://[::ffff:c0a8:1]/"),
            ),
            ("https://notlocalhost.com/", Ok("https://notlocalhost.com/")),
            (
                "https://localhost.example/",
                Ok("https://localhost.example/"),
            ),
            // loopback
            ("http://127.0.0.1/", Err(HostLoopback)),
            ("http://127.255.255.254:1/", Err(HostLoopback)),
            ("http://127.1/", Err(HostLoopback)),
            ("http://2130706433/", Err(HostLoopback)),
            ("http://0x7f.1/", Err(HostLoopback)),
            ("http://0x7f000001/", Err(HostLoopback)),
            ("http://0177.0.0.1/", Err(HostLoopback)),
            ("http://127.0.0.1./", Err(HostLoopback)),
            ("http://%31%32%37.0.0.1/", Err(HostLoopback)),
            ("http://[::1]:8080/", Err(HostLoopback)),
            ("http://[0:0:0:0:0:0:0:1]/", Err(HostLoopback)),
            ("http://[::ffff:127.0.0.1]/", Err(HostLoopback)),
            ("http://[::ffff:7f00:1]/", Err(HostLoopback)),
            ("http://[::127.0.0.1]/", Err(HostLoopback)),
            ("http://[64:ff9b::127.0.0.1]/", Err(HostLoopback)),
            ("http://localhost/", Err(HostLoopback)),
            ("http://LOCALHOST:3000/", Err(HostLoopback)),
            ("http://localhost./", Err(HostLoopback)),
            ("http://foo.localhost/", Err(HostLoopback)),
            ("http://a.b.LocalHost./", Err(HostLoopback)),
            // link-local
            (
                "http://169.254.169.254/latest/meta-data",
                Err(HostLinkLocal),
            ),
            ("http://169.254.0.1/", Err(HostLinkLocal)),
            ("http://0xa9fea9fe/", Err(HostLinkLocal)),
            ("http://[fe80::1]/", Err(HostLinkLocal)),
            ("http://[febf::1]/", Err(HostLinkLocal)),
            ("http://[::ffff:169.254.1.1]/", Err(HostLinkLocal)),
            // unspecified
            ("http://0.0.0.0/", Err(HostUnspecified)),
            ("http://0/", Err(HostUnspecified)),
            ("http://0x0/", Err(HostUnspecified)),
            ("http://0.1.2.3/", Err(HostUnspecified)),
            ("http://[::]/", Err(HostUnspecified)),
            ("http://[::ffff:0.0.0.0]/", Err(HostUnspecified)),
        ];
        for (u, want) in cases {
            let got = check_url(u).map(|x| x.as_str().to_owned());
            match want {
                Ok(c) => assert_eq!(got.as_deref(), Ok(*c), "{u}"),
                Err(e) => assert_eq!(got, Err(*e), "{u}"),
            }
        }
        // Same policy on the push path.
        assert_eq!(check_push_url("http://localhost/"), Err(HostLoopback));
    }

    /// N1 (QA re-check): the remaining self-pointing / non-unicast forms.
    #[test]
    fn host_policy_n1() {
        use RejectReason::*;
        let cases: &[(&str, Result<(), RejectReason>)] = &[
            // IPv4-translated ::ffff:0:a.b.c.d (RFC 2765)
            ("http://[::ffff:0:127.0.0.1]/", Err(HostLoopback)),
            ("http://[::ffff:0:169.254.1.1]/", Err(HostLinkLocal)),
            ("http://[::ffff:0:0.0.0.0]/", Err(HostUnspecified)),
            ("http://[::ffff:0:192.168.1.1]/", Ok(())),
            // local-use NAT64 64:ff9b:1::/48 (RFC 8215), every RFC 6052 placement
            ("http://[64:ff9b:1::127.0.0.1]/", Err(HostLoopback)),
            ("http://[64:ff9b:1:7f00:0:100::]/", Err(HostLoopback)), // /48 placement
            ("http://[64:ff9b:1:a9:fe:101::]/", Err(HostLinkLocal)), // /56 placement
            ("http://[64:ff9b:1::8.8.8.8]/", Ok(())),
            // 6to4 2002::/16 embedding loopback / link-local / unspecified
            ("http://[2002:7f00:1::1]/", Err(HostLoopback)),
            ("http://[2002:a9fe:101::]/", Err(HostLinkLocal)),
            ("http://[2002::1]/", Err(HostUnspecified)),
            ("http://[2002:808:808::1]/", Ok(())),
            // deprecated site-local
            ("http://[fec0::1]/", Err(HostSiteLocal)),
            ("http://[feff::1]/", Err(HostSiteLocal)),
            // hosts-file loopback aliases
            ("http://localhost.localdomain/", Err(HostLoopback)),
            ("http://LOCALHOST.LOCALDOMAIN./", Err(HostLoopback)),
            ("http://ip6-localhost/", Err(HostLoopback)),
            ("http://ip6-loopback:80/", Err(HostLoopback)),
            ("http://my-ip6-localhost.example/", Ok(())),
            // multicast and broadcast
            ("http://224.0.0.1/", Err(HostMulticast)),
            ("http://239.255.255.250:1900/", Err(HostMulticast)),
            ("http://[ff02::1]/", Err(HostMulticast)),
            ("http://[::ffff:224.0.0.251]/", Err(HostMulticast)),
            ("http://255.255.255.255/", Err(HostBroadcast)),
            ("http://4294967295/", Err(HostBroadcast)),
            // still allowed
            ("http://192.168.1.255/", Ok(())),
            ("http://223.255.255.255/", Ok(())),
        ];
        for (u, want) in cases {
            assert_eq!(check_url(u).map(|_| ()), *want, "{u}");
        }
    }

    /// DNS rebinding (e.g. `127.0.0.1.nip.io`) is an accepted, documented
    /// risk: names are never resolved here (PROTOCOL §9.1.1).
    #[test]
    fn dns_names_are_not_resolved_accepted_risk() {
        assert!(check_url("http://127.0.0.1.nip.io/").is_ok());
    }

    #[test]
    fn stray_percent_is_encoded_d6() {
        assert_eq!(canon("https://x/%zz"), "https://x/%25zz");
        assert_eq!(canon("https://x/%"), "https://x/%25");
        assert_eq!(canon("https://x/a%4"), "https://x/a%254");
        assert_eq!(canon("https://x/?q=100%"), "https://x/?q=100%25");
        assert_eq!(canon("https://x/#%g1"), "https://x/#%25g1");
        // Valid escapes are untouched (case kept), so canon is a fixed point.
        assert_eq!(canon("https://x/%41%e9"), "https://x/%41%e9");
        assert_eq!(canon("https://x/%2525"), "https://x/%2525");
        for u in [
            "https://x/%zz",
            "https://x/%",
            "https://x/%%41",
            "https://x/%4%41",
        ] {
            let c = canon(u);
            assert_eq!(canon(&c), c, "idempotent: {u}");
            let b = c.as_bytes();
            for (i, _) in c.match_indices('%') {
                assert!(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit), "{c}");
                assert!(b.get(i + 2).is_some_and(u8::is_ascii_hexdigit), "{c}");
            }
        }
    }

    #[test]
    fn rejection_text_never_echoes_the_scheme_d11() {
        let e = check_url("javascript:alert(1)").unwrap_err();
        assert_eq!(e, RejectReason::SchemeNotAllowed);
        assert!(!e.to_string().contains("javascript"));
        assert!(!format!("{e:?}").contains("javascript"));
    }

    #[test]
    fn size_cap_on_canon() {
        let base = "https://example.com/";
        let ok = format!("{base}{}", "a".repeat(MAX_URL_BYTES - base.len()));
        assert!(check_url(&ok).is_ok());
        let too = format!("{base}{}", "a".repeat(MAX_URL_BYTES - base.len() + 1));
        assert_eq!(check_url(&too), Err(RejectReason::UrlTooLong));
        // Raw fits, canon grows past the cap (percent-encoding inflation).
        let grow = format!("{base}{}", "é".repeat((MAX_URL_BYTES - base.len()) / 2));
        assert_eq!(check_url(&grow), Err(RejectReason::UrlTooLong));
        // Push path has its own cap.
        let push_ok = format!("{base}{}", "a".repeat(MAX_PUSH_URL_BYTES - base.len()));
        assert!(check_push_url(&push_ok).is_ok());
        assert_eq!(
            check_push_url(&format!("{push_ok}a")),
            Err(RejectReason::UrlTooLong)
        );
    }
}
