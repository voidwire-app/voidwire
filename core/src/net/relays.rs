//! Settings → Relays (M4 §5.1): the saved list, relay links, and the
//! per-relay status line. Shared by the PC and the phone.
//!
//! A relay link is `voidwire:relay?r=<url>&m=<mailbox id>&n=<nickname>`
//! (`voidwire-mailbox --print-relay-link` prints one). `m` and `n` are
//! optional; a missing `m` means the relay's default mailbox.

use crate::ids::DeviceId;
use crate::keys::valid_device_name;
use crate::pairwise::{
    PairError, RelayEntry, RelayRef, RelaySettings, RelaySource, MAX_SAVED_RELAYS,
};

/// Why a Settings → Relays action was refused (shown as is).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    #[error("That isn't a Voidwire relay link.")]
    BadLink,
    #[error("Enter a relay URL starting with https:// (or http:// on your own network).")]
    BadUrl,
    #[error("The mailbox ID is 64 hex characters.")]
    BadMailbox,
    #[error("Pick a shorter nickname.")]
    BadName,
    #[error("That relay is already saved.")]
    Duplicate,
    #[error("You can save up to 8 relays. Remove one first.")]
    SavedFull,
    #[error("Up to 4 relays can be in use at once.")]
    InUseFull,
    #[error("Pairings use this relay. Move them to another relay first.")]
    InUse,
    #[error("The built-in relay can't be removed.")]
    Builtin,
    #[error("That relay isn't saved.")]
    NotFound,
    #[error("{0}")]
    Other(String),
}

impl From<super::NetError> for RelayError {
    fn from(e: super::NetError) -> Self {
        RelayError::Other(e.to_string())
    }
}

/// Live status of one relay, local only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatus {
    Connected,
    /// Can't reach it since this wall-clock time (ms).
    Unreachable {
        since_ms: u64,
    },
    /// Not in use right now (no pairing on it, or a phone in background).
    Idle,
}

/// One row in Settings → Relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayInfo {
    pub nickname: String,
    pub url: String,
    pub host: String,
    /// Hex mailbox id; empty for the relay's default mailbox.
    pub mailbox_id: String,
    pub home: bool,
    pub builtin: bool,
    /// Pairings on this relay (pairings with no relay of their own count
    /// for the home relay).
    pub used_by: u32,
    pub status: RelayStatus,
    /// A link for this relay to share with another device.
    pub link: String,
}

/// Normalised relay URL: trimmed, no trailing `/`, http(s) with a host.
pub fn normalize_url(url: &str) -> Result<String, RelayError> {
    let t = url.trim();
    let u = url::Url::parse(t).map_err(|_| RelayError::BadUrl)?;
    if !matches!(u.scheme(), "https" | "http") || u.host_str().is_none_or(str::is_empty) {
        return Err(RelayError::BadUrl);
    }
    if u.query().is_some() || u.fragment().is_some() || !u.username().is_empty() {
        return Err(RelayError::BadUrl);
    }
    let s = t.trim_end_matches('/').to_owned();
    let r = RelayRef::new(s.clone(), None);
    r.validate().map_err(|_| RelayError::BadUrl)?;
    Ok(s)
}

fn parse_mailbox(m: &str) -> Result<Option<DeviceId>, RelayError> {
    let m = m.trim();
    if m.is_empty() {
        return Ok(None);
    }
    if m.len() != 64 {
        return Err(RelayError::BadMailbox);
    }
    let id = DeviceId::from_hex(&m.to_ascii_lowercase()).ok_or(RelayError::BadMailbox)?;
    Ok((id != super::mailbox_client::default_mailbox_device_id()).then_some(id))
}

/// A relay from its URL and (optional) mailbox id.
pub fn relay_ref(url: &str, mailbox_hex: &str) -> Result<RelayRef, RelayError> {
    Ok(RelayRef::new(
        normalize_url(url)?,
        parse_mailbox(mailbox_hex)?,
    ))
}

/// `voidwire:relay?r=…&m=…&n=…`
pub fn format_link(url: &str, mailbox: Option<&DeviceId>, nickname: &str) -> String {
    let mut s = String::from("voidwire:relay?");
    let mut q = url::form_urlencoded::Serializer::new(String::new());
    q.append_pair("r", url);
    if let Some(m) = mailbox {
        q.append_pair("m", &m.to_hex());
    }
    if !nickname.is_empty() {
        q.append_pair("n", nickname);
    }
    s.push_str(&q.finish());
    s
}

/// The relay and nickname in a relay link (nickname defaults to the host).
pub fn parse_link(link: &str) -> Result<(RelayRef, String), RelayError> {
    let t = link.trim();
    let rest = t
        .strip_prefix("voidwire:relay?")
        .or_else(|| t.strip_prefix("voidwire://relay?"))
        .ok_or(RelayError::BadLink)?;
    if rest.len() > 2048 {
        return Err(RelayError::BadLink);
    }
    let (mut r, mut m, mut n) = (None, None, None);
    for (k, v) in url::form_urlencoded::parse(rest.as_bytes()) {
        let slot = match k.as_ref() {
            "r" => &mut r,
            "m" => &mut m,
            "n" => &mut n,
            _ => continue,
        };
        if slot.is_some() {
            return Err(RelayError::BadLink);
        }
        *slot = Some(v.into_owned());
    }
    let url = r.ok_or(RelayError::BadLink)?;
    let relay = relay_ref(&url, m.as_deref().unwrap_or(""))?;
    let nickname = match n.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) {
        Some(n) if valid_device_name(&n) => n,
        Some(_) => return Err(RelayError::BadName),
        None => super::pair2::relay_host(&relay.url),
    };
    Ok((relay, nickname))
}

fn map_pair_err(e: PairError) -> RelayError {
    match e {
        PairError::LimitReached => RelayError::SavedFull,
        PairError::Duplicate => RelayError::Duplicate,
        PairError::BadName => RelayError::BadName,
        PairError::BadRelay => RelayError::BadUrl,
        PairError::InUse => RelayError::InUse,
        PairError::NotFound => RelayError::NotFound,
        other => RelayError::Other(format!("{other:?}")),
    }
}

/// Add a relay to the saved list (limits checked).
pub(crate) fn add(
    s: &mut RelaySettings,
    relay: RelayRef,
    nickname: &str,
    source: RelaySource,
) -> Result<(), RelayError> {
    let nickname = nickname.trim();
    let nickname = if nickname.is_empty() {
        super::pair2::relay_host(&relay.url)
    } else {
        nickname.to_owned()
    };
    if s.relays
        .iter()
        .any(|e| super::away::same_relay(&e.relay.url, &relay.url))
    {
        return Err(RelayError::Duplicate);
    }
    if s.relays.len() >= MAX_SAVED_RELAYS {
        return Err(RelayError::SavedFull);
    }
    s.add(RelayEntry {
        nickname,
        relay,
        source,
    })
    .map_err(map_pair_err)
}

/// Remove a saved relay: not the built-in one, not home, not one a pairing
/// uses.
pub(crate) fn remove(
    s: &mut RelaySettings,
    url: &str,
    pairing_relays: &[Option<String>],
) -> Result<(), RelayError> {
    let e = s
        .relays
        .iter()
        .find(|e| super::away::same_relay(&e.relay.url, url))
        .ok_or(RelayError::NotFound)?;
    if e.source == RelaySource::Builtin {
        return Err(RelayError::Builtin);
    }
    let key = e.relay.url.clone();
    let home = s
        .home_relay
        .as_deref()
        .is_some_and(|h| super::away::same_relay(h, &key));
    let used = pairing_relays
        .iter()
        .flatten()
        .any(|u| super::away::same_relay(u, &key));
    if home || used {
        return Err(RelayError::InUse);
    }
    s.relays.retain(|e| e.relay.url != key);
    Ok(())
}

pub(crate) fn rename(s: &mut RelaySettings, url: &str, nickname: &str) -> Result<(), RelayError> {
    let nickname = nickname.trim();
    if !valid_device_name(nickname) {
        return Err(RelayError::BadName);
    }
    let e = s
        .relays
        .iter_mut()
        .find(|e| super::away::same_relay(&e.relay.url, url))
        .ok_or(RelayError::NotFound)?;
    e.nickname = nickname.to_owned();
    Ok(())
}

/// Distinct relays in use: home plus every pairing relay.
pub(crate) fn in_use(home: Option<&str>, pairing_relays: &[Option<String>]) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for u in home
        .map(str::to_owned)
        .into_iter()
        .chain(pairing_relays.iter().flatten().cloned())
    {
        if !v.iter().any(|x| super::away::same_relay(x, &u)) {
            v.push(u);
        }
    }
    v
}

/// May one more pairing use `url` (the 4-in-use limit)?
#[cfg(test)]
pub(crate) fn room_for(home: Option<&str>, pairing_relays: &[Option<String>], url: &str) -> bool {
    let v = in_use(home, pairing_relays);
    v.iter().any(|u| super::away::same_relay(u, url))
        || v.len() < crate::pairwise::MAX_RELAYS_IN_USE
}

/// The rows for Settings → Relays.
pub(crate) fn list(
    s: &RelaySettings,
    pairing_relays: &[Option<String>],
    status: impl Fn(&str, bool) -> RelayStatus,
) -> Vec<RelayInfo> {
    s.relays
        .iter()
        .map(|e| {
            let home = s
                .home_relay
                .as_deref()
                .is_some_and(|h| super::away::same_relay(h, &e.relay.url));
            let used_by = pairing_relays
                .iter()
                .filter(|p| match p {
                    Some(u) => super::away::same_relay(u, &e.relay.url),
                    None => home,
                })
                .count() as u32;
            RelayInfo {
                nickname: e.nickname.clone(),
                url: e.relay.url.clone(),
                host: super::pair2::relay_host(&e.relay.url),
                mailbox_id: e.relay.mailbox_id.map(|m| m.to_hex()).unwrap_or_default(),
                home,
                builtin: e.source == RelaySource::Builtin,
                used_by,
                status: status(&e.relay.url, home || used_by > 0),
                link: format_link(&e.relay.url, e.relay.mailbox_id.as_ref(), &e.nickname),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKeypair;

    fn builtin() -> RelayRef {
        RelayRef::new(super::super::DEFAULT_RELAY_URL, None)
    }

    #[test]
    fn link_round_trips() {
        let m = DeviceKeypair::generate().device_id();
        let l = format_link("https://relay.friend.net", Some(&m), "Friend & co");
        let (r, n) = parse_link(&l).unwrap();
        assert_eq!(r.url, "https://relay.friend.net");
        assert_eq!(r.mailbox_id, Some(m));
        assert_eq!(n, "Friend & co");
        let (r, n) = parse_link("voidwire:relay?r=https%3A%2F%2Fr.example%2F").unwrap();
        assert_eq!(
            (r.url.as_str(), r.mailbox_id, n.as_str()),
            ("https://r.example", None, "r.example")
        );
    }

    #[test]
    fn bad_links_are_refused() {
        for l in [
            "https://relay.example",
            "voidwire:relay?",
            "voidwire:relay?r=ftp://x",
            "voidwire:relay?r=https://x&r=https://y",
            "voidwire:relay?r=https://x&m=abc",
            "voidwire:relay?r=https://x?y=1",
            "voidwire:relay?r=https://user@x",
        ] {
            assert!(parse_link(l).is_err(), "{l}");
        }
    }

    #[test]
    fn saved_list_is_capped_at_8_and_builtin_home_and_used_relays_stay() {
        let mut s = RelaySettings::new(builtin());
        for i in 1..MAX_SAVED_RELAYS {
            add(
                &mut s,
                relay_ref(&format!("https://r{i}.example"), "").unwrap(),
                "",
                RelaySource::Manual,
            )
            .unwrap();
        }
        assert_eq!(s.relays.len(), MAX_SAVED_RELAYS);
        assert_eq!(
            add(
                &mut s,
                relay_ref("https://r9.example", "").unwrap(),
                "",
                RelaySource::Manual
            ),
            Err(RelayError::SavedFull)
        );
        assert_eq!(
            add(
                &mut s,
                relay_ref("https://r1.example/", "").unwrap(),
                "",
                RelaySource::Manual
            ),
            Err(RelayError::Duplicate)
        );
        let used = vec![Some("https://r2.example".to_owned()), None];
        assert_eq!(
            remove(&mut s, super::super::DEFAULT_RELAY_URL, &used),
            Err(RelayError::Builtin)
        );
        assert_eq!(
            remove(&mut s, "https://r2.example", &used),
            Err(RelayError::InUse)
        );
        s.home_relay = Some("https://r3.example".into());
        assert_eq!(
            remove(&mut s, "https://r3.example", &used),
            Err(RelayError::InUse)
        );
        remove(&mut s, "https://r1.example", &used).unwrap();
        assert_eq!(s.relays.len(), MAX_SAVED_RELAYS - 1);
        let rows = list(&s, &used, |_, _| RelayStatus::Idle);
        let r2 = rows.iter().find(|r| r.url == "https://r2.example").unwrap();
        assert_eq!(r2.used_by, 1);
        let home = rows.iter().find(|r| r.home).unwrap();
        assert_eq!((home.url.as_str(), home.used_by), ("https://r3.example", 1));
    }

    #[test]
    fn at_most_4_relays_in_use() {
        let home = Some("https://h.example");
        let p: Vec<Option<String>> = [
            "https://a.example",
            "https://b.example",
            "https://c.example",
        ]
        .iter()
        .map(|s| Some((*s).to_owned()))
        .collect();
        assert_eq!(in_use(home, &p).len(), 4);
        assert!(room_for(home, &p, "https://a.example/"));
        assert!(!room_for(home, &p, "https://d.example"));
        assert!(room_for(home, &p[..2], "https://d.example"));
    }
}
