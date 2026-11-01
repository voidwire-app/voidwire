//! Settings → Relays (M4 §5.1): the saved list, relay links, and the
//! per-relay status line. Shared by the PC and the phone.
//!
//! A relay link is `voidwire:relay?r=<url>&m=<mailbox id>&n=<nickname>&q=0&t=<token>`
//! (`voidwire-mailbox --print-relay-link` prints one). `m`, `n`, `q` and `t`
//! are optional; a missing `m` means the relay's default mailbox. `q=0` means
//! "no UDP 7842": the relay sits behind an HTTPS tunnel, so devices skip
//! QUIC address discovery there instead of probing a port that never answers.
//! `t` is the access token of a relay that only lets in holders of its link
//! (iroh-relay `access.shared_token`); a link with a `t` is a secret.

use crate::ids::DeviceId;
use crate::keys::valid_device_name;
use crate::pairwise::{
    PairError, RelayEntry, RelayLimits, RelayRef, RelaySettings, RelaySource, RelayToken,
    MAX_SAVED_RELAYS,
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
    /// 64 hex characters that aren't a usable Ed25519 key (not a curve
    /// point, or a weak one like 00…01).
    #[error("That mailbox ID isn't a valid relay key. Copy it again from the relay's link.")]
    InvalidMailboxKey,
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
    /// Added or retried, not connected yet (the grace period before
    /// "Can't reach").
    Connecting,
    /// The relay refused our access token. No retries until its link is
    /// pasted again.
    TokenRefused,
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
    let bytes = crate::hex::decode_array::<32>(m).ok_or(RelayError::BadMailbox)?;
    let id = DeviceId::from_bytes(bytes).map_err(|_| RelayError::InvalidMailboxKey)?;
    Ok((id != super::mailbox_client::default_mailbox_device_id()).then_some(id))
}

/// A relay from its URL and (optional) mailbox id.
pub fn relay_ref(url: &str, mailbox_hex: &str) -> Result<RelayRef, RelayError> {
    Ok(RelayRef::new(
        normalize_url(url)?,
        parse_mailbox(mailbox_hex)?,
    ))
}

/// A parsed relay link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLink {
    pub relay: RelayRef,
    /// Defaults to the relay's host.
    pub nickname: String,
    /// `q=0`: skip QUIC address discovery (UDP 7842) at this relay.
    pub no_udp: bool,
    /// `t=`: the relay's access token.
    pub token: Option<RelayToken>,
}

/// `voidwire:relay?r=…&m=…&n=…[&q=0][&t=…]`
pub fn format_link(
    url: &str,
    mailbox: Option<&DeviceId>,
    nickname: &str,
    no_udp: bool,
    token: Option<&RelayToken>,
) -> String {
    let mut s = String::from("voidwire:relay?");
    let mut q = url::form_urlencoded::Serializer::new(String::new());
    q.append_pair("r", url);
    if let Some(m) = mailbox {
        q.append_pair("m", &m.to_hex());
    }
    if !nickname.is_empty() {
        q.append_pair("n", nickname);
    }
    if no_udp {
        q.append_pair("q", "0");
    }
    if let Some(t) = token {
        q.append_pair("t", t.as_str());
    }
    s.push_str(&q.finish());
    s
}

/// The relay, nickname and UDP marker in a relay link.
pub fn parse_link(link: &str) -> Result<RelayLink, RelayError> {
    let t = link.trim();
    let rest = t
        .strip_prefix("voidwire:relay?")
        .or_else(|| t.strip_prefix("voidwire://relay?"))
        .ok_or(RelayError::BadLink)?;
    if rest.len() > 2048 {
        return Err(RelayError::BadLink);
    }
    let (mut r, mut m, mut n, mut q, mut tk) = (None, None, None, None, None);
    for (k, v) in url::form_urlencoded::parse(rest.as_bytes()) {
        let slot = match k.as_ref() {
            "r" => &mut r,
            "m" => &mut m,
            "n" => &mut n,
            "q" => &mut q,
            "t" => &mut tk,
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
    let no_udp = match q.as_deref() {
        None | Some("1") => false,
        Some("0") => true,
        Some(_) => return Err(RelayError::BadLink),
    };
    let token = match tk {
        None => None,
        Some(t) => Some(RelayToken::new(&t).ok_or(RelayError::BadLink)?),
    };
    Ok(RelayLink {
        relay,
        nickname,
        no_udp,
        token,
    })
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
    no_udp: bool,
    token: Option<RelayToken>,
) -> Result<(), RelayError> {
    let nickname = nickname.trim();
    let nickname = if nickname.is_empty() {
        super::pair2::relay_host(&relay.url)
    } else {
        nickname.to_owned()
    };
    if let Some(e) = s
        .relays
        .iter_mut()
        .find(|e| super::away::same_relay(&e.relay.url, &relay.url))
    {
        let _ = (e, no_udp, token);
        return Err(RelayError::Duplicate);
    }
    if s.relays.len() >= MAX_SAVED_RELAYS {
        return Err(RelayError::SavedFull);
    }
    s.add(RelayEntry {
        nickname,
        relay,
        source,
        no_udp,
        token,
        limits: None,
    })
    .map_err(map_pair_err)?;
    remember_relay_opts(s);
    Ok(())
}

/// What adding a relay link did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    /// A new saved relay.
    Added,
    /// The relay was already saved: its access token and UDP setting now
    /// come from the new link (its mailbox id and nickname are kept). The
    /// caller rebuilds the live connection.
    Updated,
}

/// Add a relay from a pasted link. Pasting a saved relay's link again
/// updates it in place: the token (a link without one forgets the old one)
/// and the UDP setting. Nothing else changes, so pairings on it stay put.
pub(crate) fn add_link(
    s: &mut RelaySettings,
    relay: RelayRef,
    nickname: &str,
    source: RelaySource,
    no_udp: bool,
    token: Option<RelayToken>,
) -> Result<AddOutcome, RelayError> {
    if let Some(e) = s
        .relays
        .iter_mut()
        .find(|e| super::away::same_relay(&e.relay.url, &relay.url))
    {
        // The built-in relay has no token and always uses UDP.
        if e.source != RelaySource::Builtin {
            e.token = token;
            e.no_udp = no_udp;
        }
        let url = e.relay.url.clone();
        set_relay_opts(&url, e.no_udp, e.token.clone());
        return Ok(AddOutcome::Updated);
    }
    add(s, relay, nickname, source, no_udp, token).map(|()| AddOutcome::Added)
}

/// Replace this relay's UDP marker and token in the process-wide tables.
fn set_relay_opts(url: &str, no_udp: bool, token: Option<RelayToken>) {
    let mut v = NO_UDP.lock().unwrap_or_else(|e| e.into_inner());
    v.retain(|u| !super::away::same_relay(u, url));
    if no_udp {
        v.push(url.to_owned());
    }
    drop(v);
    let mut t = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    t.retain(|(u, _)| !super::away::same_relay(u, url));
    if let Some(tok) = token {
        t.push((url.to_owned(), tok));
    }
}

/// Relays saved with `q=0`, for [`super::relay_config_for`]. Process-wide
/// because endpoints are built from a URL. Loading only adds (a stale entry
/// just skips a probe that would fail anyway); a re-pasted link sets it.
static NO_UDP: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Access tokens by relay URL, for [`super::relay_config_for`]. A token is
/// only ever sent to the relay it belongs to.
static TOKENS: std::sync::Mutex<Vec<(String, RelayToken)>> = std::sync::Mutex::new(Vec::new());

/// What each relay last said about its limits, by URL. Filled from inbox
/// pull and enqueue replies (any session, any pairing) and from
/// [`fetch_limits`]; saved into the relay's entry by [`store_limits`].
static LIMITS: std::sync::Mutex<Vec<(String, RelayLimits)>> = std::sync::Mutex::new(Vec::new());

fn set_limits(url: &str, f: impl FnOnce(&mut RelayLimits)) {
    let mut v = LIMITS.lock().unwrap_or_else(|e| e.into_inner());
    let i = match v.iter().position(|(u, _)| super::away::same_relay(u, url)) {
        Some(i) => i,
        None => {
            v.push((
                url.trim_end_matches('/').to_owned(),
                RelayLimits {
                    file_cap_bytes: 0,
                    inbox_ttl_secs: 0,
                },
            ));
            v.len() - 1
        }
    };
    f(&mut v[i].1);
}

/// A relay's inbox pull reply (it always carries the relay's limits).
pub(crate) fn note_caps(url: &str, caps: &crate::mailbox::AdvertisedInboxCaps) {
    set_limits(url, |l| {
        l.file_cap_bytes = caps.max_relay_file_bytes;
        l.inbox_ttl_secs = caps.inbox_ttl_secs;
    });
}

/// A relay's enqueue reply (file limit only).
pub(crate) fn note_file_cap(url: &str, cap: u64) {
    set_limits(url, |l| l.file_cap_bytes = cap);
}

/// What the relay at `url` last said about its limits (`None`: never asked).
pub fn limits_for(url: &str) -> Option<RelayLimits> {
    LIMITS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|(u, _)| super::away::same_relay(u, url))
        .map(|(_, l)| *l)
}

/// The file limit to check a send through `url` against. Unknown: the
/// public relay's published default for the built-in relay, otherwise no
/// limit of ours (the relay enforces its own; callers fetch first).
pub(crate) fn file_cap_for(url: &str) -> u64 {
    match limits_for(url) {
        Some(l) => l.file_cap_bytes,
        None if is_builtin_url(url) => crate::file_transfer::DEFAULT_RELAY_FILE_CAP_BYTES,
        None => 0,
    }
}

fn is_builtin_url(url: &str) -> bool {
    super::away::same_relay(url, super::DEFAULT_RELAY_URL)
}

/// How long the relay at `url` keeps a queued item, when it has said.
pub fn hold_secs_for(url: &str) -> Option<u32> {
    limits_for(url).map(|l| l.inbox_ttl_secs).filter(|t| *t > 0)
}

/// Copy the learned limits into the saved entries. Returns whether
/// anything changed (the caller saves).
pub(crate) fn store_limits(s: &mut RelaySettings) -> bool {
    let mut changed = false;
    for e in &mut s.relays {
        if let Some(l) = limits_for(&e.relay.url) {
            if e.limits != Some(l) {
                e.limits = Some(l);
                changed = true;
            }
        }
    }
    changed
}

/// Ask the relay at `url` for its limits now: an empty inbox pull with
/// throwaway keys over a throwaway session (nothing identifies us).
pub(crate) async fn fetch_limits(
    url: &str,
    mailbox: Option<crate::ids::DeviceId>,
) -> Result<RelayLimits, super::NetError> {
    let mailbox = mailbox.unwrap_or_else(super::mailbox_client::default_mailbox_device_id);
    let keys = crate::mailbox::EpochSecret::generate().derive_device_inbox_keys(
        &crate::ids::GroupId(rand_array()),
        0,
        &crate::keys::DeviceKeypair::generate().device_id(),
        &crate::keys::ReceiveKeypair::generate().public(),
    );
    let sess = super::mailbox_client::ThrowawaySession::connect(&mailbox, url).await?;
    let res = sess.pull_device_inbox_with_caps(&keys).await;
    sess.close().await;
    match res?.1 {
        Some(c) => {
            note_caps(url, &c);
            Ok(limits_for(url).expect("just noted"))
        }
        None => Err(super::NetError::Protocol("relay sent no limits".into())),
    }
}

fn rand_array() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b
}

/// Note the saved relays' UDP markers and tokens (on load and after an add).
pub(crate) fn remember_relay_opts(s: &RelaySettings) {
    for e in &s.relays {
        if let (Some(l), None) = (e.limits, limits_for(&e.relay.url)) {
            set_limits(&e.relay.url, |x| *x = l);
        }
    }
    let mut v = NO_UDP.lock().unwrap_or_else(|e| e.into_inner());
    for e in s.relays.iter().filter(|e| e.no_udp) {
        if !v.iter().any(|u| super::away::same_relay(u, &e.relay.url)) {
            v.push(e.relay.url.clone());
        }
    }
    drop(v);
    for e in &s.relays {
        if let Some(t) = &e.token {
            remember_relay_token(&e.relay.url, t.clone());
        }
    }
}

/// Use `token` whenever this process connects to the relay at `url` (the
/// mailbox daemon calls this for its own relay).
pub fn remember_relay_token(url: &str, token: RelayToken) {
    let mut v = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    v.retain(|(u, _)| !super::away::same_relay(u, url));
    v.push((url.to_owned(), token));
}

/// The access token saved for the relay at `url`, if any.
pub(crate) fn token_for(url: &str) -> Option<RelayToken> {
    TOKENS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|(u, _)| super::away::same_relay(u, url))
        .map(|(_, t)| t.clone())
}

/// Was `url` saved from a link with `q=0`?
pub(crate) fn skips_udp(url: &str) -> bool {
    NO_UDP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|u| super::away::same_relay(u, url))
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
                link: format_link(
                    &e.relay.url,
                    e.relay.mailbox_id.as_ref(),
                    &e.nickname,
                    e.no_udp,
                    e.token.as_ref(),
                ),
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
    fn mailbox_errors_say_what_is_wrong() {
        let url = "https://r1.example.invalid";
        assert_eq!(relay_ref(url, "abc").unwrap_err(), RelayError::BadMailbox);
        assert_eq!(
            relay_ref(url, &"g".repeat(64)).unwrap_err(),
            RelayError::BadMailbox
        );
        // 64 hex characters, but the identity point (a weak key).
        let weak = format!("{}1", "0".repeat(63));
        assert_eq!(
            relay_ref(url, &weak).unwrap_err(),
            RelayError::InvalidMailboxKey
        );
        let good = DeviceKeypair::from_secret_bytes(&[1; 32]).device_id();
        let r = relay_ref(url, &format!(" {} ", good.to_hex().to_uppercase())).unwrap();
        assert_eq!(r.mailbox_id, Some(good));
    }

    /// The test sheet's made-up relay mailbox IDs (valid keys).
    #[test]
    #[ignore]
    fn print_sample_mailbox_ids() {
        for i in 1..=9u8 {
            println!(
                "{}",
                DeviceKeypair::from_secret_bytes(&[i; 32])
                    .device_id()
                    .to_hex()
            );
        }
    }

    #[test]
    fn link_round_trips() {
        let m = DeviceKeypair::generate().device_id();
        let l = format_link(
            "https://relay.friend.net",
            Some(&m),
            "Friend & co",
            false,
            None,
        );
        let k = parse_link(&l).unwrap();
        assert_eq!(k.relay.url, "https://relay.friend.net");
        assert_eq!(k.relay.mailbox_id, Some(m));
        assert_eq!(k.nickname, "Friend & co");
        assert!(!k.no_udp && !l.contains("q="));
        let k = parse_link("voidwire:relay?r=https%3A%2F%2Fr.example%2F").unwrap();
        assert_eq!(
            (
                k.relay.url.as_str(),
                k.relay.mailbox_id,
                k.nickname.as_str()
            ),
            ("https://r.example", None, "r.example")
        );
        let l = format_link("https://t.example", None, "", true, None);
        assert!(l.ends_with("&q=0"), "{l}");
        assert!(parse_link(&l).unwrap().no_udp);
        assert!(
            !parse_link("voidwire:relay?r=https://t.example&q=1")
                .unwrap()
                .no_udp
        );
    }

    #[test]
    fn no_udp_relays_skip_quic_address_discovery() {
        let url = "https://no-udp.example.test";
        let parsed: iroh::RelayUrl = url.parse().unwrap();
        assert!(super::super::relay_config_for(&parsed).quic.is_some());
        let mut s = RelaySettings::new(builtin());
        let k = parse_link(&format_link(url, None, "", true, None)).unwrap();
        add(&mut s, k.relay, "", RelaySource::Manual, k.no_udp, None).unwrap();
        assert!(s.relays.iter().any(|e| e.no_udp));
        assert!(skips_udp("https://NO-UDP.example.test/"));
        assert!(super::super::relay_config_for(&parsed).quic.is_none());
        // The marker survives a save and reload.
        let back = RelaySettings::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        let other: iroh::RelayUrl = "https://udp.example.test".parse().unwrap();
        assert!(super::super::relay_config_for(&other).quic.is_some());
    }

    #[test]
    fn token_relays_send_their_token_only_to_that_relay() {
        let url = "https://private.example.test";
        let parsed: iroh::RelayUrl = url.parse().unwrap();
        assert!(super::super::relay_config_for(&parsed).auth_token.is_none());
        let t = RelayToken::new("Tok_en-0123456789.abc~").unwrap();
        let l = format_link(url, None, "Home", false, Some(&t));
        assert!(l.ends_with("&t=Tok_en-0123456789.abc%7E"), "{l}");
        let k = parse_link(&l).unwrap();
        assert_eq!(k.token.as_ref(), Some(&t));
        assert_eq!(format!("{:?}", k.token), "Some(RelayToken(..))");
        let mut s = RelaySettings::new(builtin());
        add(
            &mut s,
            k.relay.clone(),
            "",
            RelaySource::Manual,
            false,
            k.token,
        )
        .unwrap();
        assert_eq!(
            super::super::relay_config_for(&parsed)
                .auth_token
                .as_deref(),
            Some(t.as_str())
        );
        let other: iroh::RelayUrl = "https://other.example.test".parse().unwrap();
        assert!(super::super::relay_config_for(&other).auth_token.is_none());
        // The token survives a save and reload, and is in the share link.
        let back = RelaySettings::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        let rows = list(&s, &[], |_, _| RelayStatus::Idle);
        let row = rows.iter().find(|r| r.url == url).unwrap();
        assert_eq!(parse_link(&row.link).unwrap().token, Some(t.clone()));
        // A plain URL for a saved relay is a duplicate and changes nothing.
        assert_eq!(
            add(
                &mut s,
                k.relay.clone(),
                "",
                RelaySource::Manual,
                false,
                None
            ),
            Err(RelayError::Duplicate)
        );
        assert_eq!(
            super::super::relay_config_for(&parsed)
                .auth_token
                .as_deref(),
            Some(t.as_str())
        );
        // Re-pasting the relay's link updates it in place: a new token and
        // UDP setting replace the old ones; the mailbox id and nickname stay.
        let before = s
            .relays
            .iter()
            .find(|e| e.relay.url == url)
            .cloned()
            .unwrap();
        let other_mailbox =
            RelayRef::new(url.to_owned(), Some(DeviceKeypair::generate().device_id()));
        let t2 = RelayToken::new("second-token-0123456789").unwrap();
        assert_eq!(
            add_link(
                &mut s,
                other_mailbox,
                "New name",
                RelaySource::Manual,
                true,
                Some(t2.clone()),
            ),
            Ok(AddOutcome::Updated)
        );
        let after = s
            .relays
            .iter()
            .find(|e| e.relay.url == url)
            .cloned()
            .unwrap();
        assert_eq!(after.relay.mailbox_id, before.relay.mailbox_id);
        assert_eq!(after.nickname, before.nickname);
        assert_eq!(after.token.as_ref(), Some(&t2));
        assert!(after.no_udp && skips_udp(url));
        assert_eq!(
            super::super::relay_config_for(&parsed)
                .auth_token
                .as_deref(),
            Some(t2.as_str())
        );
        assert!(super::super::relay_config_for(&parsed).quic.is_none());
        // The same link again is still an update (it rebuilds the
        // connection), and a link without a token forgets the old one.
        assert_eq!(
            add_link(
                &mut s,
                k.relay.clone(),
                "",
                RelaySource::Manual,
                false,
                None
            ),
            Ok(AddOutcome::Updated)
        );
        assert!(super::super::relay_config_for(&parsed).auth_token.is_none());
        assert!(!skips_udp(url));
        assert_eq!(s.relays.iter().filter(|e| e.relay.url == url).count(), 1);
        // A new relay's link is a plain add.
        let k3 = parse_link(&format_link(
            "https://third.example.test",
            None,
            "",
            false,
            None,
        ))
        .unwrap();
        assert_eq!(
            add_link(&mut s, k3.relay, "", RelaySource::Manual, false, None),
            Ok(AddOutcome::Added)
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
            "voidwire:relay?r=https://x&q=no",
            "voidwire:relay?r=https://x&q=0&q=0",
            "voidwire:relay?r=https://x&t=short",
            "voidwire:relay?r=https://x&t=0123456789abcdef%20x",
            "voidwire:relay?r=https://x&t=0123456789abcdef&t=0123456789abcdef",
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
                false,
                None,
            )
            .unwrap();
        }
        assert_eq!(s.relays.len(), MAX_SAVED_RELAYS);
        assert_eq!(
            add(
                &mut s,
                relay_ref("https://r9.example", "").unwrap(),
                "",
                RelaySource::Manual,
                false,
                None
            ),
            Err(RelayError::SavedFull)
        );
        assert_eq!(
            add(
                &mut s,
                relay_ref("https://r1.example/", "").unwrap(),
                "",
                RelaySource::Manual,
                false,
                None
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

    fn send_over(url: &str, size: u64) -> crate::file_transfer::RelayPolicyOutcome {
        let mut p = crate::file_transfer::RelayTransferPolicy::default();
        p.set_server_cap_bytes(file_cap_for(url));
        p.evaluate(
            size,
            crate::file_transfer::TransportPathKind::Relayed,
            Some(crate::file_transfer::RelayPromptDecision::SendViaRelay),
        )
    }

    #[test]
    fn file_limit_is_per_relay() {
        use crate::file_transfer::RelayPolicyOutcome as O;
        const MB: u64 = 1024 * 1024;
        let (big, small) = (
            "https://big-limits.example.test",
            "https://small-limits.example.test",
        );
        // A relay that advertises 0 (= the 2 GiB file limit) takes 607 MB.
        note_caps(
            big,
            &crate::mailbox::AdvertisedInboxCaps {
                max_relay_file_bytes: 0,
                inbox_max_items: 8,
                inbox_ttl_secs: 7200,
            },
        );
        assert_eq!(send_over(big, 607 * MB), O::ProceedViaRelay);
        assert_eq!(hold_secs_for(big), Some(7200));
        // A 25 MB relay refuses 30 MB, naming its own limit.
        note_file_cap(small, 25 * MB);
        assert_eq!(
            send_over(small, 30 * MB),
            O::ExceedsRelayCap {
                size: 30 * MB,
                effective_cap: 25 * MB
            }
        );
        assert_eq!(hold_secs_for(small), None);
        // Unknown: no 25 MB guess for anyone but the built-in relay.
        assert_eq!(file_cap_for("https://never-asked.example.test"), 0);
        assert_eq!(
            send_over("https://never-asked.example.test", 607 * MB),
            O::ProceedViaRelay
        );
        if limits_for(super::super::DEFAULT_RELAY_URL).is_none() {
            assert_eq!(
                file_cap_for(super::super::DEFAULT_RELAY_URL),
                crate::file_transfer::DEFAULT_RELAY_FILE_CAP_BYTES
            );
        }
        // Learned limits are saved per relay.
        let mut rs = RelaySettings::new(RelayRef::new(big, None));
        assert!(store_limits(&mut rs));
        assert_eq!(rs.relays[0].limits.map(|l| l.inbox_ttl_secs), Some(7200));
        assert!(!store_limits(&mut rs));
    }
}
