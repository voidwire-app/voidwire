//! Away relays (M4 §5.6).
//!
//! The main endpoint's relay map holds only the home relay. A pairing that
//! lives on another relay ("away") gets a second endpoint with the **same
//! identity key**, relay-only (no IP transports, no address lookup, only
//! [`ALPN_APP`]), whose one relay is that pairing's relay. Peers reach us
//! there because the relay routes by endpoint id.
//!
//! * PC: every relay a pairing uses is held (cap [`MAX_RELAYS_IN_USE`],
//!   home included).
//! * Phone: away endpoints are held only while the app UI is open. When it
//!   closes they shut down after a grace period ([`AWAY_IDLE_MS`], one
//!   delayed check, not a timer loop). The background service never holds
//!   one; background work reaches away pairings through their inboxes.
//! * A user action (a send from the share sheet, accepting a file) may open
//!   one on demand. It closes again after the same grace period.
//!
//! Each away endpoint gets its own [`RelayWatch`], so a dead relay backs off
//! slowly and affects only the pairings on it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use iroh::endpoint::{presets, Incoming};
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey};

use super::relay_watch::{RelayWatch, WatchStats};
use super::{NetError, ALPN_APP};
use crate::pairwise::record::MAX_RELAYS_IN_USE;
use crate::relay_supervisor::DeviceMode;

/// How long an away endpoint stays up after its last use once it is no
/// longer held (phone UI closed, or opened on demand).
pub const AWAY_IDLE_MS: u64 = 60_000;

static IDLE_OVERRIDE: AtomicU64 = AtomicU64::new(0);

/// Tests compress the grace period with this (0 restores the default).
#[cfg(any(test, feature = "test-util"))]
pub fn set_away_idle_ms_for_tests(ms: u64) {
    IDLE_OVERRIDE.store(ms, Ordering::SeqCst);
}

fn idle_ms() -> u64 {
    match IDLE_OVERRIDE.load(Ordering::SeqCst) {
        0 => AWAY_IDLE_MS,
        v => v,
    }
}

/// How many away endpoints a mode may hold at once (home not counted).
pub fn away_cap(mode: DeviceMode) -> usize {
    match mode {
        DeviceMode::Pc => MAX_RELAYS_IN_USE - 1,
        DeviceMode::PhoneForeground => 2,
        DeviceMode::PhoneBackground => 0,
    }
}

/// Two relay URLs name the same relay (iroh adds a trailing `/`).
pub fn same_relay(a: &str, b: &str) -> bool {
    let n = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
    n(a) == n(b)
}

/// Called for every connection that arrives on an away endpoint.
pub(crate) type Serve = Arc<dyn Fn(Incoming) + Send + Sync>;
/// "Is a file transfer still running?" Delays an idle close.
pub(crate) type Busy = Arc<dyn Fn() -> bool + Send + Sync>;

struct Slot {
    ep: Endpoint,
    watch: RelayWatch,
    accept: tokio::task::JoinHandle<()>,
    held: bool,
    /// Bumped on every use; a pending idle close only fires if unchanged.
    gen: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.accept.abort();
        let ep = self.ep.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move { ep.close().await });
        } else {
            drop(ep);
        }
    }
}

#[derive(Default)]
struct State {
    wanted: Vec<String>,
    mode: Option<DeviceMode>,
    slots: HashMap<String, Slot>,
    /// Relays being bound right now (keeps two binds of one relay apart).
    opening: Vec<String>,
}

/// One away relay, for the status line in Settings → Relays.
#[derive(Debug, Clone)]
pub struct AwayInfo {
    pub url: String,
    pub held: bool,
    pub stats: Arc<WatchStats>,
}

pub(crate) struct Away {
    rt: tokio::runtime::Handle,
    secret: [u8; 32],
    serve: Serve,
    busy: Busy,
    st: Arc<Mutex<State>>,
    opened: AtomicU64,
}

impl std::fmt::Debug for Away {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Away").finish_non_exhaustive()
    }
}

impl Away {
    pub(crate) fn new(
        rt: tokio::runtime::Handle,
        secret: [u8; 32],
        serve: Serve,
        busy: Busy,
    ) -> Arc<Away> {
        Arc::new(Away {
            rt,
            secret,
            serve,
            busy,
            st: Arc::new(Mutex::new(State::default())),
            opened: AtomicU64::new(0),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Endpoints bound so far (tests).
    pub(crate) fn opened(&self) -> u64 {
        self.opened.load(Ordering::SeqCst)
    }

    /// Relays with an open away endpoint right now.
    pub(crate) fn open_relays(&self) -> Vec<AwayInfo> {
        let st = self.lock();
        let mut v: Vec<_> = st
            .slots
            .iter()
            .map(|(u, s)| AwayInfo {
                url: u.clone(),
                held: s.held,
                stats: s.watch.stats(),
            })
            .collect();
        v.sort_by(|a, b| a.url.cmp(&b.url));
        v
    }

    /// The away relays this device's pairings use, most-used first. Opens
    /// what's missing (up to the mode's cap) and lets the rest go.
    pub(crate) fn set_urls(self: &Arc<Self>, urls: Vec<String>) {
        let mut dedup: Vec<String> = Vec::new();
        for u in urls {
            if !dedup.iter().any(|d| same_relay(d, &u)) {
                dedup.push(u);
            }
        }
        {
            let mut st = self.lock();
            if st.wanted == dedup {
                return;
            }
            st.wanted = dedup;
        }
        self.apply(false);
    }

    /// PC, or phone UI open / closed.
    pub(crate) fn set_mode(self: &Arc<Self>, mode: DeviceMode) {
        let changed = {
            let mut st = self.lock();
            let changed = st.mode != Some(mode);
            st.mode = Some(mode);
            changed
        };
        if changed {
            self.apply(true);
        }
    }

    pub(crate) fn mode(&self) -> DeviceMode {
        self.lock().mode.unwrap_or(DeviceMode::PhoneBackground)
    }

    fn apply(self: &Arc<Self>, mode_changed: bool) {
        let mut to_open = Vec::new();
        let mut released = Vec::new();
        {
            let mut st = self.lock();
            let mode = st.mode.unwrap_or(DeviceMode::PhoneBackground);
            let hold: Vec<String> = st.wanted.iter().take(away_cap(mode)).cloned().collect();
            // A relay no pairing uses any more (removed, or now the home
            // relay) closes at once: no traffic to it from here on.
            let wanted = st.wanted.clone();
            st.slots
                .retain(|url, _| wanted.iter().any(|w| same_relay(w, url)));
            for (url, slot) in st.slots.iter_mut() {
                let want = hold.iter().any(|h| same_relay(h, url));
                if want {
                    slot.held = true;
                } else if slot.held {
                    slot.held = false;
                    slot.gen += 1;
                    released.push((url.clone(), slot.gen));
                }
                if mode_changed && mode != DeviceMode::PhoneBackground {
                    slot.watch.set_mode(mode);
                }
            }
            for h in &hold {
                let open = st.slots.keys().any(|k| same_relay(k, h))
                    || st.opening.iter().any(|k| same_relay(k, h));
                if !open {
                    st.opening.push(h.clone());
                    to_open.push(h.clone());
                }
            }
        }
        for (url, gen) in released {
            self.schedule_idle_close(url, gen);
        }
        for url in to_open {
            let me = self.clone();
            self.rt.spawn(async move {
                let _ = me.open(&url, true).await;
            });
        }
    }

    /// Retry every away relay now (app opened, network changed, Retry).
    pub(crate) fn retry_now(&self, network_change: bool) {
        for s in self.lock().slots.values() {
            if network_change {
                s.watch.network_change();
            } else {
                s.watch.retry_now();
            }
        }
    }

    /// Retry one relay (Settings → Relays → Retry).
    pub(crate) fn retry_relay(&self, url: &str) -> bool {
        let st = self.lock();
        match st.slots.iter().find(|(k, _)| same_relay(k, url)) {
            Some((_, s)) => {
                s.watch.retry_now();
                true
            }
            None => false,
        }
    }

    /// The endpoint for a dial to a pairing on `url`. Opens one on demand
    /// (`user_action`, never for background work) and keeps it for the
    /// grace period after this use.
    pub(crate) async fn endpoint_for(
        self: &Arc<Self>,
        url: &str,
        user_action: bool,
    ) -> Result<Endpoint, NetError> {
        if let Some(ep) = self.touch(url) {
            return Ok(ep);
        }
        let opening = self.lock().opening.iter().any(|k| same_relay(k, url));
        if opening {
            for _ in 0..50 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if let Some(ep) = self.touch(url) {
                    return Ok(ep);
                }
                if !self.lock().opening.iter().any(|k| same_relay(k, url)) {
                    break;
                }
            }
            if let Some(ep) = self.touch(url) {
                return Ok(ep);
            }
        }
        if !user_action {
            return Err(NetError::Unreachable(
                "that pairing's relay isn't connected now".into(),
            ));
        }
        {
            let mut st = self.lock();
            let mode = st.mode.unwrap_or(DeviceMode::PhoneBackground);
            // On-demand use counts against the foreground cap even when the
            // UI is closed: a user action is, by definition, foreground.
            let cap = away_cap(mode).max(away_cap(DeviceMode::PhoneForeground));
            if st.slots.len() + st.opening.len() >= cap {
                let idle = st
                    .slots
                    .iter()
                    .filter(|(_, s)| !s.held)
                    .map(|(k, _)| k.clone())
                    .next();
                match idle {
                    Some(k) => {
                        st.slots.remove(&k);
                    }
                    None => {
                        return Err(NetError::Unreachable(
                            "too many relays in use right now".into(),
                        ))
                    }
                }
            }
            st.opening.push(url.to_owned());
        }
        let ep = self.open(url, false).await?;
        Ok(ep)
    }

    fn touch(self: &Arc<Self>, url: &str) -> Option<Endpoint> {
        let (key, ep, gen) = {
            let mut st = self.lock();
            let (k, slot) = st.slots.iter_mut().find(|(k, _)| same_relay(k, url))?;
            slot.gen += 1;
            if slot.held {
                return Some(slot.ep.clone());
            }
            (k.clone(), slot.ep.clone(), slot.gen)
        };
        self.schedule_idle_close(key, gen);
        Some(ep)
    }

    /// Bind the away endpoint for `url`. The caller has put `url` in
    /// `opening`.
    async fn open(self: &Arc<Self>, url: &str, held: bool) -> Result<Endpoint, NetError> {
        let res = self.bind(url).await;
        let unwanted = {
            let mut st = self.lock();
            st.opening.retain(|k| !same_relay(k, url));
            let (ep, cfg) = res?;
            // Still wanted? (The UI may have closed while we were binding.)
            let mode = st.mode.unwrap_or(DeviceMode::PhoneBackground);
            let still_held = st
                .wanted
                .iter()
                .take(away_cap(mode))
                .any(|w| same_relay(w, url));
            if held && !still_held {
                Some(ep)
            } else {
                self.opened.fetch_add(1, Ordering::SeqCst);
                let watch_mode = match mode {
                    DeviceMode::PhoneBackground => DeviceMode::PhoneForeground,
                    m => m,
                };
                let watch = RelayWatch::spawn(
                    &self.rt,
                    ep.clone(),
                    cfg,
                    watch_mode,
                    super::relay_watch::supervisor_config_pub(),
                );
                let accept = self.spawn_accept(url.to_owned(), ep.clone());
                // An on-demand open of a relay that is wanted is held.
                let held = held || still_held;
                st.slots.insert(
                    url.to_owned(),
                    Slot {
                        ep: ep.clone(),
                        watch,
                        accept,
                        held,
                        gen: 1,
                    },
                );
                if !held {
                    drop(st);
                    self.schedule_idle_close(url.to_owned(), 1);
                }
                return Ok(ep);
            }
        };
        if let Some(ep) = unwanted {
            ep.close().await;
        }
        Err(NetError::Unreachable("relay no longer wanted".into()))
    }

    async fn bind(&self, url: &str) -> Result<(Endpoint, iroh::RelayConfig), NetError> {
        let parsed: RelayUrl = url
            .parse()
            .map_err(|_| NetError::Unreachable("bad relay URL".into()))?;
        let cfg = super::relay_config_for(&parsed);
        let map = RelayMap::from_iter([cfg.clone()]);
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&self.secret))
            .relay_mode(RelayMode::Custom(map))
            .clear_ip_transports()
            .clear_address_lookup()
            .alpns(vec![ALPN_APP.to_vec()])
            .bind()
            .await
            .map_err(|e| NetError::Unreachable(format!("away endpoint: {e}")))?;
        Ok((ep, cfg))
    }

    fn spawn_accept(self: &Arc<Self>, url: String, ep: Endpoint) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        self.rt.spawn(async move {
            while let Some(inc) = ep.accept().await {
                let Some(me) = weak.upgrade() else { return };
                // A peer reaching us counts as use.
                let _ = me.touch(&url);
                (me.serve)(inc);
            }
        })
    }

    /// Close `url` after the grace period unless it was used (or held)
    /// again in between, or a file transfer is still running.
    fn schedule_idle_close(self: &Arc<Self>, url: String, gen: u64) {
        let weak = Arc::downgrade(self);
        let ms = idle_ms();
        self.rt.spawn(async move {
            let mut gen = gen;
            loop {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                let Some(me) = weak.upgrade() else { return };
                let busy = (me.busy)();
                let mut st = me.lock();
                let Some(slot) = st.slots.get_mut(&url) else {
                    return;
                };
                if slot.held || slot.gen != gen {
                    return;
                }
                if busy {
                    // One more grace period, only while a transfer runs.
                    slot.gen += 1;
                    gen = slot.gen;
                    continue;
                }
                st.slots.remove(&url);
                return;
            }
        });
    }

    /// Close everything (shutdown, identity change).
    pub(crate) fn close_all(&self) {
        let mut st = self.lock();
        st.slots.clear();
        st.wanted.clear();
    }
}

/// Dial `peer`, whose pairing lives on away relay `url`: straight to its
/// LAN addresses from the main endpoint first (no relay), then through
/// the away endpoint, relay only. Never through the home relay: the pair
/// chose `url`.
pub(crate) async fn dial_via(
    away: &Arc<Away>,
    main: &Endpoint,
    mdns: bool,
    peer: &crate::ids::DeviceId,
    addrs: &[std::net::SocketAddr],
    url: &str,
    user_action: bool,
) -> Result<iroh::endpoint::Connection, NetError> {
    let id = super::endpoint_id_of(peer)?;
    let mut direct = addrs.to_vec();
    if direct.is_empty() && mdns {
        direct = super::phone::discover_addrs(main, peer, Duration::from_millis(1200)).await;
    }
    if !direct.is_empty() {
        let mut a = iroh::EndpointAddr::new(id);
        for x in &direct {
            a = a.with_ip_addr(*x);
        }
        if let Ok(Ok(c)) =
            tokio::time::timeout(Duration::from_millis(1500), main.connect(a, ALPN_APP)).await
        {
            return Ok(c);
        }
    }
    let u: RelayUrl = url
        .parse()
        .map_err(|_| NetError::Unreachable("bad relay URL".into()))?;
    let ep = away.endpoint_for(url, user_action).await?;
    let _ = tokio::time::timeout(Duration::from_millis(1500), ep.online()).await;
    let addr = iroh::EndpointAddr::new(id).with_relay_url(u);
    match tokio::time::timeout(Duration::from_secs(6), ep.connect(addr, ALPN_APP)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(NetError::Unreachable(e.to_string())),
        Err(_) => Err(NetError::Unreachable("no answer through that relay".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_per_mode() {
        assert_eq!(away_cap(DeviceMode::Pc), 3);
        assert_eq!(away_cap(DeviceMode::PhoneForeground), 2);
        assert_eq!(away_cap(DeviceMode::PhoneBackground), 0);
        // Home + away never exceeds the in-use limit.
        assert!(away_cap(DeviceMode::Pc) < MAX_RELAYS_IN_USE);
    }

    #[test]
    fn same_relay_ignores_trailing_slash_and_case() {
        assert!(same_relay(
            "https://Relay.example/",
            "https://relay.example"
        ));
        assert!(!same_relay("https://a.example", "https://b.example"));
    }
}
