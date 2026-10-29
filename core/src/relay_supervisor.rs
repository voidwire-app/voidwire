#![forbid(unsafe_code)]
//! Relay supervisor (M4 §5.6): a pure state machine with an injected clock.
//!
//! * A relay that stays disconnected for 30 s is **parked**: it is removed
//!   from the endpoint's relay map, so the transport stops its own fast
//!   reconnect loop.
//! * A parked relay is retried at 30 s, doubling up to 30 min, ±25 % jitter.
//!   A retry is one lightweight reachability probe (one TCP connect); only a
//!   successful probe puts the relay back into the endpoint.
//! * Backoff resets on a network change, app open, or the user's Retry.
//! * Phone in background: relays other than home are never retried (they are
//!   parked while the app is closed); home is retried on backoff and network
//!   change.
//!
//! The net layer (`net::relay_watch`) feeds it relay status and probe
//! results and carries out its [`Action`]s.

use crate::time::MonoMillis;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorConfig {
    pub park_after_ms: u64,
    /// After an unpark the transport may still be inside its own reconnect
    /// backoff (iroh: up to 16 s plus the dial), so a relay that just
    /// passed a probe gets this long to connect before it is parked again.
    pub unpark_grace_ms: u64,
    pub base_retry_ms: u64,
    pub max_retry_ms: u64,
    /// ± jitter, in percent of the delay.
    pub jitter_pct: u64,
}

impl SupervisorConfig {
    pub const DEFAULT: SupervisorConfig = SupervisorConfig {
        park_after_ms: 30_000,
        unpark_grace_ms: 60_000,
        base_retry_ms: 30_000,
        max_retry_ms: 30 * 60_000,
        jitter_pct: 25,
    };
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMode {
    /// PCs keep every relay in use live.
    Pc,
    /// Phone with the app open.
    PhoneForeground,
    /// Phone with the app closed (background service only).
    PhoneBackground,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRole {
    Home,
    Away,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPhase {
    /// In the endpoint, not (yet) connected. `attempt` carries the backoff
    /// step over a probe that succeeded but a connection that didn't.
    Connecting {
        since: MonoMillis,
        attempt: u32,
    },
    Connected,
    /// Out of the endpoint, waiting for the next retry.
    Parked {
        attempt: u32,
        next_retry: MonoMillis,
    },
    /// A probe is running.
    Probing {
        attempt: u32,
    },
    /// Away relay held out while the phone is in background.
    Held,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Remove the relay from the endpoint.
    Park(String),
    /// Run one reachability probe and report it with `on_probe_result`.
    Probe(String),
    /// Put the relay back into the endpoint.
    Unpark(String),
}

#[derive(Debug, Clone)]
struct Tracked {
    url: String,
    role: RelayRole,
    phase: RelayPhase,
}

#[derive(Debug, Clone)]
pub struct RelaySupervisor {
    cfg: SupervisorConfig,
    mode: DeviceMode,
    relays: Vec<Tracked>,
    rng: u64,
    probes: u64,
}

impl RelaySupervisor {
    /// `seed`: any non-constant value (jitter only; not security relevant).
    pub fn new(cfg: SupervisorConfig, mode: DeviceMode, seed: u64) -> Self {
        RelaySupervisor {
            cfg,
            mode,
            relays: Vec::new(),
            rng: seed | 1,
            probes: 0,
        }
    }

    pub fn mode(&self) -> DeviceMode {
        self.mode
    }

    /// Probes started so far (each is one TCP connect attempt).
    pub fn probes_started(&self) -> u64 {
        self.probes
    }

    pub fn phase(&self, url: &str) -> Option<RelayPhase> {
        self.relays.iter().find(|r| r.url == url).map(|r| r.phase)
    }

    pub fn urls(&self) -> impl Iterator<Item = &str> {
        self.relays.iter().map(|r| r.url.as_str())
    }

    /// How long a relay in the endpoint may stay unconnected: `attempt > 0`
    /// means it was just put back after a successful probe.
    fn connect_window(&self, attempt: u32) -> u64 {
        if attempt > 0 {
            self.cfg.park_after_ms.max(self.cfg.unpark_grace_ms)
        } else {
            self.cfg.park_after_ms
        }
    }

    fn held_back(&self, role: RelayRole) -> bool {
        self.mode == DeviceMode::PhoneBackground && role == RelayRole::Away
    }

    /// Start supervising a relay that is in the endpoint now.
    pub fn add_relay(&mut self, url: &str, role: RelayRole, now: MonoMillis) -> Vec<Action> {
        if self.relays.iter().any(|r| r.url == url) {
            return Vec::new();
        }
        let held = self.held_back(role);
        self.relays.push(Tracked {
            url: url.to_owned(),
            role,
            phase: if held {
                RelayPhase::Held
            } else {
                RelayPhase::Connecting {
                    since: now,
                    attempt: 0,
                }
            },
        });
        if held {
            vec![Action::Park(url.to_owned())]
        } else {
            Vec::new()
        }
    }

    pub fn remove_relay(&mut self, url: &str) {
        self.relays.retain(|r| r.url != url);
    }

    fn rand(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    /// Delay before retry number `attempt` (0-based), jittered.
    pub fn backoff_ms(&mut self, attempt: u32) -> u64 {
        let base = self
            .cfg
            .base_retry_ms
            .saturating_mul(1u64 << attempt.min(32))
            .min(self.cfg.max_retry_ms);
        let span = base * self.cfg.jitter_pct / 100;
        if span == 0 {
            return base;
        }
        let r = self.rand() % (2 * span + 1);
        base - span + r
    }

    fn park(&mut self, i: usize, attempt: u32, now: MonoMillis) -> RelayPhase {
        let d = self.backoff_ms(attempt);
        let held = self.held_back(self.relays[i].role);
        let p = if held {
            RelayPhase::Held
        } else {
            RelayPhase::Parked {
                attempt,
                next_retry: now.saturating_add(d),
            }
        };
        self.relays[i].phase = p;
        p
    }

    /// The endpoint reported a relay connected or not.
    pub fn on_status(&mut self, url: &str, connected: bool, now: MonoMillis) -> Vec<Action> {
        let Some(r) = self.relays.iter_mut().find(|r| r.url == url) else {
            return Vec::new();
        };
        match (r.phase, connected) {
            (RelayPhase::Connecting { .. }, true) => r.phase = RelayPhase::Connected,
            (RelayPhase::Connected, false) => {
                r.phase = RelayPhase::Connecting {
                    since: now,
                    attempt: 0,
                }
            }
            _ => {}
        }
        Vec::new()
    }

    /// Advance timers: park relays down for too long, start due probes.
    pub fn tick(&mut self, now: MonoMillis) -> Vec<Action> {
        let mut out = Vec::new();
        for i in 0..self.relays.len() {
            match self.relays[i].phase {
                RelayPhase::Connecting { since, attempt }
                    if now.saturating_sub(since) >= self.connect_window(attempt) =>
                {
                    // A relay that never came up after an unpark keeps its
                    // backoff step, so a flapping relay backs off too.
                    self.park(i, attempt, now);
                    out.push(Action::Park(self.relays[i].url.clone()));
                }
                RelayPhase::Parked {
                    attempt,
                    next_retry,
                } if now >= next_retry && !self.held_back(self.relays[i].role) => {
                    self.relays[i].phase = RelayPhase::Probing { attempt };
                    self.probes += 1;
                    out.push(Action::Probe(self.relays[i].url.clone()));
                }
                _ => {}
            }
        }
        out
    }

    /// Result of a probe started by [`Action::Probe`].
    pub fn on_probe_result(&mut self, url: &str, reachable: bool, now: MonoMillis) -> Vec<Action> {
        let Some(i) = self.relays.iter().position(|r| r.url == url) else {
            return Vec::new();
        };
        let RelayPhase::Probing { attempt } = self.relays[i].phase else {
            return Vec::new();
        };
        if self.held_back(self.relays[i].role) {
            self.relays[i].phase = RelayPhase::Held;
            return Vec::new();
        }
        let next = attempt.saturating_add(1);
        if reachable {
            self.relays[i].phase = RelayPhase::Connecting {
                since: now,
                attempt: next,
            };
            vec![Action::Unpark(url.to_owned())]
        } else {
            self.park(i, next, now);
            Vec::new()
        }
    }

    /// Reset the backoff of every relay allowed to retry and retry now.
    fn reset(&mut self, now: MonoMillis, only: Option<&str>) {
        for i in 0..self.relays.len() {
            if only.is_some_and(|u| u != self.relays[i].url) {
                continue;
            }
            if self.held_back(self.relays[i].role) {
                continue;
            }
            match self.relays[i].phase {
                RelayPhase::Parked { .. } | RelayPhase::Held => {
                    self.relays[i].phase = RelayPhase::Parked {
                        attempt: 0,
                        next_retry: now,
                    };
                }
                RelayPhase::Connecting { since, .. } => {
                    self.relays[i].phase = RelayPhase::Connecting { since, attempt: 0 };
                }
                _ => {}
            }
        }
    }

    pub fn on_network_change(&mut self, now: MonoMillis) -> Vec<Action> {
        self.reset(now, None);
        self.tick(now)
    }

    /// The user pressed Retry on a relay.
    pub fn retry_now(&mut self, url: &str, now: MonoMillis) -> Vec<Action> {
        self.reset(now, Some(url));
        self.tick(now)
    }

    /// App opened / closed (phones), or PC.
    pub fn set_mode(&mut self, mode: DeviceMode, now: MonoMillis) -> Vec<Action> {
        let was = self.mode;
        self.mode = mode;
        let mut out = Vec::new();
        if mode == DeviceMode::PhoneBackground {
            for r in &mut self.relays {
                if r.role == RelayRole::Away {
                    let in_endpoint = matches!(
                        r.phase,
                        RelayPhase::Connecting { .. } | RelayPhase::Connected
                    );
                    r.phase = RelayPhase::Held;
                    if in_endpoint {
                        out.push(Action::Park(r.url.clone()));
                    }
                }
            }
        } else if was == DeviceMode::PhoneBackground {
            // App open: everything retries now with a fresh backoff.
            self.reset(now, None);
            out.extend(self.tick(now));
        }
        out
    }

    /// The next time [`tick`](Self::tick) has work, if any.
    pub fn next_deadline(&self) -> Option<MonoMillis> {
        self.relays
            .iter()
            .filter_map(|r| match r.phase {
                RelayPhase::Connecting { since, attempt } => {
                    Some(since.saturating_add(self.connect_window(attempt)))
                }
                RelayPhase::Parked { next_retry, .. } if !self.held_back(r.role) => {
                    Some(next_retry)
                }
                _ => None,
            })
            .min()
    }

    /// Relays that must be in the endpoint now.
    pub fn live_relays(&self) -> Vec<&str> {
        self.relays
            .iter()
            .filter(|r| {
                matches!(
                    r.phase,
                    RelayPhase::Connecting { .. } | RelayPhase::Connected
                )
            })
            .map(|r| r.url.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "https://home.example.test";
    const AWAY: &str = "https://away.example.test";
    const HOUR: u64 = 3_600_000;

    /// Run with a dead relay (every probe fails) for `ms`, returning the
    /// times at which probes started.
    fn simulate_dead(
        sup: &mut RelaySupervisor,
        url: &str,
        start: MonoMillis,
        ms: u64,
    ) -> Vec<MonoMillis> {
        let mut now = start;
        let end = start.saturating_add(ms);
        let mut probes = Vec::new();
        while let Some(d) = sup.next_deadline() {
            if d > end {
                break;
            }
            now = d.max(now);
            for a in sup.tick(now) {
                if let Action::Probe(u) = a {
                    assert_eq!(u, url);
                    probes.push(now);
                    sup.on_probe_result(&u, false, now);
                }
            }
        }
        probes
    }

    #[test]
    fn dead_relay_parks_after_30s_then_at_most_8_attempts_per_hour() {
        for seed in 1..200u64 {
            let mut s = RelaySupervisor::new(SupervisorConfig::DEFAULT, DeviceMode::Pc, seed);
            s.add_relay(HOME, RelayRole::Home, MonoMillis(0));
            assert!(s.tick(MonoMillis(29_999)).is_empty());
            assert_eq!(s.tick(MonoMillis(30_000)), vec![Action::Park(HOME.into())]);
            assert!(s.live_relays().is_empty());
            let parked = MonoMillis(30_000);
            let first_hour = simulate_dead(&mut s, HOME, parked, HOUR);
            assert!(
                first_hour.len() <= 8,
                "seed {seed}: {} attempts in the first hour",
                first_hour.len()
            );
            // Steady state at the 30 min cap (±25 %): at most 3 an hour.
            let later = simulate_dead(&mut s, HOME, parked.saturating_add(HOUR), 10 * HOUR);
            assert!(later.len() <= 30, "seed {seed}: {}", later.len());
            for w in later.windows(2) {
                let gap = w[1].saturating_sub(w[0]);
                assert!(gap >= 22 * 60_000 + 30_000, "gap {gap}");
            }
        }
    }

    #[test]
    fn four_dead_relays_at_the_cap_make_about_8_attempts_per_hour() {
        let mut s = RelaySupervisor::new(SupervisorConfig::DEFAULT, DeviceMode::Pc, 42);
        let urls: Vec<String> = (0..4)
            .map(|i| format!("https://r{i}.example.test"))
            .collect();
        for u in &urls {
            s.add_relay(u, RelayRole::Away, MonoMillis(0));
        }
        let mut now = MonoMillis(0);
        let mut probes_after_warmup = 0;
        let end = MonoMillis(12 * HOUR);
        while let Some(d) = s.next_deadline() {
            if d > end {
                break;
            }
            now = d.max(now);
            for a in s.tick(now) {
                if let Action::Probe(u) = a {
                    if now.0 >= 2 * HOUR {
                        probes_after_warmup += 1;
                    }
                    s.on_probe_result(&u, false, now);
                }
            }
        }
        let per_hour = probes_after_warmup as f64 / 10.0;
        assert!((6.0..=10.7).contains(&per_hour), "{per_hour}/h");
    }

    #[test]
    fn healthy_relay_is_never_touched() {
        let mut s = RelaySupervisor::new(SupervisorConfig::DEFAULT, DeviceMode::Pc, 7);
        s.add_relay(HOME, RelayRole::Home, MonoMillis(0));
        s.on_status(HOME, true, MonoMillis(500));
        assert!(s.tick(MonoMillis(HOUR)).is_empty());
        assert_eq!(s.next_deadline(), None);
        // A short drop (< 30 s) isn't parked.
        s.on_status(HOME, false, MonoMillis(HOUR));
        s.on_status(HOME, true, MonoMillis(HOUR + 10_000));
        assert!(s.tick(MonoMillis(HOUR + 60_000)).is_empty());
    }

    #[test]
    fn probe_success_unparks_and_a_flapping_relay_keeps_backing_off() {
        let mut s = RelaySupervisor::new(
            SupervisorConfig {
                jitter_pct: 0,
                ..SupervisorConfig::DEFAULT
            },
            DeviceMode::Pc,
            1,
        );
        s.add_relay(HOME, RelayRole::Home, MonoMillis(0));
        s.tick(MonoMillis(30_000));
        assert_eq!(s.tick(MonoMillis(60_000)), vec![Action::Probe(HOME.into())]);
        // Port open, relay broken: unpark, never connects, parked again
        // with a longer delay.
        assert_eq!(
            s.on_probe_result(HOME, true, MonoMillis(60_100)),
            vec![Action::Unpark(HOME.into())]
        );
        // It gets the unpark grace (60 s), not just the 30 s park window.
        assert!(s.tick(MonoMillis(90_100)).is_empty());
        assert_eq!(s.tick(MonoMillis(120_100)), vec![Action::Park(HOME.into())]);
        assert_eq!(
            s.phase(HOME),
            Some(RelayPhase::Parked {
                attempt: 1,
                next_retry: MonoMillis(180_100)
            })
        );
        // Comes up for real (slowly, inside the grace): backoff resets.
        s.tick(MonoMillis(180_100));
        s.on_probe_result(HOME, true, MonoMillis(180_200));
        assert!(s.tick(MonoMillis(225_000)).is_empty());
        s.on_status(HOME, true, MonoMillis(226_000));
        assert_eq!(s.phase(HOME), Some(RelayPhase::Connected));
        s.on_status(HOME, false, MonoMillis(300_000));
        s.tick(MonoMillis(330_000));
        assert_eq!(
            s.phase(HOME),
            Some(RelayPhase::Parked {
                attempt: 0,
                next_retry: MonoMillis(360_000)
            })
        );
    }

    #[test]
    fn network_change_and_retry_reset_backoff() {
        let mut s = RelaySupervisor::new(SupervisorConfig::DEFAULT, DeviceMode::Pc, 3);
        s.add_relay(HOME, RelayRole::Home, MonoMillis(0));
        s.tick(MonoMillis(30_000));
        let probes = simulate_dead(&mut s, HOME, MonoMillis(30_000), 3 * HOUR);
        assert!(probes.len() >= 6);
        let now = MonoMillis(4 * HOUR);
        assert_eq!(s.on_network_change(now), vec![Action::Probe(HOME.into())]);
        s.on_probe_result(HOME, false, now);
        match s.phase(HOME) {
            Some(RelayPhase::Parked { attempt: 1, .. }) => {}
            p => panic!("{p:?}"),
        }
        let now = now.saturating_add(1000);
        assert_eq!(s.retry_now(HOME, now), vec![Action::Probe(HOME.into())]);
    }

    #[test]
    fn phone_background_never_retries_away_relays() {
        let mut s = RelaySupervisor::new(SupervisorConfig::DEFAULT, DeviceMode::PhoneForeground, 9);
        s.add_relay(HOME, RelayRole::Home, MonoMillis(0));
        s.add_relay(AWAY, RelayRole::Away, MonoMillis(0));
        s.on_status(AWAY, true, MonoMillis(100));
        // App closes: the away relay leaves the endpoint at once.
        let a = s.set_mode(DeviceMode::PhoneBackground, MonoMillis(1000));
        assert_eq!(a, vec![Action::Park(AWAY.into())]);
        assert_eq!(s.live_relays(), vec![HOME]);
        // Hours in background with both relays dead, network changes too:
        // only home is ever probed.
        let mut now = MonoMillis(1000);
        for h in 0..6 {
            for a in s.on_network_change(MonoMillis(h * HOUR + 5_000).max(now)) {
                let Action::Probe(u) = a else { panic!() };
                assert_eq!(u, HOME);
                s.on_probe_result(&u, false, now);
            }
            while let Some(d) = s.next_deadline() {
                if d.0 > (h + 1) * HOUR {
                    break;
                }
                now = d.max(now);
                for a in s.tick(now) {
                    match a {
                        Action::Probe(u) => {
                            assert_eq!(u, HOME, "away relay retried in background");
                            s.on_probe_result(&u, false, now);
                        }
                        Action::Park(u) => assert_eq!(u, HOME),
                        Action::Unpark(_) => panic!(),
                    }
                }
                assert!(!s.live_relays().contains(&AWAY));
            }
        }
        assert_eq!(s.phase(AWAY), Some(RelayPhase::Held));
        // App opens: the away relay is retried right away.
        let a = s.set_mode(DeviceMode::PhoneForeground, MonoMillis(7 * HOUR));
        assert!(a.contains(&Action::Probe(AWAY.into())));
        // A new away relay added in background is parked straight away.
        s.set_mode(DeviceMode::PhoneBackground, MonoMillis(7 * HOUR));
        assert_eq!(
            s.add_relay(
                "https://third.example.test",
                RelayRole::Away,
                MonoMillis(7 * HOUR)
            ),
            vec![Action::Park("https://third.example.test".into())]
        );
    }

    #[test]
    fn backoff_schedule() {
        let mut s = RelaySupervisor::new(
            SupervisorConfig {
                jitter_pct: 0,
                ..SupervisorConfig::DEFAULT
            },
            DeviceMode::Pc,
            1,
        );
        let v: Vec<u64> = (0..8).map(|a| s.backoff_ms(a) / 1000).collect();
        assert_eq!(v, vec![30, 60, 120, 240, 480, 960, 1800, 1800]);
        let mut s = RelaySupervisor::new(SupervisorConfig::DEFAULT, DeviceMode::Pc, 5);
        for _ in 0..1000 {
            let d = s.backoff_ms(10);
            assert!((1_350_000..=2_250_000).contains(&d));
        }
    }
}
