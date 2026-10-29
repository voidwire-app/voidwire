//! Runs a [`RelaySupervisor`] against a live iroh endpoint.
//!
//! One task per endpoint. It watches the endpoint's home-relay status,
//! wakes at the supervisor's next deadline, and carries out its actions:
//! park = `remove_relay` (iroh stops its own unbounded reconnect loop),
//! probe = one TCP connection to the relay, unpark = `insert_relay`.
//!
//! The lighter background check (internal experiment, off by default):
//! while a phone is in background and the flag is on, the home relay is
//! re-inserted without QUIC address discovery, which is most of the idle
//! packet traffic. Direct (IP) paths stay enabled.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, RelayConfig, RelayUrl, Watcher};
use tokio::sync::mpsc;

use crate::relay_supervisor::{
    Action, DeviceMode, RelayPhase, RelayRole, RelaySupervisor, SupervisorConfig,
};
use crate::time::{Clock, MonoMillis, SystemClock};

/// Process-wide switch for the lighter background check experiment.
static LIGHT_BACKGROUND_CHECKS: AtomicBool = AtomicBool::new(false);

/// Turn the lighter background check experiment on or off (internal flag;
/// no UI). Takes effect on the next mode change of each endpoint.
pub fn set_light_background_checks(on: bool) {
    LIGHT_BACKGROUND_CHECKS.store(on, Ordering::Relaxed);
}

pub fn light_background_checks() -> bool {
    LIGHT_BACKGROUND_CHECKS.load(Ordering::Relaxed)
}

/// How long a probe waits for the TCP handshake.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// After connecting, a live TLS/HTTP server waits silently for the client.
/// A dead backend behind a proxy or load balancer closes at once. Holding
/// the connection this long tells the two apart with one connection.
const PROBE_HOLD: Duration = Duration::from_millis(750);

/// Counters for tests and the measurement harness.
#[derive(Debug, Default)]
pub struct WatchStats {
    pub parks: AtomicU64,
    pub probes: AtomicU64,
    pub unparks: AtomicU64,
    pub light_switches: AtomicU64,
    parked: AtomicBool,
    light: AtomicBool,
}

impl WatchStats {
    pub fn is_parked(&self) -> bool {
        self.parked.load(Ordering::Relaxed)
    }
    pub fn is_light(&self) -> bool {
        self.light.load(Ordering::Relaxed)
    }
}

enum Ctl {
    NetworkChange,
    RetryNow,
    Mode(DeviceMode),
    Light(bool),
    ProbeDone(bool),
}

/// Handle to a running watcher. Dropping it stops the task.
pub struct RelayWatch {
    tx: mpsc::UnboundedSender<Ctl>,
    task: tokio::task::JoinHandle<()>,
    stats: Arc<WatchStats>,
}

impl Drop for RelayWatch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl std::fmt::Debug for RelayWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayWatch").finish_non_exhaustive()
    }
}

impl RelayWatch {
    /// Start supervising `home` on `ep`. `home` must already be in the
    /// endpoint's relay map.
    pub fn spawn(
        rt: &tokio::runtime::Handle,
        ep: Endpoint,
        home: RelayConfig,
        mode: DeviceMode,
        cfg: SupervisorConfig,
    ) -> RelayWatch {
        let (tx, rx) = mpsc::unbounded_channel();
        let stats = Arc::new(WatchStats::default());
        let seed = rand_core::RngCore::next_u64(&mut rand_core::OsRng);
        let task = rt.spawn(run(
            ep,
            home,
            mode,
            cfg,
            seed,
            rx,
            tx.clone(),
            stats.clone(),
        ));
        let w = RelayWatch { tx, task, stats };
        w.set_light(light_background_checks());
        w
    }

    pub fn stats(&self) -> Arc<WatchStats> {
        self.stats.clone()
    }

    /// The network changed: retry parked relays now.
    pub fn network_change(&self) {
        let _ = self.tx.send(Ctl::NetworkChange);
    }

    /// The user acted (app opened, retry tapped): retry parked relays now.
    pub fn retry_now(&self) {
        let _ = self.tx.send(Ctl::RetryNow);
    }

    pub fn set_mode(&self, mode: DeviceMode) {
        let _ = self.tx.send(Ctl::Mode(mode));
    }

    /// Experiment flag for this endpoint (normally taken from the global).
    pub fn set_light(&self, on: bool) {
        let _ = self.tx.send(Ctl::Light(on));
    }
}

static CONFIG_OVERRIDE: std::sync::Mutex<Option<SupervisorConfig>> = std::sync::Mutex::new(None);

/// Supervisor timings for watchers started after this call (tests and the
/// measurement harness compress time with it).
#[cfg(any(test, feature = "test-util"))]
pub fn set_supervisor_config_for_tests(cfg: Option<SupervisorConfig>) {
    *CONFIG_OVERRIDE.lock().unwrap_or_else(|p| p.into_inner()) = cfg;
}

fn supervisor_config() -> SupervisorConfig {
    CONFIG_OVERRIDE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .unwrap_or(SupervisorConfig::DEFAULT)
}

/// Watch the relay an app endpoint was bound with (`relay_url` as passed to
/// [`super::build_relay_mode`]). `None` when relays are off.
pub(crate) fn for_app_endpoint(
    rt: &tokio::runtime::Handle,
    ep: &Endpoint,
    relay_url: Option<&str>,
    mode: DeviceMode,
) -> Option<RelayWatch> {
    let (_, url) = super::build_relay_mode(relay_url).ok()?;
    let url = url?;
    Some(RelayWatch::spawn(
        rt,
        ep.clone(),
        super::relay_config_for(&url),
        mode,
        supervisor_config(),
    ))
}

fn now() -> MonoMillis {
    SystemClock.now().mono
}

#[allow(clippy::too_many_arguments)]
async fn run(
    ep: Endpoint,
    home: RelayConfig,
    mode: DeviceMode,
    cfg: SupervisorConfig,
    seed: u64,
    mut rx: mpsc::UnboundedReceiver<Ctl>,
    tx: mpsc::UnboundedSender<Ctl>,
    stats: Arc<WatchStats>,
) {
    let url: RelayUrl = home.url.clone();
    let key = url.to_string();
    let mut sup = RelaySupervisor::new(cfg, mode, seed);
    let mut light_flag = false;
    let mut light_applied = false;
    let mut status = ep.home_relay_status();
    let mut actions = sup.add_relay(&key, RelayRole::Home, now());
    // The relay may already be up.
    let connected = status
        .get()
        .iter()
        .any(|s| s.url() == &url && s.is_connected());
    if connected {
        actions.extend(sup.on_status(&key, true, now()));
    }
    loop {
        for a in std::mem::take(&mut actions) {
            match a {
                Action::Park(_) => {
                    stats.parks.fetch_add(1, Ordering::Relaxed);
                    stats.parked.store(true, Ordering::Relaxed);
                    ep.remove_relay(&url).await;
                }
                Action::Probe(_) => {
                    stats.probes.fetch_add(1, Ordering::Relaxed);
                    let (u, tx) = (url.clone(), tx.clone());
                    tokio::spawn(async move {
                        let ok = probe(&u).await;
                        let _ = tx.send(Ctl::ProbeDone(ok));
                    });
                }
                Action::Unpark(_) => {
                    stats.unparks.fetch_add(1, Ordering::Relaxed);
                    stats.parked.store(false, Ordering::Relaxed);
                    let want = light_flag && sup.mode() == DeviceMode::PhoneBackground;
                    ep.insert_relay(url.clone(), Arc::new(config(&home, want)))
                        .await;
                    light_applied = want;
                    stats.light.store(want, Ordering::Relaxed);
                }
            }
        }
        // Lighter background check: switch the live relay's config.
        let want = light_flag && sup.mode() == DeviceMode::PhoneBackground;
        let live = matches!(
            sup.phase(&key),
            Some(RelayPhase::Connected) | Some(RelayPhase::Connecting { .. })
        );
        if live && want != light_applied {
            ep.insert_relay(url.clone(), Arc::new(config(&home, want)))
                .await;
            light_applied = want;
            stats.light.store(want, Ordering::Relaxed);
            stats.light_switches.fetch_add(1, Ordering::Relaxed);
        }

        let sleep_ms = sup
            .next_deadline()
            .map(|d| d.saturating_sub(now()).max(1))
            .unwrap_or(24 * 3_600_000);
        tokio::select! {
            changed = status.updated() => {
                let Ok(list) = changed else { break };
                let connected = list.iter().any(|s| s.url() == &url && s.is_connected());
                actions = sup.on_status(&key, connected, now());
            }
            _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {
                actions = sup.tick(now());
            }
            ctl = rx.recv() => {
                let Some(ctl) = ctl else { break };
                let t = now();
                actions = match ctl {
                    Ctl::NetworkChange => sup.on_network_change(t),
                    Ctl::RetryNow => sup.retry_now(&key, t),
                    Ctl::Mode(m) => sup.set_mode(m, t),
                    Ctl::Light(on) => { light_flag = on; Vec::new() }
                    Ctl::ProbeDone(ok) => sup.on_probe_result(&key, ok, t),
                };
            }
        }
        if ep.is_closed() {
            break;
        }
    }
}

fn config(home: &RelayConfig, light: bool) -> RelayConfig {
    let mut c = home.clone();
    if light {
        c.quic = None;
    }
    c
}

/// One reachability probe: resolve, open one TCP connection, and hold it
/// briefly. Reachable = the server accepted and did not close at once.
pub async fn probe(url: &RelayUrl) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let Some(port) = url.port_or_known_default() else {
        return false;
    };
    let addrs = match tokio::time::timeout(
        PROBE_CONNECT_TIMEOUT,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(a)) => a.collect::<Vec<_>>(),
        _ => return false,
    };
    // At most one v4 and one v6 address: a single "attempt" either way.
    let mut tried = (false, false);
    for addr in addrs {
        let fam = addr.is_ipv6();
        if (fam && tried.1) || (!fam && tried.0) {
            continue;
        }
        if fam {
            tried.1 = true;
        } else {
            tried.0 = true;
        }
        let Ok(Ok(mut s)) =
            tokio::time::timeout(PROBE_CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr)).await
        else {
            continue;
        };
        let mut b = [0u8; 1];
        return match tokio::time::timeout(PROBE_HOLD, tokio::io::AsyncReadExt::read(&mut s, &mut b))
            .await
        {
            Err(_) => true,      // still open and silent: a live server
            Ok(Ok(n)) => n > 0,  // sent something: alive; closed: dead
            Ok(Err(_)) => false, // reset
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_tells_live_from_closing_and_refusing_servers() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // live: accepts and stays silent
            let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let lport = live.local_addr().unwrap().port();
            tokio::spawn(async move {
                let mut keep = Vec::new();
                while let Ok((s, _)) = live.accept().await {
                    keep.push(s);
                }
            });
            // closing: accepts and closes at once
            let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dport = dead.local_addr().unwrap().port();
            tokio::spawn(async move {
                while let Ok((s, _)) = dead.accept().await {
                    drop(s);
                }
            });
            // refusing: nothing listening
            let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let gport = gone.local_addr().unwrap().port();
            drop(gone);
            let u = |p: u16| -> RelayUrl { format!("http://127.0.0.1:{p}").parse().unwrap() };
            assert!(probe(&u(lport)).await);
            assert!(!probe(&u(dport)).await);
            assert!(!probe(&u(gport)).await);
        });
    }
}
