//! M4.1 measurement harness: the relay supervisor and the lighter background
//! check experiment, against real iroh relay servers on loopback, each behind
//! a TCP+UDP proxy that counts traffic and can play "relay down".
//!
//! Run: `cargo run --manifest-path tools/relay-bench/Cargo.toml -- [secs]`
//! (`secs` = length of each idle-cost window and of the real-time parked
//! window, default 240, at least 180 for the parked one). Prints one
//! `BENCH key=value` line per measurement and exits non-zero if a threshold
//! fails. Supervisor timings are compressed 60x (30 s -> 0.5 s), so one
//! "hour" of supervisor behavior takes one minute.
//!
//! Window length matters: the traffic being counted is a few periodic
//! events (iroh's jittered 16-32 s relay redial, its 20-26 s net report,
//! one relay TCP connect per report in light mode). A 60 s window holds
//! 2-4 of them, so one event more or less moved a per-hour figure by 20-40 %
//! and decided pass or fail. Windows of several minutes average that out.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use iroh::endpoint::presets;
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, Watcher};
use iroh_relay::{RelayConfig, RelayMap, RelayQuicConfig};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use voidwire_core::net::relay_watch::RelayWatch;
use voidwire_core::relay_supervisor::{DeviceMode, SupervisorConfig};
use voidwire_core::time::Stopwatch;

/// Elapsed time since `t` (the app's one clock wrapper).
fn since(t: &Stopwatch) -> Duration {
    Duration::from_micros(t.elapsed_us())
}

const ALPN: &[u8] = b"voidwire-relay-bench/0";
fn scale() -> u64 {
    std::env::var("BENCH_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60)
}

#[derive(Default)]
struct Counters {
    tcp_conns: AtomicU64,
    tcp_refused: AtomicU64,
    tcp_reads: AtomicU64,
    tcp_bytes: AtomicU64,
    udp_pkts: AtomicU64,
    udp_bytes: AtomicU64,
    udp_dropped: AtomicU64,
}

#[derive(Clone, Copy, Default, Debug)]
struct Snap {
    attempts: u64,
    reads: u64,
    tcp_bytes: u64,
    udp_pkts: u64,
    udp_bytes: u64,
    udp_dropped: u64,
}

impl Counters {
    fn snap(&self) -> Snap {
        Snap {
            attempts: self.tcp_conns.load(Relaxed) + self.tcp_refused.load(Relaxed),
            reads: self.tcp_reads.load(Relaxed),
            tcp_bytes: self.tcp_bytes.load(Relaxed),
            udp_pkts: self.udp_pkts.load(Relaxed),
            udp_bytes: self.udp_bytes.load(Relaxed),
            udp_dropped: self.udp_dropped.load(Relaxed),
        }
    }
}

impl std::ops::Sub for Snap {
    type Output = Snap;
    fn sub(self, a: Snap) -> Snap {
        Snap {
            attempts: self.attempts - a.attempts,
            reads: self.reads - a.reads,
            tcp_bytes: self.tcp_bytes - a.tcp_bytes,
            udp_pkts: self.udp_pkts - a.udp_pkts,
            udp_bytes: self.udp_bytes - a.udp_bytes,
            udp_dropped: self.udp_dropped - a.udp_dropped,
        }
    }
}

struct Relay {
    _server: iroh_relay::server::Server,
    cfg: RelayConfig,
    c: Arc<Counters>,
    up: watch::Sender<bool>,
}

impl Relay {
    fn map(&self) -> RelayMap {
        RelayMap::from(self.cfg.clone())
    }
    fn set_up(&self, v: bool) {
        let _ = self.up.send(v);
    }
}

async fn pump(mut a: TcpStream, mut b: TcpStream, c: Arc<Counters>, mut up: watch::Receiver<bool>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();
    let one = |c: Arc<Counters>| {
        move |n: usize| {
            c.tcp_reads.fetch_add(1, Relaxed);
            c.tcp_bytes.fetch_add(n as u64, Relaxed);
        }
    };
    let (f1c, f2c) = (one(c.clone()), one(c.clone()));
    let f1 = async {
        let mut buf = vec![0u8; 65536];
        while let Ok(n @ 1..) = ar.read(&mut buf).await {
            f1c(n);
            if bw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    };
    let f2 = async {
        let mut buf = vec![0u8; 65536];
        while let Ok(n @ 1..) = br.read(&mut buf).await {
            f2c(n);
            if aw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    };
    let down = async {
        while up.changed().await.is_ok() {
            if !*up.borrow() {
                break;
            }
        }
    };
    tokio::select! { _ = f1 => {}, _ = f2 => {}, _ = down => {} }
}

async fn tcp_proxy(
    l: TcpListener,
    target: SocketAddr,
    c: Arc<Counters>,
    up: watch::Receiver<bool>,
) {
    loop {
        let Ok((s, _)) = l.accept().await else {
            continue;
        };
        if !*up.borrow() {
            // A dead relay behind a load balancer: accept, then close.
            c.tcp_refused.fetch_add(1, Relaxed);
            drop(s);
            continue;
        }
        c.tcp_conns.fetch_add(1, Relaxed);
        let (c, up) = (c.clone(), up.clone());
        tokio::spawn(async move {
            if let Ok(t) = TcpStream::connect(target).await {
                pump(s, t, c, up).await
            }
        });
    }
}

async fn udp_proxy(
    sock: Arc<UdpSocket>,
    target: SocketAddr,
    c: Arc<Counters>,
    up: watch::Receiver<bool>,
) {
    let mut peers: std::collections::HashMap<SocketAddr, Arc<UdpSocket>> = Default::default();
    let mut buf = vec![0u8; 65536];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if !*up.borrow() {
            c.udp_dropped.fetch_add(1, Relaxed);
            continue;
        }
        c.udp_pkts.fetch_add(1, Relaxed);
        c.udp_bytes.fetch_add(n as u64, Relaxed);
        let upstream = match peers.get(&from) {
            Some(u) => u.clone(),
            None => {
                let u = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                u.connect(target).await.unwrap();
                let (u2, s2, c2) = (u.clone(), sock.clone(), c.clone());
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    while let Ok(n) = u2.recv(&mut b).await {
                        c2.udp_pkts.fetch_add(1, Relaxed);
                        c2.udp_bytes.fetch_add(n as u64, Relaxed);
                        let _ = s2.send_to(&b[..n], from).await;
                    }
                });
                peers.insert(from, u.clone());
                u
            }
        };
        let _ = upstream.send(&buf[..n]).await;
    }
}

async fn spawn_relay() -> Result<Relay> {
    let (_m, _u, server) = iroh::test_utils::run_relay_server().await?;
    let https = server.https_addr().unwrap();
    let quic = server.quic_addr().unwrap();
    let c = Arc::new(Counters::default());
    let (up_tx, up_rx) = watch::channel(true);
    let tl = TcpListener::bind("127.0.0.1:0").await?;
    let us = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let (tport, uport) = (tl.local_addr()?.port(), us.local_addr()?.port());
    tokio::spawn(tcp_proxy(tl, https, c.clone(), up_rx.clone()));
    tokio::spawn(udp_proxy(us, quic, c.clone(), up_rx));
    let url: iroh::RelayUrl = format!("https://127.0.0.1:{tport}").parse()?;
    let cfg = RelayConfig::new(url, Some(RelayQuicConfig::new(uport)));
    Ok(Relay {
        _server: server,
        cfg,
        c,
        up: up_tx,
    })
}

async fn endpoint(r: &Relay, ip: bool) -> Result<Endpoint> {
    let mut b = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .relay_mode(RelayMode::Custom(r.map()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .alpns(vec![ALPN.to_vec()])
        .net_report_config(voidwire_core::net::default_net_report_config());
    if !ip {
        b = b.clear_ip_transports();
    }
    Ok(b.bind().await?)
}

fn compressed() -> SupervisorConfig {
    let d = SupervisorConfig::DEFAULT;
    SupervisorConfig {
        park_after_ms: d.park_after_ms / scale(),
        unpark_grace_ms: d.unpark_grace_ms / scale(),
        base_retry_ms: d.base_retry_ms / scale(),
        max_retry_ms: d.max_retry_ms / scale(),
        jitter_pct: d.jitter_pct,
    }
}

fn spawn_echo(e: Endpoint) {
    tokio::spawn(async move {
        while let Some(inc) = e.accept().await {
            tokio::spawn(async move {
                if let Ok(conn) = inc.await {
                    if let Ok((mut s, mut r)) = conn.accept_bi().await {
                        let mut b = [0u8; 4];
                        let _ = r.read_exact(&mut b).await;
                        let _ = s.write_all(&b).await;
                        let _ = s.finish();
                        let _ = conn.closed().await;
                    }
                }
            });
        }
    });
}

/// Dial `to` with the given address; Ok(conn) after one echo round trip.
async fn dial(from: &Endpoint, addr: EndpointAddr) -> Result<iroh::endpoint::Connection> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let conn = from.connect(addr, ALPN).await?;
        let (mut s, mut r) = conn.open_bi().await?;
        s.write_all(b"ping").await?;
        s.finish()?;
        let mut b = [0u8; 4];
        r.read_exact(&mut b).await?;
        anyhow::Ok(conn)
    })
    .await?
}

async fn wait_connected(e: &Endpoint, r: &Relay, secs: u64) -> bool {
    let t = Stopwatch::start();
    while since(&t) < Duration::from_secs(secs) {
        if e.home_relay_status()
            .get()
            .iter()
            .any(|s| s.url() == &r.cfg.url && s.is_connected())
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

struct Checks(Vec<String>);
impl Checks {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        println!("BENCH check={name} ok={ok} {detail}");
        if !ok {
            self.0.push(name.into());
        }
    }
}

/// Supervised endpoint on `r`; waits until it has parked the dead relay.
async fn park_dead(r: &Relay, cfg: SupervisorConfig) -> Result<(Endpoint, RelayWatch, Duration)> {
    let e = endpoint(r, true).await?;
    let w = RelayWatch::spawn(
        &tokio::runtime::Handle::current(),
        e.clone(),
        r.cfg.clone(),
        DeviceMode::PhoneBackground,
        cfg,
    );
    if !wait_connected(&e, r, 20).await {
        bail!("supervised endpoint never reached the relay");
    }
    r.set_up(false);
    let t = Stopwatch::start();
    while !w.stats().is_parked() && since(&t) < Duration::from_secs(90) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok((e, w, since(&t)))
}

/// Counts TCP attempts in `secs`, in 5 s buckets.
async fn watch_attempts(r: &Relay, secs: u64) -> (Snap, String) {
    let a = r.c.snap();
    let mut last = a;
    let mut timeline = Vec::new();
    for _ in 0..secs / 5 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let now = r.c.snap();
        timeline.push((now - last).attempts.to_string());
        last = now;
    }
    (r.c.snap() - a, timeline.join(","))
}

/// Dead home relay. Three runs on fresh relays:
/// 1. no supervisor (iroh alone), real time;
/// 2. supervisor at 60x compressed timings: its own probes in one "hour";
/// 3. supervisor at real timings: everything that still hits the relay
///    after parking (iroh's own leftover redials included), per real hour.
///
/// Then recovery at real timings: relay back + network change, peer dials
/// in via the relay.
async fn dead_relay(ck: &mut Checks, real_secs: u64) -> Result<()> {
    // 1. Baseline.
    let r = spawn_relay().await?;
    let base = endpoint(&r, true).await?;
    if !wait_connected(&base, &r, 20).await {
        bail!("baseline endpoint never reached the relay");
    }
    r.set_up(false);
    let (d, _) = watch_attempts(&r, 30).await;
    let baseline_h = d.attempts * 120;
    println!("BENCH scenario=dead_home_no_supervisor tcp_attempts_per_hour={baseline_h}");
    base.close().await;

    // 2. Supervisor schedule, compressed.
    let r = spawn_relay().await?;
    let (e, w, parked_after) = park_dead(&r, compressed()).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let p0 = w.stats().probes.load(Relaxed);
    let (d, timeline) = watch_attempts(&r, 3600 / scale()).await;
    let probes = w.stats().probes.load(Relaxed) - p0;
    ck.check(
        "dead_home_parks",
        w.stats().is_parked(),
        format!("parked_after_ms_at_60x={}", parked_after.as_millis()),
    );
    ck.check(
        "supervisor_probes_first_hour_after_park_le_8",
        probes <= 8 && w.stats().unparks.load(Relaxed) == 0,
        format!(
            "probes={probes} all_tcp_attempts_at_60x={} timeline_per_5min=[{timeline}]",
            d.attempts
        ),
    );

    drop(w);
    e.close().await;

    // 3. Real timings: total attempts in the first hour after parking.
    // Two parts with different shapes: iroh's own leftover redials to the
    // removed home relay (steady, one per 16-32 s) and the supervisor's
    // probes (front-loaded: 30 s, 60 s, 2 min, ...). Scaling a few minutes
    // of the sum to an hour would count the early probes twelve times over,
    // so the redial rate is measured here and the probes come from the
    // compressed first hour above. Each probe is one TCP attempt.
    let first_hour_probes = probes;
    let r = spawn_relay().await?;
    let (e, w, parked_after) = park_dead(&r, SupervisorConfig::DEFAULT).await?;
    let p0 = w.stats().probes.load(Relaxed);
    let (d, timeline) = watch_attempts(&r, real_secs).await;
    let probes = w.stats().probes.load(Relaxed) - p0;
    let redials = d.attempts.saturating_sub(probes);
    let redials_h = redials * 3600 / real_secs;
    let total_h = redials_h + first_hour_probes;
    println!(
        "BENCH scenario=dead_home_supervised_real parked_after_ms={} window_s={real_secs} \
         tcp_attempts={} probes={probes} iroh_redials={redials} iroh_redials_per_hour={redials_h} \
         first_hour_probes={first_hour_probes} tcp_attempts_first_hour={total_h} timeline_per_5s=[{timeline}]",
        parked_after.as_millis(),
        d.attempts
    );
    // iroh 1.3 keeps redialing a removed home relay (16 s cap, jittered), so
    // parking cuts traffic rather than ending it. Guard the cut.
    ck.check(
        "parked_total_at_most_15pct_of_unsupervised",
        total_h * 100 <= baseline_h * 15,
        format!("supervised={total_h}/h unsupervised={baseline_h}/h"),
    );

    // Recovery at real timings, on the same endpoint: relay back + network
    // change. One probe, one unpark (no re-park while iroh's own reconnect
    // backoff runs out), then a peer dials in via the relay.
    r.set_up(true);
    let u0 = w.stats().unparks.load(Relaxed);
    w.network_change();
    let t_back = Stopwatch::start();
    let back = wait_connected(&e, &r, 90).await;
    let back_ms = since(&t_back).as_millis();
    // iroh keeps redialing the removed relay, so it can reconnect on its own
    // a moment before the network-change probe finishes and unparks (bench
    // 40995059459: reconnected, unparks=0). Give that probe up to 10 s to
    // land before counting. Bench-only wait; the app has no such loop.
    let probe_deadline = Stopwatch::start();
    while back
        && w.stats().unparks.load(Relaxed) == u0
        && since(&probe_deadline) < Duration::from_secs(10)
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let unparks = w.stats().unparks.load(Relaxed) - u0;
    spawn_echo(e.clone());
    // Created only now: a second endpoint on the relay adds its own redials.
    let peer = endpoint(&r, false).await?;
    wait_connected(&peer, &r, 20).await;
    let reach = dial(
        &peer,
        EndpointAddr::new(e.id()).with_relay_url(r.cfg.url.clone()),
    )
    .await;
    println!("BENCH scenario=recovery_real reconnected_after_ms={back_ms} unparks={unparks}");
    ck.check(
        "recovers_once_and_is_reachable",
        back && unparks == 1 && w.stats().parks.load(Relaxed) == 1 && reach.is_ok(),
        format!(
            "relay_connected={back} unparks={unparks} parks={} peer_dial_via_relay={}",
            w.stats().parks.load(Relaxed),
            reach.is_ok()
        ),
    );
    drop(w);
    e.close().await;
    peer.close().await;
    Ok(())
}

/// Idle cost per hour, plus a direct-path check, for one setup.
async fn idle(name: &str, ip: bool, light: Option<bool>, secs: u64) -> Result<(Snap, bool)> {
    let r = spawn_relay().await?;
    let e = endpoint(&r, ip).await?;
    let w = light.map(|on| {
        let w = RelayWatch::spawn(
            &tokio::runtime::Handle::current(),
            e.clone(),
            r.cfg.clone(),
            DeviceMode::PhoneBackground,
            SupervisorConfig::DEFAULT,
        );
        w.set_light(on);
        w
    });
    if !wait_connected(&e, &r, 20).await {
        bail!("{name}: endpoint never reached the relay");
    }
    if let (Some(w), Some(true)) = (&w, light) {
        let t = Stopwatch::start();
        while !w.stats().is_light() && since(&t) < Duration::from_secs(10) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if !w.stats().is_light() {
            bail!("{name}: light mode never applied");
        }
        wait_connected(&e, &r, 20).await;
    }
    tokio::time::sleep(Duration::from_secs(10)).await; // settle
    let a = r.c.snap();
    tokio::time::sleep(Duration::from_secs(secs)).await;
    let d = r.c.snap() - a;
    let k = 3600 / secs;
    let per_h = Snap {
        attempts: d.attempts * k,
        reads: d.reads * k,
        tcp_bytes: d.tcp_bytes * k,
        udp_pkts: d.udp_pkts * k,
        udp_bytes: d.udp_bytes * k,
        udp_dropped: d.udp_dropped * k,
    };
    println!(
        "BENCH scenario=idle_{name} per_hour: packet_events={} tcp_conns={} tcp_bytes={} udp_pkts={} udp_bytes={}",
        per_h.reads + per_h.udp_pkts,
        per_h.attempts,
        per_h.tcp_bytes,
        per_h.udp_pkts,
        per_h.udp_bytes
    );
    // Direct connections: a peer with IP on dials us by id + relay; the
    // connection must move to a direct (IP) path.
    let mut direct = false;
    if ip {
        spawn_echo(e.clone());
        let peer = endpoint(&r, true).await?;
        wait_connected(&peer, &r, 20).await;
        match dial(
            &peer,
            EndpointAddr::new(e.id()).with_relay_url(r.cfg.url.clone()),
        )
        .await
        {
            Ok(conn) => {
                let t = Stopwatch::start();
                while since(&t) < Duration::from_secs(15) && !direct {
                    direct = conn.paths().iter().any(|p| p.is_ip());
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                conn.close(0u32.into(), b"done");
            }
            Err(err) => println!("BENCH scenario=idle_{name} dial_failed={err}"),
        }
        println!("BENCH scenario=idle_{name} direct_path={direct}");
        peer.close().await;
    }
    drop(w);
    e.close().await;
    Ok((per_h, direct))
}

#[tokio::main]
async fn main() -> Result<()> {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(240);
    let mut ck = Checks(Vec::new());
    dead_relay(&mut ck, secs.max(180)).await?;
    if std::env::var_os("BENCH_ONLY_DEAD").is_some() {
        return Ok(());
    }
    let (std_cost, std_direct) = idle("standard", true, Some(false), secs).await?;
    let (light_cost, light_direct) = idle("light", true, Some(true), secs).await?;
    let (ro_cost, _) = idle("relay_only", false, None, secs).await?;
    let ev = |s: Snap| s.reads + s.udp_pkts;
    ck.check("standard_direct_path", std_direct, String::new());
    ck.check("light_keeps_direct_path", light_direct, String::new());
    ck.check(
        "light_cuts_packet_events_by_a_third",
        ev(light_cost) * 3 <= ev(std_cost) * 2,
        format!(
            "standard={} light={} relay_only={}",
            ev(std_cost),
            ev(light_cost),
            ev(ro_cost)
        ),
    );
    if ck.0.is_empty() {
        println!("BENCH result=pass");
        Ok(())
    } else {
        bail!("failed checks: {:?}", ck.0)
    }
}
