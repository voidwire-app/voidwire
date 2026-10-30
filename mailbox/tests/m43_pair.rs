//! M4.3: new pairing flows. Any device shows a QR or a typed code, any
//! device joins, over a relay picked on the invite. The PAIR suite for
//! every role combination, the refusals, and M3 compatibility.

mod common;
use common::*;

use voidwire_core::net::pair2::{self, HostStatus, Opened, RelayCheck, ShowInfo};
use voidwire_core::net::NetError;
use voidwire_core::reject::RejectReason;

trait Pair2 {
    fn show(&self, relay: Option<&str>) -> ShowInfo;
    fn status(&self) -> HostStatus;
    fn submit(&self, sas: &str) -> Result<pair2::Paired2, NetError>;
    fn cancel(&self);
    fn open_code(&self, code: &str, relay: Option<&str>) -> Result<Opened, NetError>;
    fn open_qr(&self, qr: &str) -> Result<Opened, NetError>;
    fn add_relay(&self) -> Result<(), NetError>;
    fn join(&self) -> Result<String, NetError>;
    fn join_wait(&self) -> Result<pair2::Paired2, NetError>;
    fn save(&self, r: &RelayBox);
    fn paired_with(&self, peer: &DeviceId) -> Option<Option<String>>;
}

impl Pair2 for Dev {
    fn show(&self, relay: Option<&str>) -> ShowInfo {
        match self {
            Dev::Pc { node, .. } => node.pair2_show(relay),
            Dev::Phone { node, .. } => node.pair2_show(relay),
        }
        .expect("show")
    }
    fn status(&self) -> HostStatus {
        match self {
            Dev::Pc { node, .. } => node.pair2_status(),
            Dev::Phone { node, .. } => node.pair2_status(),
        }
    }
    fn submit(&self, sas: &str) -> Result<pair2::Paired2, NetError> {
        match self {
            Dev::Pc { node, .. } => node.pair2_submit_code(sas),
            Dev::Phone { node, .. } => node.pair2_submit_code(sas),
        }
    }
    fn cancel(&self) {
        match self {
            Dev::Pc { node, .. } => node.pair2_cancel(),
            Dev::Phone { node, .. } => node.pair2_cancel(),
        }
    }
    fn open_code(&self, code: &str, relay: Option<&str>) -> Result<Opened, NetError> {
        match self {
            Dev::Pc { node, .. } => node.pair2_open_code(code, relay),
            Dev::Phone { node, .. } => node.pair2_open_code(code, relay),
        }
    }
    fn open_qr(&self, qr: &str) -> Result<Opened, NetError> {
        match self {
            Dev::Pc { node, .. } => node.pair2_open_qr(qr),
            Dev::Phone { node, .. } => node.pair2_open_qr(qr),
        }
    }
    fn add_relay(&self) -> Result<(), NetError> {
        match self {
            Dev::Pc { node, .. } => node.pair2_add_relay(),
            Dev::Phone { node, .. } => node.pair2_add_relay(),
        }
    }
    fn join(&self) -> Result<String, NetError> {
        match self {
            Dev::Pc { node, .. } => node.pair2_join(),
            Dev::Phone { node, .. } => node.pair2_join(),
        }
    }
    fn join_wait(&self) -> Result<pair2::Paired2, NetError> {
        match self {
            Dev::Pc { node, .. } => node.pair2_join_wait(),
            Dev::Phone { node, .. } => node.pair2_join_wait(),
        }
    }
    fn save(&self, r: &RelayBox) {
        match self {
            Dev::Pc { node, .. } => node.add_saved_relay_for_tests(r.rref()),
            Dev::Phone { node, .. } => node.add_saved_relay_for_tests(r.rref()),
        }
        .expect("save relay")
    }
    /// `Some(relay url)` when paired with `peer` over a v2 pairing.
    fn paired_with(&self, peer: &DeviceId) -> Option<Option<String>> {
        let list = match self {
            Dev::Pc { node, .. } => node.pairings(),
            Dev::Phone { node, .. } => node.pairings(),
        };
        list.into_iter()
            .find(|p| p.peer == *peer && !p.legacy)
            .map(|p| p.relay_url)
    }
}

fn rejected<T: std::fmt::Debug>(r: Result<T, NetError>) -> RejectReason {
    match r {
        Err(NetError::Rejected(r)) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

enum Via {
    Code,
    Qr,
}

/// `a` shows, `b` joins; `b` adds the relay when asked. Returns once both
/// kept the pairing: `true` when both say it replaced an older one.
fn pair_flow(a: &Dev, b: &Dev, via: Via, relay: &RelayBox) -> bool {
    let info = a.show(Some(&relay.url()));
    assert!(matches!(a.status(), HostStatus::Showing { .. }));
    let opened = match via {
        Via::Code => b
            .open_code(info.code.as_deref().expect("code"), Some(&relay.url()))
            .expect("open code"),
        Via::Qr => b.open_qr(&info.qr).expect("open qr"),
    };
    assert_eq!(opened.inviter_name.as_deref(), Some(a.name().as_str()));
    assert_eq!(opened.relay_url, relay.url());
    match opened.relay {
        RelayCheck::Saved => {}
        RelayCheck::Ask { host } => {
            assert_eq!(host, "127.0.0.1");
            b.add_relay().expect("add relay");
        }
        RelayCheck::Full { .. } => panic!("relay limit"),
    }
    let sas = b.join().expect("join");
    assert_eq!(sas.len(), 6);
    assert!(matches!(a.status(), HostStatus::AwaitingCode { .. }));
    let refreshed = std::thread::scope(|s| {
        let j = s.spawn(|| b.join_wait());
        let sub = a.submit(&sas);
        let jw = j.join().unwrap();
        let host = sub.unwrap_or_else(|e| panic!("submit: {e:?}, joiner: {jw:?}"));
        assert_eq!(host.peer, b.id());
        assert_eq!(host.name, b.name());
        let joiner = jw.expect("join wait");
        assert_eq!(joiner.peer, a.id());
        assert_eq!(joiner.name, a.name());
        assert_eq!(host.refreshed, joiner.refreshed, "both sides agree");
        host.refreshed
    });
    assert!(matches!(a.status(), HostStatus::Paired { .. }));
    assert_eq!(a.paired_with(&b.id()), Some(Some(relay.url())));
    assert_eq!(b.paired_with(&a.id()), Some(Some(relay.url())));
    refreshed
}

fn world(root: &std::path::Path) -> (RelayBox, RelayBox, [Dev; 4]) {
    let home = RelayBox::start();
    let pr = RelayBox::start();
    let h = Some(home.url());
    let devs = [
        pc("PC A", h.clone(), root),
        pc("PC B", h.clone(), root),
        phone("Phone A", h.clone(), root),
        phone("Phone B", h.clone(), root),
    ];
    for d in &devs {
        let id = d.id();
        wait("device on the home relay", || home.relay.has_peer(&id));
    }
    (home, pr, devs)
}

#[test]
fn m43_every_role_combination_pairs_by_code_and_qr_and_sends_both_ways() {
    let root = temp_dir("m43-roles");
    let (_home, pr, [pc_a, pc_b, ph_a, ph_b]) = world(&root);
    // Inviters pick the pairing relay from their saved relays; code
    // joiners pick it to look the code up.
    for d in [&pc_a, &pc_b, &ph_a] {
        d.save(&pr);
    }
    let pairs: [(&Dev, &Dev, Via); 4] = [
        (&pc_a, &pc_b, Via::Code), // PC ↔ PC, typed code
        (&ph_a, &ph_b, Via::Qr),   // phone ↔ phone, QR (B is asked to add the relay)
        (&pc_a, &ph_a, Via::Qr),   // PC shows, phone scans
        (&ph_b, &pc_b, Via::Code), // phone shows, PC types
    ];
    for (i, (a, b, via)) in pairs.into_iter().enumerate() {
        assert!(
            !pair_flow(a, b, via, &pr),
            "a first pairing isn't a refresh"
        );
        let there = format!("https://example.com/m43/{i}/there");
        a.send_url(&b.id(), &there);
        wait(&format!("url {i} a->b"), || b.got_url(&there));
        let back = format!("https://example.com/m43/{i}/back");
        b.send_url(&a.id(), &back);
        wait(&format!("url {i} b->a"), || a.got_url(&back));
    }
    // Pairing again (0.8.1 field test): both sides say "refreshed", the
    // new pairing replaces the old one (still one entry each side), and
    // links go over the new pairing's keys and inbox.
    for (i, (a, b, via)) in [(&ph_a, &pc_a, Via::Code), (&pc_b, &pc_a, Via::Qr)]
        .into_iter()
        .enumerate()
    {
        let count = |d: &Dev, peer: &DeviceId| {
            let list = match d {
                Dev::Pc { node, .. } => node.pairings(),
                Dev::Phone { node, .. } => node.pairings(),
            };
            list.into_iter().filter(|p| p.peer == *peer).count()
        };
        assert!(pair_flow(a, b, via, &pr), "re-pair {i} is a refresh");
        assert_eq!(count(a, &b.id()), 1, "one pairing with the peer, not two");
        assert_eq!(count(b, &a.id()), 1);
        let there = format!("https://example.com/m43/again/{i}/there");
        a.send_url(&b.id(), &there);
        wait(&format!("re-pair url {i} a->b"), || b.got_url(&there));
        let back = format!("https://example.com/m43/again/{i}/back");
        b.send_url(&a.id(), &back);
        wait(&format!("re-pair url {i} b->a"), || a.got_url(&back));
    }
}

#[test]
fn m43_pair_refusals_expiry_single_use_sas_check_hostile_and_relay_swap() {
    let root = temp_dir("m43-refuse");
    let (_home, pr, [pc_a, pc_b, ph_a, ph_b]) = world(&root);
    let other = RelayBox::start();
    for d in [&pc_a, &pc_b, &ph_a, &ph_b] {
        d.save(&pr);
    }

    // A typo in a code is caught before any traffic.
    let info = pc_a.show(Some(&pr.url()));
    let code = info.code.clone().expect("code");
    let mut typo = code.clone().into_bytes();
    let k = 4;
    typo[k] = if typo[k] == b'7' { b'8' } else { b'7' };
    assert_eq!(
        rejected(pc_b.open_code(std::str::from_utf8(&typo).unwrap(), Some(&pr.url()))),
        RejectReason::PairingCodeInvalid
    );
    // Checked locally first: no relay lookup or network for a typo (an
    // unsaved, unreachable relay would otherwise be refused).
    assert_eq!(
        rejected(pc_b.open_code(
            std::str::from_utf8(&typo).unwrap(),
            Some("https://unreachable.invalid")
        )),
        RejectReason::PairingCodeInvalid
    );
    // A well-formed code nobody shows.
    let stranger = pair2::encode_code(&[7u8; 16]);
    assert_eq!(
        rejected(pc_b.open_code(&stranger, Some(&pr.url()))),
        RejectReason::PairingSecretUnknown
    );
    // A code looked up on another relay than the one it was shown on.
    pc_b.save(&other);
    assert_eq!(
        rejected(pc_b.open_code(&code, Some(&other.url()))),
        RejectReason::PairingSecretUnknown
    );
    // Showing on your own device and scanning it.
    assert_eq!(rejected(pc_a.open_qr(&info.qr)), RejectReason::FromSelf);

    // SAS mismatch: one try, both sides fail, the code is spent.
    let o = ph_a.open_qr(&info.qr).expect("open");
    assert_eq!(o.relay, RelayCheck::Saved);
    let sas = ph_a.join().expect("join");
    let wrong = if sas == "000000" { "111111" } else { "000000" };
    std::thread::scope(|s| {
        let j = s.spawn(|| ph_a.join_wait());
        assert_eq!(rejected(pc_a.submit(wrong)), RejectReason::SasRejected);
        assert_eq!(rejected(j.join().unwrap()), RejectReason::SasRejected);
    });
    assert_eq!(
        pc_a.status(),
        HostStatus::Failed {
            reason: RejectReason::SasRejected
        }
    );
    // Single use: the same QR again, from another device.
    ph_b.open_qr(&info.qr).expect("still parses");
    let r = rejected(ph_b.join());
    assert!(
        matches!(
            r,
            RejectReason::PairingSecretUsed | RejectReason::PairingSecretUnknown
        ),
        "{r:?}"
    );
    assert_eq!(pc_a.paired_with(&ph_a.id()), None);
    assert_eq!(ph_a.paired_with(&pc_a.id()), None);

    // Relay swap: the QR's relay replaced by another one the joiner has
    // saved. The transcript binds the relay, so the proof fails.
    let info = ph_b.show(Some(&pr.url()));
    let swapped = info.qr.replace(
        &format!("r={}", urlenc(&pr.url())),
        &format!("r={}", urlenc(&other.url())),
    );
    let swapped = swapped.replace(
        &format!("m={}", pr.server.device_id().to_hex()),
        &format!("m={}", other.server.device_id().to_hex()),
    );
    assert_ne!(swapped, info.qr);
    let o = pc_b.open_qr(&swapped).expect("opens");
    assert_eq!(o.relay_url, other.url());
    assert_eq!(rejected(pc_b.join()), RejectReason::PairingHmacBad);
    assert_eq!(ph_b.paired_with(&pc_b.id()), None);
    assert_eq!(pc_b.paired_with(&ph_b.id()), None);

    // Expiry: a code lives 5 minutes; one shown 4:59.5 ago is refused once
    // its time is up.
    assert_eq!(pair2::CODE_TTL_MS, 300_000);
    let old = pc_b.show_aged(&pr, pair2::CODE_TTL_MS - 500);
    std::thread::sleep(std::time::Duration::from_millis(800));
    assert_eq!(
        rejected(ph_a.open_qr(&old.qr)),
        RejectReason::PairingSecretExpired
    );
    let card_gone =
        |code: &str| !pair2::card_waiting_for_tests(code, &pr.url(), &pr.server.device_id());
    let old_code = old.code.clone().expect("code");
    assert!(matches!(
        pc_b.status(),
        HostStatus::Failed {
            reason: RejectReason::PairingSecretExpired
        }
    ));
    // Seeing the expiry deletes the card (no timer: the status read is the event).
    wait("card deleted on expiry", || card_gone(&old_code));
    pc_b.cancel();
    // Typing takes longer than scanning: a code shown 2:10 ago (past the M1
    // QR's 120 s) still opens.
    let mid = ph_b.show_aged(&pr, 130_000);
    let mid_code = mid.code.clone().expect("code");
    assert!(pair2::card_waiting_for_tests(
        &mid_code,
        &pr.url(),
        &pr.server.device_id()
    ));
    pc_a.open_code(&mid_code, Some(&pr.url()))
        .expect("a 2:10-old code still opens");
    pc_a.cancel();
    // "New code" replaces a live code: the old card goes, the new one waits.
    let first = ph_b.show(Some(&pr.url())).code.expect("code");
    let fresh_code = ph_b.show(Some(&pr.url())).code.expect("code");
    assert_ne!(fresh_code, first);
    wait("card deleted on replace", || card_gone(&first));
    assert!(pair2::card_waiting_for_tests(
        &fresh_code,
        &pr.url(),
        &pr.server.device_id()
    ));
    ph_b.cancel();
    wait("card deleted on cancel (peek)", || card_gone(&fresh_code));
    assert_eq!(pc_b.status(), HostStatus::Idle);

    // Hostile QR texts.
    let good = pc_a.show(Some(&pr.url())).qr;
    let hostile = [
        good.replace("v=2", "v=3"),
        good.replace("&m=", "&x=1&m="),
        format!("{good}&s=00000000000000000000000000000000"),
        good.replace(&urlenc(&pr.url()), "http%3A%2F%2Fevil.example"),
        good.replace("voidwire:pair?", "voidwire:pairs?"),
        format!("{good}&n=%07bell"),
        good.split("&m=").next().unwrap().to_owned(),
        format!("{good}&a={}", "1.2.3.4:5,".repeat(7)),
        format!("{good}{}", "&n=x".repeat(400)),
    ];
    for (i, h) in hostile.iter().enumerate() {
        let r = ph_b.open_qr(h);
        assert!(r.is_err(), "hostile QR {i} accepted");
    }
    assert_eq!(
        rejected(ph_b.open_qr(&hostile[0])),
        RejectReason::UnsupportedVersion
    );
    // Hostile codes.
    for c in [
        "",
        "VW-",
        "VW-ÄÄÄÄ",
        &"Z".repeat(300),
        "VW-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU",
    ] {
        assert_eq!(
            rejected(ph_b.open_code(c, Some(&pr.url()))),
            RejectReason::PairingCodeInvalid
        );
    }
    // The rendezvous card is single use: gone once the code is cancelled…
    let shown = pc_a.show(Some(&pr.url()));
    let code = shown.code.clone().expect("code");
    pc_a.cancel();
    wait("card deleted on cancel", || {
        matches!(
            pc_b.open_code(&code, Some(&pr.url())),
            Err(NetError::Rejected(RejectReason::PairingSecretUnknown))
        )
    });
    // …and once its code was used (here over the QR, so nobody fetched it).
    let shown = ph_a.show(Some(&pr.url()));
    let code = shown.code.clone().expect("code");
    ph_b.open_qr(&shown.qr).expect("open");
    let sas = ph_b.join().expect("join");
    std::thread::scope(|s| {
        let j = s.spawn(|| ph_b.join_wait());
        ph_a.submit(&sas).expect("submit");
        j.join().unwrap().expect("joined");
    });
    wait("card deleted on use", || {
        matches!(
            pc_b.open_code(&code, Some(&pr.url())),
            Err(NetError::Rejected(RejectReason::PairingSecretUnknown))
        )
    });

    // After all that, a fresh code still pairs.
    pair_flow(&pc_a, &ph_b, Via::Code, &pr);
}

#[test]
fn m43_m3_compatibility_pc_qr_stays_v1_and_v2_needs_an_update() {
    let root = temp_dir("m43-m3");
    let pc_a = pc("PC A", None, &root);
    let ph = phone("Phone", None, &root);
    let ph2 = phone("Phone 2", None, &root);
    let (pc_node, ph_node) = (pc_node(&pc_a), phone_node(&ph));
    // The PC's phone QR is still v=1, and the M3 path still pairs.
    let inv = pc_node.pair_start().expect("qr");
    assert!(
        inv.qr_uri.starts_with("voidwire:pair?v=1&"),
        "{}",
        inv.qr_uri
    );
    let s = ph_node.begin_pairing(&inv.qr_uri).expect("begin");
    pc_node.pair_submit_code(&s.sas()).expect("code");
    s.wait_welcome(std::time::Duration::from_secs(10))
        .expect("welcome");
    // A phone-shown QR is v=2: the M3 parser refuses it as an unsupported
    // version (the app says "Update Voidwire on this phone").
    let relay = RelayBox::start();
    ph2.save(&relay);
    let shown = phone_node(&ph2).pair2_show(Some(&relay.url())).unwrap();
    assert!(shown.qr.starts_with("voidwire:pair?v=2&"));
    assert_eq!(pair2::qr_version(&shown.qr).as_deref(), Some("2"));
    assert_eq!(
        rejected(ph_node.begin_pairing(&shown.qr).map(|_| ())),
        RejectReason::UnsupportedVersion
    );
}

fn urlenc(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

trait Aged {
    fn show_aged(&self, r: &RelayBox, age_ms: u64) -> ShowInfo;
}

impl Aged for Dev {
    fn show_aged(&self, r: &RelayBox, age_ms: u64) -> ShowInfo {
        match self {
            Dev::Pc { node, .. } => node.pair2_show_aged_for_tests(Some(&r.url()), age_ms),
            Dev::Phone { node, .. } => node.pair2_show_aged_for_tests(Some(&r.url()), age_ms),
        }
        .expect("show aged")
    }
}
