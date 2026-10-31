//! End-to-end tests of the inbound pipeline with the fake malicious peer
//! (TEST-PLAN H-5/H-6). Every negative case asserts the exact RejectReason,
//! zero opener calls, and that the next valid message still opens.

use std::collections::HashMap;
use voidwire_core::ids::{DeviceId, GroupId};
use voidwire_core::keys::DeviceKeypair;
use voidwire_core::limits::{MAX_URL_BYTES, TIMESTAMP_WINDOW_MS};
use voidwire_core::opener::{deliver, Delivery, OpenMode};
use voidwire_core::opener::{OpenApproval, PendingOpen};
use voidwire_core::ratelimit::RateLimit;
use voidwire_core::reject::RejectReason;
use voidwire_core::test_util::{
    keypair_from_label, link_inbox, receive_keypair_from_label, try_link_inbox, FakeClock,
    FakePeer, SpyOpener,
};
use voidwire_core::time::{Clock, UnixMillis};
use voidwire_core::verify::{Inbox, InboxConfig, InboxError, VerifiedUrl};
use voidwire_core::wire::RawBody;

static_assertions::assert_not_impl_any!(
    VerifiedUrl: Clone, Copy, Default, From<String>, From<&'static str>, From<url::Url>, std::str::FromStr
);
static_assertions::assert_not_impl_any!(
    OpenApproval: Clone, Copy, Default, From<String>, From<VerifiedUrl>, From<url::Url>, std::str::FromStr
);
static_assertions::assert_not_impl_any!(PendingOpen: Clone, Copy, Default, From<VerifiedUrl>);
static_assertions::assert_not_impl_any!(Inbox: Default, Clone);

fn policy(e: voidwire_core::opener::OpenError) -> RejectReason {
    match e {
        voidwire_core::opener::OpenError::Policy(r) => r,
        other => panic!("{other:?}"),
    }
}

const T0: u64 = 1_800_000_000_000;

/// A test model of the PC's receive path, routing by transport peer. It
/// copies the PC's routing, so these tests prove the verifier, opener and
/// tag rules; that the real PC answers `NotPaired` for a peer with no link is
/// proven against the real node (`e2e_v2.rs`, `src/net/link_verify_tests.rs`).
struct World {
    clock: FakeClock,
    pc: DeviceKeypair,
    cfg: InboxConfig,
    /// One verifier per pairing link, as on the PC.
    links: HashMap<DeviceId, Inbox>,
    next_pairing: u8,
    spy: SpyOpener,
    sends: u64,
}

impl World {
    fn new() -> Self {
        Self::with_config(InboxConfig::default())
    }

    fn with_config(cfg: InboxConfig) -> Self {
        World {
            clock: FakeClock::new(T0),
            pc: keypair_from_label("pc"),
            cfg,
            links: HashMap::new(),
            next_pairing: 0,
            spy: SpyOpener::default(),
            sends: 0,
        }
    }

    /// Pair a device (a new link with its own pairing id and receive key)
    /// and return a FakePeer holding its key.
    fn paired(&mut self, label: &str) -> FakePeer {
        let k = keypair_from_label(label);
        self.next_pairing += 1;
        let ib = link_inbox(
            self.pc.device_id(),
            k.device_id(),
            GroupId([self.next_pairing; 32]),
            self.cfg,
        );
        let fp = FakePeer::new(k, &ib);
        self.links.insert(fp.id(), ib);
        fp
    }

    /// "Forget this device" on the PC: the link and its verifier are gone.
    fn forget(&mut self, peer: &DeviceId) -> bool {
        self.links.remove(peer).is_some()
    }

    fn inbox(&self, peer: &DeviceId) -> &Inbox {
        &self.links[peer]
    }

    fn inbox_mut(&mut self, peer: &DeviceId) -> &mut Inbox {
        self.links.get_mut(peer).expect("paired")
    }

    /// The PC's receive path: route by transport peer; no link is `NotPaired`.
    fn recv(&mut self, peer: &DeviceId, frame: &[u8]) -> Result<VerifiedUrl, RejectReason> {
        let now = self.clock.now();
        match self.links.get_mut(peer) {
            Some(ib) => ib.receive(peer, frame, now),
            None => Err(RejectReason::NotPaired),
        }
    }

    /// The PC's open path (deliver now, or confirm a prompt later): it looks
    /// the sender's link up again, so a forgotten device finds none.
    fn open_via_link(
        &self,
        v: VerifiedUrl,
        mode: OpenMode,
    ) -> Result<Option<PendingOpen>, RejectReason> {
        let Some(ib) = self.links.get(&v.sender()) else {
            return Err(RejectReason::NotPaired);
        };
        match deliver(ib, v, mode, &self.spy).map_err(policy)? {
            Delivery::Opened => Ok(None),
            Delivery::NeedsConfirmation(p) => Ok(Some(p)),
        }
    }

    fn confirm_via_link(&self, p: PendingOpen) -> Result<(), RejectReason> {
        let Some(ib) = self.links.get(&p.sender()) else {
            return Err(RejectReason::NotPaired);
        };
        p.confirm(ib, &self.spy).map_err(policy)
    }

    fn send(&mut self, peer: &DeviceId, frame: &[u8]) -> Result<(), RejectReason> {
        let v = self.recv(peer, frame)?;
        // Alternate the two minting paths: no-prompt (`deliver` in
        // OpenImmediately) and the user's click (`PendingOpen::confirm`).
        self.sends += 1;
        let mode = if self.sends.is_multiple_of(2) {
            OpenMode::OpenImmediately
        } else {
            OpenMode::ConfirmBeforeOpen
        };
        match self.open_via_link(v, mode)? {
            None => {
                assert_eq!(mode, OpenMode::OpenImmediately);
                Ok(())
            }
            Some(p) => {
                assert_eq!(mode, OpenMode::ConfirmBeforeOpen);
                self.confirm_via_link(p)
            }
        }
    }

    fn now_wall(&self) -> UnixMillis {
        self.clock.now().wall
    }

    /// Standard NO-OPEN assertion (TEST-PLAN §0.1).
    fn assert_rejected(
        &mut self,
        peer: &DeviceId,
        frame: &[u8],
        want: RejectReason,
        honest: &FakePeer,
    ) {
        let before = self.spy.count();
        assert_eq!(self.send(peer, frame), Err(want));
        assert_eq!(
            self.spy.count(),
            before,
            "opener must not be called for {want:?}"
        );
        // No lockout: the next valid message from a paired device still opens.
        self.clock.advance(60_000);
        let ok = honest.frame("https://example.com/after-reject", self.now_wall());
        assert_eq!(
            self.send(&honest.id(), &ok),
            Ok(()),
            "valid message after {want:?}"
        );
    }
}

#[test]
fn valid_path_opens_exact_canonical_string_once() {
    let mut w = World::new();
    let phone = w.paired("phone");
    let f = phone.frame("HTTPS://Example.COM/a b?q=|x", w.now_wall());
    // Raw space is refused, so use an encodable variant for the happy path.
    assert_eq!(w.send(&phone.id(), &f), Err(RejectReason::UrlBadChars));
    let f = phone.frame("HTTPS://Example.COM/a?q=|x", w.now_wall());
    assert_eq!(w.send(&phone.id(), &f), Ok(()));
    assert_eq!(
        w.spy.calls(),
        vec!["https://example.com/a?q=%7Cx".to_string()]
    );
    assert_eq!(w.inbox(&phone.id()).counters().accepted, 1);
}

/// No-prompt is the default. A fresh default-mode
/// delivery opens at once, and the only way there is `deliver` with a
/// `VerifiedUrl`, i.e. after full verification: a message that fails any
/// check never yields one, so the opener is never reached.
#[test]
fn default_mode_opens_without_prompt_via_deliver() {
    assert_eq!(OpenMode::default(), OpenMode::OpenImmediately);
    let mut w = World::new();
    let phone = w.paired("phone");
    let v = w
        .recv(
            &phone.id(),
            &phone.frame("https://example.com/", w.now_wall()),
        )
        .unwrap();
    assert!(
        !format!("{v:?}").contains("example.com"),
        "Debug must redact"
    );
    let d = deliver(w.inbox(&phone.id()), v, OpenMode::default(), &w.spy).unwrap();
    assert!(matches!(d, Delivery::Opened), "{d:?}");
    assert_eq!(w.spy.calls(), vec!["https://example.com/".to_string()]);

    // Unverified input never becomes an approval in the default mode:
    // an unpaired sender and a tampered envelope stop at `receive`.
    let stranger = FakePeer::new(keypair_from_label("stranger"), w.inbox(&phone.id()));
    w.clock.advance(1_000);
    assert_eq!(
        w.recv(
            &stranger.id(),
            &stranger.frame("https://example.com/s", w.now_wall())
        )
        .map(|_| ()),
        Err(RejectReason::NotPaired)
    );
    let f = phone.frame("https://example.com/t", w.now_wall());
    let bad = FakePeer::bit_flip(&f, 8 * (f.len() - 1));
    assert!(w.recv(&phone.id(), &bad).is_err());
    assert_eq!(w.spy.count(), 1);
}

/// "Ask before opening" (ConfirmBeforeOpen) still works: nothing opens until
/// the user confirms, a declined prompt never opens, and confirm opens once.
#[test]
fn ask_before_opening_mode_waits_for_confirm() {
    let mut w = World::new();
    let phone = w.paired("phone");
    let next = |w: &mut World, path: &str| {
        w.clock.advance(1_000);
        let f = phone.frame(&format!("https://example.com/{path}"), w.now_wall());
        w.recv(&phone.id(), &f).unwrap()
    };
    let v = next(&mut w, "a");
    let Ok(Delivery::NeedsConfirmation(p)) =
        deliver(w.inbox(&phone.id()), v, OpenMode::ConfirmBeforeOpen, &w.spy)
    else {
        panic!("ask mode must prompt")
    };
    assert_eq!(p.host_for_display(), "example.com");
    assert_eq!(w.spy.count(), 0, "nothing opens before the click");
    p.confirm(w.inbox(&phone.id()), &w.spy).unwrap();
    assert_eq!(w.spy.calls(), vec!["https://example.com/a".to_string()]);

    // Declined (dropped) prompt: never opens.
    let v = next(&mut w, "b");
    let d = deliver(w.inbox(&phone.id()), v, OpenMode::ConfirmBeforeOpen, &w.spy).unwrap();
    assert!(matches!(d, Delivery::NeedsConfirmation(_)));
    drop(d);
    assert_eq!(w.spy.count(), 1);
}

/// The open re-looks the sender's link up in both modes: a device forgotten
/// between verification and the open has no link, so nothing opens
/// (`NotPaired`, the PC's "no longer paired"). A prompt that outlives the
/// forget can't be confirmed through the device's next link either
/// (`ForeignInbox`): it belongs to the old verifier.
#[test]
fn forgotten_between_verify_and_open_is_refused_in_both_modes() {
    for mode in [OpenMode::OpenImmediately, OpenMode::ConfirmBeforeOpen] {
        let mut w = World::new();
        let p = w.paired("phone");
        let v = w
            .recv(&p.id(), &p.frame("https://example.com/r", w.now_wall()))
            .unwrap();
        assert!(w.forget(&p.id()));
        assert_eq!(
            w.open_via_link(v, mode).map(|_| ()),
            Err(RejectReason::NotPaired),
            "{mode:?}"
        );
        assert_eq!(w.spy.count(), 0, "{mode:?}");
    }
    // Ask mode, forgotten while the prompt is up: the click is refused.
    let mut w = World::new();
    let p = w.paired("phone");
    let v = w
        .recv(&p.id(), &p.frame("https://example.com/r2", w.now_wall()))
        .unwrap();
    let pending = w
        .open_via_link(v, OpenMode::ConfirmBeforeOpen)
        .unwrap()
        .expect("ask mode prompts");
    assert!(w.forget(&p.id()));
    let v2 = w
        .recv(&p.id(), &p.frame("https://example.com/r3", w.now_wall()))
        .unwrap_err();
    assert_eq!(v2, RejectReason::NotPaired);
    // Paired again before the click: the old prompt is not the new link's.
    let p = w.paired("phone");
    let new = w.inbox(&p.id());
    assert!(matches!(
        pending.confirm(new, &w.spy),
        Err(voidwire_core::opener::OpenError::Policy(
            RejectReason::ForeignInbox
        ))
    ));
    assert_eq!(w.spy.count(), 0);
}

#[test]
fn unpaired_sender_rejected_before_parsing() {
    let mut w = World::new();
    let honest = w.paired("phone");
    let stranger = FakePeer::new(DeviceKeypair::generate(), w.inbox(&honest.id()));
    let f = stranger.frame("https://example.com/", w.now_wall());
    w.assert_rejected(&stranger.id(), &f, RejectReason::NotPaired, &honest);
    // Garbage from a stranger is also NotPaired (never reaches the parser).
    w.assert_rejected(
        &stranger.id(),
        b"\xff\x00garbage",
        RejectReason::NotPaired,
        &honest,
    );
}

#[test]
fn attacker_own_valid_signature_is_not_authentication() {
    // AUTH-06 below transport: well-formed, correctly signed, sealed to us.
    let mut w = World::new();
    let honest = w.paired("phone");
    let attacker = FakePeer::new(keypair_from_label("attacker"), w.inbox(&honest.id()));
    let f = attacker.frame("https://evil.example/", w.now_wall());
    w.assert_rejected(&attacker.id(), &f, RejectReason::NotPaired, &honest);
}

#[test]
fn sender_must_match_transport_peer() {
    let mut w = World::new();
    let a = w.paired("a");
    let b = w.paired("b");
    // B's valid message delivered over A's connection (AUTH-11): it is
    // sealed to B's link, so A's link can't even decrypt it.
    let f = b.frame("https://example.com/", w.now_wall());
    w.assert_rejected(&a.id(), &f, RejectReason::DecryptFailed, &a);
    // Sealed to A's link but signed by B: the sender check refuses it.
    let b_over_a = FakePeer::new(keypair_from_label("b"), w.inbox(&a.id()));
    let f = b_over_a.frame("https://example.com/", w.now_wall());
    w.assert_rejected(&a.id(), &f, RejectReason::SenderMismatch, &a);
    // A claims to be B, signs with A's key, seals to B's link and delivers
    // over B's connection (AUTH-05).
    let a_to_b = FakePeer::new(keypair_from_label("a"), w.inbox(&b.id()));
    let forged = a_to_b.forged("https://example.com/", w.now_wall(), |body| {
        body.sender = *b.id().as_bytes()
    });
    w.assert_rejected(&b.id(), &forged, RejectReason::BadSignature, &a);
}

#[test]
fn bad_signatures_rejected() {
    let mut w = World::new();
    let p = w.paired("phone");
    let body = p.body("https://example.com/", w.now_wall());
    for sig in [[0u8; 64], [0xff; 64]] {
        let f = p.seal_raw(&body.with_signature(&sig));
        w.assert_rejected(&p.id(), &f, RejectReason::BadSignature, &p);
    }
    let mut signed = body.sign_with(&p.key);
    let n = signed.len();
    signed[n - 1] ^= 0x01;
    w.assert_rejected(
        &p.id(),
        &p.seal_raw(&signed),
        RejectReason::BadSignature,
        &p,
    );
    // Signed by a different (valid) key.
    let other = DeviceKeypair::generate();
    let f = p.seal_raw(&body.sign_with(&other));
    w.assert_rejected(&p.id(), &f, RejectReason::BadSignature, &p);
}

#[test]
fn weak_sender_key_rejected() {
    let mut w = World::new();
    let p = w.paired("phone");
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let f = p.forged("https://example.com/", w.now_wall(), |b| {
        b.sender = identity
    });
    w.assert_rejected(&p.id(), &f, RejectReason::BadSignature, &p);
}

#[test]
fn signature_covers_every_field() {
    // AUTH-09: mutate each field after signing.
    let mut w = World::new();
    let p = w.paired("phone");
    type Mutate = fn(&mut RawBody);
    let cases: [(&str, Mutate); 4] = [
        ("msg_id", |b| b.msg_id[0] ^= 1),
        ("timestamp", |b| b.timestamp ^= 1),
        ("url", |b| b.url[8] ^= 1),
        ("recipient-same-len-url", |b| {
            let l = b.url.len();
            b.url[l - 1] = b'Z';
        }),
    ];
    for (name, m) in cases {
        let honest = p.body("https://example.com/x", w.now_wall());
        let signed = honest.sign_with(&p.key);
        let mut mutated = honest.clone();
        m(&mut mutated);
        let sig: [u8; 64] = signed[signed.len() - 64..].try_into().unwrap();
        let f = p.seal_raw(&mutated.with_signature(&sig));
        let before = w.spy.count();
        assert_eq!(
            w.send(&p.id(), &f),
            Err(RejectReason::BadSignature),
            "{name}"
        );
        assert_eq!(w.spy.count(), before);
        w.clock.advance(60_000);
    }
    // group / recipient mutations are caught by addressing first.
    let f = p.forged("https://example.com/", w.now_wall(), |b| b.group = [9; 32]);
    w.assert_rejected(&p.id(), &f, RejectReason::WrongGroup, &p);
    let other = DeviceKeypair::generate().device_id();
    let f = p.forged("https://example.com/", w.now_wall(), |b| {
        b.recipient = *other.as_bytes()
    });
    w.assert_rejected(&p.id(), &f, RejectReason::WrongRecipient, &p);
}

#[test]
fn replay_rejected_and_survives_clock_jump() {
    let mut w = World::new();
    let p = w.paired("phone");
    let f = p.frame("https://example.com/once", w.now_wall());
    assert_eq!(w.send(&p.id(), &f), Ok(()));
    w.clock.advance(1_000);
    w.assert_rejected(&p.id(), &f, RejectReason::Replay, &p);
    // Wall clock jumps back 30 min (CLK-03): still a replay, not a fresh open.
    w.clock.set_wall(T0 - 30 * 60_000);
    let before = w.spy.count();
    let r = w.send(&p.id(), &f);
    assert!(
        r == Err(RejectReason::Replay) || r == Err(RejectReason::FutureTimestamp),
        "{r:?}"
    );
    assert_eq!(w.spy.count(), before);
}

#[test]
fn replay_after_window_is_stale() {
    let mut w = World::new();
    let p = w.paired("phone");
    let f = p.frame("https://example.com/", w.now_wall());
    assert_eq!(w.send(&p.id(), &f), Ok(()));
    w.clock.advance(TIMESTAMP_WINDOW_MS + 1);
    w.assert_rejected(&p.id(), &f, RejectReason::StaleTimestamp, &p);
}

#[test]
fn timestamp_boundaries_env_04() {
    let mut w = World::new();
    let p = w.paired("phone");
    let now = w.now_wall().0;
    for (ts, want) in [
        (now - TIMESTAMP_WINDOW_MS, Ok(())),
        (now + TIMESTAMP_WINDOW_MS, Ok(())),
        (
            now - TIMESTAMP_WINDOW_MS - 1,
            Err(RejectReason::StaleTimestamp),
        ),
        (
            now + TIMESTAMP_WINDOW_MS + 1,
            Err(RejectReason::FutureTimestamp),
        ),
        (0, Err(RejectReason::StaleTimestamp)),
        (u64::MAX, Err(RejectReason::FutureTimestamp)),
    ] {
        let mut wi = World::new();
        let p2 = wi.paired("phone");
        let f = p2.frame("https://example.com/", UnixMillis(ts));
        assert_eq!(
            wi.send(&p2.id(), &f),
            want,
            "ts offset {}",
            ts as i128 - now as i128
        );
    }
    let _ = p;
}

#[test]
fn per_device_rate_limit_burst_and_recovery() {
    let mut w = World::new();
    let p = w.paired("phone");
    for i in 0..5 {
        assert_eq!(
            w.send(
                &p.id(),
                &p.frame(&format!("https://example.com/{i}"), w.now_wall())
            ),
            Ok(())
        );
    }
    assert_eq!(
        w.send(&p.id(), &p.frame("https://example.com/6", w.now_wall())),
        Err(RejectReason::RateLimitedDevice)
    );
    assert_eq!(w.spy.count(), 5);
    assert_eq!(
        w.inbox(&p.id())
            .counters()
            .rejected_for(&RejectReason::RateLimitedDevice),
        1
    );
    // 10/min refill: one token after 6 s.
    w.clock.advance(5_999);
    assert_eq!(
        w.send(&p.id(), &p.frame("https://example.com/7", w.now_wall())),
        Err(RejectReason::RateLimitedDevice)
    );
    w.clock.advance(6_001);
    assert_eq!(
        w.send(&p.id(), &p.frame("https://example.com/8", w.now_wall())),
        Ok(())
    );
}

#[test]
fn invalid_authenticated_messages_count_against_device_limit() {
    // RL-06: a compromised device can't spin forever with bad-scheme messages.
    let mut w = World::new();
    let p = w.paired("phone");
    for _ in 0..5 {
        let f = p.frame("javascript:alert(1)", w.now_wall());
        assert!(matches!(
            w.send(&p.id(), &f),
            Err(RejectReason::SchemeNotAllowed)
        ));
    }
    let f = p.frame("javascript:alert(1)", w.now_wall());
    assert_eq!(w.send(&p.id(), &f), Err(RejectReason::RateLimitedDevice));
    assert_eq!(w.spy.count(), 0);
}

/// Every link has its own verifier, so its budgets are its own: one device
/// flooding at any rate never costs another anything, and a link accepts
/// exactly its per-device burst (5 by default; there is no separate global
/// budget, L7).
#[test]
fn rate_limits_are_per_link() {
    let mut w = World::with_config(InboxConfig::default());
    let peers: Vec<FakePeer> = (0..3).map(|i| w.paired(&format!("dev{i}"))).collect();
    for i in 0..50 {
        let _ = w.send(
            &peers[0].id(),
            &peers[0].frame(&format!("https://a.example/{i}"), w.now_wall()),
        );
    }
    assert_eq!(w.spy.count(), 5, "a link accepts exactly its burst");
    for p in &peers[1..] {
        for i in 0..5 {
            assert_eq!(
                w.send(
                    &p.id(),
                    &p.frame(&format!("https://b.example/{i}"), w.now_wall())
                ),
                Ok(()),
                "another link's flood cost this one"
            );
        }
        assert_eq!(
            w.send(&p.id(), &p.frame("https://b.example/x", w.now_wall())),
            Err(RejectReason::RateLimitedDevice)
        );
    }
    assert_eq!(w.spy.count(), 15);
}

#[test]
fn default_limits_match_decision() {
    let c = InboxConfig::default();
    assert_eq!(c.per_device.burst, 5);
    assert_eq!(c.per_device.per_minute, 10);
}

#[test]
fn non_http_schemes_rejected() {
    let mut w = World::new();
    let p = w.paired("phone");
    for (i, u) in [
        "javascript:alert(1)",
        "file:///C:/Windows/System32/calc.exe",
        "data:text/html,<b>x</b>",
        "intent://scan/#Intent;scheme=zxing;end",
        "ms-msdt:/id",
        "vbscript:x",
        "ftp://x/",
    ]
    .iter()
    .enumerate()
    {
        if i % 4 == 0 {
            w.clock.advance(60_000);
        }
        let r = w.send(&p.id(), &p.frame(u, w.now_wall()));
        assert!(
            matches!(r, Err(RejectReason::SchemeNotAllowed)),
            "{u}: {r:?}"
        );
    }
    assert_eq!(w.spy.count(), 0);
}

#[test]
fn local_only_hosts_rejected_private_allowed_oq8() {
    let mut w = World::new();
    let p = w.paired("phone");
    for (u, want) in [
        ("http://2130706433/", RejectReason::HostLoopback),
        ("http://0x7f.1/", RejectReason::HostLoopback),
        ("http://localhost:8080/admin", RejectReason::HostLoopback),
        ("http://[::ffff:127.0.0.1]/", RejectReason::HostLoopback),
        (
            "http://169.254.169.254/latest/meta-data/",
            RejectReason::HostLinkLocal,
        ),
        ("http://[fe80::1]/", RejectReason::HostLinkLocal),
        ("http://0.0.0.0:3000/", RejectReason::HostUnspecified),
        ("http://[::]/", RejectReason::HostUnspecified),
    ] {
        w.clock.advance(60_000);
        let before = w.spy.count();
        assert_eq!(w.send(&p.id(), &p.frame(u, w.now_wall())), Err(want), "{u}");
        assert_eq!(w.spy.count(), before);
        assert!(w.inbox(&p.id()).counters().rejected_for(&want) > 0);
    }
    w.clock.advance(60_000);
    assert_eq!(
        w.send(&p.id(), &p.frame("http://192.168.1.20:8123/", w.now_wall())),
        Ok(())
    );
    assert_eq!(
        w.send(&p.id(), &p.frame("http://[fd00::20]/", w.now_wall())),
        Ok(())
    );
    assert_eq!(
        w.spy.calls(),
        vec![
            "http://192.168.1.20:8123/".to_string(),
            "http://[fd00::20]/".to_string()
        ]
    );
}

#[test]
fn oversize_url_rejected() {
    let mut w = World::new();
    let p = w.paired("phone");
    let base = "https://example.com/";
    let at_cap = format!("{base}{}", "a".repeat(MAX_URL_BYTES - base.len()));
    assert_eq!(w.send(&p.id(), &p.frame(&at_cap, w.now_wall())), Ok(()));
    let over = format!("{at_cap}a");
    w.assert_rejected(
        &p.id(),
        &p.frame(&over, w.now_wall()),
        RejectReason::UrlTooLong,
        &p,
    );
    // An envelope larger than the top padding bucket is refused unparsed.
    w.assert_rejected(&p.id(), &vec![0u8; 9000], RejectReason::MalformedFrame, &p);
}

#[test]
fn forgotten_device_rejected() {
    let mut w = World::new();
    let a = w.paired("a");
    let b = w.paired("b");
    // Forget a: immediate, local; its link is gone.
    assert!(w.forget(&a.id()));
    let f = a.frame("https://example.com/", w.now_wall());
    w.assert_rejected(&a.id(), &f, RejectReason::NotPaired, &b);
}

#[test]
fn bit_flips_never_open_and_never_panic() {
    let mut w = World::with_config(InboxConfig {
        per_device: RateLimit {
            burst: voidwire_core::limits::RATE_BURST_MAX,
            per_minute: 1,
        },
        ..InboxConfig::default()
    });
    let p = w.paired("phone");
    let f = p.frame("https://example.com/bitflip", w.now_wall());
    // Every bit of the body region plus a sample of the padding.
    let body_bits = (4 + 222 + 28) * 8;
    for bit in (0..body_bits).chain((body_bits..f.len() * 8).step_by(97)) {
        let flipped = FakePeer::bit_flip(&f, bit);
        let r = w.recv(&p.id(), &flipped);
        assert!(r.is_err(), "bit {bit} produced a VerifiedUrl");
    }
    assert_eq!(w.spy.count(), 0);
}

#[test]
fn truncation_and_extension_rejected() {
    let mut w = World::new();
    let p = w.paired("phone");
    let f = p.frame("https://example.com/", w.now_wall());
    for cut in [0, 1, 3, 4, 100, f.len() - 1] {
        assert_eq!(
            w.recv(&p.id(), &f[..cut]).unwrap_err(),
            RejectReason::MalformedFrame
        );
    }
    let mut ext = f.clone();
    ext.push(0);
    assert_eq!(
        w.recv(&p.id(), &ext).unwrap_err(),
        RejectReason::MalformedFrame
    );
    let mut big = f.clone();
    big.resize(1 << 20, 0);
    assert_eq!(
        w.recv(&p.id(), &big).unwrap_err(),
        RejectReason::MalformedFrame
    );
    assert_eq!(w.spy.count(), 0);
}

#[test]
fn replay_cache_full_fails_closed() {
    let mut w = World::with_config(InboxConfig {
        replay_cache_max_entries: 2,
        ..InboxConfig::default()
    });
    let p = w.paired("phone");
    assert_eq!(
        w.send(&p.id(), &p.frame("https://example.com/1", w.now_wall())),
        Ok(())
    );
    assert_eq!(
        w.send(&p.id(), &p.frame("https://example.com/2", w.now_wall())),
        Ok(())
    );
    assert_eq!(
        w.send(&p.id(), &p.frame("https://example.com/3", w.now_wall())),
        Err(RejectReason::CacheFull)
    );
}

#[test]
fn deterministic_keys_and_rng() {
    assert_eq!(
        keypair_from_label("x").device_id(),
        keypair_from_label("x").device_id()
    );
    let a = DeviceKeypair::generate_with(&mut voidwire_core::test_util::seeded_rng(7)).device_id();
    let b = DeviceKeypair::generate_with(&mut voidwire_core::test_util::seeded_rng(7)).device_id();
    assert_eq!(a, b);
}

/// AUTH-17 (QA probe p01, runtime half): a VerifiedUrl minted by a link
/// verifier the attacker built for *their own* key cannot be delivered or
/// confirmed through the app's link. (The compile-time half, calling
/// `UrlOpener::open` with a bare VerifiedUrl, is a compile_fail doctest in lib.rs.)
#[test]
fn verified_url_from_foreign_inbox_cannot_open_auth_17() {
    let mut app = World::new();
    let phone = app.paired("phone");
    let ours = app.inbox(&phone.id());

    // Attacker: own link verifier, even with our self id and pairing id.
    let clock = FakeClock::new(T0);
    let att = keypair_from_label("attacker");
    let me = keypair_from_label("pc");
    let mut evil = link_inbox(
        me.device_id(),
        att.device_id(),
        GroupId([1; 32]),
        InboxConfig::default(),
    );
    let peer = FakePeer::new(att, &evil);
    let v = evil
        .receive(
            &peer.id(),
            &peer.frame("https://evil.example/x", clock.now().wall),
            clock.now(),
        )
        .expect("verifies against the attacker's link");

    for mode in [OpenMode::OpenImmediately, OpenMode::ConfirmBeforeOpen] {
        let v = evil
            .receive(
                &peer.id(),
                &peer.frame("https://evil.example/y", clock.now().wall),
                clock.now(),
            )
            .unwrap();
        let r = deliver(ours, v, mode, &app.spy);
        assert!(
            matches!(
                r,
                Err(voidwire_core::opener::OpenError::Policy(
                    RejectReason::ForeignInbox
                ))
            ),
            "{mode:?}: {r:?}"
        );
    }
    // A pending prompt from the attacker's link can't be confirmed via ours either.
    let Ok(Delivery::NeedsConfirmation(p)) =
        deliver(&evil, v, OpenMode::ConfirmBeforeOpen, &app.spy)
    else {
        panic!()
    };
    assert!(p.confirm(ours, &app.spy).is_err());
    assert_eq!(app.spy.count(), 0);
}

/// The PC's "Ask before opening" click after Forget: the link is gone, so the
/// click finds none and nothing opens (`NotPaired`, "no longer paired").
#[test]
fn pending_open_from_sender_forgotten_before_click_is_refused() {
    let mut w = World::new();
    let p = w.paired("phone");
    let v = w
        .recv(&p.id(), &p.frame("https://example.com/", w.now_wall()))
        .unwrap();
    let pending = w
        .open_via_link(v, OpenMode::ConfirmBeforeOpen)
        .unwrap()
        .expect("ask mode prompts");
    assert!(w.forget(&p.id()));
    assert_eq!(w.confirm_via_link(pending), Err(RejectReason::NotPaired));
    assert_eq!(w.spy.count(), 0);
}

/// D5 / FC-04: out-of-range config is rejected, never silently accepted.
#[test]
fn inbox_config_floors_and_ceilings_d5() {
    use voidwire_core::limits::*;
    let mk = |cfg: InboxConfig| {
        let pc = keypair_from_label("pc");
        let phone = keypair_from_label("phone");
        try_link_inbox(pc.device_id(), phone.device_id(), GroupId([1; 32]), cfg).map(|_| ())
    };
    let d = InboxConfig::default();
    assert!(mk(d).is_ok());
    let rl = |burst, per_minute| RateLimit { burst, per_minute };
    let bad: Vec<(InboxConfig, &str)> = vec![
        (
            InboxConfig {
                per_device: rl(0, 10),
                ..d
            },
            "per_device.burst",
        ),
        (
            InboxConfig {
                per_device: rl(u32::MAX, 10),
                ..d
            },
            "per_device.burst",
        ),
        (
            InboxConfig {
                per_device: rl(RATE_BURST_MAX + 1, 10),
                ..d
            },
            "per_device.burst",
        ),
        (
            InboxConfig {
                per_device: rl(5, 0),
                ..d
            },
            "per_device.per_minute",
        ),
        (
            InboxConfig {
                per_device: rl(5, u32::MAX),
                ..d
            },
            "per_device.per_minute",
        ),
        (
            InboxConfig {
                timestamp_window_ms: 0,
                ..d
            },
            "timestamp_window_ms",
        ),
        (
            InboxConfig {
                timestamp_window_ms: TIMESTAMP_WINDOW_MIN_MS - 1,
                ..d
            },
            "timestamp_window_ms",
        ),
        (
            InboxConfig {
                timestamp_window_ms: TIMESTAMP_WINDOW_MS + 1,
                ..d
            },
            "timestamp_window_ms",
        ),
        (
            InboxConfig {
                timestamp_window_ms: u64::MAX,
                ..d
            },
            "timestamp_window_ms",
        ),
        (
            InboxConfig {
                replay_cache_max_entries: 0,
                ..d
            },
            "replay_cache_max_entries",
        ),
        (
            InboxConfig {
                replay_cache_max_entries: usize::MAX,
                ..d
            },
            "replay_cache_max_entries",
        ),
    ];
    for (cfg, field) in bad {
        match mk(cfg) {
            Err(InboxError::Config(e)) => assert_eq!(e.field, field, "{cfg:?}"),
            other => panic!("{cfg:?}: {other:?}"),
        }
    }
    // Boundaries themselves are accepted.
    for cfg in [
        InboxConfig {
            per_device: rl(RATE_BURST_MIN, RATE_PER_MINUTE_MIN),
            ..d
        },
        InboxConfig {
            per_device: rl(RATE_BURST_MAX, RATE_PER_MINUTE_MAX),
            ..d
        },
        InboxConfig {
            timestamp_window_ms: TIMESTAMP_WINDOW_MIN_MS,
            ..d
        },
        InboxConfig {
            timestamp_window_ms: TIMESTAMP_WINDOW_MAX_MS,
            ..d
        },
        InboxConfig {
            replay_cache_max_entries: REPLAY_CACHE_MAX_ENTRIES_CEILING,
            ..d
        },
    ] {
        assert!(mk(cfg).is_ok(), "{cfg:?}");
    }
}

/// R2: the no-prompt branch (`deliver` in `OpenImmediately`, the default
/// since 10-11-2026) opens exactly once, with no prompt, and still re-checks
/// the inbox tag and the sender's membership right before opening.
#[test]
fn no_prompt_branch_opens_once_and_rechecks_r2() {
    use voidwire_core::envelope::ENCRYPTION_IMPLEMENTED;
    const { assert!(ENCRYPTION_IMPLEMENTED) };
    assert_eq!(OpenMode::default(), OpenMode::OpenImmediately);
    let mut w = World::new();
    let p = w.paired("phone");
    let v = w
        .recv(&p.id(), &p.frame("https://example.com/a", w.now_wall()))
        .unwrap();
    let d = deliver(w.inbox(&p.id()), v, OpenMode::OpenImmediately, &w.spy).unwrap();
    assert!(matches!(d, Delivery::Opened), "{d:?}");
    assert_eq!(w.spy.calls(), vec!["https://example.com/a".to_string()]);

    // Forgotten between receive and deliver: no-prompt mode refuses too.
    let v = w
        .recv(&p.id(), &p.frame("https://example.com/b", w.now_wall()))
        .unwrap();
    assert!(w.forget(&p.id()));
    assert_eq!(
        w.open_via_link(v, OpenMode::OpenImmediately).map(|_| ()),
        Err(RejectReason::NotPaired)
    );
    assert_eq!(w.spy.count(), 1);
}

/// R2 + D2: a VerifiedUrl from another inbox is refused on the no-prompt path.
#[test]
fn no_prompt_branch_refuses_foreign_inbox_r2() {
    let mut a = World::new();
    let mut b = World::new();
    let pa = a.paired("phone");
    let pb = b.paired("phone");
    let v = a
        .recv(&pa.id(), &pa.frame("https://example.com/", a.now_wall()))
        .unwrap();
    assert!(matches!(
        deliver(b.inbox(&pb.id()), v, OpenMode::OpenImmediately, &b.spy),
        Err(voidwire_core::opener::OpenError::Policy(
            RejectReason::ForeignInbox
        ))
    ));
    assert_eq!(b.spy.count(), 0);
}

/// Envelope crypto through the full pipeline: sealed to another device's key,
/// tampered ciphertext, wrong padding bucket.
#[test]
fn envelope_wrong_recipient_tamper_and_padding_rejected() {
    let mut w = World::new();
    let mut p = w.paired("phone");
    // Sealed to some other device's receive key.
    let honest_key = p.seal_to;
    p.seal_to = receive_keypair_from_label("someone-else").public();
    let f = p.frame("https://example.com/", w.now_wall());
    p.seal_to = honest_key;
    w.assert_rejected(&p.id(), &f, RejectReason::DecryptFailed, &p);
    // Tampered ciphertext / enc.
    let good = p.frame("https://example.com/", w.now_wall());
    for i in [4usize, 40, good.len() - 1] {
        let mut t = good.clone();
        t[i] ^= 0x80;
        w.assert_rejected(&p.id(), &t, RejectReason::DecryptFailed, &p);
    }
    // Not a bucket size.
    let mut longer = good.clone();
    longer.push(0);
    w.assert_rejected(&p.id(), &longer, RejectReason::MalformedFrame, &p);
}

/// D13: an active member flooding garbage is cut off by the per-peer budget
/// before any decryption; other devices are unaffected.
#[test]
fn pre_decrypt_budget_d13() {
    let mut w = World::new();
    let p = w.paired("phone");
    let q = w.paired("tablet");
    let garbage = vec![0u8; 600];
    let burst = InboxConfig::default().pre_decrypt.burst;
    for _ in 0..burst {
        assert_eq!(
            w.recv(&p.id(), &garbage).unwrap_err(),
            RejectReason::MalformedFrame
        );
    }
    assert_eq!(
        w.recv(&p.id(), &garbage).unwrap_err(),
        RejectReason::RateLimitedPeer
    );
    let f = q.frame("https://example.com/", w.now_wall());
    assert_eq!(w.send(&q.id(), &f), Ok(()));
}

/// M26-R1: `Inbox::verify_file_offer` replay protection (`Replay`) and
/// active `.part` resume.
#[test]
fn verify_file_offer_replay_m26_r1() {
    use voidwire_core::file_transfer::{
        compute_file_hashes, seal_file_offer, FileOffer, TransferId,
    };

    let mut w = World::new();
    let p = w.paired("phone");

    let payload = b"hello voidwire m26-r1";
    let (root, chunk_hashes) = compute_file_hashes(payload);
    let now = w.clock.now();
    let exp = UnixMillis(now.wall.0 + 3_600_000);

    let make_env = |tid_byte: u8| -> Vec<u8> {
        let offer = FileOffer::new(
            p.group,
            p.id(),
            w.pc.device_id(),
            TransferId([tid_byte; 16]),
            "notes.txt",
            "text/plain",
            payload.len() as u64,
            root,
            chunk_hashes.clone(),
            now.wall,
            exp,
        )
        .unwrap();
        let (env, _k) = seal_file_offer(&offer, &p.key, &p.seal_to).unwrap();
        env
    };

    // Accepted, and recorded in ReplayCache.
    let env_ok = make_env(0x03);
    w.inbox_mut(&p.id())
        .verify_file_offer(&p.id(), &env_ok, |_| false, now)
        .expect("a fresh offer passes verify_file_offer");

    // 4. Replaying the same transfer_id when not an active resume -> Replay.
    assert_eq!(
        w.inbox_mut(&p.id())
            .verify_file_offer(&p.id(), &env_ok, |_| false, now)
            .unwrap_err(),
        RejectReason::Replay
    );

    // 5. Legitimate resume of an active in-progress transfer (`is_active_resume = true`) -> Ok.
    assert!(w
        .inbox_mut(&p.id())
        .verify_file_offer(&p.id(), &env_ok, |_| true, now)
        .is_ok());
}
