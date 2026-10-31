//! Security properties of verifying a v2 link's messages, written against
//! behaviour only so they survive the roster removal (M4-ROSTER-REMOVAL §5).
//! `link_inbox` is the one place that knows how a link's verifier is built.

use super::links::PairLink;
use crate::ids::{DeviceId, GroupId, MsgId};
use crate::keys::{DeviceCert, DeviceKeypair, Platform};
use crate::opener::{deliver, OpenApproval, OpenError, OpenMode, UrlOpener};
use crate::reject::RejectReason;
use crate::replay::NoPersistence;
use crate::time::{MonoMillis, Now, UnixMillis};
use crate::verify::{Inbox, InboxConfig, VerifiedMessage};
use crate::wire::{RawBody, MAGIC};

const T0: u64 = 1_800_000_000_000;

fn now() -> Now {
    Now {
        wall: UnixMillis(T0),
        mono: MonoMillis(1_000),
    }
}

fn ident(name: &str) -> (DeviceKeypair, DeviceCert) {
    let k = DeviceKeypair::generate();
    let c = DeviceCert::issue(&k, name, Platform::Windows, UnixMillis(1)).unwrap();
    (k, c)
}

fn link_inbox(link: &PairLink) -> Inbox {
    Inbox::for_link(
        link.binding(),
        link.rx(),
        InboxConfig::default(),
        Box::new(NoPersistence),
    )
    .unwrap()
}

/// The PC `me` paired with A and with B, and each peer's view of its link.
struct World {
    me: DeviceKeypair,
    a: DeviceKeypair,
    b: DeviceKeypair,
    /// me's link to A / to B.
    to_a: PairLink,
    to_b: PairLink,
    /// A's link to me (A's honest sending side).
    a_to_me: PairLink,
}

fn world() -> World {
    let (me, mc) = ident("PC");
    let (a, ac) = ident("A");
    let (b, bc) = ident("B");
    let (pm_a, pa) = crate::pairwise::v2::pair_for_tests(&me, mc.clone(), &a, ac, None);
    let (pm_b, _) = crate::pairwise::v2::pair_for_tests(&me, mc, &b, bc, None);
    let to_a = PairLink::from_pairing(&me.device_id(), &pm_a).unwrap();
    let to_b = PairLink::from_pairing(&me.device_id(), &pm_b).unwrap();
    let a_to_me = PairLink::from_pairing(&a.device_id(), &pa).unwrap();
    World {
        me,
        a,
        b,
        to_a,
        to_b,
        a_to_me,
    }
}

/// A body addressed to `me` on link `on` (as the honest peer would send it).
fn body(sender: &DeviceId, on: &PairLink, me: &DeviceId) -> RawBody {
    RawBody {
        magic: MAGIC,
        group: on.pairing_id.0,
        sender: *sender.as_bytes(),
        recipient: *me.as_bytes(),
        msg_id: MsgId::random().0,
        timestamp: T0,
        url: b"https://example.com/".to_vec(),
    }
}

fn seal(body: &RawBody, signer: &DeviceKeypair, on: &PairLink, me: &DeviceId) -> Vec<u8> {
    crate::envelope::seal(me, &on.rx().public(), &body.sign_with(signer)).unwrap()
}

fn both_paths(
    inbox: &mut Inbox,
    transport: &DeviceId,
    env: &[u8],
) -> [Result<(), RejectReason>; 2] {
    [
        inbox.receive_message(transport, env, now()).map(|_| ()),
        inbox.receive_from_device_inbox(env, 60, now()).map(|_| ()),
    ]
}

#[test]
fn honest_peer_message_verifies_on_both_paths() {
    let w = world();
    let me = w.me.device_id();
    assert_eq!(w.a_to_me.peer, me);
    let mut inbox = link_inbox(&w.to_a);
    let env = seal(&body(&w.a.device_id(), &w.to_a, &me), &w.a, &w.to_a, &me);
    assert!(matches!(
        inbox.receive_message(&w.a.device_id(), &env, now()),
        Ok(VerifiedMessage::Url(_))
    ));
    let env = seal(&body(&w.a.device_id(), &w.to_a, &me), &w.a, &w.to_a, &me);
    assert!(inbox.receive_from_device_inbox(&env, 60, now()).is_ok());
}

#[test]
fn link_rejects_message_signed_by_other_paired_peer() {
    // B is paired with this PC on its own link, signs honestly as itself,
    // and seals to A's link key: A's link must not accept it.
    let w = world();
    let me = w.me.device_id();
    let mut inbox = link_inbox(&w.to_a);
    let env = seal(&body(&w.b.device_id(), &w.to_a, &me), &w.b, &w.to_a, &me);
    let [t, p] = both_paths(&mut inbox, &w.a.device_id(), &env);
    assert_eq!(t, Err(RejectReason::SenderMismatch));
    assert_eq!(p, Err(RejectReason::SenderMismatch));
    // B's own transport identity on A's link: see
    // `unpaired_peer_closed_before_decrypt`.
}

/// H1: a transport peer that is not this link's peer is refused with
/// `NotPaired` before the envelope is opened. Nothing is decrypted, no
/// pre-decrypt budget is spent, and the honest peer keeps its full budget.
#[test]
fn unpaired_peer_closed_before_decrypt() {
    let w = world();
    let me = w.me.device_id();
    let cfg = InboxConfig::default();
    let mut inbox = link_inbox(&w.to_a);
    let opens = crate::probe::envelope_opens_on_this_thread;
    let env = seal(&body(&w.b.device_id(), &w.to_a, &me), &w.b, &w.to_a, &me);
    let o0 = opens();
    // Far more than any budget: none of it may cost a decrypt.
    for _ in 0..(cfg.pre_decrypt.burst + cfg.per_device.burst + 5) {
        assert_eq!(
            inbox
                .receive_message(&w.b.device_id(), &env, now())
                .map(|_| ()),
            Err(RejectReason::NotPaired)
        );
        assert_eq!(
            inbox
                .receive_message(&w.b.device_id(), b"not even an envelope", now())
                .map(|_| ()),
            Err(RejectReason::NotPaired)
        );
    }
    assert_eq!(opens(), o0, "an unpaired peer caused an HPKE open");
    assert_eq!(inbox.counters().accepted, 0);
    // A still gets its whole burst, so the stranger spent none of it.
    for i in 0..cfg
        .per_device
        .burst
        .min(cfg.pre_decrypt.burst)
        .min(cfg.global.burst)
    {
        let env = seal(&body(&w.a.device_id(), &w.to_a, &me), &w.a, &w.to_a, &me);
        assert!(
            inbox.receive_message(&w.a.device_id(), &env, now()).is_ok(),
            "honest message {i} refused"
        );
    }
    assert!(opens() > o0, "the probe counts opens");
}

#[test]
fn forged_sender_rejected_on_transport_and_inbox_pull() {
    let w = world();
    let me = w.me.device_id();
    let mut inbox = link_inbox(&w.to_a);
    // Claims to be A, signed by B.
    let env = seal(&body(&w.a.device_id(), &w.to_a, &me), &w.b, &w.to_a, &me);
    let [t, p] = both_paths(&mut inbox, &w.a.device_id(), &env);
    assert_eq!(t, Err(RejectReason::BadSignature));
    assert_eq!(p, Err(RejectReason::BadSignature));
    // Claims to be me, signed by me.
    let env = seal(&body(&me, &w.to_a, &me), &w.me, &w.to_a, &me);
    let [t, p] = both_paths(&mut inbox, &w.a.device_id(), &env);
    assert_eq!(t, Err(RejectReason::SenderMismatch));
    assert_eq!(p, Err(RejectReason::FromSelf));
}

#[test]
fn wrong_group_rejected() {
    let w = world();
    let me = w.me.device_id();
    let mut inbox = link_inbox(&w.to_a);
    let mut b = body(&w.a.device_id(), &w.to_a, &me);
    b.group = GroupId([7; 32]).0;
    let env = seal(&b, &w.a, &w.to_a, &me);
    let [t, p] = both_paths(&mut inbox, &w.a.device_id(), &env);
    assert_eq!(t, Err(RejectReason::WrongGroup));
    assert_eq!(p, Err(RejectReason::WrongGroup));
    // The B pairing's id, signed by A, on A's link.
    let mut b = body(&w.a.device_id(), &w.to_a, &me);
    b.group = w.to_b.pairing_id.0;
    let env = seal(&b, &w.a, &w.to_a, &me);
    assert_eq!(
        inbox.receive_message(&w.a.device_id(), &env, now()).err(),
        Some(RejectReason::WrongGroup)
    );
}

#[test]
fn replayed_message_rejected_on_both_paths() {
    let w = world();
    let me = w.me.device_id();
    let mut inbox = link_inbox(&w.to_a);
    let env = seal(&body(&w.a.device_id(), &w.to_a, &me), &w.a, &w.to_a, &me);
    assert!(inbox.receive_message(&w.a.device_id(), &env, now()).is_ok());
    let [t, p] = both_paths(&mut inbox, &w.a.device_id(), &env);
    assert_eq!(t, Err(RejectReason::Replay));
    assert_eq!(p, Err(RejectReason::Replay));
}

struct NeverOpen;
impl UrlOpener for NeverOpen {
    fn open(&self, _: OpenApproval) -> Result<(), OpenError> {
        panic!("must not open")
    }
}

#[test]
fn url_verified_on_one_link_cannot_open_through_another() {
    let w = world();
    let me = w.me.device_id();
    let mut on_a = link_inbox(&w.to_a);
    let on_b = link_inbox(&w.to_b);
    for mode in [OpenMode::OpenImmediately, OpenMode::ConfirmBeforeOpen] {
        let env = seal(&body(&w.a.device_id(), &w.to_a, &me), &w.a, &w.to_a, &me);
        let u = on_a.receive(&w.a.device_id(), &env, now()).unwrap();
        assert!(matches!(
            deliver(&on_b, u, mode, &NeverOpen),
            Err(OpenError::Policy(RejectReason::ForeignInbox))
        ));
    }
}

/// B14: a message in the v1 format (an older Voidwire: version byte 1 and
/// a 32-byte group-log head after the recipient), honestly signed by the
/// paired peer, is refused cleanly as `OlderVoidwire` on both paths.
#[test]
fn old_format_message_rejected_cleanly() {
    let w = world();
    let me = w.me.device_id();
    let mut inbox = link_inbox(&w.to_a);
    let v2 = body(&w.a.device_id(), &w.to_a, &me).sign_with(&w.a);
    let signed = &v2[..v2.len() - crate::wire::SIG_LEN];
    let mut v1 = signed[..100].to_vec();
    v1.extend_from_slice(&[3; 32]);
    v1.extend_from_slice(&signed[100..]);
    v1[2] = 1;
    let sig = w.a.sign(&crate::wire::signing_input(&v1));
    v1.extend_from_slice(&sig.to_bytes());
    let env = crate::envelope::seal(&me, &w.to_a.rx().public(), &v1).unwrap();
    let [t, p] = both_paths(&mut inbox, &w.a.device_id(), &env);
    assert_eq!(t, Err(RejectReason::OlderVoidwire));
    assert_eq!(p, Err(RejectReason::OlderVoidwire));
    // Truncated and padded v1 frames never panic and are refused as an
    // older or malformed frame on both paths, never anything vaguer.
    let mut padded = v1.clone();
    padded.extend_from_slice(&[0; 64]);
    let cuts = [1, 3, 4, 100, 131, 157, v1.len() - 1];
    let frames = cuts
        .iter()
        .map(|&c| v1[..c].to_vec())
        .chain(std::iter::once(padded));
    for (i, f) in frames.enumerate() {
        let env = crate::envelope::seal(&me, &w.to_a.rx().public(), &f).unwrap();
        for r in both_paths(&mut inbox, &w.a.device_id(), &env) {
            assert!(
                matches!(
                    r,
                    Err(RejectReason::OlderVoidwire | RejectReason::MalformedFrame)
                ),
                "frame {i} (len {}): {r:?}",
                f.len()
            );
        }
    }
}

/// L1: a message refused by a rate limit does not burn its replay entry, so
/// the same bytes are accepted once the bucket has refilled.
#[test]
fn rate_limited_message_can_be_retried() {
    use crate::ratelimit::RateLimit;
    let w = world();
    let me = w.me.device_id();
    let roomy = RateLimit {
        burst: 50,
        per_minute: 600,
    };
    let cfg = InboxConfig {
        pre_decrypt: roomy,
        per_device: roomy,
        global: RateLimit {
            burst: 1,
            per_minute: 1,
        },
        ..InboxConfig::default()
    };
    let mut inbox =
        Inbox::for_link(w.to_a.binding(), w.to_a.rx(), cfg, Box::new(NoPersistence)).unwrap();
    let a = w.a.device_id();
    let m1 = seal(&body(&a, &w.to_a, &me), &w.a, &w.to_a, &me);
    let m2 = seal(&body(&a, &w.to_a, &me), &w.a, &w.to_a, &me);
    assert!(inbox.receive_message(&a, &m1, now()).is_ok());
    assert_eq!(
        inbox.receive_message(&a, &m2, now()).map(|_| ()),
        Err(RejectReason::RateLimitedGlobal)
    );
    let later = Now {
        wall: UnixMillis(T0 + 61_000),
        mono: MonoMillis(1_000 + 61_000),
    };
    assert!(
        inbox.receive_message(&a, &m2, later).is_ok(),
        "the retry of a rate-limited message was refused"
    );
    let refilled = Now {
        wall: UnixMillis(T0 + 122_000),
        mono: MonoMillis(1_000 + 122_000),
    };
    assert_eq!(
        inbox.receive_message(&a, &m2, refilled).map(|_| ()),
        Err(RejectReason::Replay)
    );
}

fn offer(
    group: GroupId,
    sender: &DeviceId,
    recipient: &DeviceId,
    tid: u8,
) -> crate::file_transfer::FileOffer {
    let payload = b"voidwire file offer test";
    let (root, hashes) = crate::file_transfer::compute_file_hashes(payload);
    crate::file_transfer::FileOffer::new(
        group,
        *sender,
        *recipient,
        crate::file_transfer::TransferId([tid; 16]),
        "notes.txt",
        "text/plain",
        payload.len() as u64,
        root,
        hashes,
        UnixMillis(T0),
        UnixMillis(T0 + 3_600_000),
    )
    .unwrap()
}

fn seal_offer(
    o: &crate::file_transfer::FileOffer,
    signer: &DeviceKeypair,
    on: &PairLink,
) -> Vec<u8> {
    crate::file_transfer::seal_file_offer(o, signer, &on.rx().public())
        .unwrap()
        .0
}

/// M1: a file offer gets the same link checks as a message: sender bound to
/// the transport peer, a valid signature by the claimed sender, this link's
/// pairing id, this device as recipient, and strangers refused before any
/// decrypt. A refused offer leaves no replay entry behind.
#[test]
fn file_offer_link_checks_match_message_checks() {
    let w = world();
    let me = w.me.device_id();
    let (a, b) = (w.a.device_id(), w.b.device_id());
    let g = w.to_a.pairing_id;
    let roomy = crate::ratelimit::RateLimit {
        burst: 50,
        per_minute: 600,
    };
    let cfg = InboxConfig {
        pre_decrypt: roomy,
        per_device: roomy,
        global: roomy,
        ..InboxConfig::default()
    };
    let mut inbox =
        Inbox::for_link(w.to_a.binding(), w.to_a.rx(), cfg, Box::new(NoPersistence)).unwrap();
    let check = |inbox: &mut Inbox, peer: &DeviceId, env: &[u8]| {
        inbox
            .verify_file_offer(peer, env, |_| false, now())
            .map(|_| ())
    };
    // Honest control.
    let ok = seal_offer(&offer(g, &a, &me, 1), &w.a, &w.to_a);
    assert_eq!(check(&mut inbox, &a, &ok), Ok(()));
    // B, signing honestly as itself, over A's transport.
    let env = seal_offer(&offer(g, &b, &me, 2), &w.b, &w.to_a);
    assert_eq!(
        check(&mut inbox, &a, &env),
        Err(RejectReason::SenderMismatch)
    );
    // Claims to be A, signed by B.
    let env = crate::file_transfer::seal_forged_offer_for_tests(
        &offer(g, &a, &me, 3),
        &w.b,
        &me,
        &w.to_a.rx().public(),
    );
    assert_eq!(check(&mut inbox, &a, &env), Err(RejectReason::BadSignature));
    // B's pairing id on A's link.
    let env = seal_offer(&offer(w.to_b.pairing_id, &a, &me, 4), &w.a, &w.to_a);
    assert_eq!(check(&mut inbox, &a, &env), Err(RejectReason::WrongGroup));
    // Addressed to B.
    let env = crate::file_transfer::seal_forged_offer_for_tests(
        &offer(g, &a, &b, 5),
        &w.a,
        &me,
        &w.to_a.rx().public(),
    );
    assert_eq!(
        check(&mut inbox, &a, &env),
        Err(RejectReason::WrongRecipient)
    );
    // B's transport identity: refused before any decrypt.
    let env6 = seal_offer(&offer(g, &a, &me, 6), &w.a, &w.to_a);
    let o0 = crate::probe::envelope_opens_on_this_thread();
    assert_eq!(check(&mut inbox, &b, &env6), Err(RejectReason::NotPaired));
    assert_eq!(crate::probe::envelope_opens_on_this_thread(), o0);
    // None of the refusals recorded a replay entry: the honest offers with
    // the same transfer ids still pass, and a real replay is still caught.
    for tid in [2u8, 3, 4, 5] {
        let env = seal_offer(&offer(g, &a, &me, tid), &w.a, &w.to_a);
        assert_eq!(check(&mut inbox, &a, &env), Ok(()), "tid {tid}");
    }
    assert_eq!(check(&mut inbox, &a, &env6), Ok(()));
    assert_eq!(check(&mut inbox, &a, &ok), Err(RejectReason::Replay));
}

/// L1 on files: an offer refused by the per-device budget can be retried
/// byte for byte after the bucket refills.
#[test]
fn rate_limited_file_offer_can_be_retried() {
    use crate::ratelimit::RateLimit;
    let w = world();
    let me = w.me.device_id();
    let a = w.a.device_id();
    let roomy = RateLimit {
        burst: 50,
        per_minute: 600,
    };
    let cfg = InboxConfig {
        pre_decrypt: roomy,
        per_device: RateLimit {
            burst: 1,
            per_minute: 1,
        },
        global: roomy,
        ..InboxConfig::default()
    };
    let mut inbox =
        Inbox::for_link(w.to_a.binding(), w.to_a.rx(), cfg, Box::new(NoPersistence)).unwrap();
    let g = w.to_a.pairing_id;
    let o1 = seal_offer(&offer(g, &a, &me, 1), &w.a, &w.to_a);
    let o2 = seal_offer(&offer(g, &a, &me, 2), &w.a, &w.to_a);
    let v = |inbox: &mut Inbox, env: &[u8], at: Now| {
        inbox.verify_file_offer(&a, env, |_| false, at).map(|_| ())
    };
    assert_eq!(v(&mut inbox, &o1, now()), Ok(()));
    assert_eq!(
        v(&mut inbox, &o2, now()),
        Err(RejectReason::RateLimitedDevice)
    );
    let later = Now {
        wall: UnixMillis(T0 + 61_000),
        mono: MonoMillis(1_000 + 61_000),
    };
    assert_eq!(v(&mut inbox, &o2, later), Ok(()));
}
