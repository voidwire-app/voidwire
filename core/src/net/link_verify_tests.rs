//! Security properties of verifying a v2 link's messages, written against
//! behaviour only so they survive the roster removal (M4-ROSTER-REMOVAL §5).
//! `link_inbox` is the one place that knows how a link's verifier is built.

use super::links::PairLink;
use crate::ids::{DeviceId, GroupId, MsgId};
use crate::keys::{DeviceCert, DeviceKeypair, Platform, ReceiveKeypair};
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
    let rx = ReceiveKeypair::generate();
    let c = DeviceCert::issue(&k, rx.public(), name, Platform::Windows, UnixMillis(1)).unwrap();
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
    assert!(
        matches!(
            p,
            Err(RejectReason::SenderMismatch | RejectReason::NotInRoster)
        ),
        "{p:?}"
    );
    // B's own transport identity on A's link is refused before any decrypt.
    let before = inbox.counters().clone();
    let r = inbox.receive_message(&w.b.device_id(), &env, now());
    assert!(r.is_err());
    assert_eq!(inbox.counters().accepted, before.accepted);
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
    // Truncated and padded v1 frames never panic and stay clean errors.
    for cut in [1, 3, 4, 100, 131, 157, v1.len() - 1] {
        let env = crate::envelope::seal(&me, &w.to_a.rx().public(), &v1[..cut]).unwrap();
        let [t, _] = both_paths(&mut inbox, &w.a.device_id(), &env);
        assert!(t.is_err(), "cut {cut}");
    }
}
