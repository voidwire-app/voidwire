use super::*;
use crate::ids::{DeviceId, GroupId};
use crate::keys::{DeviceCert, DeviceKeypair, Platform, ReceiveKeypair};
use crate::time::UnixMillis;
use std::collections::VecDeque;

const T0: UnixMillis = UnixMillis(1_800_000_000_000);

fn cert(kp: &DeviceKeypair, name: &str, p: Platform) -> DeviceCert {
    DeviceCert::issue(kp, ReceiveKeypair::generate().public(), name, p, T0).unwrap()
}

struct Pair {
    a: DeviceKeypair,
    b: DeviceKeypair,
    la: PairLog,
    lb: PairLog,
}

fn new_pair() -> Pair {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let body = PairBody::Genesis {
        kind: PairingKind::Own,
        inviter: cert(&a, "Desk", Platform::Linux),
        joiner: cert(&b, "Phone", Platform::Android),
        inviter_rx: ReceiveKeypair::generate().public(),
        joiner_rx: ReceiveKeypair::generate().public(),
        relay: Some(RelayRef::new("https://relay.example.test", None)),
    };
    let g = PairLog::propose_genesis(&a, GroupId([7; 32]), T0, body).unwrap();
    // Over the wire.
    let g = PairOp::decode(&g.encode()).unwrap();
    let (lb, cosigned) = PairLog::accept_genesis(&b, g).unwrap();
    let la = PairLog::from_genesis(PairOp::decode(&cosigned.encode()).unwrap()).unwrap();
    assert_eq!(la.head(), lb.head());
    Pair { a, b, la, lb }
}

fn relay(n: u64) -> PairBody {
    PairBody::SetRelay {
        relay: Some(RelayRef::new(format!("https://r{n}.example.test"), None)),
    }
}

fn rekey(epoch: u64) -> PairBody {
    PairBody::Rekey {
        epoch,
        wrapped: [epoch as u8; crate::mailbox::WRAPPED_EPOCH_SECRET_LEN],
        author_rx: ReceiveKeypair::generate().public(),
        cosigner_rx: ReceiveKeypair::generate().public(),
    }
}

#[test]
fn genesis_needs_both_signatures() {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let body = PairBody::Genesis {
        kind: PairingKind::Own,
        inviter: cert(&a, "Desk", Platform::Linux),
        joiner: cert(&b, "Phone", Platform::Android),
        inviter_rx: ReceiveKeypair::generate().public(),
        joiner_rx: ReceiveKeypair::generate().public(),
        relay: None,
    };
    let g = PairLog::propose_genesis(&a, GroupId([1; 32]), T0, body.clone()).unwrap();
    assert_eq!(
        PairLog::from_genesis(g.clone()).unwrap_err(),
        PairError::MissingCosign
    );
    // Someone else can't co-sign in the joiner's place.
    let c = DeviceKeypair::generate();
    assert_eq!(
        PairLog::accept_genesis(&c, g.clone()).unwrap_err(),
        PairError::BadGenesis
    );
    // The inviter can't author a genesis for someone else's cert.
    assert_eq!(
        PairLog::propose_genesis(&b, GroupId([1; 32]), T0, body).unwrap_err(),
        PairError::BadGenesis
    );
}

#[test]
fn cosigned_op_round_trip() {
    let mut p = new_pair();
    let Proposed::NeedsCosign(op) = p.la.propose(&p.a, T0, relay(1)).unwrap() else {
        panic!("needs cosign")
    };
    assert!(!op.is_cosigned());
    let wire = PairOp::decode(&op.encode()).unwrap();
    let Received::Cosigned { op: back, requeue } = p.lb.receive(&p.b, wire).unwrap() else {
        panic!("cosigned")
    };
    assert!(requeue.is_empty());
    let back = PairOp::decode(&back.encode()).unwrap();
    assert_eq!(
        p.la.receive(&p.a, back).unwrap(),
        Received::Applied { requeue: vec![] }
    );
    assert_eq!(p.la.head(), p.lb.head());
    assert_eq!(p.la.relay().unwrap().url, "https://r1.example.test");
    assert!(p.la.pending().is_none());
}

#[test]
fn non_cosigned_ops_are_rejected_on_apply() {
    let p = new_pair();
    // A proposal (no co-signature) can't be smuggled in as applied: the
    // author's own replica only applies it when it comes back co-signed.
    let mut la = p.la.clone();
    let op = PairOp::propose(&p.a, la.pairing(), la.head(), T0, relay(2)).unwrap();
    assert_eq!(
        la.receive(&p.a, op.clone()).unwrap_err(),
        PairError::MissingCosign
    );
    // Restoring a stored log with an un-co-signed op in it fails.
    let mut lb = p.lb.clone();
    let Received::Cosigned { op: good, .. } = lb.receive(&p.b, op).unwrap() else {
        panic!()
    };
    let mut bad = good.encode();
    let n = bad.len();
    bad[n - 129] = 0; // clear the co-signed flag...
    bad.truncate(n - 64); // ...and drop the co-signature
    let bad = PairOp::decode(&bad).unwrap();
    assert!(!bad.is_cosigned());
    assert_eq!(la.receive(&p.a, bad).unwrap_err(), PairError::MissingCosign);
}

#[test]
fn cosignature_must_be_the_peer() {
    let p = new_pair();
    let mut la = p.la.clone();
    let mut op = PairOp::propose(&p.a, la.pairing(), la.head(), T0, relay(3)).unwrap();
    // Author signs twice (as if it were its own co-signer).
    op.sig_cosigner_for_tests(&p.a);
    assert_eq!(la.receive(&p.a, op).unwrap_err(), PairError::BadSignature);
    // A stranger co-signs.
    let stranger = DeviceKeypair::generate();
    let mut op = PairOp::propose(&p.a, la.pairing(), la.head(), T0, relay(3)).unwrap();
    op.sig_cosigner_for_tests(&stranger);
    assert_eq!(la.receive(&p.a, op).unwrap_err(), PairError::BadSignature);
    // A stranger authors.
    let op = PairOp::propose(&stranger, la.pairing(), la.head(), T0, relay(3)).unwrap();
    assert_eq!(la.receive(&p.a, op).unwrap_err(), PairError::NotMember);
}

#[test]
fn self_signed_ops_cannot_carry_cosign_and_rename_is_self_only() {
    let mut p = new_pair();
    let mut op = PairOp::propose(
        &p.b,
        p.la.pairing(),
        p.la.head(),
        T0,
        PairBody::Rename {
            name: "Pocket".into(),
        },
    )
    .unwrap();
    op.sig_cosigner_for_tests(&p.a);
    assert_eq!(
        p.la.receive(&p.a, op).unwrap_err(),
        PairError::UnexpectedCosign
    );
    let Proposed::Applied(op) =
        p.lb.propose(
            &p.b,
            T0,
            PairBody::Rename {
                name: "Pocket".into(),
            },
        )
        .unwrap()
    else {
        panic!()
    };
    p.la.receive(&p.a, op).unwrap();
    assert_eq!(p.la.name_of(&p.b.device_id()), Some("Pocket"));
    assert_eq!(p.la.name_of(&p.a.device_id()), Some("Desk"));
    assert_eq!(p.la.head(), p.lb.head());
}

#[test]
fn tampering_breaks_the_author_signature() {
    let p = new_pair();
    let op = PairOp::propose(&p.a, p.la.pairing(), p.la.head(), T0, relay(4)).unwrap();
    let mut b = op.encode();
    let i = b.len() - 70; // inside the body
    b[i] ^= 1;
    assert!(PairOp::decode(&b).is_err());
}

#[test]
fn rekey_epochs_must_increase_by_one() {
    let mut p = new_pair();
    assert_eq!(
        p.la.propose(&p.a, T0, rekey(2)).unwrap_err(),
        PairError::BadEpoch
    );
    let Proposed::NeedsCosign(op) = p.la.propose(&p.a, T0, rekey(1)).unwrap() else {
        panic!()
    };
    let Received::Cosigned { op, .. } = p.lb.receive(&p.b, op).unwrap() else {
        panic!()
    };
    p.la.receive(&p.a, op.clone()).unwrap();
    assert_eq!(p.la.epoch(), 1);
    let PairBody::Rekey {
        author_rx,
        cosigner_rx,
        ..
    } = op.body()
    else {
        panic!()
    };
    assert_eq!(p.lb.rx_of(&p.a.device_id()), Some(*author_rx));
    assert_eq!(p.lb.rx_of(&p.b.device_id()), Some(*cosigner_rx));
}

#[test]
fn unpair_is_local_final_and_immediate() {
    let mut p = new_pair();
    let op = p.lb.unpair(&p.b, T0).unwrap();
    assert!(p.lb.is_unpaired());
    assert_eq!(
        p.lb.propose(&p.b, T0, relay(5)).unwrap_err(),
        PairError::Unpaired
    );
    // The notice reaches the other side and ends it there too.
    p.la.receive(&p.a, op).unwrap();
    assert!(p.la.is_unpaired());
}

#[test]
fn caps_gate_v2() {
    let mut p = new_pair();
    assert!(p.la.caps().is_none());
    let Proposed::NeedsCosign(op) = p.la.propose(&p.a, T0, PairBody::Caps(Caps::V2)).unwrap()
    else {
        panic!()
    };
    let Received::Cosigned { op, .. } = p.lb.receive(&p.b, op).unwrap() else {
        panic!()
    };
    p.la.receive(&p.a, op).unwrap();
    assert!(p.la.caps().unwrap().supports_pairwise());
    assert!(!Caps::V1.supports_pairwise());
}

fn cosign_round(p: &mut Pair, body: PairBody) {
    let Proposed::NeedsCosign(op) = p.la.propose(&p.a, T0, body).unwrap() else {
        panic!()
    };
    let Received::Cosigned { op, .. } = p.lb.receive(&p.b, op).unwrap() else {
        panic!()
    };
    p.la.receive(&p.a, op).unwrap();
}

#[test]
fn compaction_keeps_state_and_restores() {
    let mut p = new_pair();
    let mut epoch = 0;
    for i in 0..600u64 {
        match i % 3 {
            0 => cosign_round(&mut p, relay(i)),
            1 => {
                epoch += 1;
                cosign_round(&mut p, rekey(epoch));
            }
            _ => cosign_round(
                &mut p,
                PairBody::Caps(Caps {
                    proto: 2,
                    features: i,
                }),
            ),
        }
        assert!(p.la.retained_len() < COMPACT_AT_OPS);
        assert!(p.lb.retained_len() < COMPACT_AT_OPS);
    }
    assert_eq!(p.la.len(), 601);
    assert_eq!(p.la.head(), p.lb.head());
    for l in [&p.la, &p.lb] {
        let r = PairLog::decode(&l.encode()).unwrap();
        assert_eq!(r.head(), l.head());
        assert_eq!(r.len(), l.len());
        assert_eq!(r.epoch(), epoch);
        assert_eq!(r.relay(), l.relay());
        assert_eq!(r.caps(), l.caps());
        assert_eq!(r.rx_of(&p.a.device_id()), l.rx_of(&p.a.device_id()));
    }
    // Still usable after a restore.
    p.la = PairLog::decode(&p.la.encode()).unwrap();
    p.lb = PairLog::decode(&p.lb.encode()).unwrap();
    cosign_round(&mut p, relay(9999));
    assert_eq!(p.la.head(), p.lb.head());
}

#[test]
fn stored_log_with_broken_chain_is_refused() {
    let mut p = new_pair();
    cosign_round(&mut p, relay(1));
    cosign_round(&mut p, relay(2));
    let mut b = p.la.encode();
    // Flip a byte inside the first tail op's prev hash.
    let g_len = u16::from_be_bytes([b[1], b[2]]) as usize;
    let tail_op_start = 1 + 2 + g_len + 2 + 1 + 2 + 2;
    b[tail_op_start + 4 + 1 + 32] ^= 0x40;
    assert!(PairLog::decode(&b).is_err());
}

// ---- concurrent proposals converge (property test) ----

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

struct Side {
    kp: DeviceKeypair,
    log: PairLog,
    out: VecDeque<Vec<u8>>,
    requeue: Vec<PairBody>,
}

fn fresh(body: &PairBody, log: &PairLog, rng: &mut XorShift) -> PairBody {
    match body {
        PairBody::Rekey { .. } => rekey(log.epoch() + 1),
        PairBody::SetRelay { .. } => relay(rng.next()),
        b => b.clone(),
    }
}

fn random_body(rng: &mut XorShift, log: &PairLog) -> PairBody {
    match rng.below(4) {
        0 => relay(rng.next()),
        1 => rekey(log.epoch() + 1),
        2 => PairBody::Caps(Caps {
            proto: 2,
            features: rng.next(),
        }),
        _ => PairBody::Rename {
            name: format!("Dev {}", rng.below(1000)),
        },
    }
}

fn try_propose(s: &mut Side, body: PairBody) {
    match s.log.propose(&s.kp, T0, body.clone()) {
        Ok(Proposed::NeedsCosign(op)) | Ok(Proposed::Applied(op)) => s.out.push_back(op.encode()),
        Err(PairError::TooManyPending) => s.requeue.push(body),
        Err(e) => panic!("propose failed: {e:?}"),
    }
}

static RACES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn deliver(from: &mut Side, to: &mut Side) -> bool {
    let Some(b) = from.out.pop_front() else {
        return false;
    };
    let op = PairOp::decode(&b).unwrap();
    match to.log.receive(&to.kp, op) {
        Ok(Received::Applied { requeue }) => {
            RACES.fetch_add(requeue.len(), std::sync::atomic::Ordering::Relaxed);
            to.requeue.extend(requeue)
        }
        Ok(Received::Cosigned { op, requeue }) => {
            RACES.fetch_add(requeue.len(), std::sync::atomic::Ordering::Relaxed);
            to.out.push_back(op.encode());
            to.requeue.extend(requeue);
        }
        Ok(Received::Ignored) | Err(PairError::WrongPrev) => {}
        Err(e) => panic!("receive failed: {e:?}"),
    }
    true
}

fn run_sim(seed: u64, steps: usize) {
    let mut rng = XorShift(seed | 1);
    let p = new_pair();
    let mut sa = Side {
        kp: p.a,
        log: p.la,
        out: VecDeque::new(),
        requeue: vec![],
    };
    let mut sb = Side {
        kp: p.b,
        log: p.lb,
        out: VecDeque::new(),
        requeue: vec![],
    };
    for _ in 0..steps {
        match rng.below(4) {
            0 => {
                let b = random_body(&mut rng, &sa.log);
                if sa.log.pending().is_none() {
                    try_propose(&mut sa, b);
                }
            }
            1 => {
                let b = random_body(&mut rng, &sb.log);
                if sb.log.pending().is_none() {
                    try_propose(&mut sb, b);
                }
            }
            2 => {
                deliver(&mut sa, &mut sb);
            }
            _ => {
                deliver(&mut sb, &mut sa);
            }
        }
    }
    // Drain: deliver everything, re-propose what lost, until quiet.
    for round in 0..10_000 {
        let moved = deliver(&mut sa, &mut sb) | deliver(&mut sb, &mut sa);
        if moved {
            continue;
        }
        let mut proposed = false;
        for s in [&mut sa, &mut sb] {
            if s.log.pending().is_some_and(|p| p.prev() != s.log.head()) {
                panic!("stale pending proposal left behind");
            }
            if s.log.pending().is_none() {
                if let Some(b) = s.requeue.pop() {
                    let b = fresh(&b, &s.log, &mut rng);
                    try_propose(s, b);
                    proposed = true;
                }
            }
        }
        if !proposed {
            let quiet = sa.out.is_empty()
                && sb.out.is_empty()
                && sa.log.pending().is_none()
                && sb.log.pending().is_none();
            if quiet {
                break;
            }
            // A proposal is in flight with nothing to carry it: a deadlock.
            panic!("seed {seed}: stuck in round {round}");
        }
    }
    assert_eq!(sa.log.head(), sb.log.head(), "seed {seed}: heads diverged");
    assert_eq!(sa.log.len(), sb.log.len());
    assert_eq!(sa.log.epoch(), sb.log.epoch());
    assert_eq!(sa.log.relay(), sb.log.relay());
    assert_eq!(sa.log.caps(), sb.log.caps());
    for id in [sa.kp.device_id(), sb.kp.device_id()] {
        assert_eq!(sa.log.name_of(&id), sb.log.name_of(&id));
        assert_eq!(sa.log.rx_of(&id), sb.log.rx_of(&id));
    }
    // Both replicas survive a save/restore.
    let ra = PairLog::decode(&sa.log.encode()).unwrap();
    assert_eq!(ra.head(), sa.log.head());
}

#[test]
fn concurrent_proposals_converge_property() {
    for seed in 0..200u64 {
        run_sim(
            0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0x2545_F491_4F6C_DD1D),
            120,
        );
    }
    // The runs really raced (ops lost and were re-proposed).
    let races = RACES.load(std::sync::atomic::Ordering::Relaxed);
    assert!(races > 100, "only {races} races");
}

#[test]
fn concurrent_proposals_lower_hash_wins() {
    let mut p = new_pair();
    let Proposed::NeedsCosign(xa) = p.la.propose(&p.a, T0, relay(10)).unwrap() else {
        panic!()
    };
    let Proposed::NeedsCosign(xb) = p.lb.propose(&p.b, T0, relay(20)).unwrap() else {
        panic!()
    };
    let a_wins = xa.hash().0 < xb.hash().0;
    let ra = p.la.receive(&p.a, xb.clone()).unwrap();
    let rb = p.lb.receive(&p.b, xa.clone()).unwrap();
    let (winner_url, back, to_a) = if a_wins {
        assert_eq!(ra, Received::Ignored);
        let Received::Cosigned { op, requeue } = rb else {
            panic!()
        };
        assert_eq!(requeue.len(), 1);
        ("https://r10.example.test", op, true)
    } else {
        assert_eq!(rb, Received::Ignored);
        let Received::Cosigned { op, requeue } = ra else {
            panic!()
        };
        assert_eq!(requeue.len(), 1);
        ("https://r20.example.test", op, false)
    };
    if to_a {
        p.la.receive(&p.a, back).unwrap();
    } else {
        p.lb.receive(&p.b, back).unwrap();
    }
    assert_eq!(p.la.head(), p.lb.head());
    assert_eq!(p.la.relay().unwrap().url, winner_url);
}

// ---- records, migration, limits ----

fn peer(id: DeviceId, name: &str) -> PeerInfo {
    PeerInfo {
        id,
        name: name.into(),
        platform: Platform::Android,
    }
}

#[test]
fn legacy_ids_match_on_both_sides() {
    let g = GroupId([3; 32]);
    let pc = DeviceKeypair::generate().device_id();
    let ph = DeviceKeypair::generate().device_id();
    assert_eq!(
        legacy_pairing_id(&g, &pc, &ph),
        legacy_pairing_id(&g, &ph, &pc)
    );
    assert_ne!(
        legacy_pairing_id(&g, &pc, &ph),
        legacy_pairing_id(&GroupId([4; 32]), &pc, &ph)
    );
}

#[test]
fn sync_legacy_splits_one_pairing_per_peer() {
    let me = DeviceKeypair::generate().device_id();
    let g = GroupId([5; 32]);
    let phones: Vec<DeviceId> = (0..20)
        .map(|_| DeviceKeypair::generate().device_id())
        .collect();
    let links: Vec<LegacyLink> = phones
        .iter()
        .enumerate()
        .map(|(i, id)| LegacyLink {
            group: g,
            peer: peer(*id, &format!("Phone {i}")),
            peer_cert: None,
            relay: Some(RelayRef::new("https://relay.example.test", None)),
            epoch: 3,
        })
        .collect();
    let mut set = PairingSet::new();
    assert!(set.sync_legacy(&me, &links));
    // Existing v0.4.x pairings are kept even above the limit...
    assert_eq!(set.len(), 20);
    assert!(!set.has_room());
    assert!(!set.sync_legacy(&me, &links));
    // ...but new ones are refused.
    let extra = Pairing::from_legacy(
        &me,
        &LegacyLink {
            group: GroupId([6; 32]),
            ..links[0].clone()
        },
    );
    assert_eq!(set.add(extra).unwrap_err(), PairError::LimitReached);
    // A forgotten phone's pairing goes away.
    assert!(set.sync_legacy(&me, &links[1..]));
    assert_eq!(set.len(), 19);
    assert_eq!(set.by_peer(&phones[0]).count(), 0);
    for p in set.iter() {
        assert_eq!(p.peer_caps, Caps::V1);
        assert!(!p.v2_active());
        assert!(matches!(p.my_rx, MyRx::DeviceKey));
        assert_eq!(p.epoch, 3);
    }
}

#[test]
fn pairing_set_round_trip_with_secrets_and_log() {
    let seal = [9u8; 32];
    let p = new_pair();
    let mut set = PairingSet::new();
    let me = p.a.device_id();
    set.sync_legacy(
        &me,
        &[LegacyLink {
            group: GroupId([2; 32]),
            peer: peer(DeviceKeypair::generate().device_id(), "Old phone"),
            peer_cert: None,
            relay: None,
            epoch: 0,
        }],
    );
    let rx = ReceiveKeypair::generate();
    let rx_pub = rx.public();
    set.add(Pairing {
        pairing_id: p.la.pairing(),
        kind: PairingKind::Own,
        origin: PairingOrigin::V2,
        peer: peer(p.b.device_id(), "Phone"),
        peer_cert: p.la.cert_of(&p.b.device_id()).cloned(),
        my_rx: MyRx::Own(rx),
        peer_rx: p.la.rx_of(&p.b.device_id()),
        relay: p.la.relay().cloned(),
        epoch: 0,
        gs_e: Some(crate::mailbox::EpochSecret::from_bytes([1; 32])),
        prev_gs_e: None,
        log: Some(p.la.clone()),
        peer_caps: Caps::V2,
        label: Some("Kitchen".into()),
    })
    .unwrap();
    let enc = set.encode(&seal);
    // Secrets are sealed, never in clear.
    assert!(!enc.windows(32).any(|w| w == [1u8; 32]));
    let back = PairingSet::decode(&seal, &enc).unwrap();
    assert_eq!(back.len(), 2);
    let v2 = back.get(&p.la.pairing()).unwrap();
    assert_eq!(v2.display_name(), "Kitchen");
    assert_eq!(v2.log.as_ref().unwrap().head(), p.la.head());
    assert_eq!(v2.gs_e.as_ref().unwrap().as_bytes(), &[1; 32]);
    let MyRx::Own(k) = &v2.my_rx else { panic!() };
    assert_eq!(k.public(), rx_pub);
    // Wrong seal key: refused.
    assert!(PairingSet::decode(&[8u8; 32], &enc).is_none());
    // Unpair removes it.
    let mut back = back;
    assert!(back.remove(&p.la.pairing()).is_some());
    assert_eq!(back.len(), 1);
}

#[test]
fn relay_settings_limits() {
    let builtin = RelayRef::new("https://relay.voidwire.app", None);
    let mut s = RelaySettings::from_legacy(builtin.clone(), Some(builtin.clone()));
    assert_eq!(s.relays.len(), 1);
    assert_eq!(s.home_relay.as_deref(), Some("https://relay.voidwire.app"));
    for i in 0..7 {
        s.add(RelayEntry {
            nickname: format!("R{i}"),
            relay: RelayRef::new(format!("https://r{i}.example.test"), None),
            source: RelaySource::Manual,
            no_udp: i == 3,
        })
        .unwrap();
    }
    assert_eq!(
        s.add(RelayEntry {
            nickname: "R9".into(),
            relay: RelayRef::new("https://r9.example.test", None),
            source: RelaySource::Manual,
            no_udp: false,
        })
        .unwrap_err(),
        PairError::LimitReached
    );
    let empty = PairingSet::new();
    assert_eq!(
        s.remove("https://relay.voidwire.app", &empty).unwrap_err(),
        PairError::InUse
    );
    s.remove("https://r0.example.test", &empty).unwrap();
    // 4 relays in use at most.
    let me = DeviceKeypair::generate().device_id();
    let links: Vec<LegacyLink> = (1..4)
        .map(|i| LegacyLink {
            group: GroupId([i as u8; 32]),
            peer: peer(DeviceKeypair::generate().device_id(), "P"),
            peer_cert: None,
            relay: Some(RelayRef::new(format!("https://r{i}.example.test"), None)),
            epoch: 0,
        })
        .collect();
    let mut set = PairingSet::new();
    set.sync_legacy(&me, &links);
    assert_eq!(s.in_use(&set).len(), 4);
    assert!(s.can_use(&set, "https://r1.example.test"));
    assert!(!s.can_use(&set, "https://r5.example.test"));
    assert_eq!(
        s.remove("https://r1.example.test", &set).unwrap_err(),
        PairError::InUse
    );
    let back = RelaySettings::decode(&s.encode()).unwrap();
    assert_eq!(back, s);
    // Relay off, then a custom relay (legacy setting follows).
    let mut s2 = RelaySettings::from_legacy(builtin.clone(), None);
    assert_eq!(s2.home_relay, None);
    assert!(s2.sync_home(Some(RelayRef::new("http://127.0.0.1:3340", None))));
    assert_eq!(s2.relays.len(), 2);
    assert!(!s2.sync_home(Some(RelayRef::new("http://127.0.0.1:3340", None))));
}
