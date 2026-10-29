//! M4.2: v2 pairings carry every direction. Two PCs and two phones, each
//! pair joined the v2 way, send URL, text, a small file and a large file
//! across all 12 directed pairs, over the LAN and over relays.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use voidwire_core::file_transfer::{RelayPromptDecision, TransferId};
use voidwire_core::ids::DeviceId;
use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{IncomingItemKind, PhoneClient, PhoneConfig};
use voidwire_core::net::state::MemoryStateStore;
use voidwire_core::net::test_relay::TestRelay;
use voidwire_core::net::{pair_v2_for_tests, V2Node};
use voidwire_core::pairwise::RelayRef;
use voidwire_core::ratelimit::RateLimit;
use voidwire_core::test_util::SharedSpyOpener;
use voidwire_core::verify::InboxConfig;
use voidwire_mailbox::{MailboxLimits, MailboxServer, MailboxServerConfig};

/// A test relay with a blind mailbox service on it.
pub struct RelayBox {
    pub relay: TestRelay,
    pub server: MailboxServer,
    _rt: tokio::runtime::Runtime,
}

impl RelayBox {
    pub fn start() -> Self {
        let relay = TestRelay::start();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&(relay.addr().port() as u64).to_le_bytes());
        key[31] = 0x42;
        let server = rt
            .block_on(MailboxServer::start(MailboxServerConfig {
                secret_key: key,
                relay_url: relay.url(),
                data_dir: None,
                healthz_addr: None,
                signed_config: None,
                limits: MailboxLimits::default(),
                log: "off".into(),
            }))
            .expect("mailbox server");
        let id = server.device_id();
        wait("mailbox on relay", || relay.has_peer(&id));
        Self {
            relay,
            server,
            _rt: rt,
        }
    }
    pub fn url(&self) -> String {
        self.relay.url()
    }
    pub fn rref(&self) -> RelayRef {
        RelayRef {
            url: self.relay.url(),
            mailbox_id: Some(self.server.device_id()),
        }
    }
}

pub enum Dev {
    Pc {
        node: PcNode,
        spy: Arc<SharedSpyOpener>,
        dl: PathBuf,
    },
    Phone {
        node: PhoneClient,
        dl: PathBuf,
    },
}

pub fn temp_dir(tag: &str) -> PathBuf {
    let uniq = voidwire_core::keys::DeviceKeypair::generate()
        .device_id()
        .to_hex();
    let d = std::env::temp_dir().join(format!("vw-m42-{tag}-{uniq}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn roomy() -> InboxConfig {
    let r = RateLimit {
        burst: 500,
        per_minute: 2000,
    };
    InboxConfig {
        pre_decrypt: r,
        per_device: r,
        global: r,
        ..InboxConfig::default()
    }
}

pub fn pc(name: &str, relay: Option<String>, root: &Path) -> Dev {
    pc_on(name, relay, root, Arc::new(MemoryStateStore::default()))
}

/// A PC on `store` (pass the same store to "restart" it).
pub fn pc_on(name: &str, relay: Option<String>, root: &Path, store: Arc<MemoryStateStore>) -> Dev {
    let dl = root.join(format!("{name}-dl"));
    std::fs::create_dir_all(&dl).unwrap();
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new(name, store, spy.clone())
        .with_download_dir(dl.clone())
        .with_auto_accept_files(true);
    cfg.mdns = false;
    cfg.port = Some(0);
    // On a relay, no direct hints: traffic starts on the relay.
    cfg.advertise_loopback = relay.is_none();
    cfg.unchecked_inbox_for_tests = true;
    cfg.inbox = roomy();
    cfg.relay_url = Some(relay.unwrap_or_else(|| "off".into()));
    let node = PcNode::start(cfg).expect("pc");
    Dev::Pc { node, spy, dl }
}

pub fn phone(name: &str, relay: Option<String>, root: &Path) -> Dev {
    phone_on(name, relay, root, Arc::new(MemoryStateStore::default()))
}

/// A phone on `store` (pass the same store to "restart" it).
pub fn phone_on(
    name: &str,
    relay: Option<String>,
    root: &Path,
    store: Arc<MemoryStateStore>,
) -> Dev {
    let dl = root.join(format!("{name}-dl"));
    std::fs::create_dir_all(&dl).unwrap();
    let node = PhoneClient::new(PhoneConfig {
        state: store,
        default_name: name.into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    node.set_relay_url(Some(relay.unwrap_or_else(|| "off".into())))
        .unwrap();
    node.set_download_dir(dl.clone());
    node.set_auto_accept_files(true);
    Dev::Phone { node, dl }
}

fn loopback(v: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    v.into_iter()
        .filter(|a| a.is_ipv4())
        .map(|a| std::net::SocketAddr::from(([127, 0, 0, 1], a.port())))
        .collect()
}

impl Dev {
    pub fn id(&self) -> DeviceId {
        match self {
            Dev::Pc { node, .. } => node.device_id(),
            Dev::Phone { node, .. } => node.device_id(),
        }
    }
    pub fn v2(&self) -> V2Node<'_> {
        match self {
            Dev::Pc { node, .. } => V2Node::Pc(node),
            Dev::Phone { node, .. } => V2Node::Phone(node),
        }
    }
    /// Direct loopback addresses (empty: relay only).
    pub fn lan(&self) -> Vec<std::net::SocketAddr> {
        match self {
            Dev::Pc { node, .. } => loopback(node.bound_sockets()),
            Dev::Phone { node, .. } => loopback(node.bound_sockets_for_tests()),
        }
    }
    pub fn dl(&self) -> &Path {
        match self {
            Dev::Pc { dl, .. } | Dev::Phone { dl, .. } => dl,
        }
    }
    pub fn name(&self) -> String {
        match self {
            Dev::Pc { node, .. } => node.device_name(),
            Dev::Phone { node, .. } => node.device_name(),
        }
    }

    pub fn send_url(&self, to: &DeviceId, url: &str) {
        match self {
            Dev::Pc { node, .. } => {
                node.send_url_to_phone(to, url).expect("pc url");
            }
            Dev::Phone { node, .. } => {
                node.send_url(to, url).expect("phone url");
            }
        }
    }
    pub fn send_text(&self, to: &DeviceId, text: &str) {
        match self {
            Dev::Pc { node, .. } => {
                node.send_clipboard_to_phone(to, text).expect("pc text");
            }
            Dev::Phone { node, .. } => {
                node.send_clipboard_text(to, text).expect("phone text");
            }
        }
    }
    pub fn send_file(&self, to: &DeviceId, name: &str, data: &[u8]) {
        let tid = TransferId::random();
        let d = Some(RelayPromptDecision::SendViaRelay);
        match self {
            Dev::Pc { node, .. } => {
                node.send_file_bytes_to_phone(to, tid, name, "application/octet-stream", data, d)
                    .expect("pc file");
            }
            Dev::Phone { node, .. } => {
                node.send_file_bytes(to, tid, name, "application/octet-stream", data, d)
                    .expect("phone file");
            }
        }
    }

    /// Whether `url` arrived (opened on a PC, listed on a phone).
    pub fn got_url(&self, url: &str) -> bool {
        match self {
            Dev::Pc { spy, .. } => spy.calls().iter().any(|c| c == url),
            Dev::Phone { node, .. } => node
                .poll_incoming()
                .items
                .iter()
                .any(|i| i.kind == IncomingItemKind::Url && i.payload_text == url),
        }
    }
    pub fn got_text(&self, text: &str) -> bool {
        match self {
            Dev::Pc { node, .. } => node.pending_clipboards().iter().any(|p| p.text == text),
            Dev::Phone { node, .. } => node
                .poll_incoming()
                .items
                .iter()
                .any(|i| i.kind == IncomingItemKind::ClipboardText && i.payload_text == text),
        }
    }
    pub fn got_file(&self, name: &str, data: &[u8]) -> bool {
        std::fs::read(self.dl().join(name)).is_ok_and(|b| b == data)
    }
}

pub fn wait(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..800 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

pub fn pair(a: &Dev, b: &Dev, lan: bool, relay: Option<RelayRef>) {
    let (aa, ba) = if lan {
        (a.lan(), b.lan())
    } else {
        (vec![], vec![])
    };
    pair_v2_for_tests(a.v2(), aa, b.v2(), ba, relay).expect("v2 pair");
}

/// Every directed pair among `devs` sends all four kinds.
pub fn run_matrix(devs: &[&Dev], tag: &str) {
    let small = vec![0x5au8; 64 * 1024];
    let large = vec![0xa5u8; 1024 * 1024 + 123];
    let mut n = 0;
    for (i, a) in devs.iter().enumerate() {
        for (j, b) in devs.iter().enumerate() {
            if i == j {
                continue;
            }
            n += 1;
            let to = b.id();
            let url = format!("https://example.com/{tag}/{i}-{j}");
            a.send_url(&to, &url);
            wait(&format!("{tag} url {i}->{j}"), || b.got_url(&url));
            let text = format!("{tag} note {i} to {j}");
            a.send_text(&to, &text);
            wait(&format!("{tag} text {i}->{j}"), || b.got_text(&text));
            let sname = format!("{tag}-small-{i}-{j}.bin");
            a.send_file(&to, &sname, &small);
            wait(&format!("{tag} small file {i}->{j}"), || {
                b.got_file(&sname, &small)
            });
            let lname = format!("{tag}-large-{i}-{j}.bin");
            a.send_file(&to, &lname, &large);
            wait(&format!("{tag} large file {i}->{j}"), || {
                b.got_file(&lname, &large)
            });
        }
    }
    assert_eq!(n, devs.len() * (devs.len() - 1));
}

#[test]
fn m42_matrix_two_pcs_two_phones_over_lan() {
    let root = temp_dir("lan");
    let pc_a = pc("PC A", None, &root);
    let pc_b = pc("PC B", None, &root);
    let ph_a = phone("Phone A", None, &root);
    let ph_b = phone("Phone B", None, &root);
    let devs = [&pc_a, &pc_b, &ph_a, &ph_b];
    for (i, a) in devs.iter().enumerate() {
        for b in &devs[i + 1..] {
            pair(a, b, true, None);
        }
    }
    run_matrix(&devs, "lan");
}

/// Four devices on one home relay (live traffic), every pairing with its
/// inboxes on its own relay. Returns the pairing relays too.
fn relay_world(root: &Path) -> (RelayBox, [Dev; 4], Vec<RelayBox>) {
    let home = RelayBox::start();
    let h = Some(home.url());
    let devs = [
        pc("PC A", h.clone(), root),
        pc("PC B", h.clone(), root),
        phone("Phone A", h.clone(), root),
        phone("Phone B", h.clone(), root),
    ];
    let mut boxes = Vec::new();
    for i in 0..4 {
        for j in i + 1..4 {
            let b = RelayBox::start();
            pair(&devs[i], &devs[j], false, Some(b.rref()));
            boxes.push(b);
        }
    }
    for d in &devs {
        let id = d.id();
        wait("device on the home relay", || home.relay.has_peer(&id));
    }
    (home, devs, boxes)
}

#[test]
fn m42_matrix_two_pcs_two_phones_over_relay_each_pairing_on_its_own_relay() {
    let root = temp_dir("relay");
    let (_home, devs, boxes) = relay_world(&root);
    assert_eq!(boxes.len(), 6);
    let urls: std::collections::HashSet<String> = boxes.iter().map(|b| b.url()).collect();
    assert_eq!(urls.len(), 6, "every pairing has its own relay");
    let refs: Vec<&Dev> = devs.iter().collect();
    let before = _home.relay.relayed_datagrams().len();
    run_matrix(&refs, "relay");
    assert!(
        _home.relay.relayed_datagrams().len() > before,
        "live traffic went through the home relay"
    );
}

fn phone_node(d: &Dev) -> &PhoneClient {
    match d {
        Dev::Phone { node, .. } => node,
        _ => panic!("not a phone"),
    }
}

fn pc_node(d: &Dev) -> &PcNode {
    match d {
        Dev::Pc { node, .. } => node,
        _ => panic!("not a PC"),
    }
}

#[test]
fn m42_offline_peer_gets_queued_items_on_its_next_pull_and_unpair_notices() {
    let root = temp_dir("offline");
    let home = RelayBox::start();
    let h = Some(home.url());
    let store_b = Arc::new(MemoryStateStore::default());
    let pc_a = pc("PC A", h.clone(), &root);
    let pc_b = pc_on("PC B", h.clone(), &root, store_b.clone());
    let ph_a = phone("Phone A", h.clone(), &root);
    let ph_b = phone("Phone B", h.clone(), &root);
    let mut boxes = Vec::new();
    {
        let devs = [&pc_a, &pc_b, &ph_a, &ph_b];
        for i in 0..4 {
            for j in i + 1..4 {
                let b = RelayBox::start();
                pair(devs[i], devs[j], false, Some(b.rref()));
                boxes.push(b);
            }
        }
        for d in devs {
            let id = d.id();
            wait("device on the home relay", || home.relay.has_peer(&id));
        }
    }
    let (pa, pb, fa, fb) = (pc_a.id(), pc_b.id(), ph_a.id(), ph_b.id());

    // 1. Phone A is offline: a PC and a phone queue for it.
    phone_node(&ph_a).set_offline_for_tests(true);
    pc_a.send_url(&fa, "https://example.com/queued/pc-a");
    pc_b.send_text(&fa, "queued note from PC B");
    let r = phone_node(&ph_b)
        .send_url(&fa, "https://example.com/queued/phone-b")
        .expect("queued for an offline phone");
    assert_eq!(r.outcome, voidwire_core::net::SendOutcome::Prompted);
    phone_node(&ph_b)
        .send_clipboard_text(&fa, "queued note from Phone B")
        .expect("queued text");
    assert!(!ph_a.got_url("https://example.com/queued/pc-a"));
    // Back online: one pull (an event, not a timer) delivers all four.
    phone_node(&ph_a).set_offline_for_tests(false);
    let n = phone_node(&ph_a).pull_device_inbox_now().expect("pull");
    assert_eq!(n, 4, "four queued items");
    assert!(ph_a.got_url("https://example.com/queued/pc-a"));
    assert!(ph_a.got_url("https://example.com/queued/phone-b"));
    assert!(ph_a.got_text("queued note from PC B"));
    assert!(ph_a.got_text("queued note from Phone B"));
    // Acked: a second pull finds nothing.
    assert_eq!(phone_node(&ph_a).pull_device_inbox_now().unwrap(), 0);

    // 2. PC B is off: the other three queue for it; it pulls when it starts.
    let Dev::Pc { node, .. } = pc_b else {
        unreachable!()
    };
    node.shutdown();
    pc_a.send_url(&pb, "https://example.com/queued/to-pc-b-from-pc");
    let r = phone_node(&ph_a)
        .send_url(&pb, "https://example.com/queued/to-pc-b-from-phone")
        .expect("queued for an offline PC");
    assert_eq!(r.outcome, voidwire_core::net::SendOutcome::Prompted);
    phone_node(&ph_b)
        .send_clipboard_text(&pb, "queued note for PC B")
        .expect("queued text for PC B");
    let pc_b = pc_on("PC B", h.clone(), &root, store_b);
    assert_eq!(pc_b.id(), pb);
    wait("PC B start pull", || {
        pc_b.got_url("https://example.com/queued/to-pc-b-from-pc")
            && pc_b.got_url("https://example.com/queued/to-pc-b-from-phone")
            && pc_b.got_text("queued note for PC B")
    });
    // Window focus pulls too (an event): the first one pulls, then none
    // inside the 5-minute gap and exactly one after it. No timer pulls.
    {
        const GAP: u64 = voidwire_core::net::phone::EVENT_PULL_MIN_GAP_MS;
        // Real time also passes while the test runs; keep 10 s of slack.
        const SLACK: u64 = 10_000;
        let n = pc_node(&pc_b);
        let p0 = n.inbox_pulls_for_tests();
        assert_eq!(n.pull_pairing_inboxes_on_focus().unwrap(), 0);
        assert_eq!(n.inbox_pulls_for_tests(), p0 + 1, "first focus pulls");
        for _ in 0..3 {
            n.advance_event_clock_for_tests(GAP / 4);
            n.pull_pairing_inboxes_on_focus().unwrap();
        }
        n.advance_event_clock_for_tests(GAP / 4 - SLACK);
        n.pull_pairing_inboxes_on_focus().unwrap();
        assert_eq!(n.inbox_pulls_for_tests(), p0 + 1, "no pull inside the gap");
        n.advance_event_clock_for_tests(SLACK);
        n.pull_pairing_inboxes_on_focus().unwrap();
        n.pull_pairing_inboxes_on_focus().unwrap();
        assert_eq!(n.inbox_pulls_for_tests(), p0 + 2, "exactly one after it");

        // The phone's unlock / network events follow the same gate.
        let ph = phone_node(&ph_b);
        let q0 = ph.inbox_pulls_for_tests();
        ph.pull_device_inbox_on_event(false).unwrap();
        ph.advance_event_clock_for_tests(GAP - SLACK);
        ph.pull_device_inbox_on_event(false).unwrap();
        assert_eq!(ph.inbox_pulls_for_tests(), q0 + 1, "phone: none inside");
        ph.advance_event_clock_for_tests(SLACK);
        ph.pull_device_inbox_on_event(false).unwrap();
        ph.pull_device_inbox_on_event(false).unwrap();
        assert_eq!(ph.inbox_pulls_for_tests(), q0 + 2, "phone: one after");
        // Seconds without events: still nothing (no timer).
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(n.inbox_pulls_for_tests(), p0 + 2);
        assert_eq!(ph.inbox_pulls_for_tests(), q0 + 2);
    }

    // 3. Unpair while the peer is off: the notice waits in the inbox.
    phone_node(&ph_b).set_offline_for_tests(true);
    assert!(pc_node(&pc_a).forget_device(&fb).unwrap());
    assert!(pc_node(&pc_a).devices().iter().all(|d| d.id != fb));
    phone_node(&ph_b).set_offline_for_tests(false);
    assert!(phone_node(&ph_b).paired_pcs().iter().any(|p| p.id == pa));
    // The notice goes out in the background after the local erase; each
    // pull is one event (the loop stands in for the user reopening the app).
    wait("the queued unpair notice erased the pairing", || {
        let _ = phone_node(&ph_b).pull_device_inbox_now();
        phone_node(&ph_b).paired_pcs().iter().all(|p| p.id != pa)
    });

    // 4. Unpair live: phone -> PC, and PC -> PC.
    wait("PC B back on the home relay", || home.relay.has_peer(&pb));
    assert!(phone_node(&ph_a).forget_pc(&pb).unwrap());
    wait("PC B drops Phone A", || {
        pc_node(&pc_b).devices().iter().all(|d| d.id != fa)
    });
    assert!(pc_node(&pc_a).forget_device(&pb).unwrap());
    wait("PC B drops PC A", || {
        pc_node(&pc_b).devices().iter().all(|d| d.id != pa)
    });
    // Remaining pairings still carry traffic.
    pc_b.send_url(&fb, "https://example.com/after-unpairs");
    wait("PC B -> Phone B after unpairs", || {
        ph_b.got_url("https://example.com/after-unpairs")
    });
    drop(boxes);
}

/// B10: a third device can neither derive nor use another pairing's inbox.
#[test]
fn m42_b10_third_device_cannot_derive_or_ack_another_pairings_inbox() {
    use voidwire_core::net::mailbox_client::ThrowawaySession;
    use voidwire_core::net::NetError;
    use voidwire_core::reject::RejectReason;

    let root = temp_dir("b10");
    let home = RelayBox::start();
    let shared = RelayBox::start();
    let h = Some(home.url());
    let a = pc("PC A", h.clone(), &root);
    let b = phone("Phone B", h.clone(), &root);
    let c = phone("Phone C", h.clone(), &root);
    // All three pairings keep their inboxes on the same relay.
    pair(&a, &b, false, Some(shared.rref()));
    pair(&a, &c, false, Some(shared.rref()));
    pair(&c, &b, false, Some(shared.rref()));
    for d in [&a, &b, &c] {
        let id = d.id();
        wait("device on the home relay", || home.relay.has_peer(&id));
    }
    let (ai, bi, ci) = (a.id(), b.id(), c.id());

    phone_node(&b).set_offline_for_tests(true);
    a.send_url(&bi, "https://example.com/b10/for-b-only");
    let (_, ab_b) = pc_node(&a).pairing_inbox_keys_for_tests(&bi).unwrap();
    let (ab_b_mine, _) = phone_node(&b).pairing_inbox_keys_for_tests(&ai).unwrap();
    assert_eq!(ab_b.inbox_id, ab_b_mine.inbox_id, "both ends agree");
    let count = || {
        shared
            .server
            .engine()
            .lock()
            .unwrap()
            .device_inbox_item_count(&ab_b.inbox_id)
    };
    assert_eq!(count(), 1);

    // The real derivation: B's inbox on A-B is
    // HKDF(gs_e of A-B, pairing id, epoch, B's device id, B's receive key
    // on A-B). Both ends compute it the same way.
    let ab = pc_node(&a).pairing_inbox_inputs_for_tests(&bi).unwrap();
    let ba = phone_node(&b).pairing_inbox_inputs_for_tests(&ai).unwrap();
    assert_eq!(ab.pairing_id, ba.pairing_id);
    assert_eq!(ab.epoch, ba.epoch);
    assert!(ab.peer_rx == ba.my_rx && ab.my_rx == ba.peer_rx);
    let truth = ab
        .gs_e
        .derive_device_inbox_keys(&ab.pairing_id, ab.epoch, &bi, &ab.peer_rx);
    assert_eq!(truth.inbox_id, ab_b.inbox_id, "the real derivation");
    let a_side = ab
        .gs_e
        .derive_device_inbox_keys(&ab.pairing_id, ab.epoch, &ai, &ab.my_rx);

    // C knows every public input (the pairing id, the epoch, A's and B's
    // real device ids and per-pairing receive keys) but holds only its own
    // pairings' secrets. Nothing it derives lands on either A-B inbox.
    let mut guesses = Vec::new();
    for peer in [ai, bi] {
        let mine = phone_node(&c)
            .pairing_inbox_inputs_for_tests(&peer)
            .unwrap();
        assert_ne!(mine.pairing_id, ab.pairing_id);
        for epoch in ab.epoch.saturating_sub(1)..=ab.epoch + 2 {
            for (dev, rx) in [(bi, &ab.peer_rx), (ai, &ab.my_rx), (ci, &mine.my_rx)] {
                for pid in [ab.pairing_id, mine.pairing_id] {
                    guesses.push(mine.gs_e.derive_device_inbox_keys(&pid, epoch, &dev, rx));
                }
            }
        }
    }
    assert!(guesses.len() >= 36);
    for k in &guesses {
        for target in [&truth, &a_side] {
            assert_ne!(k.inbox_id, target.inbox_id);
            assert_ne!(k.read_verifier, target.read_verifier);
            assert_ne!(k.write_verifier, target.write_verifier);
        }
    }

    // C learns the inbox id (say, by watching the relay) and tries its best
    // guess (its own secret over A-B's public inputs) on it: pull and ack
    // are refused, the item stays.
    let mine = phone_node(&c).pairing_inbox_inputs_for_tests(&bi).unwrap();
    let mut forged = mine
        .gs_e
        .derive_device_inbox_keys(&ab.pairing_id, ab.epoch, &bi, &ab.peer_rx);
    forged.inbox_id = ab_b.inbox_id;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (pull, ack) = rt.block_on(async {
        let s = ThrowawaySession::connect(&shared.server.device_id(), &shared.url())
            .await
            .expect("session");
        let pull = s
            .pull_device_inbox_with_caps(&forged)
            .await
            .map(|(i, _)| i.len());
        let ack = s.ack_device_inbox(&forged, &[[7u8; 16], [0u8; 16]]).await;
        s.close().await;
        (pull, ack)
    });
    assert_eq!(
        pull,
        Err(NetError::Rejected(RejectReason::BadSignature)),
        "forged pull refused"
    );
    assert_eq!(
        ack,
        Err(NetError::Rejected(RejectReason::BadSignature)),
        "forged ack refused"
    );
    assert_eq!(count(), 1, "the item is still there");
    // C's own pull sees nothing of it.
    assert_eq!(phone_node(&c).pull_device_inbox_now().unwrap(), 0);
    assert!(!c.got_url("https://example.com/b10/for-b-only"));
    assert_eq!(count(), 1);

    // B gets it.
    phone_node(&b).set_offline_for_tests(false);
    assert_eq!(phone_node(&b).pull_device_inbox_now().unwrap(), 1);
    assert!(b.got_url("https://example.com/b10/for-b-only"));
    assert_eq!(count(), 0);
}

/// M4.3: an unpair notice survives the app being killed right after the
/// erase. It waits in the encrypted state and goes out on the next start
/// (an event, not a timer); the peer erases its side when it pulls.
#[test]
fn m43_unpair_notice_is_durable_across_a_kill() {
    let root = temp_dir("outbox");
    let home = RelayBox::start();
    let shared = RelayBox::start();
    let h = Some(home.url());
    let store_a = Arc::new(MemoryStateStore::default());
    let store_c = Arc::new(MemoryStateStore::default());
    let pc_a = pc_on("PC A", h.clone(), &root, store_a.clone());
    let pc_b = pc("PC B", h.clone(), &root);
    let ph_b = phone("Phone B", h.clone(), &root);
    let ph_c = phone_on("Phone C", h.clone(), &root, store_c.clone());
    pair(&pc_a, &ph_b, false, Some(shared.rref()));
    pair(&ph_c, &pc_b, false, Some(shared.rref()));
    for d in [&pc_a, &pc_b, &ph_b, &ph_c] {
        let id = d.id();
        wait("device on the home relay", || home.relay.has_peer(&id));
    }
    let (pa, pb, fb, fc) = (pc_a.id(), pc_b.id(), ph_b.id(), ph_c.id());

    // PC -> phone: PC A unpairs and is killed before anything is sent.
    phone_node(&ph_b).set_offline_for_tests(true);
    pc_node(&pc_a).hold_unpair_send_for_tests(true);
    assert!(pc_node(&pc_a).forget_device(&fb).unwrap());
    assert_eq!(pc_node(&pc_a).pending_unpair_notices(), 1);
    let Dev::Pc { node, .. } = pc_a else {
        unreachable!()
    };
    node.shutdown();
    // Nothing reached Phone B.
    phone_node(&ph_b).set_offline_for_tests(false);
    assert_eq!(phone_node(&ph_b).pull_device_inbox_now().unwrap(), 0);
    assert!(phone_node(&ph_b).paired_pcs().iter().any(|p| p.id == pa));
    // Restart: the saved notice goes out on start.
    let pc_a = pc_on("PC A", h.clone(), &root, store_a);
    assert_eq!(pc_a.id(), pa);
    wait("PC A sent the saved notice", || {
        pc_node(&pc_a).pending_unpair_notices() == 0
    });
    let _ = phone_node(&ph_b).pull_device_inbox_now();
    assert!(
        phone_node(&ph_b).paired_pcs().iter().all(|p| p.id != pa),
        "Phone B erased its side"
    );

    // Phone -> PC: Phone C unpairs and is killed before anything is sent.
    phone_node(&ph_c).hold_unpair_send_for_tests(true);
    assert!(phone_node(&ph_c).forget_pc(&pb).unwrap());
    assert_eq!(phone_node(&ph_c).pending_unpair_notices(), 1);
    drop(ph_c);
    assert!(pc_node(&pc_b).devices().iter().any(|d| d.id == fc));
    let ph_c = phone_on("Phone C", h.clone(), &root, store_c);
    assert_eq!(ph_c.id(), fc);
    wait("Phone C sent the saved notice", || {
        phone_node(&ph_c).pending_unpair_notices() == 0
    });
    let _ = pc_node(&pc_b).pull_pairing_inboxes_now();
    assert!(
        pc_node(&pc_b).devices().iter().all(|d| d.id != fc),
        "PC B erased its side"
    );
}
