//! Shared harness for the multi-device tests (M4.2, M4.3).
#![allow(dead_code)]

pub use std::path::{Path, PathBuf};
pub use std::sync::Arc;
pub use std::time::Duration;

pub use voidwire_core::file_transfer::{RelayPromptDecision, TransferId};
pub use voidwire_core::ids::DeviceId;
pub use voidwire_core::keys::Platform;
pub use voidwire_core::net::pc::{PcConfig, PcNode};
pub use voidwire_core::net::phone::{IncomingItemKind, PhoneClient, PhoneConfig};
pub use voidwire_core::net::state::MemoryStateStore;
pub use voidwire_core::net::test_relay::TestRelay;
pub use voidwire_core::net::{pair_v2_for_tests, V2Node};
pub use voidwire_core::pairwise::RelayRef;
pub use voidwire_core::ratelimit::RateLimit;
pub use voidwire_core::test_util::SharedSpyOpener;
pub use voidwire_core::verify::InboxConfig;
pub use voidwire_mailbox::{MailboxLimits, MailboxServer, MailboxServerConfig};

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

pub fn roomy() -> InboxConfig {
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
    // The app UI is open (M4.4: away relays are held only then).
    node.set_app_foreground(true);
    Dev::Phone { node, dl }
}

pub fn loopback(v: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
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

pub fn phone_node(d: &Dev) -> &PhoneClient {
    match d {
        Dev::Phone { node, .. } => node,
        _ => panic!("not a phone"),
    }
}

pub fn pc_node(d: &Dev) -> &PcNode {
    match d {
        Dev::Pc { node, .. } => node,
        _ => panic!("not a PC"),
    }
}
