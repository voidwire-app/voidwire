//! R1: one live production `Inbox` per process. Its own test binary (= its
//! own process), because the check is process-global. One `#[test]` only, so
//! the steps can't race each other on the shared slot.

use voidwire_core::ids::GroupId;
use voidwire_core::keys::{DeviceKeypair, ReceiveKeypair};
use voidwire_core::roster::Roster;
use voidwire_core::verify::{Inbox, InboxConfig, InboxError};

fn roster() -> Roster {
    Roster::genesis(
        GroupId([7; 32]),
        DeviceKeypair::generate().device_id(),
        "PC",
    )
}

fn new_inbox() -> Result<Inbox, InboxError> {
    Inbox::new(roster(), ReceiveKeypair::generate(), InboxConfig::default())
}

#[test]
fn one_live_inbox_at_a_time_r1() {
    // A config error doesn't use up the one slot.
    let bad = InboxConfig {
        timestamp_window_ms: 0,
        ..InboxConfig::default()
    };
    assert!(matches!(
        Inbox::new(roster(), ReceiveKeypair::generate(), bad),
        Err(InboxError::Config(_))
    ));
    let first = new_inbox().expect("first inbox");
    // While it lives, every production constructor refuses.
    assert_eq!(new_inbox().err(), Some(InboxError::SecondInbox));
    assert_eq!(
        Inbox::with_store(
            roster(),
            ReceiveKeypair::generate(),
            InboxConfig::default(),
            Box::new(voidwire_core::replay::NoPersistence)
        )
        .err(),
        Some(InboxError::SecondInbox)
    );
    // A refused construction must not release the live one's slot.
    assert_eq!(new_inbox().err(), Some(InboxError::SecondInbox));

    // Clean restart: dropping the live Inbox releases the slot ...
    drop(first);
    let second = new_inbox().expect("restart after drop");
    // ... and the new one holds it exclusively again.
    assert_eq!(new_inbox().err(), Some(InboxError::SecondInbox));
    drop(second);

    // The same through the PC node: start, shut down, start again in one
    // process (no test-only unchecked constructor).
    #[cfg(feature = "net")]
    pc_node_restarts_in_process();
}

#[cfg(feature = "net")]
fn pc_node_restarts_in_process() {
    use std::sync::Arc;
    use voidwire_core::net::pc::{PcConfig, PcNode};
    use voidwire_core::net::state::MemoryStateStore;
    use voidwire_core::net::NetError;
    use voidwire_core::test_util::SharedSpyOpener;

    let state = Arc::new(MemoryStateStore::default());
    let cfg = |state: Arc<MemoryStateStore>| {
        let mut c = PcConfig::new("R1 PC", state, Arc::new(SharedSpyOpener::default()));
        c.mdns = false;
        c.port = Some(0);
        c
    };
    let pc = PcNode::start(cfg(state.clone())).expect("first node");
    let id = pc.device_id();
    // A second node while the first runs: refused (R1).
    match PcNode::start(cfg(Arc::new(MemoryStateStore::default()))) {
        Err(NetError::Protocol(m)) => assert!(m.contains("live PC node"), "{m}"),
        other => panic!("second live node: {other:?}"),
    }
    pc.shutdown();
    let pc = PcNode::start(cfg(state)).expect("restart in the same process");
    assert_eq!(pc.device_id(), id);
    pc.shutdown();
    // Dropping without shutdown() releases it too.
    let pc = PcNode::start(cfg(Arc::new(MemoryStateStore::default()))).expect("third");
    drop(pc);
    PcNode::start(cfg(Arc::new(MemoryStateStore::default())))
        .expect("after drop")
        .shutdown();
}
