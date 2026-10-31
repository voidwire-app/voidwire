//! R1: one live PC node per process. Its own test binary (= its own
//! process), because the check is process-global. One `#[test]` only, so the
//! steps can't race each other on the shared slot.

#[test]
fn one_live_pc_node_at_a_time_r1() {
    // Start, shut down, start again in one process (no test-only unchecked
    // constructor).
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
