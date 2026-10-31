//! Forget vs. items already queued on the relay mailbox for a phone whose
//! app was closed: a queued file offer (`FileWake`) and a queued link must
//! not show up after Forget, must not be fetchable, and must leave nothing
//! on the relay or on disk.
mod common;
use common::*;

const MIME: &str = "application/octet-stream";

fn queued_bytes(b: &RelayBox) -> usize {
    b.server
        .engine()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .device_inbox_total_bytes()
}

fn part_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                .filter(|n| n.contains(".part"))
                .collect()
        })
        .unwrap_or_default()
}

/// The PC queues a file offer and a link while the phone is offline, then
/// queues them on the pairing's relay inbox.
fn queue_offer_and_link(a: &Dev, b: &Dev, r: &RelayBox) -> TransferId {
    let bi = b.id();
    phone_node(b).set_offline_for_tests(true);
    let tid = TransferId::random();
    let rep = pc_node(a)
        .send_file_bytes_to_phone(
            &bi,
            tid,
            "queued.bin",
            MIME,
            &[7u8; 4096],
            Some(RelayPromptDecision::SendViaRelay),
        )
        .expect("queued for an offline phone");
    assert_eq!(
        rep.delivery_path,
        voidwire_core::net::DeliveryPath::QueuedInDeviceInbox
    );
    a.send_url(&bi, "https://example.com/m2/queued");
    assert!(queued_bytes(r) > 0, "both wait on the relay");
    tid
}

fn setup() -> (PathBuf, RelayBox, RelayBox, Dev, Dev) {
    let root = temp_dir("m2-queued");
    let home = RelayBox::start();
    let r = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let b = phone("Phone B", Some(home.url()), &root);
    phone_node(&b).set_auto_accept_files(false);
    pair(&a, &b, false, Some(r.rref()));
    (root, home, r, a, b)
}

/// The phone forgets the PC (its notice held, so the PC still thinks it's
/// paired) while the offer and link wait on the relay. Back online, a pull
/// shows neither, a second pull finds nothing, and the relay holds nothing.
#[test]
fn m2_phone_forget_drops_the_queued_file_offer_and_link() {
    let (_root, _home, r, a, b) = setup();
    let ai = a.id();
    let tid = queue_offer_and_link(&a, &b, &r);
    let ph = phone_node(&b);
    ph.hold_unpair_send_for_tests(true);
    assert!(ph.forget_pc(&ai).unwrap());
    ph.set_offline_for_tests(false);
    assert_eq!(ph.pull_device_inbox_now().unwrap_or(0), 0, "nothing added");
    let snap = ph.poll_incoming();
    assert!(
        snap.files.iter().all(|f| f.transfer_id != tid),
        "the queued offer is gone"
    );
    assert!(!b.got_url("https://example.com/m2/queued"));
    assert!(ph
        .accept_incoming_file(&tid, Some(b.dl()), Some(RelayPromptDecision::SendViaRelay))
        .is_err());
    assert!(part_files(b.dl()).is_empty(), "no .part");
    assert_eq!(ph.pull_device_inbox_now().unwrap_or(0), 0);
    // That pull also sent the held Forget notice to the PC's inbox; once
    // the PC reads it, the PC drops the file and the relay holds nothing.
    let _ = pc_node(&a).pull_pairing_inboxes_now();
    wait("the PC dropped the phone", || {
        pc_node(&a)
            .outgoing_files()
            .iter()
            .all(|f| f.transfer_id != tid)
    });
    wait("the relay inbox purged", || queued_bytes(&r) == 0);
}

/// The PC forgets the phone after queuing: the PC drops the file at once,
/// the phone drops the PC (and the offer and link) on the PC's notice, and
/// the file can't be fetched.
#[test]
fn m2_pc_forget_leaves_the_queued_file_offer_unfetchable() {
    let (_root, _home, r, a, b) = setup();
    let bi = b.id();
    let tid = queue_offer_and_link(&a, &b, &r);
    assert!(pc_node(&a)
        .outgoing_files()
        .iter()
        .any(|f| f.transfer_id == tid));
    assert!(pc_node(&a).forget_device(&bi).unwrap());
    assert!(
        pc_node(&a)
            .outgoing_files()
            .iter()
            .all(|f| f.transfer_id != tid),
        "the PC dropped the queued file"
    );
    let ph = phone_node(&b);
    ph.set_offline_for_tests(false);
    let _ = ph.pull_device_inbox_now();
    wait("the phone dropped the PC", || ph.paired_pcs().is_empty());
    assert!(ph
        .poll_incoming()
        .files
        .iter()
        .all(|f| f.transfer_id != tid));
    assert!(!b.got_url("https://example.com/m2/queued"));
    assert!(ph
        .accept_incoming_file(&tid, Some(b.dl()), Some(RelayPromptDecision::SendViaRelay))
        .is_err());
    assert!(part_files(b.dl()).is_empty(), "no .part");
    // Not asserted: the relay can still hold the PC's own durable copy of
    // its unpair notice if it lands after the phone's erase pull. That
    // copy is for a device that already acted on it and expires at TTL.
    let _ = &r;
}
