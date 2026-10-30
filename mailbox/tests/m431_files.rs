//! v0.7.1: files between every kind of pairing with Accept turned on (the
//! apps' default), leftover `.part` cleanup, and the saved download folder.
mod common;
use common::*;

use voidwire_core::file_transfer::{part_paths, PartResumeMeta};
use voidwire_core::time::UnixMillis;

const MIME: &str = "application/octet-stream";

/// `.part`, `.part.meta` and `.part.meta.tmp` files in `dir`.
fn part_files(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                .filter(|n| n.contains(".part"))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Wait for the offer `tid` to show up on `b`, like the receive card.
fn wait_offer(b: &Dev, tid: &TransferId) {
    wait("the offer on the receiver", || match b {
        Dev::Pc { node, .. } => node.incoming_files().iter().any(|f| f.transfer_id == *tid),
        Dev::Phone { node, .. } => node
            .poll_incoming()
            .files
            .iter()
            .any(|f| f.transfer_id == *tid),
    });
}

/// `a` sends `data` the way the app does; `b` gets an offer and taps Accept.
/// The bytes must arrive and no `.part` may stay behind on `b`.
fn send_with_accept(a: &Dev, b: &Dev, name: &str, data: &[u8], src_dir: &Path) {
    let tid = TransferId::random();
    let to = b.id();
    std::thread::scope(|s| {
        let sender = s.spawn(|| match a {
            // The PC sends the offer and returns: the receiver has to pull.
            Dev::Pc { node, .. } => {
                let r = node
                    .send_file_bytes_to_phone(
                        &to,
                        tid,
                        name,
                        MIME,
                        data,
                        Some(RelayPromptDecision::SendViaRelay),
                    )
                    .map_err(|e| format!("{e:?}"))?;
                assert!(r.awaiting_accept, "{name}: the receiver asks first");
                Ok::<(), String>(())
            }
            // The phone app path: re-offer until accepted, then push.
            Dev::Phone { node, .. } => {
                let path = src_dir.join(name);
                std::fs::write(&path, data).unwrap();
                node.send_file_awaiting_accept(
                    &to,
                    tid,
                    &path,
                    MIME,
                    Some(RelayPromptDecision::SendViaRelay),
                    150,
                    Duration::from_millis(400),
                )
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
            }
        });
        wait_offer(b, &tid);
        assert!(!b.got_file(name, data), "{name}: nothing before Accept");
        match b {
            Dev::Pc { node, .. } => {
                node.accept_file(&tid).expect("accept on the PC");
            }
            Dev::Phone { node, .. } => {
                let p = node
                    .accept_incoming_file(
                        &tid,
                        Some(b.dl()),
                        Some(RelayPromptDecision::SendViaRelay),
                    )
                    .unwrap_or_else(|e| panic!("{name}: accept on the phone: {e:?}"));
                assert_eq!(std::fs::read(&p).unwrap(), data, "{name}: saved bytes");
            }
        }
        wait(&format!("{name} on the receiver"), || {
            b.got_file(name, data)
        });
        sender
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("{name}: sender: {e}"));
    });
    wait(&format!("{name}: no .part left"), || {
        part_files(b.dl()).is_empty()
    });
}

fn manual(d: &Dev) {
    match d {
        Dev::Pc { node, .. } => node.set_auto_accept_files(false),
        Dev::Phone { node, .. } => node.set_auto_accept_files(false),
    }
}

/// The owner's hardware test: PC<->PC stalled at 0 bytes after Accept and
/// phone<->phone failed with a pairing-QR error. Both ways, small and large,
/// over direct links and (PC<->PC, phone<->phone) over the relay only.
#[test]
fn m431_files_with_accept_arrive_between_every_kind_of_pairing() {
    let root = temp_dir("m431-files");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let home = RelayBox::start();
    let h = Some(home.url());
    let pc_a = pc("PC A", h.clone(), &root);
    let pc_b = pc("PC B", h.clone(), &root);
    let ph_a = phone("Phone A", h.clone(), &root);
    let ph_b = phone("Phone B", h.clone(), &root);
    for d in [&pc_a, &pc_b, &ph_a, &ph_b] {
        manual(d);
        let id = d.id();
        wait("device on the home relay", || home.relay.has_peer(&id));
    }
    pair(&pc_a, &pc_b, true, None);
    pair(&ph_a, &ph_b, true, None);
    pair(&pc_a, &ph_a, true, None);

    let small: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let large: Vec<u8> = (0..(3 * 1024 * 1024 + 4321))
        .map(|i| (i % 249) as u8)
        .collect();
    let pairs: [(&Dev, &Dev, &str); 6] = [
        (&pc_a, &pc_b, "pc-a-to-pc-b"),
        (&pc_b, &pc_a, "pc-b-to-pc-a"),
        (&ph_a, &ph_b, "phone-a-to-phone-b"),
        (&ph_b, &ph_a, "phone-b-to-phone-a"),
        (&pc_a, &ph_a, "pc-a-to-phone-a"),
        (&ph_a, &pc_a, "phone-a-to-pc-a"),
    ];
    for (a, b, tag) in pairs {
        send_with_accept(a, b, &format!("{tag}-small.bin"), &small, &src);
        send_with_accept(a, b, &format!("{tag}-large.bin"), &large, &src);
    }
}

/// Over the relay only (no direct addresses), PC<->PC and phone<->phone.
#[test]
fn m431_files_with_accept_arrive_over_the_relay() {
    let root = temp_dir("m431-relay");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let home = RelayBox::start();
    let h = Some(home.url());
    let pc_a = pc("PC A", h.clone(), &root);
    let pc_b = pc("PC B", h.clone(), &root);
    let ph_a = phone("Phone A", h.clone(), &root);
    let ph_b = phone("Phone B", h.clone(), &root);
    for d in [&pc_a, &pc_b, &ph_a, &ph_b] {
        manual(d);
        let id = d.id();
        wait("device on the home relay", || home.relay.has_peer(&id));
    }
    pair(&pc_a, &pc_b, false, Some(home.rref()));
    pair(&ph_a, &ph_b, false, Some(home.rref()));
    let data: Vec<u8> = (0..(2 * 1024 * 1024 + 77))
        .map(|i| (i % 241) as u8)
        .collect();
    for (a, b, tag) in [
        (&pc_a, &pc_b, "relay-pc-a-to-pc-b"),
        (&pc_b, &pc_a, "relay-pc-b-to-pc-a"),
        (&ph_a, &ph_b, "relay-phone-a-to-phone-b"),
        (&ph_b, &ph_a, "relay-phone-b-to-phone-a"),
    ] {
        send_with_accept(a, b, &format!("{tag}.bin"), &data, &src);
    }
}

/// Accepting after the sender went away fails cleanly and deletes the
/// `.part` and `.part.meta` the accept created (PC and phone receivers).
#[test]
fn m431_a_failed_accept_leaves_no_part_files() {
    let root = temp_dir("m431-fail");
    let data = vec![0x42u8; 1024 * 1024 + 9];
    for receiver_is_phone in [false, true] {
        let a = pc("PC A", None, &root);
        let b = if receiver_is_phone {
            phone("Phone B", None, &root)
        } else {
            pc("PC B", None, &root)
        };
        manual(&b);
        pair(&a, &b, true, None);
        let tid = TransferId::random();
        let r = pc_node(&a)
            .send_file_bytes_to_phone(&b.id(), tid, "gone.bin", MIME, &data, None)
            .expect("offer");
        assert!(r.awaiting_accept);
        wait_offer(&b, &tid);
        drop(a); // the sender quits before the receiver taps Accept
        match &b {
            Dev::Pc { node, .. } => {
                node.accept_file(&tid).expect("accept starts");
                wait("the failed pull to end the transfer", || {
                    node.incoming_files().iter().all(|f| f.transfer_id != tid)
                });
            }
            Dev::Phone { node, .. } => {
                let e = node
                    .accept_incoming_file(
                        &tid,
                        Some(b.dl()),
                        Some(RelayPromptDecision::SendViaRelay),
                    )
                    .expect_err("the sender is gone");
                assert!(!format!("{e:?}").contains("pairing"), "{e:?}");
            }
        }
        wait("no .part left", || part_files(b.dl()).is_empty());
        assert!(!b.got_file("gone.bin", &data));
    }
}

/// Cancelling an accepted transfer on the receiver deletes its files.
#[test]
fn m431_cancel_after_accept_leaves_no_part_files() {
    let root = temp_dir("m431-cancel");
    let a = pc("PC A", None, &root);
    let b = pc("PC B", None, &root);
    manual(&b);
    pair(&a, &b, true, None);
    let data: Vec<u8> = (0..(8 * 1024 * 1024)).map(|i| (i % 253) as u8).collect();
    let tid = TransferId::random();
    pc_node(&a)
        .send_file_bytes_to_phone(&b.id(), tid, "cancel.bin", MIME, &data, None)
        .expect("offer");
    wait_offer(&b, &tid);
    pc_node(&b).accept_file(&tid).expect("accept");
    assert!(pc_node(&b).cancel_file(&tid) || part_files(b.dl()).is_empty());
    wait("no .part left after cancel", || {
        part_files(b.dl()).is_empty()
    });
}

/// On start, a PC deletes the `.part` pairs it left behind (matched by our
/// own `.part.meta`), and leaves every other file in the folder alone.
#[test]
fn m431_startup_deletes_only_our_stale_part_files() {
    let root = temp_dir("m431-startup");
    let store = Arc::new(MemoryStateStore::default());
    let dl = {
        let a = pc_on("PC A", None, &root, store.clone());
        a.dl().to_path_buf()
    };
    let tid = TransferId::random();
    let (part, meta) = part_paths(&dl, &tid);
    std::fs::write(&part, b"half a file").unwrap();
    let m = PartResumeMeta {
        transfer_id: tid,
        total_size: 2 * 1024 * 1024,
        chunk_count: 2,
        next_chunk: 1,
        blake3_root: [7u8; 32],
        filename: "photo.jpg".into(),
        // Not expired: a quit mid-transfer is stale after a restart too.
        expires_at: UnixMillis(u64::MAX / 2),
    };
    std::fs::write(&meta, m.to_bytes()).unwrap();
    let tmp = dl.join(format!("{}.part.meta.tmp", tid.to_hex()));
    std::fs::write(&tmp, b"torn").unwrap();
    // Not ours: a browser download, a .part with no meta of ours, junk meta,
    // and a meta of ours that names another transfer.
    let other = TransferId::random();
    let foreign = [
        dl.join("movie.mkv.part"),
        dl.join(format!("{}.part", other.to_hex())),
        dl.join("notes.part.meta"),
        dl.join(format!("{}.part.meta", TransferId::random().to_hex())),
    ];
    std::fs::write(&foreign[0], b"browser").unwrap();
    std::fs::write(&foreign[1], b"orphan").unwrap();
    std::fs::write(&foreign[2], b"junk").unwrap();
    let mut wrong = m.clone();
    wrong.transfer_id = other;
    std::fs::write(&foreign[3], wrong.to_bytes()).unwrap();

    let _a = pc_on("PC A", None, &root, store);
    assert!(
        !part.exists() && !meta.exists() && !tmp.exists(),
        "{:?}",
        part_files(&dl)
    );
    for f in &foreign {
        assert!(f.exists(), "{} must stay", f.display());
    }
}

/// The folder picked in Settings survives restarts and upgrades: the app
/// passes its default folder on every start and that used to win.
#[test]
fn m431_custom_download_folder_survives_a_restart() {
    let root = temp_dir("m431-folder");
    let store = Arc::new(MemoryStateStore::default());
    let custom = root.join("My Files");
    {
        let a = pc_on("PC A", None, &root, store.clone());
        pc_node(&a).set_download_dir(custom.clone()).expect("pick");
        assert_eq!(pc_node(&a).download_dir(), custom);
    }
    for _ in 0..2 {
        let a = pc_on("PC A", None, &root, store.clone());
        assert_eq!(pc_node(&a).download_dir(), custom, "kept after a restart");
    }
    // Picking the default again goes back to following the default.
    let a = pc_on("PC A", None, &root, store.clone());
    pc_node(&a).reset_download_dir().expect("reset");
    drop(a);
    let a = pc_on("PC A", None, &root, store);
    assert_eq!(pc_node(&a).download_dir(), a.dl());
}
