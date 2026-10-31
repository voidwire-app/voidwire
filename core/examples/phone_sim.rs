//! A phone simulator for QA and support: pairs with a Voidwire PC and sends
//! links, using the same client code as the Android app.
//!
//! ```text
//! cargo run -p voidwire-core --features net --example phone_sim -- \
//!     --state /tmp/phone.bin pair 'voidwire:pair?...'     # prints the code
//! cargo run ... --example phone_sim -- --state /tmp/phone.bin list
//! cargo run ... --example phone_sim -- --state /tmp/phone.bin send https://example.com [count]
//! ```
//! `--no-mdns` uses only the QR's address hints.

// Latency printout for humans only.
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use voidwire_core::keys::Platform;
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::FileStateStore;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut state = std::env::temp_dir().join("voidwire-phone-sim.bin");
    let mut mdns = true;
    let mut name = "Phone simulator".to_string();
    loop {
        match args.first().map(String::as_str) {
            Some("--state") => {
                state = args[1].clone().into();
                args.drain(..2);
            }
            Some("--name") => {
                name = args[1].clone();
                args.drain(..2);
            }
            Some("--no-mdns") => {
                mdns = false;
                args.remove(0);
            }
            _ => break,
        }
    }
    let client = PhoneClient::new(PhoneConfig {
        state: Arc::new(FileStateStore::new(&state)),
        default_name: name.clone(),
        platform: Platform::Android,
        mdns,
    })
    .unwrap_or_else(|e| die(&format!("start: {e}")));
    match args.first().map(String::as_str) {
        Some("pair") => {
            let qr = args.get(1).unwrap_or_else(|| die("pair <qr text>"));
            let _ = client.set_device_name(&name);
            let opened = client
                .pair2_open_qr(qr)
                .unwrap_or_else(|e| die(&format!("pair: {e}")));
            if !matches!(opened.relay, voidwire_core::net::pair2::RelayCheck::Saved) {
                client
                    .pair2_add_relay()
                    .unwrap_or_else(|e| die(&format!("add relay: {e}")));
            }
            let sas = client
                .pair2_join()
                .unwrap_or_else(|e| die(&format!("pair: {e}")));
            let shown = opened.inviter_name.as_deref().unwrap_or("the other device");
            println!("Type this code on \"{shown}\": {sas}");
            match client.pair2_join_wait() {
                Ok(p) => println!("Paired with {} ({})", p.name, p.peer.to_hex()),
                Err(e) => die(&format!("pairing failed: {e}")),
            }
        }
        Some("list") => {
            for pc in client.paired_pcs() {
                println!(
                    "{}  {}{}  {:?}",
                    pc.id.to_hex(),
                    pc.name,
                    if pc.removed { " (removed us)" } else { "" },
                    pc.addrs
                );
            }
        }
        Some("send") => {
            let url = args.get(1).unwrap_or_else(|| die("send <url> [count]"));
            let count: usize = args.get(2).and_then(|c| c.parse().ok()).unwrap_or(1);
            let pc = client
                .paired_pcs()
                .into_iter()
                .next()
                .unwrap_or_else(|| die("not paired"));
            for i in 0..count {
                let u = if count > 1 {
                    format!("{url}{}n={i}", if url.contains('?') { '&' } else { '?' })
                } else {
                    url.clone()
                };
                match client.send_url(&pc.id, &u) {
                    Ok(r) => println!(
                        "{i}: {:?} in {:.2} ms",
                        r.outcome,
                        r.latency_us as f64 / 1000.0
                    ),
                    Err(e) => println!("{i}: refused: {e}"),
                }
            }
        }
        _ => die("usage: phone_sim [--state FILE] [--name NAME] [--no-mdns] pair <qr> | list | send <url> [count]"),
    }
}

fn die(msg: &str) -> ! {
    panic!("{msg}")
}
