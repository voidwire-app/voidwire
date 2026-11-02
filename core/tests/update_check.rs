//! U1 update check end to end against a local HTTP server: signature, key
//! list, channel, anti-rollback, the once-a-day rule (no request when not
//! due), the download hash check, and the settings that survive a restart.
#![cfg(all(feature = "updates", feature = "test-util"))]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use voidwire_core::update::{
    check, download, sig, verify_file, Channel, CheckError, DownloadError, Outcome, Platform,
    Source, Trigger, UpdatePrefs,
};

const TEST_SEED: [u8; 32] = [0x31; 32];
const NEXT_SEED: [u8; 32] = [0x32; 32];
const STABLE_SEED: [u8; 32] = [0x33; 32];
const DAY: u32 = 20_394;

type Routes = Arc<Mutex<HashMap<String, (u16, Vec<u8>, Option<String>)>>>;

struct Server {
    base: String,
    routes: Routes,
    hits: Arc<AtomicUsize>,
}

impl Server {
    async fn start() -> Server {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let routes: Routes = Arc::default();
        let hits = Arc::new(AtomicUsize::new(0));
        let (r, h) = (routes.clone(), hits.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                let (r, h) = (r.clone(), h.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&b[..n]),
                        }
                    }
                    h.fetch_add(1, Ordering::SeqCst);
                    let req = String::from_utf8_lossy(&buf);
                    let path = req.split_whitespace().nth(1).unwrap_or("").to_owned();
                    assert!(
                        req.to_ascii_lowercase()
                            .contains("user-agent: voidwire\r\n"),
                        "anonymous UA only: {req}"
                    );
                    assert!(!path.contains('?'), "no query string");
                    let (code, body, loc) =
                        r.lock()
                            .unwrap()
                            .get(&path)
                            .cloned()
                            .unwrap_or((404, Vec::new(), None));
                    let mut head = format!(
                        "HTTP/1.1 {code} X\r\ncontent-length: {}\r\nconnection: close\r\n",
                        body.len()
                    );
                    if let Some(l) = loc {
                        head.push_str(&format!("location: {l}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(&body).await;
                });
            }
        });
        Server { base, routes, hits }
    }

    fn put(&self, path: &str, body: Vec<u8>) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_owned(), (200, body, None));
    }

    fn get(&self, path: &str) -> Vec<u8> {
        self.routes.lock().unwrap()[path].1.clone()
    }

    fn redirect(&self, path: &str, to: &str) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_owned(), (302, Vec::new(), Some(to.to_owned())));
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// Publish `channel.json` signed with `seed`, offering `file` as build
    /// `build` for Windows.
    fn publish(&self, seed: &[u8; 32], channel: &str, seq: u64, build: u32, file: &[u8]) {
        use sha2::Digest;
        self.put("/setup.exe", file.to_vec());
        let m = format!(
            r#"{{"schema":1,"channel":"{channel}","seq":{seq},"version":"9.9.{build}","build":{build},
"released":"2026-11-05","notes_url":"{}/releases/tag/v9.9.{build}",
"files":{{"windows-x86_64-nsis":{{"url":"{}/setup.exe","sha256":"{}","size":{}}}}}}}"#,
            voidwire_core::update::REPO_URL,
            self.base,
            voidwire_core::hex::encode(&sha2::Sha256::digest(file)),
            file.len()
        );
        self.put(
            &format!("/{channel}.json.sig"),
            sig::sign(seed, m.as_bytes()).into_bytes(),
        );
        self.put(&format!("/{channel}.json"), m.into_bytes());
    }

    fn source(&self, installed: u32, build_channel: Channel) -> Source {
        Source::for_tests(
            &self.base,
            installed,
            build_channel,
            vec![sig::public_key(&STABLE_SEED)],
            vec![sig::public_key(&TEST_SEED), sig::public_key(&NEXT_SEED)],
        )
    }
}

async fn run(src: &Source, p: &mut UpdatePrefs, t: Trigger, day: u32) -> Outcome {
    check(src, p, t, day, Platform::WindowsNsis).await
}

#[tokio::test]
async fn signed_newer_build_is_offered_and_downloads() {
    let s = Server::start().await;
    s.publish(&TEST_SEED, "test", 1_000, 34, b"installer-34");
    let src = s.source(33, Channel::Test);
    let mut p = UpdatePrefs::default();
    let Outcome::Available(o) = run(&src, &mut p, Trigger::AppStart, DAY).await else {
        panic!("no offer")
    };
    assert_eq!((o.build, o.version.as_str()), (34, "9.9.34"));
    assert_eq!((p.last_check_day, p.seen_seq(Channel::Test)), (DAY, 1_000));

    let dir = std::env::temp_dir().join(format!("vw-upd-{}", s.base.rsplit(':').next().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("setup.exe");
    let mut seen = Vec::new();
    let v = download(&src, &o, &dest, &mut |d, t| seen.push((d, t)))
        .await
        .expect("download");
    assert_eq!(std::fs::read(v.path()).unwrap(), b"installer-34");
    assert_eq!(seen.last(), Some(&(12, 12)));
    assert!(verify_file(&dest, &o).is_ok());

    // Swapped asset: deleted, security error.
    s.put("/setup.exe", b"installer-XX".to_vec());
    assert_eq!(
        download(&src, &o, &dest, &mut |_, _| {}).await,
        Err(DownloadError::Security)
    );
    assert!(!dest.exists() && !dest.with_extension("part").exists());
    // Longer than signed: refused, nothing left behind.
    s.put("/setup.exe", b"installer-34-and-more".to_vec());
    assert_eq!(
        download(&src, &o, &dest, &mut |_, _| {}).await,
        Err(DownloadError::Security)
    );
    assert!(!dest.exists() && !dest.with_extension("part").exists());
    // Changed on disk after the download: verify deletes it.
    std::fs::write(&dest, b"installer-35").unwrap();
    assert_eq!(verify_file(&dest, &o), Err(DownloadError::Security));
    assert!(!dest.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn signature_and_key_list() {
    let s = Server::start().await;
    let src = s.source(33, Channel::Test);
    // Signed by the stable key: not trusted on the test channel.
    s.publish(&STABLE_SEED, "test", 1, 34, b"x");
    let mut p = UpdatePrefs::default();
    assert_eq!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Failed(CheckError::Signature)
    );
    assert_eq!(
        p,
        UpdatePrefs::default(),
        "nothing stored from a bad manifest"
    );
    // The second pinned test key (rotation) is accepted.
    s.publish(&NEXT_SEED, "test", 1, 34, b"x");
    assert!(matches!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Available(_)
    ));
    // Missing signature file.
    s.routes.lock().unwrap().remove("/test.json.sig");
    assert_eq!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Failed(CheckError::Signature)
    );
}

#[tokio::test]
async fn rollback_and_downgrade_refused() {
    let s = Server::start().await;
    let src = s.source(33, Channel::Test);
    let mut p = UpdatePrefs::default();
    s.publish(&TEST_SEED, "test", 500, 35, b"x");
    assert!(matches!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Available(_)
    ));
    // A replayed older manifest (lower seq) is refused even with a newer build.
    s.publish(&TEST_SEED, "test", 499, 36, b"x");
    assert_eq!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Failed(CheckError::Rollback)
    );
    // Same or older build: up to date.
    s.publish(&TEST_SEED, "test", 501, 33, b"x");
    assert_eq!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::UpToDate
    );
    s.publish(&TEST_SEED, "test", 502, 30, b"x");
    assert_eq!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::UpToDate
    );
    assert_eq!(p.seen_seq(Channel::Test), 502);
}

#[tokio::test]
async fn channels() {
    let s = Server::start().await;
    // A stable build reads stable.json; none published yet: up to date.
    let stable = s.source(33, Channel::Stable);
    let mut p = UpdatePrefs::default();
    s.publish(&TEST_SEED, "test", 1, 34, b"x");
    assert_eq!(
        run(&stable, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::UpToDate
    );
    // "Test builds" on: the same install reads test.json.
    p.test_builds = Some(true);
    assert!(matches!(
        run(&stable, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Available(_)
    ));
    // A stable.json that says "test" inside is refused, even when signed by
    // the stable key.
    let body = s.get("/test.json");
    s.put(
        "/stable.json.sig",
        sig::sign(&STABLE_SEED, &body).into_bytes(),
    );
    s.put("/stable.json", body);
    p.test_builds = Some(false);
    assert_eq!(
        run(&stable, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Failed(CheckError::Channel)
    );
    // A real stable manifest signed by the stable key.
    s.publish(&STABLE_SEED, "stable", 7, 34, b"x");
    assert!(matches!(
        run(&stable, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Available(_)
    ));
    assert_eq!(
        (p.seen_seq(Channel::Stable), p.seen_seq(Channel::Test)),
        (7, 1)
    );
}

#[tokio::test]
async fn no_request_unless_due() {
    let s = Server::start().await;
    s.publish(&TEST_SEED, "test", 1, 33, b"x");
    let src = s.source(33, Channel::Test);
    let mut p = UpdatePrefs::default();
    assert_eq!(
        run(&src, &mut p, Trigger::AppStart, DAY).await,
        Outcome::UpToDate
    );
    let after_first = s.hits();
    assert_eq!(after_first, 2, "one manifest GET and one signature GET");
    // Same UTC day: start and window-open triggers make no request.
    for t in [Trigger::AppStart, Trigger::WindowOpened, Trigger::AppStart] {
        assert_eq!(run(&src, &mut p, t, DAY).await, Outcome::Skipped);
    }
    assert_eq!(s.hits(), after_first);
    // "Check now" always asks.
    assert_eq!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::UpToDate
    );
    assert_eq!(s.hits(), after_first + 2);
    // Next day: one more.
    assert_eq!(
        run(&src, &mut p, Trigger::WindowOpened, DAY + 1).await,
        Outcome::UpToDate
    );
    assert_eq!(s.hits(), after_first + 4);
    // Checks off: automatic triggers never ask.
    p.checks_on = false;
    assert_eq!(
        run(&src, &mut p, Trigger::AppStart, DAY + 9).await,
        Outcome::Skipped
    );
    assert_eq!(s.hits(), after_first + 4);
    // A failed check does not count as done for the day.
    let mut q = UpdatePrefs::default();
    s.routes
        .lock()
        .unwrap()
        .insert("/test.json".into(), (500, vec![], None));
    assert_eq!(
        run(&src, &mut q, Trigger::AppStart, DAY).await,
        Outcome::Failed(CheckError::Network)
    );
    assert_eq!(q.last_check_day, 0);
}

#[tokio::test]
async fn redirects_only_to_allowed_hosts() {
    let s = Server::start().await;
    s.publish(&TEST_SEED, "test", 1, 34, b"x");
    let src = s.source(33, Channel::Test);
    // The manifest moved to another host: not followed.
    s.redirect("/test.json", "http://localhost:1/test.json");
    let mut p = UpdatePrefs::default();
    assert_eq!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Failed(CheckError::Network)
    );
    // Same host: followed.
    s.publish(&TEST_SEED, "test", 1, 34, b"x");
    s.put("/v1/test.json", s.get("/test.json"));
    s.redirect("/test.json", &format!("{}/v1/test.json", s.base));
    assert!(matches!(
        run(&src, &mut p, Trigger::CheckNow, DAY).await,
        Outcome::Available(_)
    ));
}

#[test]
fn prefs_survive_restart_and_off_clears_state() {
    use voidwire_core::keys::Platform as DevPlatform;
    use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
    use voidwire_core::net::state::MemoryStateStore;
    let store = Arc::new(MemoryStateStore::default());
    let open = || {
        PhoneClient::new(PhoneConfig {
            state: store.clone(),
            default_name: "Phone".into(),
            platform: DevPlatform::Android,
            mdns: false,
        })
        .expect("phone")
    };
    let p = open();
    assert_eq!(p.update_prefs(), UpdatePrefs::default());
    let mut u = p.update_prefs();
    u.test_builds = Some(true);
    u.last_check_day = DAY;
    u.seen_seq = [3, 4];
    p.set_update_prefs(&u).unwrap();
    drop(p);
    let p = open();
    assert_eq!(p.update_prefs(), u);
    u.checks_on = false;
    p.set_update_prefs(&u).unwrap();
    drop(p);
    let p = open();
    let got = p.update_prefs();
    assert!(!got.checks_on);
    assert_eq!(got.test_builds, Some(true));
    assert_eq!((got.last_check_day, got.seen_seq), (0, [0, 0]));
}
