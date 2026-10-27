// expect: E0308
// QA probe p01 on the D2 API: verify against an attacker-built roster, then
// call UrlOpener::open directly with the VerifiedUrl (skipping deliver/confirm).
use voidwire_core::{ids::*, keys::{DeviceKeypair, ReceiveKeypair}, opener::*, pairing::*, roster::*, time::*, verify::*, wire::*, envelope};
struct Print;
impl UrlOpener for Print {
    fn open(&self, a: OpenApproval) -> Result<(), OpenError> { println!("OPENED {}", a.as_str()); Ok(()) }
}
fn main() {
    let now = SystemClock.now();
    let me = DeviceKeypair::generate(); let att = DeviceKeypair::generate();
    let roster = Roster::genesis(GroupId([9; 32]), me.device_id(), "pc");
    let mut reg = PairingRegistry::new(me.device_id(), roster.group());
    let mut inbox = Inbox::new(roster, ReceiveKeypair::generate(), InboxConfig::default()).unwrap();
    let inv = reg.issue(now, &mut rand_core::OsRng).unwrap();
    let sc = ScannedInvite::parse(&inv.qr_uri(""), now).unwrap();
    let req = PairingRequest::create(&sc, att.device_id(), "x", b"h");
    let g = reg.redeem(&req, b"h", now).unwrap();
    let code = sc.sas_code(&att.device_id(), "x", b"h");
    inbox.add_paired_device(g.confirm_typed_code(&code, now).unwrap(), Role::Owner);
    let r = inbox.roster();
    let body = RawBody { magic: MAGIC, group: r.group().0, sender: *att.device_id().as_bytes(), recipient: *me.device_id().as_bytes(), log_head: r.head().0, msg_id: MsgId::random().0, timestamp: now.wall.0, url: b"https://evil.example/x".to_vec() };
    let env = envelope::seal(&me.device_id(), &inbox.receive_public(), &body.sign_with(&att)).unwrap();
    let v = inbox.receive(&att.device_id(), &env, now).unwrap();
    Print.open(v).unwrap(); // must not compile: open() needs an OpenApproval
}
