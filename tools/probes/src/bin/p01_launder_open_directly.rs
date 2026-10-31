// expect: E0308
// QA probe p01 on the D2 API: verify a message with a link verifier (even
// one the attacker holds), then call UrlOpener::open directly with the
// VerifiedUrl (skipping deliver/confirm).
use voidwire_core::{ids::DeviceId, opener::*, time::*, verify::*};
struct Print;
impl UrlOpener for Print {
    fn open(&self, a: OpenApproval) -> Result<(), OpenError> { println!("OPENED {}", a.as_str()); Ok(()) }
}
fn launder(inbox: &mut Inbox, att: &DeviceId, env: &[u8]) {
    let v = inbox.receive(att, env, SystemClock.now()).unwrap();
    Print.open(v).unwrap(); // must not compile: open() needs an OpenApproval
}
fn main() { let _ = launder; }
