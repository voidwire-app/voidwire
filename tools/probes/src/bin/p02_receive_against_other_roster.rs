// expect: E0061
use voidwire_core::{ids::DeviceId, roster::Roster, time::Now, verify::Inbox};
fn f(i: &mut Inbox, r: &Roster, p: &DeviceId, b: &[u8], n: Now) { let _ = i.receive(r, p, b, n); }
fn main() {}
