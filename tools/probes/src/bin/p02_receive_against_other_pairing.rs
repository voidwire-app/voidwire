// expect: E0061
use voidwire_core::{ids::{DeviceId, GroupId}, time::Now, verify::Inbox};
fn f(i: &mut Inbox, other: GroupId, p: &DeviceId, b: &[u8], n: Now) { let _ = i.receive(other, p, b, n); }
fn main() {}
