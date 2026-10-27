// expect-msg: cannot construct `VerifiedUrl` with struct literal syntax due to private fields
use voidwire_core::{ids::{DeviceId, MsgId}, verify::VerifiedUrl};
fn mint(u: url::Url, s: DeviceId, m: MsgId) -> VerifiedUrl { VerifiedUrl { url: u, sender: s, msg_id: m } }
fn main() {}
