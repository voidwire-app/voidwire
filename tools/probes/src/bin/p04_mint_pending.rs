// expect: E0451
use voidwire_core::{opener::PendingOpen, verify::VerifiedUrl};
fn mint(v: VerifiedUrl) -> PendingOpen { PendingOpen { url: v } }
fn main() {}
