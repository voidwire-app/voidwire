// expect: E0451
use voidwire_core::{opener::OpenApproval, verify::VerifiedUrl};
fn mint(v: VerifiedUrl) -> OpenApproval { OpenApproval { url: v } }
fn main() {}
