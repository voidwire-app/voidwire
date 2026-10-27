// expect: E0277
use voidwire_core::{opener::OpenApproval, verify::VerifiedUrl};
fn f(v: VerifiedUrl) -> OpenApproval { v.into() }
fn main() {}
