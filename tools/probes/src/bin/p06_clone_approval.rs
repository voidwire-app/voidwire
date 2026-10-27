// expect: E0599
use voidwire_core::opener::OpenApproval;
fn dup(a: OpenApproval) -> (OpenApproval, OpenApproval) { let b: OpenApproval = a.clone(); (a, b) }
fn main() {}
