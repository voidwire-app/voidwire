// expect: E0277
fn main() { let _v: voidwire_core::verify::VerifiedUrl = String::from("https://example.com/").into(); }
