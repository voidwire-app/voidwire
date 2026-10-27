// expect: E0308
use voidwire_core::opener::{SystemOpener, UrlOpener};
fn main() { let _ = SystemOpener.open(String::from("https://example.com/")); }
