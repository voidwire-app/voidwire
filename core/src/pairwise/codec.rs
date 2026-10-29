//! Tiny length-prefixed codec for pairing records and ops (big-endian).

pub(crate) struct Enc(pub Vec<u8>);

impl Enc {
    pub fn new() -> Self {
        Enc(Vec::new())
    }
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    /// Callers keep `b` under 256 bytes (checked by validation first).
    pub fn bytes8(&mut self, b: &[u8]) {
        debug_assert!(b.len() <= u8::MAX as usize);
        self.u8(b.len().min(u8::MAX as usize) as u8);
        self.raw(&b[..b.len().min(u8::MAX as usize)]);
    }
    pub fn bytes16(&mut self, b: &[u8]) {
        debug_assert!(b.len() <= u16::MAX as usize);
        self.u16(b.len().min(u16::MAX as usize) as u16);
        self.raw(&b[..b.len().min(u16::MAX as usize)]);
    }
    pub fn bytes32(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.raw(b);
    }
}

impl Drop for Enc {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

pub(crate) struct Dec<'a> {
    b: &'a [u8],
}

impl<'a> Dec<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Dec { b }
    }
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.b.len() < n {
            return None;
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Some(h)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes(b.try_into().expect("4")))
    }
    pub fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_be_bytes(b.try_into().expect("8")))
    }
    pub fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).map(|b| b.try_into().expect("N"))
    }
    pub fn bytes8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    pub fn bytes16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    pub fn bytes32(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn str8(&mut self) -> Option<String> {
        std::str::from_utf8(self.bytes8()?).ok().map(str::to_owned)
    }
    pub fn str16(&mut self) -> Option<String> {
        std::str::from_utf8(self.bytes16()?).ok().map(str::to_owned)
    }
    pub fn is_empty(&self) -> bool {
        self.b.is_empty()
    }
    pub fn remaining(&self) -> usize {
        self.b.len()
    }
}
