#![forbid(unsafe_code)]
//! Tiny lowercase-hex helpers (avoids a dependency for two functions).

pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let a = [0u8, 1, 0xab, 0xff];
        let s = super::encode(&a);
        assert_eq!(s, "0001abff");
        assert_eq!(super::decode_array::<4>(&s), Some(a));
        assert_eq!(super::decode_array::<4>("zz01abff"), None);
        assert_eq!(super::decode_array::<4>("01"), None);
    }
}
