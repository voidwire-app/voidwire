//! Codecs for the v2 pairing handshake bodies (M4.3, `pair2`): the
//! inviter's genesis offer (sealed inside `WELCOME`), the joiner's
//! `PAIR_ACCEPT` (co-signed genesis + `Caps`) and the inviter's `PAIR_CAPS`
//! (co-signed `Caps`).

use crate::mailbox::WRAPPED_EPOCH_SECRET_LEN;
use crate::pairwise::PairOp;
use crate::reject::RejectReason;

/// Largest single pair op on the split wire (a genesis carries two certs
/// and a relay URL).
pub(crate) const MAX_PAIR_OP: usize = 4096;

fn put16(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn take16<'a>(b: &mut &'a [u8]) -> Result<&'a [u8], RejectReason> {
    if b.len() < 2 {
        return Err(RejectReason::MalformedFrame);
    }
    let n = u16::from_be_bytes([b[0], b[1]]) as usize;
    if n > MAX_PAIR_OP || b.len() < 2 + n {
        return Err(RejectReason::MalformedFrame);
    }
    let (x, rest) = b[2..].split_at(n);
    *b = rest;
    Ok(x)
}

fn op(b: &[u8]) -> Result<PairOp, RejectReason> {
    PairOp::decode(b).map_err(|_| RejectReason::MalformedFrame)
}

pub(crate) fn encode_offer(genesis: &PairOp, wrapped: &[u8; WRAPPED_EPOCH_SECRET_LEN]) -> Vec<u8> {
    let mut v = Vec::new();
    put16(&mut v, &genesis.encode());
    v.extend_from_slice(wrapped);
    v
}

pub(crate) fn decode_offer(
    mut b: &[u8],
) -> Result<(PairOp, [u8; WRAPPED_EPOCH_SECRET_LEN]), RejectReason> {
    let g = op(take16(&mut b)?)?;
    let w = b.try_into().map_err(|_| RejectReason::MalformedFrame)?;
    Ok((g, w))
}

pub(crate) fn encode_accept(cosigned_genesis: &PairOp, caps: &PairOp) -> Vec<u8> {
    let mut v = Vec::new();
    put16(&mut v, &cosigned_genesis.encode());
    put16(&mut v, &caps.encode());
    v
}

pub(crate) fn decode_accept(mut b: &[u8]) -> Result<(PairOp, PairOp), RejectReason> {
    let g = op(take16(&mut b)?)?;
    let c = op(take16(&mut b)?)?;
    if !b.is_empty() {
        return Err(RejectReason::MalformedFrame);
    }
    Ok((g, c))
}

pub(crate) fn decode_caps(b: &[u8]) -> Result<PairOp, RejectReason> {
    if b.len() > MAX_PAIR_OP {
        return Err(RejectReason::MalformedFrame);
    }
    op(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_frames_refuse_truncation_and_trailing_bytes() {
        let mut b: &[u8] = &[0, 5, 1, 2];
        assert!(take16(&mut b).is_err());
        let mut v = Vec::new();
        put16(&mut v, &[9; 3]);
        let mut s: &[u8] = &v;
        assert_eq!(take16(&mut s).unwrap(), &[9, 9, 9]);
        assert!(s.is_empty());
        assert!(decode_offer(&[0, 0]).is_err());
        assert!(decode_accept(&[0, 0, 0, 0]).is_err());
        let big = vec![0u8; MAX_PAIR_OP + 1];
        assert!(decode_caps(&big).is_err());
    }
}
