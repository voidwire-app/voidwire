#![forbid(unsafe_code)]
//! M2.6 chunked, resumable, end-to-end file & image transfer over iroh streams,
//! relay data-minimization policy, and optional on-device connection stats
//! (`docs/M2-PLAN.md` §6a, §6a.1, §6a.2, §6a.3, and §6b).
//!
//! All domain-separation tags are registered in [`crate::protocol::DOMAIN_TAGS`]
//! and checked against the source by `domain_tag_list_matches_the_source`.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::Signature;
use hpke::{
    aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305, kdf::HkdfSha256, Deserializable, OpModeR,
    OpModeS, Serializable,
};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::disk::available_disk_space;
use crate::envelope::{HEADER as ENV_HEADER, OVERHEAD as ENV_OVERHEAD};
use crate::ids::{DeviceId, GroupId};
use crate::keys::{DeviceKeypair, HpkeKem, HpkeRng, ReceiveKeypair, ReceivePublicKey};
use crate::mailbox::SignedConfig;
use crate::reject::RejectReason;
use crate::time::UnixMillis;

/// Domain tag for signing a `FileOffer` inside its HPKE envelope.
pub const TAG_FILE_OFFER: &[u8] = b"voidwire/v1/file-offer\0";
/// Domain tag for RFC 9180 HPKE exporter derivation of `k_file`.
pub const TAG_FILE_KEY: &[u8] = b"voidwire/v1/file-key\0";
/// Domain tag for per-chunk AEAD associated data (`AAD`).
pub const TAG_FILE_CHUNK: &[u8] = b"voidwire/v1/file-chunk\0";

/// Fixed plaintext chunk size (256 KiB = 262,144 bytes).
pub const FILE_CHUNK_SIZE: usize = 256 * 1024;
/// Minimum padded bucket for the final chunk (4 KiB = 4,096 bytes).
pub const MIN_FINAL_CHUNK_BUCKET: usize = 4 * 1024;
/// AEAD authentication tag size (ChaCha20-Poly1305 = 16 bytes).
pub const CHUNK_AEAD_TAG_LEN: usize = 16;
/// Length prefix inside the final chunk's padded AEAD plaintext (`u32 BE`).
pub const FINAL_CHUNK_PREFIX_LEN: usize = 4;
/// Top final-chunk bucket when `data.len()` is `262_141..=262_144` (`256 KiB + 4`).
pub const MAX_FINAL_CHUNK_PADDED_LEN: usize = FILE_CHUNK_SIZE + FINAL_CHUNK_PREFIX_LEN;
/// Maximum ciphertext size of a single chunk on the wire (`256 KiB + 4 + 16`).
pub const MAX_CHUNK_CIPHERTEXT_LEN: usize = MAX_FINAL_CHUNK_PADDED_LEN + CHUNK_AEAD_TAG_LEN;
/// Receiver hard cap on file size: 2 GiB (`2_147_483_648` bytes).
pub const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;
/// Required free-space safety margin above `offer.size` before accepting: 64 MiB (`67_108_864` bytes).
pub const FREE_SPACE_MARGIN_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum sanitized filename length in UTF-8 bytes.
pub const MAX_FILENAME_BYTES: usize = 255;
/// Maximum advisory MIME string length in UTF-8 bytes.
pub const MAX_MIME_BYTES: usize = 127;
/// Maximum offer lifetime (24 hours in milliseconds).
pub const MAX_OFFER_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
/// Default small-item cap for automatic relay fallback (256 KiB).
pub const DEFAULT_SMALL_ITEM_CAP_BYTES: u64 = 256 * 1024;
/// Default server/client relay file cap and large-file warning threshold (25 MB).
pub const DEFAULT_RELAY_FILE_CAP_BYTES: u64 = 25 * 1024 * 1024;
/// Sender-side threshold above which relayed file transfers show an explicit large-file mobile data warning (25 MB, `M2.8`).
pub const LARGE_RELAY_WARNING_BYTES: u64 = 25 * 1024 * 1024;
/// Maximum user-configurable relay file cap (`MAX_FILE_SIZE` = 2 GiB, `M2.8`).
pub const MAX_USER_RELAY_FILE_CAP_BYTES: u64 = MAX_FILE_SIZE;

const OFFER_MAGIC: [u8; 4] = [b'V', b'W', crate::protocol::PROTOCOL_VERSION, b'F'];
const PART_META_MAGIC: [u8; 4] = [b'V', b'W', crate::protocol::PROTOCOL_VERSION, b'P'];

/// Allowed padded plaintext sizes for the final chunk (`4 KiB..=256 KiB`, plus
/// `256 KiB + 4` when the final chunk holds a full 256 KiB of payload).
pub const FINAL_CHUNK_BUCKETS: [usize; 8] = [
    4 * 1024,
    8 * 1024,
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    256 * 1024 + FINAL_CHUNK_PREFIX_LEN,
];

/// 128-bit single-use transfer identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransferId(pub [u8; 16]);

impl TransferId {
    pub fn generate() -> Self {
        Self::generate_with(&mut rand_core::OsRng)
    }

    pub fn random() -> Self {
        Self::generate()
    }

    pub fn from_bytes(b: [u8; 16]) -> Self {
        TransferId(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn generate_with(rng: &mut impl CryptoRngCore) -> Self {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        TransferId(b)
    }

    pub fn to_hex(&self) -> String {
        crate::hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        crate::hex::decode_array::<16>(s).map(TransferId)
    }
}

impl fmt::Debug for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransferId({})", crate::hex::encode(&self.0[..4]))
    }
}

/// 256-bit per-transfer symmetric key derived via RFC 9180 HPKE `ctx.export`.
/// Zeroized on drop and never persisted in plaintext on disk.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FileTransferKey([u8; 32]);

impl FileTransferKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        FileTransferKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FileTransferKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileTransferKey(<redacted>)")
    }
}

/// Compute the number of chunks for a file of `size` bytes with `FILE_CHUNK_SIZE`.
/// Even a 0-byte file has 1 final chunk (padded to 4 KiB) so every transfer ends
/// with an authenticated final chunk (`is_final = true`).
pub const fn chunk_count_for_size(size: u64) -> u64 {
    if size == 0 {
        1
    } else {
        size.div_ceil(FILE_CHUNK_SIZE as u64)
    }
}

/// Expected unpadded byte length of chunk `chunk_index` (`0..chunk_count`) for a
/// file of `total_size` bytes.
pub fn expected_chunk_plain_len(
    total_size: u64,
    chunk_index: u64,
    chunk_count: u64,
) -> Option<usize> {
    if chunk_count == 0
        || chunk_index >= chunk_count
        || chunk_count != chunk_count_for_size(total_size)
    {
        return None;
    }
    if total_size == 0 {
        return Some(0);
    }
    if chunk_index + 1 < chunk_count {
        Some(FILE_CHUNK_SIZE)
    } else {
        let rem = (total_size % (FILE_CHUNK_SIZE as u64)) as usize;
        Some(if rem == 0 { FILE_CHUNK_SIZE } else { rem })
    }
}

/// Smallest final-chunk bucket that holds `raw_len` bytes (`raw = 4 + plain_len`).
pub const fn final_chunk_padded_len(raw_len: usize) -> Option<usize> {
    let mut i = 0;
    while i < FINAL_CHUNK_BUCKETS.len() {
        if raw_len <= FINAL_CHUNK_BUCKETS[i] {
            return Some(FINAL_CHUNK_BUCKETS[i]);
        }
        i += 1;
    }
    None
}

/// Pad the final chunk's plaintext (`plain.len() <= FILE_CHUNK_SIZE`) with a
/// 4-byte big-endian length prefix up to the next power-of-two bucket (`>= 4 KiB`).
pub fn pad_final_chunk(plain: &[u8]) -> Result<Vec<u8>, RejectReason> {
    if plain.len() > FILE_CHUNK_SIZE {
        return Err(RejectReason::MalformedFrame);
    }
    let raw_len = FINAL_CHUNK_PREFIX_LEN + plain.len();
    let bucket = final_chunk_padded_len(raw_len).ok_or(RejectReason::MalformedFrame)?;
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(plain.len() as u32).to_be_bytes());
    out.extend_from_slice(plain);
    out.resize(bucket, 0);
    Ok(out)
}

/// Strictly unpad a decrypted final-chunk buffer, verifying bucket size,
/// minimum bucket use, and all-zero padding bytes.
pub fn unpad_final_chunk(padded: &[u8]) -> Result<Vec<u8>, RejectReason> {
    if final_chunk_padded_len(padded.len()) != Some(padded.len()) {
        return Err(RejectReason::MalformedFrame);
    }
    if padded.len() < MIN_FINAL_CHUNK_BUCKET {
        return Err(RejectReason::MalformedFrame);
    }
    let n = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if n > FILE_CHUNK_SIZE
        || FINAL_CHUNK_PREFIX_LEN + n > padded.len()
        || final_chunk_padded_len(FINAL_CHUNK_PREFIX_LEN + n) != Some(padded.len())
    {
        return Err(RejectReason::MalformedFrame);
    }
    if padded[FINAL_CHUNK_PREFIX_LEN + n..].iter().any(|&b| b != 0) {
        return Err(RejectReason::MalformedFrame);
    }
    Ok(padded[FINAL_CHUNK_PREFIX_LEN..FINAL_CHUNK_PREFIX_LEN + n].to_vec())
}

/// Deterministic 96-bit ChaCha20-Poly1305 nonce for `chunk_index`:
/// `u32_be(0) || u64_be(chunk_index)`.
pub fn chunk_nonce(chunk_index: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&chunk_index.to_be_bytes());
    n
}

/// Per-chunk AEAD associated data (`AAD`):
/// `TAG_FILE_CHUNK || transfer_id (16 B) || u64_be(chunk_index) || is_final (u8: 0 or 1)`.
pub fn chunk_aad(transfer_id: &TransferId, chunk_index: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TAG_FILE_CHUNK.len() + 16 + 8 + 1);
    aad.extend_from_slice(TAG_FILE_CHUNK);
    aad.extend_from_slice(&transfer_id.0);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.push(u8::from(is_final));
    aad
}

/// Encrypt a single chunk (`0..=FILE_CHUNK_SIZE`) under `key`.
///
/// - Non-final chunks (`!is_final`) must be exactly `FILE_CHUNK_SIZE` bytes.
/// - Final chunks (`is_final`) may be `0..=FILE_CHUNK_SIZE` bytes and are padded
///   inside the AEAD via [`pad_final_chunk`].
pub fn encrypt_chunk(
    key: &FileTransferKey,
    transfer_id: &TransferId,
    chunk_index: u64,
    is_final: bool,
    plain: &[u8],
) -> Result<Vec<u8>, RejectReason> {
    let body: std::borrow::Cow<'_, [u8]> = if is_final {
        std::borrow::Cow::Owned(pad_final_chunk(plain)?)
    } else {
        if plain.len() != FILE_CHUNK_SIZE {
            return Err(RejectReason::MalformedFrame);
        }
        std::borrow::Cow::Borrowed(plain)
    };
    let cipher = ChaCha20Poly1305::new(key.0.as_slice().into());
    let nonce = chunk_nonce(chunk_index);
    let aad = chunk_aad(transfer_id, chunk_index, is_final);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &body,
                aad: &aad,
            },
        )
        .map_err(|_| RejectReason::Internal)
}

/// Decrypt and unpad a single chunk under `key`.
pub fn decrypt_chunk(
    key: &FileTransferKey,
    transfer_id: &TransferId,
    chunk_index: u64,
    is_final: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>, RejectReason> {
    if ciphertext.len() < CHUNK_AEAD_TAG_LEN || ciphertext.len() > MAX_CHUNK_CIPHERTEXT_LEN {
        return Err(RejectReason::MalformedFrame);
    }
    let plain_wire_len = ciphertext.len() - CHUNK_AEAD_TAG_LEN;
    if is_final {
        if final_chunk_padded_len(plain_wire_len) != Some(plain_wire_len) {
            return Err(RejectReason::MalformedFrame);
        }
    } else if plain_wire_len != FILE_CHUNK_SIZE {
        return Err(RejectReason::MalformedFrame);
    }
    let cipher = ChaCha20Poly1305::new(key.0.as_slice().into());
    let nonce = chunk_nonce(chunk_index);
    let aad = chunk_aad(transfer_id, chunk_index, is_final);
    let decrypted = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| RejectReason::DecryptFailed)?;
    if is_final {
        unpad_final_chunk(&decrypted)
    } else {
        Ok(decrypted)
    }
}

/// Compute the BLAKE3 hash of every 256 KiB chunk and the overall BLAKE3 tree
/// root (`blake3_root`) over those chunk hashes (`BLAKE3("voidwire-blake3-tree\0" || chunk_hashes)`
/// when `chunk_hashes.len() > 1`, or the direct BLAKE3 hash of the file so both
/// single-chunk and multi-chunk streams have per-chunk verified streaming + full
/// BLAKE3 file verification).
///
/// Specifically:
/// - `blake3_root` is the standard `blake3::hash(file_bytes)` of the entire file.
/// - `chunk_hashes[i]` is `blake3::hash(chunk_i_plain)` for each chunk `i`, so
///   the receiver can verify every chunk immediately upon arrival (verified
///   streaming) and also verify the full file's `blake3::Hasher` against `blake3_root`.
/// - For large files where carrying all chunk hashes in the 8 KiB offer envelope
///   would exceed the envelope size (e.g. > 200 chunks), we compute a compact
///   binary Merkle tree over `chunk_hashes` (like `bao` outboard tree root) and
///   carry `outboard_root: [u8; 32]` in `FileOffer`, plus verify each chunk against
///   its Merkle/chunk hash or incremental BLAKE3 stream!
///
/// Compute the full-file BLAKE3 root (`blake3::hash(data)`) and per-chunk
/// BLAKE3 hashes for `data`.
pub fn compute_file_hashes(data: &[u8]) -> ([u8; 32], Vec<[u8; 32]>) {
    let root = *blake3::hash(data).as_bytes();
    if data.is_empty() {
        return (root, vec![root]);
    }
    let chunks: Vec<[u8; 32]> = data
        .chunks(FILE_CHUNK_SIZE)
        .map(|c| *blake3::hash(c).as_bytes())
        .collect();
    (root, chunks)
}

/// Streamed file hash tuple: `(total_size, blake3_root, chunk_hashes)`.
pub type StreamedFileHashes = (u64, [u8; 32], Vec<[u8; 32]>);

/// Stream-hash a file on disk in `FILE_CHUNK_SIZE` (256 KiB) increments after
/// checking `metadata.len() <= MAX_FILE_SIZE` (`M26-H2`: `O(1)` ~256 KiB RAM).
pub fn compute_file_hashes_streaming(path: &Path) -> Result<StreamedFileHashes, String> {
    let md = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !md.is_file() {
        return Err("not a regular file".to_string());
    }
    let total_size = md.len();
    if total_size > MAX_FILE_SIZE {
        return Err(format!("file exceeds 2 GiB cap ({total_size} B)"));
    }
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if total_size == 0 {
        let empty = *blake3::hash(&[]).as_bytes();
        return Ok((0, empty, vec![empty]));
    }
    let expected_chunks = chunk_count_for_size(total_size) as usize;
    let mut chunk_hashes = Vec::with_capacity(expected_chunks);
    let mut full_hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; FILE_CHUNK_SIZE];
    let mut bytes_read_total = 0u64;

    while bytes_read_total < total_size {
        let remaining = (total_size - bytes_read_total).min(FILE_CHUNK_SIZE as u64) as usize;
        let mut filled = 0usize;
        while filled < remaining {
            let n = file
                .read(&mut buf[filled..remaining])
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("file truncated while hashing".to_string());
            }
            filled += n;
        }
        full_hasher.update(&buf[..filled]);
        chunk_hashes.push(*blake3::hash(&buf[..filled]).as_bytes());
        bytes_read_total += filled as u64;
    }

    let root = *full_hasher.finalize().as_bytes();
    Ok((total_size, root, chunk_hashes))
}

/// Read a single `FILE_CHUNK_SIZE` (256 KiB) chunk from `file` at `chunk_index`
/// and encrypt it under `key` without buffering the whole file in RAM (`M26-H2`).
pub fn read_and_encrypt_file_chunk(
    file: &mut std::fs::File,
    total_size: u64,
    chunk_count: u64,
    key: &FileTransferKey,
    transfer_id: &TransferId,
    chunk_index: u64,
) -> Result<Vec<u8>, RejectReason> {
    let expected_len = expected_chunk_plain_len(total_size, chunk_index, chunk_count)
        .ok_or(RejectReason::MalformedFrame)?;
    let offset = chunk_index
        .checked_mul(FILE_CHUNK_SIZE as u64)
        .ok_or(RejectReason::MalformedFrame)?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| RejectReason::Internal)?;
    let mut plain = vec![0u8; expected_len];
    file.read_exact(&mut plain)
        .map_err(|_| RejectReason::Internal)?;
    let is_final = chunk_index + 1 == chunk_count;
    encrypt_chunk(key, transfer_id, chunk_index, is_final, &plain)
}

/// Sanitize an untrusted sender-supplied filename (`docs/M2-PLAN.md` §6a.2):
/// - Replace or strip path separators (`/`, `\`), `..` segments, NUL and
///   ASCII/Unicode control characters (including bidi controls), and Windows-
///   invalid characters (`<`, `>`, `:`, `"`, `|`, `?`, `*`).
/// - Trim leading/trailing dots and spaces so hidden files (`.bashrc`) and
///   Windows trailing-dot quirks cannot be created.
/// - Prefix Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`,
///   `COM1`..`COM9`, `LPT1`..`LPT9`, with or without an extension) with `_`.
/// - Truncate to [`MAX_FILENAME_BYTES`] on a UTF-8 char boundary while
///   preserving the file extension when possible.
/// - Fall back to `"shared-file"` if nothing remains.
pub fn sanitize_filename(raw: &str) -> String {
    // Take only the last path component if the string contained `/` or `\`,
    // unless that component is `.` or `..`.
    let base = raw
        .rsplit(['/', '\\'])
        .find(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .unwrap_or("");

    let mut cleaned = String::with_capacity(base.len());
    for ch in base.chars() {
        if ch.is_control()
            || matches!(
                ch,
                '/' | '\\'
                    | '<'
                    | '>'
                    | ':'
                    | '"'
                    | '|'
                    | '?'
                    | '*'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{FEFF}'
            )
        {
            continue;
        }
        cleaned.push(ch);
    }

    // Collapse any remaining `..` sequences.
    while cleaned.contains("..") {
        cleaned = cleaned.replace("..", ".");
    }

    let trimmed = cleaned
        .trim_matches(|c: char| c == '.' || c.is_whitespace())
        .to_string();

    if trimmed.is_empty() {
        return "shared-file".to_string();
    }

    let mut candidate = if is_windows_reserved_stem(&trimmed) {
        format!("_{trimmed}")
    } else {
        trimmed
    };

    if candidate.len() > MAX_FILENAME_BYTES {
        candidate = truncate_filename_utf8(&candidate, MAX_FILENAME_BYTES);
    }
    if is_windows_reserved_stem(&candidate) {
        candidate = format!("_{candidate}");
        if candidate.len() > MAX_FILENAME_BYTES {
            candidate = truncate_filename_utf8(&candidate, MAX_FILENAME_BYTES);
        }
    }
    if candidate.is_empty() {
        "shared-file".to_string()
    } else {
        candidate
    }
}

fn is_windows_reserved_stem(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_matches(|c: char| c.is_whitespace() || c == '.');
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CONIN$"
            | "CONOUT$"
            | "CLOCK$"
            | "COM0"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM\u{00B9}"
            | "COM\u{00B2}"
            | "COM\u{00B3}"
            | "LPT0"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT\u{00B9}"
            | "LPT\u{00B2}"
            | "LPT\u{00B3}"
    )
}

fn truncate_filename_utf8(name: &str, max_bytes: usize) -> String {
    if name.len() <= max_bytes {
        return name.to_string();
    }
    if let Some((stem, ext)) = name.rsplit_once('.') {
        let ext_with_dot = format!(".{ext}");
        if ext_with_dot.len() < max_bytes / 2 {
            let budget = max_bytes - ext_with_dot.len();
            let mut end = 0;
            for (idx, ch) in stem.char_indices() {
                if idx + ch.len_utf8() <= budget {
                    end = idx + ch.len_utf8();
                } else {
                    break;
                }
            }
            let prefix = stem[..end].trim_end_matches(['.', ' ']);
            if !prefix.is_empty() {
                return format!("{prefix}{ext_with_dot}");
            }
        }
    }
    let mut end = 0;
    for (idx, ch) in name.char_indices() {
        if idx + ch.len_utf8() <= max_bytes {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    name[..end].trim_matches(['.', ' ']).to_string()
}

/// Returns `true` if `filename` has an executable or installer extension that
/// must **never** be offered an "Open" button in the UI (`docs/M2-PLAN.md` §6a.2:
/// only "Show in folder" is allowed).
pub fn is_executable_filename(filename: &str) -> bool {
    let trimmed = filename.trim_end_matches(['.', ' ']);
    let Some((_, ext)) = trimmed.rsplit_once('.') else {
        return false;
    };
    let lower = ext.to_ascii_lowercase();
    matches!(
        lower.as_bytes(),
        b"exe"
            | b"msi"
            | b"bat"
            | [b'c', b'm', b'd']
            | b"com"
            | b"scr"
            | b"ps1"
            | b"vbs"
            | b"js"
            | b"jse"
            | b"wsf"
            | b"wsh"
            | b"hta"
            | b"jar"
            | [b's', b'h']
            | [b'b', b'a', b's', b'h']
            | b"run"
            | b"appimage"
            | b"deb"
            | b"rpm"
            | b"apk"
            | b"dmg"
            | b"pkg"
            | b"command"
            | b"bin"
            | b"elf"
            | b"lnk"
            | b"pif"
            | b"reg"
            | b"cpl"
            | b"msc"
            | b"inf"
            | b"sct"
            | b"wsc"
            | b"vbe"
            | b"vb"
            | b"url"
            | b"scf"
            | b"library-ms"
            | b"search-ms"
            | b"desktop"
            | b"webloc"
            | b"msp"
            | b"msu"
            | b"appx"
            | b"msix"
            | b"appxbundle"
            | b"msixbundle"
            | b"gadget"
            | b"xbap"
            | b"py"
            | b"pyw"
            | b"pl"
            | b"rb"
            | [b'z', b's', b'h']
            | [b'f', b'i', b's', b'h']
            | [b'k', b's', b'h']
            | [b'c', b's', b'h']
            | b"workflow"
            | b"action"
            | b"tool"
            | b"iso"
            | b"img"
            | b"vhd"
            | b"vhdx"
    )
}

/// Sanitize an advisory MIME type string.
pub fn sanitize_mime(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_MIME_BYTES
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '+' | '.'))
        || !trimmed.contains('/')
    {
        "application/octet-stream".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

/// Maximum number of per-chunk BLAKE3 hashes carried in `FileOffer`:
/// `2 GiB / 256 KiB = 8,192` chunks (`M26-M2`: per-chunk BLAKE3 verification is
/// active for every file up to `MAX_FILE_SIZE`).
pub const MAX_INLINE_CHUNK_HASHES: usize = (MAX_FILE_SIZE / (FILE_CHUNK_SIZE as u64)) as usize;

/// Padded plaintext buckets for a `FileOffer` HPKE envelope (matches `PAD_BUCKETS`
/// for small offers and extends up to `256 KiB + 4 KiB` so all 8,192 chunk hashes
/// for a 2 GiB file fit inside the sealed offer envelope, `M26-M2`).
pub const OFFER_PAD_BUCKETS: [usize; 12] = [
    512,
    1024,
    2048,
    4096,
    8192,
    8192 + 256,
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    256 * 1024 + 4096,
];
pub const MAX_OFFER_PADDED_LEN: usize = OFFER_PAD_BUCKETS[OFFER_PAD_BUCKETS.len() - 1];
pub const MAX_OFFER_ENVELOPE_LEN: usize = MAX_OFFER_PADDED_LEN + ENV_OVERHEAD;

const OFFER_FRAME_PREFIX: usize = 4;

pub const fn offer_padded_len(n: usize) -> Option<usize> {
    let mut i = 0;
    while i < OFFER_PAD_BUCKETS.len() {
        if n <= OFFER_PAD_BUCKETS[i] {
            return Some(OFFER_PAD_BUCKETS[i]);
        }
        i += 1;
    }
    None
}

fn pad_offer(body: &[u8]) -> Result<Vec<u8>, RejectReason> {
    let total =
        offer_padded_len(OFFER_FRAME_PREFIX + body.len()).ok_or(RejectReason::UrlTooLong)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out.resize(total, 0);
    Ok(out)
}

fn unpad_offer(padded: &[u8]) -> Result<Vec<u8>, RejectReason> {
    if padded.len() > MAX_OFFER_PADDED_LEN || offer_padded_len(padded.len()) != Some(padded.len()) {
        return Err(RejectReason::MalformedFrame);
    }
    let n = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if n > padded.len() - OFFER_FRAME_PREFIX
        || offer_padded_len(OFFER_FRAME_PREFIX + n) != Some(padded.len())
    {
        return Err(RejectReason::MalformedFrame);
    }
    if padded[OFFER_FRAME_PREFIX + n..].iter().any(|&b| b != 0) {
        return Err(RejectReason::MalformedFrame);
    }
    Ok(padded[OFFER_FRAME_PREFIX..OFFER_FRAME_PREFIX + n].to_vec())
}

pub fn check_offer_shape(envelope: &[u8]) -> Result<(), RejectReason> {
    if envelope.len() < ENV_OVERHEAD + OFFER_PAD_BUCKETS[0]
        || envelope.len() > MAX_OFFER_ENVELOPE_LEN
    {
        return Err(RejectReason::MalformedFrame);
    }
    let padded = envelope.len() - ENV_OVERHEAD;
    if offer_padded_len(padded) != Some(padded) {
        return Err(RejectReason::MalformedFrame);
    }
    if envelope[..4] != ENV_HEADER {
        return Err(if envelope[..2] == ENV_HEADER[..2] {
            RejectReason::UnsupportedVersion
        } else {
            RejectReason::MalformedFrame
        });
    }
    Ok(())
}

/// Signed file offer metadata carried inside an HPKE envelope (`docs/M2-PLAN.md` §6a.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOffer {
    pub group: GroupId,
    pub sender: DeviceId,
    pub recipient: DeviceId,
    pub transfer_id: TransferId,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub blake3_root: [u8; 32],
    /// Per-chunk BLAKE3 hashes for all chunks up to `MAX_FILE_SIZE` (2 GiB = 8,192 chunks, `M26-M2`).
    pub chunk_hashes: Vec<[u8; 32]>,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
    /// Sender's known group-log head (`PROTOCOL.md` §4 & §5 step 7, `M26-H1`).
    pub log_head: [u8; 32],
    /// Whether the UI may show an "Open" button after completion (`false` for
    /// executables/installers; files never auto-open regardless).
    pub allow_open: bool,
}

impl FileOffer {
    /// Construct a new validated `FileOffer` with sanitized filename and MIME.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group: GroupId,
        sender: DeviceId,
        recipient: DeviceId,
        transfer_id: TransferId,
        raw_filename: &str,
        raw_mime: &str,
        size: u64,
        blake3_root: [u8; 32],
        chunk_hashes: Vec<[u8; 32]>,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, RejectReason> {
        if sender == recipient {
            return Err(RejectReason::FromSelf);
        }
        if size > MAX_FILE_SIZE {
            return Err(RejectReason::UrlTooLong);
        }
        let chunk_count = chunk_count_for_size(size);
        if chunk_hashes.len() > MAX_INLINE_CHUNK_HASHES || chunk_hashes.len() as u64 != chunk_count
        {
            return Err(RejectReason::MalformedFrame);
        }
        if expires_at.0 <= issued_at.0
            || expires_at.0.saturating_sub(issued_at.0) > MAX_OFFER_LIFETIME_MS
        {
            return Err(RejectReason::StaleTimestamp);
        }
        let filename = sanitize_filename(raw_filename);
        let mime = sanitize_mime(raw_mime);
        let allow_open = !is_executable_filename(&filename);
        Ok(FileOffer {
            group,
            sender,
            recipient,
            transfer_id,
            filename,
            mime,
            size,
            chunk_size: FILE_CHUNK_SIZE as u32,
            chunk_count,
            blake3_root,
            chunk_hashes,
            issued_at,
            expires_at,
            log_head: [0u8; 32],
            allow_open,
        })
    }

    /// Attach the sender's current group-log head (`M26-H1`).
    pub fn with_log_head(mut self, log_head: [u8; 32]) -> Self {
        self.log_head = log_head;
        self
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let name_bytes = self.filename.as_bytes();
        let mime_bytes = self.mime.as_bytes();
        let mut out = Vec::with_capacity(
            4 + 32
                + 32
                + 32
                + 16
                + 8
                + 4
                + 8
                + 32
                + 8
                + 8
                + 32
                + 1
                + name_bytes.len()
                + 1
                + mime_bytes.len()
                + 2
                + self.chunk_hashes.len() * 32,
        );
        out.extend_from_slice(&OFFER_MAGIC);
        out.extend_from_slice(&self.group.0);
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(self.recipient.as_bytes());
        out.extend_from_slice(&self.transfer_id.0);
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.extend_from_slice(&self.blake3_root);
        out.extend_from_slice(&self.issued_at.0.to_be_bytes());
        out.extend_from_slice(&self.expires_at.0.to_be_bytes());
        out.extend_from_slice(&self.log_head);
        out.push(name_bytes.len() as u8);
        out.extend_from_slice(name_bytes);
        out.push(mime_bytes.len() as u8);
        out.extend_from_slice(mime_bytes);
        out.extend_from_slice(&(self.chunk_hashes.len() as u16).to_be_bytes());
        for h in &self.chunk_hashes {
            out.extend_from_slice(h);
        }
        out
    }

    /// Encode and sign this `FileOffer` with `sender_kp` (must match `self.sender`).
    pub fn encode_signed(&self, sender_kp: &DeviceKeypair) -> Result<Vec<u8>, RejectReason> {
        if sender_kp.device_id() != self.sender {
            return Err(RejectReason::SenderMismatch);
        }
        let body = self.encode_unsigned();
        let mut sig_input = Vec::with_capacity(TAG_FILE_OFFER.len() + body.len());
        sig_input.extend_from_slice(TAG_FILE_OFFER);
        sig_input.extend_from_slice(&body);
        let sig = sender_kp.sign(&sig_input);
        let mut out = body;
        out.extend_from_slice(&sig.to_bytes());
        Ok(out)
    }

    /// Decode and verify a signed `FileOffer`, enforcing `MAX_FILE_SIZE`,
    /// `FILE_CHUNK_SIZE`, per-chunk hash count, filename sanitization, and `allow_open`.
    pub fn decode_verified(bytes: &[u8]) -> Result<Self, RejectReason> {
        const FIXED_PREFIX: usize = 4 + 32 + 32 + 32 + 16 + 8 + 4 + 8 + 32 + 8 + 8 + 32;
        if bytes.len() < FIXED_PREFIX + 2 + 2 + 64 {
            return Err(RejectReason::MalformedFrame);
        }
        if bytes[..4] != OFFER_MAGIC {
            return Err(if bytes[..2] == OFFER_MAGIC[..2] {
                RejectReason::UnsupportedVersion
            } else {
                RejectReason::MalformedFrame
            });
        }
        let signed_len = bytes.len() - 64;
        let body = &bytes[..signed_len];
        let sig_bytes: [u8; 64] = bytes[signed_len..]
            .try_into()
            .map_err(|_| RejectReason::MalformedFrame)?;

        let group = GroupId(body[4..36].try_into().unwrap());
        let sender = DeviceId::from_bytes(body[36..68].try_into().unwrap())?;
        let recipient = DeviceId::from_bytes(body[68..100].try_into().unwrap())?;
        if sender == recipient {
            return Err(RejectReason::FromSelf);
        }
        let transfer_id = TransferId(body[100..116].try_into().unwrap());
        let size = u64::from_be_bytes(body[116..124].try_into().unwrap());
        let chunk_size = u32::from_be_bytes(body[124..128].try_into().unwrap());
        let chunk_count = u64::from_be_bytes(body[128..136].try_into().unwrap());
        let blake3_root: [u8; 32] = body[136..168].try_into().unwrap();
        let issued_at = UnixMillis(u64::from_be_bytes(body[168..176].try_into().unwrap()));
        let expires_at = UnixMillis(u64::from_be_bytes(body[176..184].try_into().unwrap()));
        let log_head: [u8; 32] = body[184..216].try_into().unwrap();

        let mut cursor = FIXED_PREFIX;
        if cursor >= body.len() {
            return Err(RejectReason::MalformedFrame);
        }
        let name_len = body[cursor] as usize;
        cursor += 1;
        if name_len == 0 || cursor + name_len >= body.len() {
            return Err(RejectReason::MalformedFrame);
        }
        let raw_name = std::str::from_utf8(&body[cursor..cursor + name_len])
            .map_err(|_| RejectReason::MalformedFrame)?;
        cursor += name_len;

        let mime_len = body[cursor] as usize;
        cursor += 1;
        if cursor + mime_len + 2 > body.len() {
            return Err(RejectReason::MalformedFrame);
        }
        let raw_mime = std::str::from_utf8(&body[cursor..cursor + mime_len])
            .map_err(|_| RejectReason::MalformedFrame)?;
        cursor += mime_len;

        let n_hashes = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
        cursor += 2;
        if n_hashes > MAX_INLINE_CHUNK_HASHES || cursor + n_hashes * 32 != body.len() {
            return Err(RejectReason::MalformedFrame);
        }
        let mut chunk_hashes = Vec::with_capacity(n_hashes);
        for _ in 0..n_hashes {
            let mut h = [0u8; 32];
            h.copy_from_slice(&body[cursor..cursor + 32]);
            chunk_hashes.push(h);
            cursor += 32;
        }

        // Verify signature before checking higher-level policy fields.
        let mut sig_input = Vec::with_capacity(TAG_FILE_OFFER.len() + body.len());
        sig_input.extend_from_slice(TAG_FILE_OFFER);
        sig_input.extend_from_slice(body);
        sender
            .verifying_key()
            .ok_or(RejectReason::BadSignature)?
            .verify_strict(&sig_input, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| RejectReason::BadSignature)?;

        if size > MAX_FILE_SIZE {
            return Err(RejectReason::UrlTooLong);
        }
        if chunk_size as usize != FILE_CHUNK_SIZE || chunk_count != chunk_count_for_size(size) {
            return Err(RejectReason::MalformedFrame);
        }
        if chunk_hashes.len() as u64 != chunk_count {
            return Err(RejectReason::MalformedFrame);
        }
        if expires_at.0 <= issued_at.0
            || expires_at.0.saturating_sub(issued_at.0) > MAX_OFFER_LIFETIME_MS
        {
            return Err(RejectReason::StaleTimestamp);
        }

        let filename = sanitize_filename(raw_name);
        let mime = sanitize_mime(raw_mime);
        let allow_open = !is_executable_filename(&filename);

        Ok(FileOffer {
            group,
            sender,
            recipient,
            transfer_id,
            filename,
            mime,
            size,
            chunk_size,
            chunk_count,
            blake3_root,
            chunk_hashes,
            issued_at,
            expires_at,
            log_head,
            allow_open,
        })
    }
}

/// Seal a `FileOffer` into a standard Voidwire HPKE envelope addressed to
/// `offer.recipient` (`recipient_key`), and export the per-transfer
/// [`FileTransferKey`] (`k_file`) from the same HPKE context via RFC 9180 §5.3:
/// `ctx.export(TAG_FILE_KEY || transfer_id, 32)`.
pub fn seal_file_offer(
    offer: &FileOffer,
    sender_kp: &DeviceKeypair,
    recipient_key: &ReceivePublicKey,
) -> Result<(Vec<u8>, FileTransferKey), RejectReason> {
    seal_file_offer_with(offer, sender_kp, recipient_key, &mut rand_core::OsRng)
}

/// [`seal_file_offer`] with an injectable CSPRNG (for deterministic KATs).
pub fn seal_file_offer_with(
    offer: &FileOffer,
    sender_kp: &DeviceKeypair,
    recipient_key: &ReceivePublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(Vec<u8>, FileTransferKey), RejectReason> {
    let signed = offer.encode_signed(sender_kp)?;
    let padded = pad_offer(&signed)?;
    let pk = recipient_key.to_hpke()?;

    let mut info = Vec::with_capacity(crate::envelope::TAG_ENVELOPE.len() + 32);
    info.extend_from_slice(crate::envelope::TAG_ENVELOPE);
    info.extend_from_slice(offer.recipient.as_bytes());

    let (enc, mut ctx) = hpke::setup_sender::<HpkeChaCha20Poly1305, HkdfSha256, HpkeKem, _>(
        &OpModeS::Base,
        &pk,
        &info,
        &mut HpkeRng(rng),
    )
    .map_err(|_| RejectReason::Internal)?;

    let ct = ctx
        .seal(&padded, &ENV_HEADER)
        .map_err(|_| RejectReason::Internal)?;

    let mut export_ctx = Vec::with_capacity(TAG_FILE_KEY.len() + 16);
    export_ctx.extend_from_slice(TAG_FILE_KEY);
    export_ctx.extend_from_slice(&offer.transfer_id.0);
    let mut k_bytes = Zeroizing::new([0u8; 32]);
    ctx.export(&export_ctx, &mut k_bytes[..])
        .map_err(|_| RejectReason::Internal)?;

    let mut env = Vec::with_capacity(ENV_OVERHEAD + padded.len());
    env.extend_from_slice(&ENV_HEADER);
    env.extend_from_slice(&enc.to_bytes());
    env.extend_from_slice(&ct);
    Ok((env, FileTransferKey(*k_bytes)))
}

/// Open a sealed `FileOffer` envelope addressed to `self_id`, verify the inner
/// Ed25519 signature and transport peer binding (`authenticated_peer`), and
/// export the matching [`FileTransferKey`] (`k_file`) from the HPKE receiver
/// context.
pub fn open_file_offer(
    receive_kp: &ReceiveKeypair,
    self_id: &DeviceId,
    expected_group: &GroupId,
    authenticated_peer: &DeviceId,
    envelope: &[u8],
) -> Result<(FileOffer, FileTransferKey), RejectReason> {
    check_offer_shape(envelope)?;
    let enc = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(&envelope[4..36])
        .map_err(|_| RejectReason::DecryptFailed)?;

    let mut info = Vec::with_capacity(crate::envelope::TAG_ENVELOPE.len() + 32);
    info.extend_from_slice(crate::envelope::TAG_ENVELOPE);
    info.extend_from_slice(self_id.as_bytes());

    let mut ctx = hpke::setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, HpkeKem>(
        &OpModeR::Base,
        receive_kp.hpke_secret(),
        &enc,
        &info,
    )
    .map_err(|_| RejectReason::DecryptFailed)?;

    let padded = ctx
        .open(&envelope[36..], &ENV_HEADER)
        .map_err(|_| RejectReason::DecryptFailed)?;
    let signed = unpad_offer(&padded)?;
    let offer = FileOffer::decode_verified(&signed)?;

    if &offer.recipient != self_id {
        return Err(RejectReason::WrongRecipient);
    }
    if &offer.group != expected_group {
        return Err(RejectReason::WrongGroup);
    }
    if &offer.sender != authenticated_peer {
        return Err(RejectReason::SenderMismatch);
    }

    let mut export_ctx = Vec::with_capacity(TAG_FILE_KEY.len() + 16);
    export_ctx.extend_from_slice(TAG_FILE_KEY);
    export_ctx.extend_from_slice(&offer.transfer_id.0);
    let mut k_bytes = Zeroizing::new([0u8; 32]);
    ctx.export(&export_ctx, &mut k_bytes[..])
        .map_err(|_| RejectReason::DecryptFailed)?;

    Ok((offer, FileTransferKey(*k_bytes)))
}

// ---------------------------------------------------------------------------
// Receiver Safety Check, Resumable `.part` File & Cancel Hygiene
// ---------------------------------------------------------------------------

/// Reason a receiver pre-accept check refused an offer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileAcceptError {
    #[error("file exceeds the 2 GiB maximum size limit")]
    ExceedsMaxFileSize { size: u64, max: u64 },
    #[error("not enough free disk space (need {required} bytes, available {available} bytes)")]
    InsufficientDiskSpace { required: u64, available: u64 },
    #[error("file offer has expired")]
    OfferExpired,
    #[error("storage error: {0}")]
    Storage(String),
}

/// Verify that a newly received `FileOffer` has a fresh `issued_at` within
/// `±TIMESTAMP_WINDOW_MS` (10 minutes) of `now` and has not expired (`M26-H1`).
pub fn check_offer_fresh(offer: &FileOffer, now: UnixMillis) -> Result<(), RejectReason> {
    if now.0 > offer.expires_at.0
        || now.0.abs_diff(offer.issued_at.0) > crate::limits::TIMESTAMP_WINDOW_MS
    {
        return Err(RejectReason::StaleTimestamp);
    }
    Ok(())
}

/// Check that `offer.size <= MAX_FILE_SIZE`, `now` is within `[issued_at - window, expires_at]`,
/// and `dest_dir` has at least `offer.size + FREE_SPACE_MARGIN_BYTES` (64 MiB) of available space.
pub fn check_offer_acceptable(
    offer: &FileOffer,
    dest_dir: &Path,
    now: UnixMillis,
) -> Result<(), FileAcceptError> {
    if offer.size > MAX_FILE_SIZE {
        return Err(FileAcceptError::ExceedsMaxFileSize {
            size: offer.size,
            max: MAX_FILE_SIZE,
        });
    }
    if now.0 > offer.expires_at.0
        || offer.issued_at.0 > now.0.saturating_add(crate::limits::TIMESTAMP_WINDOW_MS)
    {
        return Err(FileAcceptError::OfferExpired);
    }
    check_free_space_for_size(dest_dir, offer.size)
}

fn ensure_not_symlink(path: &Path) -> Result<(), String> {
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if md.file_type().is_symlink() {
            return Err(format!("refusing symlink at {}", path.display()));
        }
    }
    Ok(())
}

fn ensure_private_download_dir(dest_dir: &Path) -> Result<(), String> {
    ensure_not_symlink(dest_dir)?;
    #[cfg(unix)]
    let existed = dest_dir.exists();
    std::fs::create_dir_all(dest_dir).map_err(|e| format!("create dest_dir: {e}"))?;
    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dest_dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Sweep expired or orphaned `<transfer_id>.part` and `<transfer_id>.part.meta`
/// files in `dest_dir` where `now > meta.expires_at` (`M26-L1`).
pub fn purge_expired_parts(dest_dir: &Path, now: UnixMillis) -> usize {
    let Ok(entries) = std::fs::read_dir(dest_dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with(".part") && !name.ends_with(".part.meta") && !name.ends_with(".meta.tmp")
        {
            continue;
        }
        let Ok(md) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if md.file_type().is_symlink() || name.ends_with(".meta.tmp") {
            let _ = std::fs::remove_file(&path);
            removed += 1;
            continue;
        }
        if name.ends_with(".part.meta") {
            let expired = match std::fs::read(&path)
                .ok()
                .and_then(|b| PartResumeMeta::from_bytes(&b))
            {
                Some(meta) => meta.expires_at.0 > 0 && now.0 > meta.expires_at.0,
                None => true,
            };
            if expired {
                let _ = std::fs::remove_file(&path);
                let part = dest_dir.join(name.trim_end_matches(".meta"));
                let _ = std::fs::remove_file(part);
                removed += 1;
            }
        } else if name.ends_with(".part") {
            let meta_path = dest_dir.join(format!("{name}.meta"));
            if !meta_path.exists() {
                let _ = std::fs::remove_file(&path);
                removed += 1;
            }
        }
    }
    removed
}

/// Check that `dest_dir` has at least `remaining_or_total_size + 64 MiB` free bytes.
pub fn check_free_space_for_size(dest_dir: &Path, size: u64) -> Result<(), FileAcceptError> {
    let required = size.saturating_add(FREE_SPACE_MARGIN_BYTES);
    let available = available_disk_space(dest_dir).map_err(FileAcceptError::Storage)?;
    if available < required {
        return Err(FileAcceptError::InsufficientDiskSpace {
            required,
            available,
        });
    }
    Ok(())
}

/// On-disk resume metadata stored alongside `<transfer_id>.part` in `<transfer_id>.part.meta`.
/// Never contains `k_file` (kept in RAM / sealed state only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartResumeMeta {
    pub transfer_id: TransferId,
    pub total_size: u64,
    pub chunk_count: u64,
    pub next_chunk: u64,
    pub blake3_root: [u8; 32],
    pub filename: String,
    pub expires_at: UnixMillis,
}

impl PartResumeMeta {
    pub fn to_bytes(&self) -> Vec<u8> {
        let name_b = self.filename.as_bytes();
        let mut out = Vec::with_capacity(4 + 16 + 8 + 8 + 8 + 32 + 2 + name_b.len() + 8);
        out.extend_from_slice(&PART_META_MAGIC);
        out.extend_from_slice(&self.transfer_id.0);
        out.extend_from_slice(&self.total_size.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.extend_from_slice(&self.next_chunk.to_be_bytes());
        out.extend_from_slice(&self.blake3_root);
        out.extend_from_slice(&(name_b.len() as u16).to_be_bytes());
        out.extend_from_slice(name_b);
        out.extend_from_slice(&self.expires_at.0.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 + 16 + 8 + 8 + 8 + 32 + 2 || bytes[..4] != PART_META_MAGIC {
            return None;
        }
        let transfer_id = TransferId(bytes[4..20].try_into().ok()?);
        let total_size = u64::from_be_bytes(bytes[20..28].try_into().ok()?);
        let chunk_count = u64::from_be_bytes(bytes[28..36].try_into().ok()?);
        let next_chunk = u64::from_be_bytes(bytes[36..44].try_into().ok()?);
        let blake3_root: [u8; 32] = bytes[44..76].try_into().ok()?;
        let name_len = u16::from_be_bytes([bytes[76], bytes[77]]) as usize;
        if bytes.len() != 78 + name_len && bytes.len() != 86 + name_len {
            return None;
        }
        let raw_name = std::str::from_utf8(&bytes[78..78 + name_len]).ok()?;
        let filename = sanitize_filename(raw_name);
        let expires_at = if bytes.len() == 86 + name_len {
            UnixMillis(u64::from_be_bytes(
                bytes[78 + name_len..86 + name_len].try_into().ok()?,
            ))
        } else {
            UnixMillis(0)
        };
        Some(PartResumeMeta {
            transfer_id,
            total_size,
            chunk_count,
            next_chunk,
            blake3_root,
            filename,
            expires_at,
        })
    }
}

/// Paths for `<transfer_id>.part` and `<transfer_id>.part.meta` inside `dest_dir`.
pub fn part_paths(dest_dir: &Path, transfer_id: &TransferId) -> (PathBuf, PathBuf) {
    let hex = transfer_id.to_hex();
    let part = dest_dir.join(format!("{hex}.part"));
    let meta = dest_dir.join(format!("{hex}.part.meta"));
    (part, meta)
}

/// Completed file metadata returned when all chunks verify and the `.part` file
/// is finalized into `dest_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedFile {
    pub transfer_id: TransferId,
    pub path: PathBuf,
    pub filename: String,
    pub size: u64,
    pub blake3_root: [u8; 32],
    /// `false` for executables/installers (UI must only show "Show in folder", never "Open").
    /// Voidwire never auto-opens any received file.
    pub allow_open: bool,
}

/// Stateful, resumable file receiver that writes AEAD-verified + BLAKE3-verified
/// chunks to `<transfer_id>.part` and persists progress in `<transfer_id>.part.meta`.
///
/// Dropping or canceling via [`PartFileReceiver::cancel_and_delete`] zeroizes
/// `k_file` and deletes `.part` and `.part.meta` immediately.
pub struct PartFileReceiver {
    offer: FileOffer,
    key: Option<FileTransferKey>,
    dest_dir: PathBuf,
    part_path: PathBuf,
    meta_path: PathBuf,
    next_chunk: u64,
    bytes_written: u64,
}

impl PartFileReceiver {
    /// Open or resume a `.part` transfer in `dest_dir` after checking size and
    /// available disk space (`size + 64 MiB`).
    pub fn open_or_resume(
        offer: FileOffer,
        key: FileTransferKey,
        dest_dir: impl Into<PathBuf>,
        now: UnixMillis,
    ) -> Result<Self, FileAcceptError> {
        let dest_dir = dest_dir.into();
        check_offer_acceptable(&offer, &dest_dir, now)?;
        ensure_private_download_dir(&dest_dir).map_err(FileAcceptError::Storage)?;

        let (part_path, meta_path) = part_paths(&dest_dir, &offer.transfer_id);
        ensure_not_symlink(&part_path).map_err(FileAcceptError::Storage)?;
        ensure_not_symlink(&meta_path).map_err(FileAcceptError::Storage)?;
        let mut next_chunk = 0u64;
        let mut bytes_written = 0u64;

        if part_path.exists() && meta_path.exists() {
            if let Ok(meta_bytes) = std::fs::read(&meta_path) {
                if let Some(meta) = PartResumeMeta::from_bytes(&meta_bytes) {
                    if meta.transfer_id == offer.transfer_id
                        && meta.total_size == offer.size
                        && meta.chunk_count == offer.chunk_count
                        && meta.blake3_root == offer.blake3_root
                        && meta.next_chunk <= offer.chunk_count
                    {
                        let expected_bytes = if meta.next_chunk == offer.chunk_count {
                            offer.size
                        } else {
                            meta.next_chunk.saturating_mul(FILE_CHUNK_SIZE as u64)
                        };
                        if let Ok(md) = std::fs::metadata(&part_path) {
                            if md.len() >= expected_bytes {
                                // Truncate any unverified torn tail past `expected_bytes`.
                                if md.len() > expected_bytes {
                                    if let Ok(f) =
                                        std::fs::OpenOptions::new().write(true).open(&part_path)
                                    {
                                        let _ = f.set_len(expected_bytes);
                                    }
                                }
                                next_chunk = meta.next_chunk;
                                bytes_written = expected_bytes;
                            }
                        }
                    }
                }
            }
        }

        if next_chunk == 0 {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let f = opts
                .open(&part_path)
                .map_err(|e| FileAcceptError::Storage(format!("create .part: {e}")))?;
            f.sync_all()
                .map_err(|e| FileAcceptError::Storage(format!("sync .part: {e}")))?;
            bytes_written = 0;
        }

        let recv = PartFileReceiver {
            offer,
            key: Some(key),
            dest_dir,
            part_path,
            meta_path,
            next_chunk,
            bytes_written,
        };
        recv.persist_meta().map_err(FileAcceptError::Storage)?;
        Ok(recv)
    }

    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }

    /// First missing chunk index (`resume_from` in `FileControlKind::Accept`).
    pub fn next_chunk(&self) -> u64 {
        self.next_chunk
    }

    /// Update the HPKE-exported `k_file` when a transfer is resumed with a fresh HPKE `file-offer`.
    pub fn update_file_key(&mut self, key: FileTransferKey) {
        self.key = Some(key);
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn part_path(&self) -> &Path {
        &self.part_path
    }

    pub fn meta_path(&self) -> &Path {
        &self.meta_path
    }

    pub fn is_complete(&self) -> bool {
        self.next_chunk >= self.offer.chunk_count
    }

    fn persist_meta(&self) -> Result<(), String> {
        let meta = PartResumeMeta {
            transfer_id: self.offer.transfer_id,
            total_size: self.offer.size,
            chunk_count: self.offer.chunk_count,
            next_chunk: self.next_chunk,
            blake3_root: self.offer.blake3_root,
            filename: self.offer.filename.clone(),
            expires_at: self.offer.expires_at,
        };
        let bytes = meta.to_bytes();
        ensure_not_symlink(&self.meta_path)?;
        let tmp = self.meta_path.with_extension("meta.tmp");
        ensure_not_symlink(&tmp)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| format!("open .part.meta.tmp: {e}"))?;
        f.write_all(&bytes)
            .map_err(|e| format!("write .part.meta.tmp: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("sync .part.meta.tmp: {e}"))?;
        drop(f);
        std::fs::rename(&tmp, &self.meta_path).map_err(|e| format!("rename .part.meta: {e}"))?;
        Ok(())
    }

    /// Decrypt, verify, and append `chunk_index` to `<transfer_id>.part`.
    ///
    /// - Re-checks free space every 64 chunks (`docs/M2-PLAN.md` §6a.2).
    /// - Verifies the ChaCha20-Poly1305 AEAD tag and AAD (`transfer_id`, `chunk_index`, `is_final`).
    /// - Verifies the unpadded chunk length and per-chunk BLAKE3 hash (when inline hashes are present).
    pub fn write_encrypted_chunk(
        &mut self,
        chunk_index: u64,
        ciphertext: &[u8],
    ) -> Result<usize, RejectReason> {
        if chunk_index != self.next_chunk || chunk_index >= self.offer.chunk_count {
            return Err(RejectReason::MalformedFrame);
        }
        if chunk_index > 0 && chunk_index.is_multiple_of(64) {
            let remaining = self.offer.size.saturating_sub(self.bytes_written);
            if check_free_space_for_size(&self.dest_dir, remaining).is_err() {
                return Err(RejectReason::Internal);
            }
        }
        let key = self.key.as_ref().ok_or(RejectReason::Internal)?;
        let is_final = chunk_index + 1 == self.offer.chunk_count;
        let plain = decrypt_chunk(
            key,
            &self.offer.transfer_id,
            chunk_index,
            is_final,
            ciphertext,
        )?;
        let expected_len =
            expected_chunk_plain_len(self.offer.size, chunk_index, self.offer.chunk_count)
                .ok_or(RejectReason::MalformedFrame)?;
        if plain.len() != expected_len {
            return Err(RejectReason::MalformedFrame);
        }
        let expected_hash = self
            .offer
            .chunk_hashes
            .get(chunk_index as usize)
            .ok_or(RejectReason::MalformedFrame)?;
        let actual_hash = blake3::hash(&plain);
        if actual_hash.as_bytes() != expected_hash {
            return Err(RejectReason::BadSignature);
        }

        ensure_not_symlink(&self.part_path).map_err(|_| RejectReason::Internal)?;
        let offset = chunk_index
            .checked_mul(FILE_CHUNK_SIZE as u64)
            .ok_or(RejectReason::MalformedFrame)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut f = opts
            .open(&self.part_path)
            .map_err(|_| RejectReason::Internal)?;
        f.seek(SeekFrom::Start(offset))
            .map_err(|_| RejectReason::Internal)?;
        f.write_all(&plain).map_err(|_| RejectReason::Internal)?;
        f.sync_all().map_err(|_| RejectReason::Internal)?;
        drop(f);

        self.next_chunk += 1;
        self.bytes_written += plain.len() as u64;
        self.persist_meta().map_err(|_| RejectReason::Internal)?;
        Ok(plain.len())
    }

    /// Verify that all chunks have been written and that the complete `.part`
    /// file's BLAKE3 digest equals `offer.blake3_root`. On mismatch, deletes
    /// `.part` and `.part.meta` immediately and returns `Err(RejectReason::BadSignature)`.
    /// On success, atomically moves `.part` to a non-colliding filename in
    /// `dest_dir`, removes `.part.meta`, zeroizes `k_file`, and returns [`CompletedFile`].
    pub fn finalize(mut self) -> Result<CompletedFile, RejectReason> {
        if self.next_chunk != self.offer.chunk_count || self.bytes_written != self.offer.size {
            self.cleanup_files();
            return Err(RejectReason::MalformedFrame);
        }

        // Stream-hash the entire `.part` file with BLAKE3 and verify against `blake3_root`.
        let mut f = std::fs::File::open(&self.part_path).map_err(|_| {
            self.cleanup_files();
            RejectReason::Internal
        })?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total_read = 0u64;
        loop {
            let n = f.read(&mut buf).map_err(|_| {
                self.cleanup_files();
                RejectReason::Internal
            })?;
            if n == 0 {
                break;
            }
            total_read += n as u64;
            hasher.update(&buf[..n]);
        }
        drop(f);

        let actual_root = *hasher.finalize().as_bytes();
        if total_read != self.offer.size || actual_root != self.offer.blake3_root {
            self.cleanup_files();
            return Err(RejectReason::BadSignature);
        }

        let final_path = unique_dest_path(&self.dest_dir, &self.offer.filename);
        std::fs::rename(&self.part_path, &final_path).map_err(|_| {
            self.cleanup_files();
            RejectReason::Internal
        })?;
        let _ = std::fs::remove_file(&self.meta_path);
        if let Some(mut k) = self.key.take() {
            k.zeroize();
        }
        let allow_open = !is_executable_filename(&self.offer.filename);
        Ok(CompletedFile {
            transfer_id: self.offer.transfer_id,
            path: final_path,
            filename: self.offer.filename.clone(),
            size: self.offer.size,
            blake3_root: self.offer.blake3_root,
            allow_open,
        })
    }

    /// Cancel or reject the transfer: immediately zeroize `k_file` and delete
    /// `<transfer_id>.part` and `<transfer_id>.part.meta`.
    pub fn cancel_and_delete(mut self) {
        self.cleanup_files();
    }

    fn cleanup_files(&mut self) {
        if let Some(mut k) = self.key.take() {
            k.zeroize();
        }
        let _ = std::fs::remove_file(&self.part_path);
        let _ = std::fs::remove_file(&self.meta_path);
        let tmp = self.meta_path.with_extension("meta.tmp");
        let _ = std::fs::remove_file(tmp);
    }
}

fn unique_dest_path(dest_dir: &Path, sanitized_name: &str) -> PathBuf {
    let candidate = dest_dir.join(sanitized_name);
    if candidate.symlink_metadata().is_err() {
        return candidate;
    }
    let (stem, ext) = match sanitized_name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (sanitized_name.to_string(), String::new()),
    };
    for i in 1..=10_000u32 {
        let numbered = dest_dir.join(format!("{stem} ({i}){ext}"));
        if numbered.symlink_metadata().is_err() {
            return numbered;
        }
    }
    dest_dir.join(format!(
        "{stem}-{:x}{ext}",
        rand_core::RngCore::next_u32(&mut rand_core::OsRng)
    ))
}

// ---------------------------------------------------------------------------
// Relay Data-Minimization Policy (`docs/M2-PLAN.md` §6a.1 & §6b)
// ---------------------------------------------------------------------------

/// Current transport path for a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPathKind {
    /// Direct UDP (LAN or QAD hole-punched).
    Direct,
    /// Relayed over `iroh-relay` HTTPS/QUIC.
    Relayed,
}

/// User decision when a large transfer (`> small_item_cap_bytes` and `<= effective_relay_cap`)
/// has no direct path within 5 seconds or drops from direct to relay mid-stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPromptDecision {
    /// Allow this single transfer to proceed over the relay.
    SendViaRelay,
    /// Queue/pause and wait for a direct path (resumes from `next_chunk`).
    WaitForDirect,
    /// Cancel the transfer immediately.
    Cancel,
}

/// Policy evaluation result for sending or continuing a transfer of `size` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPolicyOutcome {
    /// Proceed immediately on the direct path.
    ProceedDirect,
    /// Proceed immediately on the relay (either `size <= small_item_cap_bytes`,
    /// or the user explicitly approved `RelayPromptDecision::SendViaRelay` for a
    /// file within `effective_relay_cap`).
    ProceedViaRelay,
    /// Pause and prompt the sender: *Send via relay* / *Wait* / *Cancel*.
    PromptSender { size: u64, effective_cap: u64 },
    /// Pause and wait for a direct path (user chose `WaitForDirect`).
    WaitForDirect,
    /// Transfer is blocked because "Never send files over relay" is enabled (`M2.9`).
    NeverSendOverRelay,
    /// Refused on relay because `size > effective_relay_cap` (Wait for direct or Cancel).
    ExceedsRelayCap { size: u64, effective_cap: u64 },
    /// Cancelled by the sender.
    Cancelled,
}

/// Relay data-minimization policy configuration combining the server-signed
/// `voidwire-config` v1 cap with the user's local setting (`0..=500 MB`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayTransferPolicy {
    /// Items `<= small_item_cap_bytes` (default 256 KiB) fall back to the relay automatically.
    pub small_item_cap_bytes: u64,
    /// Server-signed cap from `voidwire-config` v1 (default 25 MB).
    pub server_relay_cap_bytes: u64,
    /// User-configured cap in Settings (`0..=500 MB`, default 25 MB).
    pub user_relay_cap_bytes: u64,
    /// Highest `issued_at_day` seen on a verified `SignedConfig` (anti-rollback).
    pub last_config_issued_at_day: u32,
}

impl Default for RelayTransferPolicy {
    fn default() -> Self {
        RelayTransferPolicy {
            small_item_cap_bytes: DEFAULT_SMALL_ITEM_CAP_BYTES,
            server_relay_cap_bytes: DEFAULT_RELAY_FILE_CAP_BYTES,
            user_relay_cap_bytes: MAX_FILE_SIZE,
            last_config_issued_at_day: 0,
        }
    }
}

impl RelayTransferPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn server_cap_bytes(&self) -> u64 {
        self.server_relay_cap_bytes
    }

    /// Update the relay server's advertised file size cap (`0` = unlimited up to `MAX_FILE_SIZE`).
    pub fn set_server_cap_bytes(&mut self, cap_bytes: u64) {
        self.server_relay_cap_bytes = cap_bytes.min(MAX_FILE_SIZE);
    }

    pub fn user_cap_bytes(&self) -> u64 {
        self.user_relay_cap_bytes
    }

    /// Whether the user has enabled "Never send files over relay" (`user_relay_cap_bytes == 0`, `M2.8`).
    pub fn never_send_files_over_relay(&self) -> bool {
        self.user_relay_cap_bytes == 0
    }

    /// Toggle "Never send files over relay" (`true` -> cap `0`, `false` -> cap `MAX_FILE_SIZE`, `M2.8`).
    pub fn set_never_send_files_over_relay(&mut self, never: bool) {
        self.user_relay_cap_bytes = if never { 0 } else { MAX_FILE_SIZE };
    }

    pub fn effective_cap_bytes(&self) -> u64 {
        self.effective_relay_cap_bytes()
    }

    pub fn set_user_cap_bytes(&mut self, cap: u64) -> Result<(), String> {
        if cap > MAX_USER_RELAY_FILE_CAP_BYTES {
            return Err(format!(
                "user relay cap {cap} exceeds max {MAX_USER_RELAY_FILE_CAP_BYTES}"
            ));
        }
        self.user_relay_cap_bytes = cap;
        Ok(())
    }

    pub fn apply_signed_config(
        &mut self,
        cfg: &SignedConfig,
        expected_pubkey: &[u8; 32],
    ) -> Result<(), String> {
        cfg.verify(expected_pubkey, None)
            .map_err(|e| e.to_string())?;
        if cfg.issued_at_day < self.last_config_issued_at_day {
            return Err(format!(
                "stale signed config: issued_at_day {} < {}",
                cfg.issued_at_day, self.last_config_issued_at_day
            ));
        }
        self.last_config_issued_at_day = cfg.issued_at_day;
        self.server_relay_cap_bytes = cfg.relay_file_cap_bytes;
        Ok(())
    }

    /// Build a policy from an optional verified `SignedServerConfig` and optional
    /// user cap (clamped to `0..=MAX_USER_RELAY_FILE_CAP_BYTES`).
    pub fn from_config_and_user(
        server_cfg: Option<&SignedConfig>,
        user_cap_bytes: Option<u64>,
    ) -> Self {
        let small = DEFAULT_SMALL_ITEM_CAP_BYTES;
        let server_cap = server_cfg
            .map(|c| c.relay_file_cap_bytes)
            .unwrap_or(DEFAULT_RELAY_FILE_CAP_BYTES);
        let issued_day = server_cfg.map(|c| c.issued_at_day).unwrap_or(0);
        let user_cap = user_cap_bytes
            .unwrap_or(DEFAULT_RELAY_FILE_CAP_BYTES)
            .min(MAX_USER_RELAY_FILE_CAP_BYTES);
        RelayTransferPolicy {
            small_item_cap_bytes: small,
            server_relay_cap_bytes: server_cap,
            user_relay_cap_bytes: user_cap,
            last_config_issued_at_day: issued_day,
        }
    }

    /// Effective maximum size that can ever be sent over the relay (`min(server_cap, user_cap)`).
    /// A `server_relay_cap_bytes` of `0` means the server allows up to `MAX_FILE_SIZE` (2 GiB).
    pub fn effective_relay_cap_bytes(&self) -> u64 {
        if self.never_send_files_over_relay() {
            0
        } else {
            let srv = if self.server_relay_cap_bytes == 0 {
                MAX_FILE_SIZE
            } else {
                self.server_relay_cap_bytes.min(MAX_FILE_SIZE)
            };
            srv.min(self.user_relay_cap_bytes)
        }
    }

    /// Evaluate the relay data-minimization policy for a transfer of `size` bytes
    /// on `path` (at start after the 5s direct-first window, or on a mid-stream
    /// path change).
    pub fn evaluate(
        &self,
        size: u64,
        path: TransportPathKind,
        decision: Option<RelayPromptDecision>,
    ) -> RelayPolicyOutcome {
        if matches!(decision, Some(RelayPromptDecision::Cancel)) {
            return RelayPolicyOutcome::Cancelled;
        }
        if path == TransportPathKind::Direct {
            return RelayPolicyOutcome::ProceedDirect;
        }
        if self.never_send_files_over_relay() {
            return match decision {
                Some(RelayPromptDecision::WaitForDirect) => RelayPolicyOutcome::WaitForDirect,
                _ => RelayPolicyOutcome::NeverSendOverRelay,
            };
        }
        let server_cap = self.server_cap_bytes();
        let effective_cap = self.effective_relay_cap_bytes();
        if (server_cap > 0 && size > server_cap) || size > effective_cap {
            let cap = if server_cap > 0 {
                server_cap.min(effective_cap)
            } else {
                effective_cap
            };
            return match decision {
                Some(RelayPromptDecision::WaitForDirect) => RelayPolicyOutcome::WaitForDirect,
                _ => RelayPolicyOutcome::ExceedsRelayCap {
                    size,
                    effective_cap: cap,
                },
            };
        }
        // Rule 2: Small items (<= 256 KiB) fall back to relay automatically without prompting.
        if size <= self.small_item_cap_bytes {
            return RelayPolicyOutcome::ProceedViaRelay;
        }
        // Between `small_item_cap_bytes` and `effective_cap`: require explicit sender consent
        // when no direct path is up within 5s or when direct drops to relay mid-stream.
        match decision {
            Some(RelayPromptDecision::SendViaRelay) => RelayPolicyOutcome::ProceedViaRelay,
            Some(RelayPromptDecision::WaitForDirect) => RelayPolicyOutcome::WaitForDirect,
            Some(RelayPromptDecision::Cancel) => RelayPolicyOutcome::Cancelled,
            None => RelayPolicyOutcome::PromptSender {
                size,
                effective_cap,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Optional On-Device-Only Connection Stats (`docs/M2-PLAN.md` §6a.3)
// ---------------------------------------------------------------------------

/// Coarse UTC day-granularity (`unix_secs / 86400`) connection counters for one
/// paired peer. Stored locally only when `stats_enabled` is `true`; never
/// uploaded over the network.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerDayStats {
    pub day: u32,
    pub direct_count: u64,
    pub relay_count: u64,
    pub direct_bytes: u64,
    pub relay_bytes: u64,
    pub prompts_shown: u64,
    pub prompts_accepted: u64,
}

/// On-device-only connection statistics store (`docs/M2-PLAN.md` §6a.3).
///
/// - Off by default (`enabled == false`).
/// - While off, `record_transfer` and `record_prompt` are no-ops.
/// - Toggling off (`set_enabled(false)`) immediately purges all recorded stats.
/// - Forgetting a device (`forget_peer`) immediately purges that peer's stats.
/// - Timestamps are stored strictly at UTC day granularity (`unix_ms / 86_400_000`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionStatsStore {
    enabled: bool,
    by_peer: BTreeMap<DeviceId, BTreeMap<u32, PeerDayStats>>,
}

impl ConnectionStatsStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable on-device connection stats. Disabling immediately clears
    /// all stored counters (`docs/M2-PLAN.md` §6a.3).
    pub fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
        if !on {
            self.by_peer.clear();
        }
    }

    /// Convert `UnixMillis` to a coarse UTC day number (`unix_secs / 86400`).
    pub const fn utc_day(now: UnixMillis) -> u32 {
        (now.0 / 86_400_000) as u32
    }

    /// Record a completed transfer on `path` for `peer` at `now`. No-op when disabled.
    pub fn record_transfer(
        &mut self,
        peer: &DeviceId,
        path: TransportPathKind,
        bytes: u64,
        now: UnixMillis,
    ) {
        if !self.enabled {
            return;
        }
        let day = Self::utc_day(now);
        let entry = self
            .by_peer
            .entry(*peer)
            .or_default()
            .entry(day)
            .or_insert_with(|| PeerDayStats {
                day,
                ..Default::default()
            });
        match path {
            TransportPathKind::Direct => {
                entry.direct_count = entry.direct_count.saturating_add(1);
                entry.direct_bytes = entry.direct_bytes.saturating_add(bytes);
            }
            TransportPathKind::Relayed => {
                entry.relay_count = entry.relay_count.saturating_add(1);
                entry.relay_bytes = entry.relay_bytes.saturating_add(bytes);
            }
        }
    }

    /// Record a relay prompt shown (and whether accepted) for `peer` at `now`. No-op when disabled.
    pub fn record_prompt(&mut self, peer: &DeviceId, accepted: bool, now: UnixMillis) {
        if !self.enabled {
            return;
        }
        let day = Self::utc_day(now);
        let entry = self
            .by_peer
            .entry(*peer)
            .or_default()
            .entry(day)
            .or_insert_with(|| PeerDayStats {
                day,
                ..Default::default()
            });
        entry.prompts_shown = entry.prompts_shown.saturating_add(1);
        if accepted {
            entry.prompts_accepted = entry.prompts_accepted.saturating_add(1);
        }
    }

    /// Record that a relay prompt was shown (`PromptSender` returned) without double-counting
    /// when the user later accepts it (`M26-M4`).
    pub fn record_prompt_shown(&mut self, peer: &DeviceId, now: UnixMillis) {
        if !self.enabled {
            return;
        }
        let day = Self::utc_day(now);
        let entry = self
            .by_peer
            .entry(*peer)
            .or_default()
            .entry(day)
            .or_insert_with(|| PeerDayStats {
                day,
                ..Default::default()
            });
        entry.prompts_shown = entry.prompts_shown.saturating_add(1);
    }

    /// Record that a relay prompt was accepted (`SendViaRelay`) without double-incrementing
    /// `prompts_shown` if `record_prompt_shown` was already called (`M26-M4`).
    pub fn record_prompt_accepted(&mut self, peer: &DeviceId, now: UnixMillis) {
        if !self.enabled {
            return;
        }
        let day = Self::utc_day(now);
        let entry = self
            .by_peer
            .entry(*peer)
            .or_default()
            .entry(day)
            .or_insert_with(|| PeerDayStats {
                day,
                ..Default::default()
            });
        entry.prompts_accepted = entry.prompts_accepted.saturating_add(1);
        if entry.prompts_shown < entry.prompts_accepted {
            entry.prompts_shown = entry.prompts_accepted;
        }
    }

    /// Immediately purge all stats for a forgotten device (`docs/M2-PLAN.md` §6a.3).
    pub fn forget_peer(&mut self, peer: &DeviceId) {
        self.by_peer.remove(peer);
    }

    /// Clear all recorded stats while keeping the current `enabled` flag.
    pub fn clear(&mut self) {
        self.by_peer.clear();
    }

    /// Read day-granularity stats for `peer`.
    pub fn peer_days(&self, peer: &DeviceId) -> Vec<PeerDayStats> {
        if !self.enabled {
            return Vec::new();
        }
        self.by_peer
            .get(peer)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Aggregate summary across all peers and days (when enabled).
    pub fn total_summary(&self) -> PeerDayStats {
        if !self.enabled {
            return PeerDayStats::default();
        }
        let mut out = PeerDayStats::default();
        for days in self.by_peer.values() {
            for d in days.values() {
                out.direct_count = out.direct_count.saturating_add(d.direct_count);
                out.relay_count = out.relay_count.saturating_add(d.relay_count);
                out.direct_bytes = out.direct_bytes.saturating_add(d.direct_bytes);
                out.relay_bytes = out.relay_bytes.saturating_add(d.relay_bytes);
                out.prompts_shown = out.prompts_shown.saturating_add(d.prompts_shown);
                out.prompts_accepted = out.prompts_accepted.saturating_add(d.prompts_accepted);
            }
        }
        out
    }

    /// All peer-day records flattened for FFI / UI inspection.
    pub fn entries(&self) -> Vec<(DeviceId, PeerDayStats)> {
        if !self.enabled {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (peer, days) in &self.by_peer {
            for d in days.values() {
                out.push((*peer, d.clone()));
            }
        }
        out
    }

    /// Serialize for local state storage (empty when disabled).
    pub fn to_bytes(&self) -> Vec<u8> {
        if !self.enabled {
            return vec![0];
        }
        let mut out = Vec::new();
        out.push(1);
        out.extend_from_slice(&(self.by_peer.len() as u16).to_be_bytes());
        for (peer, days) in &self.by_peer {
            out.extend_from_slice(peer.as_bytes());
            out.extend_from_slice(&(days.len() as u16).to_be_bytes());
            for d in days.values() {
                out.extend_from_slice(&d.day.to_be_bytes());
                out.extend_from_slice(&d.direct_count.to_be_bytes());
                out.extend_from_slice(&d.relay_count.to_be_bytes());
                out.extend_from_slice(&d.direct_bytes.to_be_bytes());
                out.extend_from_slice(&d.relay_bytes.to_be_bytes());
                out.extend_from_slice(&d.prompts_shown.to_be_bytes());
                out.extend_from_slice(&d.prompts_accepted.to_be_bytes());
            }
        }
        out
    }

    /// Deserialize from local state storage.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        if bytes[0] == 0 {
            return Some(ConnectionStatsStore {
                enabled: false,
                by_peer: BTreeMap::new(),
            });
        }
        if bytes[0] != 1 || bytes.len() < 3 {
            return None;
        }
        let n_peers = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        let mut cursor = 3;
        let mut by_peer = BTreeMap::new();
        for _ in 0..n_peers {
            if cursor + 34 > bytes.len() {
                return None;
            }
            let peer = DeviceId::from_bytes(bytes[cursor..cursor + 32].try_into().ok()?).ok()?;
            cursor += 32;
            let n_days = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;
            let mut days = BTreeMap::new();
            for _ in 0..n_days {
                if cursor + 4 + 8 * 6 > bytes.len() {
                    return None;
                }
                let day = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().ok()?);
                cursor += 4;
                let direct_count = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().ok()?);
                cursor += 8;
                let relay_count = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().ok()?);
                cursor += 8;
                let direct_bytes = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().ok()?);
                cursor += 8;
                let relay_bytes = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().ok()?);
                cursor += 8;
                let prompts_shown = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().ok()?);
                cursor += 8;
                let prompts_accepted =
                    u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().ok()?);
                cursor += 8;
                days.insert(
                    day,
                    PeerDayStats {
                        day,
                        direct_count,
                        relay_count,
                        direct_bytes,
                        relay_bytes,
                        prompts_shown,
                        prompts_accepted,
                    },
                );
            }
            by_peer.insert(peer, days);
        }
        if cursor != bytes.len() {
            return None;
        }
        Some(ConnectionStatsStore {
            enabled: true,
            by_peer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{keypair_from_label, receive_keypair_from_label, seeded_rng};

    #[test]
    fn kat_chunk_nonce_aad_and_exporter_key_are_deterministic() {
        assert_eq!(chunk_nonce(0), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(chunk_nonce(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            chunk_nonce(0x0102_0304_0506_0708),
            [0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );

        let tid = TransferId([0x42; 16]);
        let aad0 = chunk_aad(&tid, 0, false);
        let aad0_final = chunk_aad(&tid, 0, true);
        let aad1 = chunk_aad(&tid, 1, false);
        assert_ne!(aad0, aad0_final);
        assert_ne!(aad0, aad1);
        assert!(aad0.starts_with(TAG_FILE_CHUNK));
        assert_eq!(aad0.len(), TAG_FILE_CHUNK.len() + 16 + 8 + 1);

        // Deterministic HPKE seal + exporter key KAT with seeded_rng.
        let sender_kp = keypair_from_label("m26-kat-sender");
        let recv_id_kp = keypair_from_label("m26-kat-recv");
        let recv_kp = receive_keypair_from_label("m26-kat-recv-hpke");
        let group = GroupId([0x11; 32]);
        let payload = b"Voidwire M2.6 deterministic KAT file payload";
        let (root, chunk_hashes) = compute_file_hashes(payload);

        let offer = FileOffer::new(
            group,
            sender_kp.device_id(),
            recv_id_kp.device_id(),
            tid,
            "report.pdf",
            "application/pdf",
            payload.len() as u64,
            root,
            chunk_hashes,
            UnixMillis(1_700_000_000_000),
            UnixMillis(1_700_003_600_000),
        )
        .unwrap();

        let mut rng1 = seeded_rng(0xDEAD_BEEF_CAFE_BABE);
        let (env1, key1) =
            seal_file_offer_with(&offer, &sender_kp, &recv_kp.public(), &mut rng1).unwrap();
        let mut rng2 = seeded_rng(0xDEAD_BEEF_CAFE_BABE);
        let (env2, key2) =
            seal_file_offer_with(&offer, &sender_kp, &recv_kp.public(), &mut rng2).unwrap();
        assert_eq!(env1, env2);
        assert_eq!(key1.as_bytes(), key2.as_bytes());

        // Receiver opens the offer and derives the exact same k_file.
        let (opened, recv_key) = open_file_offer(
            &recv_kp,
            &recv_id_kp.device_id(),
            &group,
            &sender_kp.device_id(),
            &env1,
        )
        .unwrap();
        assert_eq!(opened, offer);
        assert_eq!(recv_key.as_bytes(), key1.as_bytes());
        assert!(opened.allow_open);

        // Encrypt & decrypt final chunk with key1; verify ciphertext is deterministic.
        let ct1 = encrypt_chunk(&key1, &tid, 0, true, payload).unwrap();
        let ct2 = encrypt_chunk(&key2, &tid, 0, true, payload).unwrap();
        assert_eq!(ct1, ct2);
        assert_eq!(ct1.len(), MIN_FINAL_CHUNK_BUCKET + CHUNK_AEAD_TAG_LEN);
        let pt = decrypt_chunk(&recv_key, &tid, 0, true, &ct1).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn final_chunk_padding_buckets_hide_exact_size_and_reject_tamper() {
        for (plain_len, expected_bucket) in [
            (0usize, 4096usize),
            (1, 4096),
            (4092, 4096),
            (4093, 8192),
            (8188, 8192),
            (8189, 16384),
            (30_000, 32768),
            (60_000, 65536),
            (100_000, 131072),
            (200_000, 262144),
            (262_140, 262144),
            (262_144, 262144 + 4),
        ] {
            let data = vec![0x5Au8; plain_len];
            let padded = pad_final_chunk(&data).unwrap();
            assert_eq!(padded.len(), expected_bucket, "plain_len={plain_len}");
            let unpadded = unpad_final_chunk(&padded).unwrap();
            assert_eq!(unpadded.len(), plain_len);
            assert_eq!(unpadded, data);
        }

        // Non-zero padding byte is rejected.
        let mut bad = pad_final_chunk(b"hello").unwrap();
        bad[100] = 1;
        assert_eq!(unpad_final_chunk(&bad), Err(RejectReason::MalformedFrame));

        // Oversized length prefix is rejected.
        let mut bad_len = pad_final_chunk(b"hello").unwrap();
        bad_len[..4].copy_from_slice(&5000u32.to_be_bytes());
        assert_eq!(
            unpad_final_chunk(&bad_len),
            Err(RejectReason::MalformedFrame)
        );

        // Wrong bucket for payload length (e.g. 5 bytes padded to 8192 instead of 4096) is rejected.
        let mut wrong_bucket = pad_final_chunk(b"hello").unwrap();
        wrong_bucket.resize(8192, 0);
        assert_eq!(
            unpad_final_chunk(&wrong_bucket),
            Err(RejectReason::MalformedFrame)
        );
    }

    #[test]
    fn chunk_aead_rejects_reorder_truncation_and_cross_transfer_splice() {
        let key = FileTransferKey([0x77; 32]);
        let tid_a = TransferId([0xAA; 16]);
        let tid_b = TransferId([0xBB; 16]);

        let chunk0 = vec![0x11u8; FILE_CHUNK_SIZE];
        let chunk1 = b"final tail bytes".to_vec();

        let ct0 = encrypt_chunk(&key, &tid_a, 0, false, &chunk0).unwrap();
        let ct1 = encrypt_chunk(&key, &tid_a, 1, true, &chunk1).unwrap();

        // Normal decrypt works.
        assert_eq!(decrypt_chunk(&key, &tid_a, 0, false, &ct0).unwrap(), chunk0);
        assert_eq!(decrypt_chunk(&key, &tid_a, 1, true, &ct1).unwrap(), chunk1);

        // Reordering (chunk 0 presented at index 1) fails AAD check.
        assert_eq!(
            decrypt_chunk(&key, &tid_a, 1, false, &ct0),
            Err(RejectReason::DecryptFailed)
        );

        // Truncation (treating non-final chunk 0 as final) fails shape/AAD check.
        assert!(decrypt_chunk(&key, &tid_a, 0, true, &ct0).is_err());

        // Treating final chunk as non-final fails.
        assert!(decrypt_chunk(&key, &tid_a, 1, false, &ct1).is_err());

        // Cross-transfer splicing (`tid_b` instead of `tid_a`) fails AAD check.
        assert_eq!(
            decrypt_chunk(&key, &tid_b, 0, false, &ct0),
            Err(RejectReason::DecryptFailed)
        );

        // Single-bit flip in ciphertext fails AEAD tag check.
        let mut flipped = ct1.clone();
        flipped[20] ^= 0x01;
        assert_eq!(
            decrypt_chunk(&key, &tid_a, 1, true, &flipped),
            Err(RejectReason::DecryptFailed)
        );
    }

    #[test]
    fn filename_sanitization_and_executable_detection() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(
            sanitize_filename("..\\..\\Windows\\System32\\calc.exe"),
            "calc.exe"
        );
        assert_eq!(sanitize_filename("..."), "shared-file");
        assert_eq!(sanitize_filename("   ..   "), "shared-file");
        assert_eq!(sanitize_filename(".bashrc"), "bashrc");
        assert_eq!(sanitize_filename("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_filename("nul"), "_nul");
        assert_eq!(sanitize_filename("com1.log"), "_com1.log");
        assert_eq!(sanitize_filename("lpt9"), "_lpt9");
        assert_eq!(
            sanitize_filename("inv\u{202E}oice<1>:\"bad\"|?.pdf"),
            "invoice1bad.pdf"
        );

        let long_name = format!("{}.png", "a".repeat(400));
        let san_long = sanitize_filename(&long_name);
        assert!(san_long.len() <= MAX_FILENAME_BYTES);
        assert!(san_long.ends_with(".png"));

        for exec in [
            "setup.exe",
            "installer.MSI",
            "run.bat",
            "script.cmd",
            "payload.scr",
            "deploy.ps1",
            "macro.vbs",
            "app.jar",
            "install.sh",
            "Voidwire.AppImage",
            "pkg.deb",
            "pkg.rpm",
            "app.apk",
            "disk.dmg",
        ] {
            assert!(is_executable_filename(exec), "expected executable: {exec}");
        }
        for safe in [
            "photo.jpg",
            "document.pdf",
            "notes.txt",
            "archive.tar.gz",
            "README",
        ] {
            assert!(!is_executable_filename(safe), "expected non-exec: {safe}");
        }
    }

    #[test]
    fn receiver_size_cap_free_space_part_resume_and_cancel_hygiene() {
        let sender_kp = keypair_from_label("m26-res-sender");
        let recv_kp = keypair_from_label("m26-res-recv");
        let group = GroupId([0x22; 32]);
        let tid = TransferId([0x33; 16]);
        let now = UnixMillis(1_700_000_000_000);
        let exp = UnixMillis(1_700_003_600_000);

        // Offer > 2 GiB is refused before construction/decode.
        assert_eq!(
            FileOffer::new(
                group,
                sender_kp.device_id(),
                recv_kp.device_id(),
                tid,
                "huge.iso",
                "application/octet-stream",
                MAX_FILE_SIZE + 1,
                [0u8; 32],
                Vec::new(),
                now,
                exp,
            ),
            Err(RejectReason::UrlTooLong)
        );

        let dir = std::env::temp_dir().join(format!(
            "vw-m26-part-{:x}",
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Free-space check: requesting u64::MAX - 10 bytes fails with InsufficientDiskSpace.
        assert!(matches!(
            check_free_space_for_size(&dir, u64::MAX - FREE_SPACE_MARGIN_BYTES),
            Err(FileAcceptError::InsufficientDiskSpace { .. })
        ));

        // 3-chunk file transfer with kill/interrupt after chunk 1, then resume from chunk 1.
        let total_len = FILE_CHUNK_SIZE * 2 + 12_345;
        let mut file_data = vec![0u8; total_len];
        for (i, b) in file_data.iter_mut().enumerate() {
            *b = ((i * 31 + 7) & 0xFF) as u8;
        }
        let (root, chunk_hashes) = compute_file_hashes(&file_data);
        let offer = FileOffer::new(
            group,
            sender_kp.device_id(),
            recv_kp.device_id(),
            tid,
            "installer.exe",
            "application/octet-stream",
            file_data.len() as u64,
            root,
            chunk_hashes,
            now,
            exp,
        )
        .unwrap();
        assert!(!offer.allow_open, "executables must never allow Open");

        let key = FileTransferKey([0x99; 32]);
        let c0 = encrypt_chunk(&key, &tid, 0, false, &file_data[..FILE_CHUNK_SIZE]).unwrap();
        let c1 = encrypt_chunk(
            &key,
            &tid,
            1,
            false,
            &file_data[FILE_CHUNK_SIZE..FILE_CHUNK_SIZE * 2],
        )
        .unwrap();
        let c2 = encrypt_chunk(&key, &tid, 2, true, &file_data[FILE_CHUNK_SIZE * 2..]).unwrap();

        // Session 1: write chunk 0, then drop/interrupt.
        {
            let mut r1 =
                PartFileReceiver::open_or_resume(offer.clone(), key.clone(), &dir, now).unwrap();
            assert_eq!(r1.next_chunk(), 0);
            r1.write_encrypted_chunk(0, &c0).unwrap();
            assert_eq!(r1.next_chunk(), 1);
        }

        // Session 2: reopen and verify `next_chunk == 1` (resumes without re-sending chunk 0).
        let mut r2 =
            PartFileReceiver::open_or_resume(offer.clone(), key.clone(), &dir, now).unwrap();
        assert_eq!(r2.next_chunk(), 1);
        assert_eq!(r2.bytes_written(), FILE_CHUNK_SIZE as u64);

        // Tampered chunk 1 is rejected and does not advance `next_chunk`.
        let mut bad_c1 = c1.clone();
        bad_c1[50] ^= 0xFF;
        assert_eq!(
            r2.write_encrypted_chunk(1, &bad_c1),
            Err(RejectReason::DecryptFailed)
        );
        assert_eq!(r2.next_chunk(), 1);

        r2.write_encrypted_chunk(1, &c1).unwrap();
        r2.write_encrypted_chunk(2, &c2).unwrap();
        assert!(r2.is_complete());

        let part_path = r2.part_path().to_path_buf();
        let meta_path = r2.meta_path().to_path_buf();
        let done = r2.finalize().unwrap();
        assert!(!part_path.exists(), ".part moved on finalize");
        assert!(!meta_path.exists(), ".part.meta removed on finalize");
        assert!(!done.allow_open);
        assert_eq!(std::fs::read(&done.path).unwrap(), file_data);

        // Cancel hygiene: canceling mid-transfer immediately deletes .part and .part.meta.
        let tid_cancel = TransferId([0x44; 16]);
        let (_, cancel_hashes) = compute_file_hashes(&file_data);
        let offer_cancel = FileOffer::new(
            group,
            sender_kp.device_id(),
            recv_kp.device_id(),
            tid_cancel,
            "photo.png",
            "image/png",
            file_data.len() as u64,
            root,
            cancel_hashes,
            now,
            exp,
        )
        .unwrap();
        let c0_cancel =
            encrypt_chunk(&key, &tid_cancel, 0, false, &file_data[..FILE_CHUNK_SIZE]).unwrap();
        let mut r_cancel = PartFileReceiver::open_or_resume(offer_cancel, key, &dir, now).unwrap();
        r_cancel.write_encrypted_chunk(0, &c0_cancel).unwrap();
        let (p_cancel, m_cancel) = part_paths(&dir, &tid_cancel);
        assert!(p_cancel.exists() && m_cancel.exists());
        r_cancel.cancel_and_delete();
        assert!(!p_cancel.exists(), "cancel must delete .part immediately");
        assert!(
            !m_cancel.exists(),
            "cancel must delete .part.meta immediately"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relay_data_minimization_policy_enforces_small_prompt_and_cap_rules() {
        let policy = RelayTransferPolicy {
            small_item_cap_bytes: 256 * 1024,
            server_relay_cap_bytes: 25 * 1024 * 1024,
            user_relay_cap_bytes: 10 * 1024 * 1024,
            last_config_issued_at_day: 0,
        };
        assert_eq!(policy.effective_relay_cap_bytes(), 10 * 1024 * 1024);

        // Direct path always proceeds without prompt, even for 500 MB.
        assert_eq!(
            policy.evaluate(500 * 1024 * 1024, TransportPathKind::Direct, None),
            RelayPolicyOutcome::ProceedDirect
        );

        // Small items (<= 256 KiB) auto-relay without prompting.
        assert_eq!(
            policy.evaluate(256 * 1024, TransportPathKind::Relayed, None),
            RelayPolicyOutcome::ProceedViaRelay
        );

        // Medium/large items (256 KiB < size <= effective_cap) prompt when on relay.
        let five_mb = 5 * 1024 * 1024;
        assert_eq!(
            policy.evaluate(five_mb, TransportPathKind::Relayed, None),
            RelayPolicyOutcome::PromptSender {
                size: five_mb,
                effective_cap: 10 * 1024 * 1024,
            }
        );
        assert_eq!(
            policy.evaluate(
                five_mb,
                TransportPathKind::Relayed,
                Some(RelayPromptDecision::SendViaRelay)
            ),
            RelayPolicyOutcome::ProceedViaRelay
        );
        assert_eq!(
            policy.evaluate(
                five_mb,
                TransportPathKind::Relayed,
                Some(RelayPromptDecision::WaitForDirect)
            ),
            RelayPolicyOutcome::WaitForDirect
        );
        assert_eq!(
            policy.evaluate(
                five_mb,
                TransportPathKind::Relayed,
                Some(RelayPromptDecision::Cancel)
            ),
            RelayPolicyOutcome::Cancelled
        );

        // Items above effective_cap (e.g. 12 MB > 10 MB user cap) refuse relay even if SendViaRelay is passed.
        let twelve_mb = 12 * 1024 * 1024;
        assert_eq!(
            policy.evaluate(
                twelve_mb,
                TransportPathKind::Relayed,
                Some(RelayPromptDecision::SendViaRelay)
            ),
            RelayPolicyOutcome::ExceedsRelayCap {
                size: twelve_mb,
                effective_cap: 10 * 1024 * 1024,
            }
        );
    }

    #[test]
    fn connection_stats_off_by_default_day_granularity_and_purged_on_toggle_or_forget() {
        let peer_a = keypair_from_label("m26-stats-a").device_id();
        let peer_b = keypair_from_label("m26-stats-b").device_id();
        // Two timestamps on the same UTC day (1_729_814_400_000 is 2024-10-25T00:00:00Z).
        let t1 = UnixMillis(1_729_814_400_000 + 3_600_000);
        let t2 = UnixMillis(1_729_814_400_000 + 72_000_000);

        let mut stats = ConnectionStatsStore::new();
        assert!(!stats.is_enabled());

        // While disabled, nothing is recorded.
        stats.record_transfer(&peer_a, TransportPathKind::Direct, 1024, t1);
        stats.record_prompt(&peer_a, true, t1);
        assert!(stats.peer_days(&peer_a).is_empty());
        assert_eq!(stats.to_bytes(), vec![0]);

        // Enable and record across two peers on the same UTC day.
        stats.set_enabled(true);
        stats.record_transfer(&peer_a, TransportPathKind::Direct, 100_000, t1);
        stats.record_transfer(&peer_a, TransportPathKind::Relayed, 50_000, t2);
        stats.record_prompt(&peer_a, true, t2);
        stats.record_transfer(&peer_b, TransportPathKind::Direct, 200_000, t1);

        let days_a = stats.peer_days(&peer_a);
        assert_eq!(days_a.len(), 1, "coarsened to a single UTC day");
        assert_eq!(days_a[0].day, ConnectionStatsStore::utc_day(t1));
        assert_eq!(days_a[0].direct_count, 1);
        assert_eq!(days_a[0].relay_count, 1);
        assert_eq!(days_a[0].direct_bytes, 100_000);
        assert_eq!(days_a[0].relay_bytes, 50_000);
        assert_eq!(days_a[0].prompts_shown, 1);
        assert_eq!(days_a[0].prompts_accepted, 1);

        // Round-trip serialization preserves only day numbers and counters.
        let bytes = stats.to_bytes();
        let restored = ConnectionStatsStore::from_bytes(&bytes).unwrap();
        assert_eq!(restored, stats);

        // Forgetting peer_a purges only peer_a's stats immediately.
        stats.forget_peer(&peer_a);
        assert!(stats.peer_days(&peer_a).is_empty());
        assert_eq!(stats.peer_days(&peer_b).len(), 1);

        // Toggling off purges everything immediately.
        stats.set_enabled(false);
        assert!(stats.peer_days(&peer_b).is_empty());
        assert_eq!(stats.to_bytes(), vec![0]);
    }

    #[test]
    fn m26_m2_large_offer_carries_all_chunk_hashes_past_50_mib_and_rejects_missing_hashes() {
        let sender_kp = keypair_from_label("m26-m2-sender");
        let recv_id_kp = keypair_from_label("m26-m2-recv");
        let recv_kp = receive_keypair_from_label("m26-m2-recv-hpke");
        let group = GroupId([0x55; 32]);
        let tid = TransferId([0x66; 16]);
        let now = UnixMillis(1_700_000_000_000);
        let exp = UnixMillis(1_700_003_600_000);

        // 300 chunks = 75 MiB (> 50 MiB / 200 chunks).
        let n_chunks = 300usize;
        let size = (n_chunks * FILE_CHUNK_SIZE) as u64;
        let hashes: Vec<[u8; 32]> = (0..n_chunks).map(|i| [(i & 0xFF) as u8; 32]).collect();

        // Empty chunk_hashes is rejected for any file.
        assert_eq!(
            FileOffer::new(
                group,
                sender_kp.device_id(),
                recv_id_kp.device_id(),
                tid,
                "archive.tar",
                "application/x-tar",
                size,
                [0xAA; 32],
                Vec::new(),
                now,
                exp,
            ),
            Err(RejectReason::MalformedFrame)
        );

        let offer = FileOffer::new(
            group,
            sender_kp.device_id(),
            recv_id_kp.device_id(),
            tid,
            "archive.tar",
            "application/x-tar",
            size,
            [0xAA; 32],
            hashes.clone(),
            now,
            exp,
        )
        .unwrap()
        .with_log_head([0x77; 32]);
        assert_eq!(offer.chunk_hashes.len(), n_chunks);

        let (env, k1) = seal_file_offer(&offer, &sender_kp, &recv_kp.public()).unwrap();
        let (opened, k2) = open_file_offer(
            &recv_kp,
            &recv_id_kp.device_id(),
            &group,
            &sender_kp.device_id(),
            &env,
        )
        .unwrap();
        assert_eq!(opened.chunk_hashes, hashes);
        assert_eq!(opened.log_head, [0x77; 32]);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn m26_m3_l1_l2_h2_extensions_reserved_stems_streaming_hash_and_part_sweep() {
        for ext in [
            "lnk", "pif", "reg", "cpl", "msc", "inf", "sct", "wsc", "vbe", "url", "desktop",
            "webloc", "msp", "msu", "appx", "msix", "py", "pl", "rb", "iso", "vhd", "vhdx",
        ] {
            let name = format!("item.{ext}");
            assert!(is_executable_filename(&name), "must block Open for {name}");
        }

        for raw in [
            "CONIN$",
            "CONOUT$.txt",
            "CLOCK$",
            "COM\u{00B9}.log",
            "LPT\u{00B3}",
        ] {
            let san = sanitize_filename(raw);
            assert!(
                san.starts_with('_'),
                "expected reserved prefix for {raw}: got {san}"
            );
        }

        let dir = std::env::temp_dir().join(format!(
            "vw-m26-stream-{:x}",
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let src_file = dir.join("source.bin");
        let payload = vec![0x3Cu8; FILE_CHUNK_SIZE + 777];
        std::fs::write(&src_file, &payload).unwrap();

        let (mem_root, mem_hashes) = compute_file_hashes(&payload);
        let (sz, stream_root, stream_hashes) = compute_file_hashes_streaming(&src_file).unwrap();
        assert_eq!(sz, payload.len() as u64);
        assert_eq!(stream_root, mem_root);
        assert_eq!(stream_hashes, mem_hashes);

        let key = FileTransferKey([0x51; 32]);
        let tid = TransferId([0x52; 16]);
        let mut f = std::fs::File::open(&src_file).unwrap();
        let ct0 = read_and_encrypt_file_chunk(&mut f, sz, 2, &key, &tid, 0).unwrap();
        let ct1 = read_and_encrypt_file_chunk(&mut f, sz, 2, &key, &tid, 1).unwrap();
        assert_eq!(
            decrypt_chunk(&key, &tid, 0, false, &ct0).unwrap(),
            &payload[..FILE_CHUNK_SIZE]
        );
        assert_eq!(
            decrypt_chunk(&key, &tid, 1, true, &ct1).unwrap(),
            &payload[FILE_CHUNK_SIZE..]
        );

        let now = UnixMillis(1_700_000_000_000);
        let exp = UnixMillis(1_700_003_600_000);
        let (part_p, meta_p) = part_paths(&dir, &tid);
        std::fs::write(&part_p, b"partial").unwrap();
        let meta = PartResumeMeta {
            transfer_id: tid,
            total_size: sz,
            chunk_count: 2,
            next_chunk: 1,
            blake3_root: stream_root,
            filename: "source.bin".to_string(),
            expires_at: exp,
        };
        std::fs::write(&meta_p, meta.to_bytes()).unwrap();
        assert_eq!(purge_expired_parts(&dir, now), 0);
        assert!(part_p.exists() && meta_p.exists());
        assert_eq!(purge_expired_parts(&dir, UnixMillis(exp.0 + 1)), 1);
        assert!(!part_p.exists() && !meta_p.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
