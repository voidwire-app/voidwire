//! M4.3: pairing any two devices (PC↔PC, phone↔phone, PC↔phone) straight
//! into a v2 pairing.
//!
//! The device that shows the code is the inviter; the device that scans
//! the QR or types the code joins. The cryptography is the M1 pairing's:
//! a single-use 128-bit secret that lives 5 minutes (M1 QRs: 120 s), an HMAC proof over a
//! transcript bound to the TLS exporter and both certificates, and a SAS
//! the joiner shows and the inviter's user types. New in v2: the pairing
//! relay (URL and mailbox), the pairing id and the joiner's per-pairing
//! receive key are in the transcript too, so a swapped relay in a QR or
//! card fails the proof, and the pairing log starts from them.
//!
//! ```text
//! joiner                               inviter
//! HELLO(secret id, 2)          ─►
//!                              ◄─      INVITER_CERT
//! PROOF(hmac, rx, cert)        ─►      redeem (burns the secret)
//!                              ◄─      PROOF_OK            (joiner shows the SAS)
//!                                      user types the SAS
//!                              ◄─      WELCOME(sealed: genesis, gs_0)
//! JOIN(co-signed genesis, Caps) ─►
//!                              ◄─      DONE(co-signed Caps)
//! OK                           ─►      both keep the pairing
//! ```
//!
//! Typed code: `VW-` + 26 base32 characters (the 128-bit secret) + 2 check
//! characters. The inviter puts a sealed invite card (its QR without the
//! secret's owner learning anything new) into a rendezvous RAM inbox whose
//! id, keys and sealing key all come from the secret; the joiner pulls it,
//! acks it so the relay drops it, and continues as if it had scanned.

use super::{frame, pairing_exporter, pairing_handshake, parse_error, read_frame, write_frame};
use super::{NetError, ALPN_PAIR, IO_TIMEOUT};
use crate::ids::{DeviceId, GroupId};
use crate::keys::{DeviceCert, DeviceKeypair, ReceiveKeypair};
use crate::limits::{PAIRING_CODE_TTL_MS, SAS_CONFIRM_TTL_MS};
use crate::pairing::{PairingGrant, PairingRegistry, PairingRequest, ScannedInvite};
use crate::pairwise::{
    Pairing, RelayEntry, RelayRef, RelaySettings, RelaySource, MAX_RELAYS_IN_USE, MAX_SAVED_RELAYS,
};
use crate::reject::RejectReason;
use crate::time::{Clock, Now, UnixMillis};
use hkdf::Hkdf;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::Endpoint;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use zeroize::Zeroizing;

/// QR version of a v2 invite. A PC with its home relay still shows `v=1`
/// (M3 phones can scan it).
pub const QR_V2: &str = "2";
/// The pairing hello's version byte (after the 8-byte secret id).
const HELLO_V2: u8 = 2;
const TAG_CODE_CHECK: &[u8] = b"voidwire/v2/code-check\0";
const TAG_RENDEZVOUS: &[u8] = b"voidwire/v2/rendezvous\0";
/// Crockford base32 (no I, L, O, U).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters for the secret (130 bits; the top two are zero).
const CODE_SECRET_CHARS: usize = 26;
const CODE_CHECK_CHARS: usize = 2;

// ----- typed code ---------------------------------------------------------

fn code_check(secret: &[u8; 16]) -> u16 {
    let mut h = Sha256::new();
    h.update(TAG_CODE_CHECK);
    h.update(secret);
    let d = h.finalize();
    u16::from_be_bytes([d[0], d[1]]) >> 6
}

/// `VW-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`: the secret, then 2 check
/// characters that catch typos before any network traffic.
pub fn encode_code(secret: &[u8; 16]) -> String {
    let v = u128::from_be_bytes(*secret);
    let mut chars = Vec::with_capacity(CODE_SECRET_CHARS + CODE_CHECK_CHARS);
    for i in (0..CODE_SECRET_CHARS).rev() {
        let shift = i * 5;
        let d = if shift >= 128 {
            0
        } else {
            ((v >> shift) & 31) as usize
        };
        chars.push(ALPHABET[d]);
    }
    let c = code_check(secret);
    chars.push(ALPHABET[(c >> 5) as usize & 31]);
    chars.push(ALPHABET[c as usize & 31]);
    let mut out = String::from("VW");
    for g in chars.chunks(4) {
        out.push('-');
        out.push_str(std::str::from_utf8(g).expect("ascii"));
    }
    out
}

fn digit(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        c => c,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|i| i as u8)
}

/// Parse a typed code (any case, spaces and dashes ignored, `VW` prefix
/// optional). A typo is caught by the check characters:
/// `PairingCodeInvalid`.
pub fn parse_code(typed: &str) -> Result<Zeroizing<[u8; 16]>, RejectReason> {
    let mut s: String = typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if s.len() == CODE_SECRET_CHARS + CODE_CHECK_CHARS + 2 && s[..2].eq_ignore_ascii_case("VW") {
        s.drain(..2);
    }
    if s.len() != CODE_SECRET_CHARS + CODE_CHECK_CHARS {
        return Err(RejectReason::PairingCodeInvalid);
    }
    let mut v: u128 = 0;
    let mut top: u8 = 0;
    let mut ds = Vec::with_capacity(s.len());
    for c in s.chars() {
        ds.push(digit(c).ok_or(RejectReason::PairingCodeInvalid)?);
    }
    for (i, d) in ds[..CODE_SECRET_CHARS].iter().enumerate() {
        if i == 0 {
            top = d >> 3;
        }
        v = (v << 5) | u128::from(*d);
    }
    let secret = Zeroizing::new(v.to_be_bytes());
    let c = (u16::from(ds[CODE_SECRET_CHARS]) << 5) | u16::from(ds[CODE_SECRET_CHARS + 1]);
    if top != 0 || c != code_check(&secret) {
        return Err(RejectReason::PairingCodeInvalid);
    }
    Ok(secret)
}

// ----- QR v=2 ---------------------------------------------------------------

/// A v2 invite as the joiner holds it (from a QR or an invite card).
pub struct V2Invite {
    pub(crate) scanned: ScannedInvite,
    /// The pairing relay (bound into the transcript and the pairing log).
    pub relay: RelayRef,
}

impl std::fmt::Debug for V2Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2Invite").finish_non_exhaustive()
    }
}

impl V2Invite {
    pub fn inviter(&self) -> DeviceId {
        self.scanned.inviter
    }
    pub fn inviter_name(&self) -> Option<&str> {
        self.scanned.inviter_name.as_deref()
    }
    pub fn expires_at(&self) -> UnixMillis {
        self.scanned.expires_at
    }
    pub fn relay_url(&self) -> &str {
        &self.relay.url
    }
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Like `enc` but leaves `:/,[]@` as they are, for URLs and addresses: every
/// escape costs the QR two bytes, and a denser QR is harder to scan. The
/// form decoder in `parse_qr` (and in older versions) reads both forms.
fn enc_url(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:/,[]@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The QR (and invite card) text of a v2 invite.
#[allow(clippy::too_many_arguments)]
pub(crate) fn qr_uri(
    inviter: &DeviceId,
    pairing_id: &GroupId,
    relay: &RelayRef,
    mailbox: &DeviceId,
    dial_relay: Option<&str>,
    addrs: &[SocketAddr],
    name: &str,
    expires_at: UnixMillis,
    secret: &[u8; 16],
) -> String {
    let mut uri = format!(
        "voidwire:pair?v={QR_V2}&id={}&r={}&m={}&g={}&s={}&exp={}",
        inviter.to_hex(),
        enc_url(&relay.url),
        mailbox.to_hex(),
        pairing_id.to_hex(),
        crate::hex::encode(secret),
        expires_at.0
    );
    if crate::keys::valid_device_name(name) {
        uri.push_str("&n=");
        uri.push_str(&enc(name));
    }
    let a: Vec<String> = addrs
        .iter()
        .take(crate::pairing::MAX_QR_ADDRS)
        .map(|a| a.to_string())
        .collect();
    if !a.is_empty() {
        uri.push_str("&a=");
        uri.push_str(&enc_url(&a.join(",")));
    }
    if let Some(d) = dial_relay.filter(|d| *d != relay.url && !d.is_empty()) {
        uri.push_str("&d=");
        uri.push_str(&enc_url(d));
    }
    uri
}

/// The QR's version without parsing the rest (`None`: not a pairing QR).
pub fn qr_version(uri: &str) -> Option<String> {
    let q = uri.strip_prefix("voidwire:pair?")?;
    url::form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == "v")
        .map(|(_, v)| v.into_owned())
}

/// Strict parser for `voidwire:pair?v=2&…`: required fields, no
/// duplicates, `m` always present, relay URLs validated, not expired.
pub fn parse_qr(uri: &str, now: Now) -> Result<V2Invite, RejectReason> {
    if uri.len() > 1536 {
        return Err(RejectReason::MalformedFrame);
    }
    let q = uri
        .strip_prefix("voidwire:pair?")
        .ok_or(RejectReason::MalformedFrame)?;
    let mut f: HashMap<String, String> = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
        if f.insert(k.into_owned(), v.into_owned()).is_some() {
            return Err(RejectReason::MalformedFrame);
        }
    }
    let get = |k: &str| f.get(k).ok_or(RejectReason::MalformedFrame);
    if get("v")? != QR_V2 {
        return Err(RejectReason::UnsupportedVersion);
    }
    let inviter = DeviceId::from_hex(get("id")?).ok_or(RejectReason::MalformedFrame)?;
    let group = GroupId::from_hex(get("g")?).ok_or(RejectReason::MalformedFrame)?;
    let secret = crate::hex::decode_array::<16>(get("s")?).ok_or(RejectReason::MalformedFrame)?;
    let expires_at = UnixMillis(
        get("exp")?
            .parse::<u64>()
            .map_err(|_| RejectReason::MalformedFrame)?,
    );
    let relay_url =
        crate::pairing::validate_relay_url(get("r")?)?.ok_or(RejectReason::MalformedFrame)?;
    let mailbox = DeviceId::from_hex(get("m")?).ok_or(RejectReason::MalformedFrame)?;
    let dial = match f.get("d") {
        None => relay_url.clone(),
        Some(d) => crate::pairing::validate_relay_url(d)?.ok_or(RejectReason::MalformedFrame)?,
    };
    let mut addrs = Vec::new();
    if let Some(a) = f.get("a") {
        for part in a.split(',').filter(|p| !p.is_empty()) {
            if addrs.len() == crate::pairing::MAX_QR_ADDRS {
                return Err(RejectReason::MalformedFrame);
            }
            addrs.push(part.parse().map_err(|_| RejectReason::MalformedFrame)?);
        }
    }
    let name = match f.get("n") {
        Some(n) if crate::keys::valid_device_name(n) => Some(n.clone()),
        Some(_) => return Err(RejectReason::BadDeviceName),
        None => None,
    };
    let known = ["v", "id", "r", "m", "g", "s", "exp", "a", "n", "d"];
    if f.keys().any(|k| !known.contains(&k.as_str())) {
        return Err(RejectReason::MalformedFrame);
    }
    if now.wall >= expires_at {
        return Err(RejectReason::PairingSecretExpired);
    }
    Ok(V2Invite {
        scanned: ScannedInvite::from_parts(
            inviter,
            group,
            dial,
            addrs,
            name,
            Some(mailbox),
            expires_at,
            secret,
        ),
        relay: relay_with_mailbox(&relay_url, mailbox),
    })
}

// ----- rendezvous inbox -----------------------------------------------------

/// The rendezvous inbox for a secret: its keys, and the key the card is
/// sealed to. Everything comes from the secret, so only code holders find
/// or open the card.
pub(crate) struct Rendezvous {
    pub keys: crate::mailbox::DeviceInboxKeys,
    pub rx: ReceiveKeypair,
    pub id: DeviceId,
}

pub(crate) fn rendezvous(secret: &[u8; 16]) -> Rendezvous {
    let hk = Hkdf::<Sha256>::new(Some(TAG_RENDEZVOUS), secret);
    let mut out = Zeroizing::new([0u8; 96]);
    hk.expand(b"inbox|seal|id", &mut out[..])
        .expect("96 bytes is a valid HKDF length");
    let gs = crate::mailbox::EpochSecret::from_bytes(out[..32].try_into().expect("32"));
    let rx = ReceiveKeypair::from_secret_bytes(&out[32..64].try_into().expect("32"))
        .expect("x25519 accepts any 32 bytes");
    let id = DeviceKeypair::from_secret_bytes(&out[64..96].try_into().expect("32")).device_id();
    let keys = gs.derive_device_inbox_keys(&GroupId([0x52; 32]), 0, &id, &rx.public());
    Rendezvous { keys, rx, id }
}

/// Inviter: put the sealed card (the QR text) into the rendezvous inbox.
pub(crate) async fn publish_card(
    secret: &[u8; 16],
    card_uri: &str,
    relay_url: &str,
    mailbox: &DeviceId,
) -> Result<[u8; 16], NetError> {
    let r = rendezvous(secret);
    let env = crate::envelope::seal(&r.id, &r.rx.public(), card_uri.as_bytes())?;
    let mut item = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut item);
    super::mailbox_client::put_device_inbox_item(mailbox, relay_url, &r.keys, item, env)
        .await
        .map(|_| item)
}

/// A card this device put: deleted from the relay as soon as its code is
/// used, cancelled, replaced or expired (the relay's own inbox TTL is the
/// backstop when the app is killed first).
pub(crate) struct Card {
    handle: tokio::runtime::Handle,
    secret: Zeroizing<[u8; 16]>,
    relay_url: String,
    mailbox: DeviceId,
    item: [u8; 16],
}

impl Card {
    /// Delete the card in the background (one ack; best effort).
    fn retract(self) {
        let Card {
            handle,
            secret,
            relay_url,
            mailbox,
            item,
        } = self;
        handle.spawn(async move {
            let r = rendezvous(&secret);
            if let Ok(sess) =
                super::mailbox_client::ThrowawaySession::connect(&mailbox, &relay_url).await
            {
                let _ = sess.ack_device_inbox(&r.keys, &[item]).await;
                sess.close().await;
            }
        });
    }
}

/// Joiner: pull the card for a typed code from `relay_url`, ack it (the
/// relay drops it), open it and check it carries the same secret.
pub(crate) async fn fetch_card(
    secret: &[u8; 16],
    relay_url: &str,
    mailbox: &DeviceId,
    now: Now,
) -> Result<V2Invite, NetError> {
    let r = rendezvous(secret);
    let sess = super::mailbox_client::ThrowawaySession::connect(mailbox, relay_url).await?;
    let res = async {
        let items = sess.pull_device_inbox(&r.keys).await?;
        let ids: Vec<[u8; 16]> = items.iter().map(|i| i.item_id).collect();
        let _ = sess.ack_device_inbox(&r.keys, &ids).await;
        let mut found = Err(NetError::Rejected(RejectReason::PairingSecretUnknown));
        for it in items {
            let Ok(body) = crate::envelope::open(&r.rx, &r.id, &it.envelope) else {
                continue;
            };
            let Ok(uri) = std::str::from_utf8(&body) else {
                continue;
            };
            match parse_qr(uri, now) {
                Ok(inv) if *inv.scanned.secret_bytes() == *secret => {
                    found = Ok(inv);
                    break;
                }
                Ok(_) => {}
                Err(e) => found = Err(NetError::Rejected(e)),
            }
        }
        found
    }
    .await;
    sess.close().await;
    res
}

/// Test harness (M4.3): is a card for `code` still waiting in its
/// rendezvous inbox? Pulls without acking, so it never deletes the card
/// itself (the inviter's retraction is what's under test).
#[cfg(feature = "test-util")]
pub fn card_waiting_for_tests(code: &str, relay_url: &str, mailbox: &DeviceId) -> bool {
    let Ok(secret) = parse_code(code) else {
        return false;
    };
    let r = rendezvous(&secret);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let Ok(sess) = super::mailbox_client::ThrowawaySession::connect(mailbox, relay_url).await
        else {
            return true;
        };
        let n = sess.pull_device_inbox(&r.keys).await.map(|v| v.len());
        sess.close().await;
        // An unreachable relay counts as "still there" so a wait retries.
        n.map_or(true, |n| n > 0)
    })
}

// ----- transcript -------------------------------------------------------------

/// The M1 handshake bytes plus what v2 binds: the pairing relay, its
/// mailbox and the joiner's per-pairing receive key.
fn handshake_v2(
    exporter: &[u8; 32],
    inviter_cert: &[u8],
    joiner_cert: &[u8],
    relay: &RelayRef,
    joiner_rx: &crate::keys::ReceivePublicKey,
) -> Vec<u8> {
    let mut h = pairing_handshake(exporter, inviter_cert, joiner_cert);
    h.extend_from_slice(b"voidwire/v2/pair\0");
    h.extend_from_slice(&(relay.url.len() as u16).to_be_bytes());
    h.extend_from_slice(relay.url.as_bytes());
    match &relay.mailbox_id {
        Some(m) => {
            h.push(1);
            h.extend_from_slice(m.as_bytes());
        }
        None => h.push(0),
    }
    h.extend_from_slice(&joiner_rx.0);
    h
}

// ----- joiner ---------------------------------------------------------------

/// Dial the inviter on ALPN_PAIR (addresses first, then its relay).
pub(crate) async fn dial(ep: &Endpoint, inv: &V2Invite) -> Result<Connection, NetError> {
    let id = super::endpoint_id_of(&inv.scanned.inviter)?;
    let mut addr = iroh::EndpointAddr::new(id);
    for a in &inv.scanned.addrs {
        addr = addr.with_ip_addr(*a);
    }
    if let Ok(u) = inv.scanned.relay_url.parse::<iroh::RelayUrl>() {
        addr = addr.with_relay_url(u);
    }
    match tokio::time::timeout(Duration::from_secs(10), ep.connect(addr, ALPN_PAIR)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(NetError::Unreachable(e.to_string())),
        Err(_) => Err(NetError::Unreachable(
            "no answer from the other device".into(),
        )),
    }
}

/// A joiner between the proof and the WELCOME: the SAS is on screen.
pub struct Joining {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    rx: ReceiveKeypair,
    relay: RelayRef,
    inviter_cert: DeviceCert,
    /// Our certificate as proved (the genesis must carry exactly it).
    my_cert: DeviceCert,
    pub sas: String,
}

impl std::fmt::Debug for Joining {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Joining").finish_non_exhaustive()
    }
}

impl Joining {
    pub fn inviter_name(&self) -> &str {
        self.inviter_cert.name()
    }
    pub fn inviter(&self) -> DeviceId {
        self.inviter_cert.device()
    }
    pub fn close(&self) {
        self.conn
            .close(super::close_code(RejectReason::PairingCancelled), b"");
    }
}

/// Joiner, step 1: hello, check the inviter's certificate, prove the
/// secret. Returns with the SAS to show.
pub(crate) async fn join_start(
    conn: Connection,
    inv: &V2Invite,
    my_cert: &DeviceCert,
) -> Result<Joining, NetError> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| super::conn_error(&conn, e))?;
    let sid = inv.scanned.secret_id();
    let mut hello = sid.to_vec();
    hello.push(HELLO_V2);
    write_frame(&mut send, frame::HELLO, &hello).await?;
    let inviter_cert = match read_frame(&mut recv, IO_TIMEOUT).await? {
        (frame::INVITER_CERT, p) => DeviceCert::parse_verified(&p)?,
        (frame::ERROR, p) => return Err(parse_error(&p)),
        _ => return Err(NetError::Protocol("unexpected frame".into())),
    };
    if inviter_cert.device() != inv.scanned.inviter
        || inv
            .scanned
            .inviter_name
            .as_deref()
            .is_some_and(|n| n != inviter_cert.name())
    {
        conn.close(super::close_code(RejectReason::SenderMismatch), b"");
        return Err(NetError::Rejected(RejectReason::SenderMismatch));
    }
    let rx = ReceiveKeypair::generate();
    let exporter = pairing_exporter(&conn, &sid)?;
    let hs = handshake_v2(
        &exporter,
        inviter_cert.as_bytes(),
        my_cert.as_bytes(),
        &inv.relay,
        &rx.public(),
    );
    let req = PairingRequest::create_with_cert(&inv.scanned, my_cert, &hs);
    let mut p = req.proof.to_vec();
    p.extend_from_slice(&rx.public().0);
    p.extend_from_slice(my_cert.as_bytes());
    write_frame(&mut send, frame::PROOF, &p).await?;
    match read_frame(&mut recv, IO_TIMEOUT).await? {
        (frame::PROOF_OK, _) => {}
        (frame::ERROR, p) => return Err(parse_error(&p)),
        _ => return Err(NetError::Protocol("unexpected frame".into())),
    }
    let sas = inv.scanned.sas_code(&my_cert.device(), my_cert.name(), &hs);
    Ok(Joining {
        conn,
        send,
        recv,
        rx,
        relay: inv.relay.clone(),
        inviter_cert,
        my_cert: my_cert.clone(),
        sas,
    })
}

/// Joiner, step 2: wait for the inviter's user to type the SAS, then
/// build the pairing. `keep` stores it; only then do we say OK.
pub(crate) async fn join_finish(
    mut j: Joining,
    me: &DeviceKeypair,
    keep: impl FnOnce(Pairing) -> Result<bool, NetError>,
) -> Result<Paired2, NetError> {
    let wait = Duration::from_millis(SAS_CONFIRM_TTL_MS + 10_000);
    let welcome = match read_frame(&mut j.recv, wait).await? {
        (frame::WELCOME, p) => p,
        (frame::ERROR, p) => return Err(parse_error(&p)),
        _ => return Err(NetError::Protocol("unexpected frame".into())),
    };
    let me_id = me.device_id();
    let body = crate::envelope::open(&j.rx, &me_id, &welcome)?;
    let (genesis, wrapped) = super::split::decode_offer(&body)?;
    // The genesis must be the pairing we proved: our cert and key, the
    // inviter we checked, the relay in the transcript.
    match genesis.body() {
        crate::pairwise::PairBody::Genesis {
            inviter,
            joiner,
            joiner_rx,
            relay,
            ..
        } if inviter.as_bytes() == j.inviter_cert.as_bytes()
            && joiner.as_bytes() == j.my_cert.as_bytes()
            && *joiner_rx == j.rx.public()
            && relay.as_ref() == Some(&j.relay) => {}
        _ => {
            let _ = write_frame(
                &mut j.send,
                frame::ERROR,
                &super::error_payload(RejectReason::BadLogOp),
            )
            .await;
            return Err(NetError::Rejected(RejectReason::BadLogOp));
        }
    }
    let ts = crate::time::SystemClock.now().wall;
    let (mut log, cosigned, caps, gs) = crate::pairwise::v2::join(me, &j.rx, genesis, &wrapped, ts)
        .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))?;
    write_frame(
        &mut j.send,
        frame::SPLIT_ACCEPT,
        &super::split::encode_accept(&cosigned, &caps),
    )
    .await?;
    let done = match read_frame(&mut j.recv, IO_TIMEOUT).await? {
        (frame::SPLIT_CAPS, p) => super::split::decode_caps(&p)?,
        (frame::ERROR, p) => return Err(parse_error(&p)),
        _ => return Err(NetError::Protocol("unexpected frame".into())),
    };
    crate::pairwise::v2::finish_join(me, &mut log, done)
        .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))?;
    let rec = crate::pairwise::v2::record(&me_id, log, j.rx, gs)
        .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))?;
    let (peer, name) = (rec.peer.id, rec.peer.name.clone());
    let refreshed = keep(rec)?;
    write_frame(&mut j.send, frame::RESULT, &[0, 0, 0]).await?;
    let _ = j.send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(3), j.send.stopped()).await;
    Ok(Paired2 {
        peer,
        name,
        refreshed,
    })
}

// ----- inviter --------------------------------------------------------------

/// What the inviter's screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostStatus {
    Idle,
    /// The code is live until `expires_at`.
    Showing {
        expires_at: UnixMillis,
    },
    /// Type the 6-digit code shown on `device_name`.
    AwaitingCode {
        device_name: String,
    },
    Paired {
        device_name: String,
    },
    Failed {
        reason: RejectReason,
    },
}

/// A live v2 invite on the showing device.
pub struct Hosted {
    registry: PairingRegistry,
    pub(crate) pairing_id: GroupId,
    pub(crate) relay: RelayRef,
    pub qr: String,
    pub code: String,
    pub expires_at: UnixMillis,
    pub(crate) secret: Zeroizing<[u8; 16]>,
    session: Option<(PairingGrant, tokio::sync::oneshot::Sender<Confirm>)>,
    pub status: HostStatus,
    /// Bumped by every new invite or cancel; a handler from an older one
    /// stops.
    pub gen: u64,
    card: Option<Card>,
}

impl Hosted {
    /// The code is spent (used, cancelled, replaced or expired): delete
    /// its card from the relay.
    fn drop_card(&mut self) {
        if let Some(c) = self.card.take() {
            c.retract();
        }
    }
}

/// A finished v2 pairing, as both screens report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paired2 {
    pub peer: DeviceId,
    pub name: String,
    /// The device was already paired: the new pairing replaced the old one
    /// (its keys, inbox and relay), so it's still one entry. Only known
    /// after the handshake: a code doesn't say who will use it.
    pub refreshed: bool,
}

/// The pairing's outcome: the new peer, or why it failed.
pub type Outcome = Result<Paired2, RejectReason>;
type Confirm = std::sync::mpsc::SyncSender<Outcome>;

/// The inviter's v2 state: one live invite at most.
#[derive(Default)]
pub struct Host {
    pub cur: Option<Hosted>,
    gen: u64,
}

impl Host {
    /// Revoke any live invite and make a new one (QR, code, card text).
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &mut self,
        me: DeviceId,
        name: &str,
        relay: RelayRef,
        mailbox: DeviceId,
        dial_relay: Option<&str>,
        addrs: &[SocketAddr],
        now: Now,
    ) -> Result<&Hosted, RejectReason> {
        self.cancel(now);
        self.gen += 1;
        let pairing_id = crate::pairwise::v2::random_pairing_id();
        let mut registry = PairingRegistry::new(me, pairing_id);
        let invite = registry.issue_with_ttl(now, &mut rand_core::OsRng, CODE_TTL_MS)?;
        let secret = invite.secret_bytes();
        let relay = relay_with_mailbox(&relay.url, mailbox);
        let qr = qr_uri(
            &me,
            &pairing_id,
            &relay,
            &mailbox,
            dial_relay,
            addrs,
            name,
            invite.expires_at,
            &secret,
        );
        self.cur = Some(Hosted {
            registry,
            pairing_id,
            relay,
            qr,
            code: encode_code(&secret),
            expires_at: invite.expires_at,
            secret,
            card: None,
            session: None,
            status: HostStatus::Showing {
                expires_at: invite.expires_at,
            },
            gen: self.gen,
        });
        Ok(self.cur.as_ref().expect("just set"))
    }

    /// The user closed the pair screen: the secret is burnt.
    pub fn cancel(&mut self, now: Now) {
        if let Some(mut h) = self.cur.take() {
            h.registry.cancel_all(now);
            h.drop_card();
        }
        self.gen += 1;
    }

    /// A code is showing (not yet used, not expired).
    pub fn showing(&self, now: Now) -> bool {
        self.cur.as_ref().is_some_and(|h| {
            now.wall < h.expires_at
                && (h.session.is_some() || matches!(h.status, HostStatus::Showing { .. }))
        })
    }

    pub fn status(&mut self, now: Now) -> HostStatus {
        match &mut self.cur {
            None => HostStatus::Idle,
            Some(h) => {
                if matches!(h.status, HostStatus::Showing { .. }) && now.wall >= h.expires_at {
                    h.status = HostStatus::Failed {
                        reason: RejectReason::PairingSecretExpired,
                    };
                    h.drop_card();
                }
                h.status.clone()
            }
        }
    }

    /// The user typed the SAS. One try. Returns the channel the pairing's
    /// outcome arrives on.
    pub fn submit(
        &mut self,
        typed: &str,
        now: Now,
    ) -> Result<std::sync::mpsc::Receiver<Outcome>, RejectReason> {
        let h = self.cur.as_mut().ok_or(RejectReason::NoSuchPrompt)?;
        let (grant, tx) = h.session.take().ok_or(RejectReason::NoSuchPrompt)?;
        match grant.confirm_typed_code(typed, now) {
            Ok(_) => {
                let (otx, orx) = std::sync::mpsc::sync_channel(1);
                let _ = tx.send(otx);
                Ok(orx)
            }
            Err(r) => {
                h.status = HostStatus::Failed { reason: r };
                drop(tx);
                Err(r)
            }
        }
    }
}

/// What a node (PC or phone) provides to the shared v2 pairing code.
pub(crate) trait Node2: Send + Sync + 'static {
    fn host(&self) -> std::sync::MutexGuard<'_, Host>;
    fn join_slot(&self) -> std::sync::MutexGuard<'_, JoinSlot>;
    fn identity(&self) -> Result<(DeviceKeypair, DeviceCert), RejectReason>;
    /// Saved relays, the relays in use, room for one more pairing.
    fn relay_view(&self) -> RelayView;
    fn save_relay(&self, e: RelayEntry) -> Result<(), NetError>;
    /// Store the finished pairing (and the peer's addresses), replacing an
    /// older v2 pairing with the same device in one save (nothing changes
    /// if the save fails). `true`: it replaced one.
    fn keep(&self, p: Pairing, addrs: Vec<SocketAddr>) -> Result<bool, NetError>;
    fn changed(&self);

    /// Room for one more pairing (16) and its relay (4 in use)?
    fn has_room(&self, relay: &RelayRef) -> Result<(), RejectReason> {
        let v = self.relay_view();
        if !v.pairing_room {
            return Err(RejectReason::PairingLimitReached);
        }
        if !v.in_use.contains(&relay.url) && v.in_use.len() >= MAX_RELAYS_IN_USE {
            return Err(RejectReason::RelayLimitReached);
        }
        Ok(())
    }
}

/// A node's relays as the pairing screens need them.
pub(crate) struct RelayView {
    pub settings: RelaySettings,
    pub in_use: Vec<String>,
    pub pairing_room: bool,
}

/// One saved relay for the relay picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedRelay {
    pub nickname: String,
    pub url: String,
    pub home: bool,
    pub in_use: bool,
    pub builtin: bool,
}

/// Is an invite's relay one we can pair over?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayCheck {
    /// Saved already (and within the 4-in-use limit).
    Saved,
    /// "This pairing uses <host>. Add it?" [Add and pair] [Cancel]
    Ask { host: String },
    /// Over a limit (8 saved or 4 in use): [Cancel] only.
    Full { host: String },
}

/// The relay's host for prompts (`relay.friend.net`).
pub fn relay_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned())
}

/// A relay with its mailbox; the default mailbox is stored as `None`.
fn relay_with_mailbox(url: &str, mailbox: DeviceId) -> RelayRef {
    let mailbox_id =
        (mailbox != super::mailbox_client::default_mailbox_device_id()).then_some(mailbox);
    RelayRef {
        url: url.to_owned(),
        mailbox_id,
    }
}

fn mailbox_of(r: &RelayRef) -> DeviceId {
    r.mailbox_id
        .unwrap_or_else(super::mailbox_client::default_mailbox_device_id)
}

pub(crate) fn saved_relays<N: Node2>(n: &N) -> Vec<SavedRelay> {
    let v = n.relay_view();
    v.settings
        .relays
        .iter()
        .map(|e| SavedRelay {
            nickname: e.nickname.clone(),
            url: e.relay.url.clone(),
            home: v.settings.home_relay.as_deref() == Some(e.relay.url.as_str()),
            in_use: v.in_use.contains(&e.relay.url),
            builtin: e.source == RelaySource::Builtin,
        })
        .collect()
}

fn find_saved(v: &RelayView, url: &str) -> Option<RelayRef> {
    v.settings
        .relays
        .iter()
        .find(|e| e.relay.url == url)
        .map(|e| e.relay.clone())
}

pub(crate) fn check_relay<N: Node2>(n: &N, relay: &RelayRef) -> RelayCheck {
    let v = n.relay_view();
    let host = relay_host(&relay.url);
    let used = v.in_use.contains(&relay.url);
    let room_in_use = used || v.in_use.len() < MAX_RELAYS_IN_USE;
    match find_saved(&v, &relay.url) {
        Some(_) if room_in_use => RelayCheck::Saved,
        Some(_) => RelayCheck::Full { host },
        None if room_in_use && v.settings.relays.len() < MAX_SAVED_RELAYS => {
            RelayCheck::Ask { host }
        }
        None => RelayCheck::Full { host },
    }
}

/// Inviter: show a new code over `relay_url` (a saved relay; `None`: the
/// home relay, else the built-in one). Puts the invite card for typed
/// codes; if the relay can't be reached the QR still works and `code` is
/// `None`.
pub(crate) async fn show<N: Node2>(
    n: &N,
    relay_url: Option<&str>,
    dial_relay: Option<&str>,
    addrs: &[SocketAddr],
    now: Now,
) -> Result<ShowInfo, NetError> {
    let v = n.relay_view();
    let url = relay_url
        .map(str::to_owned)
        .or_else(|| v.settings.home_relay.clone())
        .unwrap_or_else(|| super::DEFAULT_RELAY_URL.to_owned());
    let relay = find_saved(&v, &url).ok_or(NetError::Rejected(RejectReason::RelayNotAdded))?;
    n.has_room(&relay)?;
    let (me, cert) = n.identity()?;
    let mailbox = mailbox_of(&relay);
    let (qr, secret, expires_at, gen) = {
        let mut host = n.host();
        let h = host.issue(
            me.device_id(),
            cert.name(),
            relay.clone(),
            mailbox,
            dial_relay,
            addrs,
            now,
        )?;
        (h.qr.clone(), h.secret.clone(), h.expires_at, h.gen)
    };
    n.changed();
    let item = publish_card(&secret, &qr, &relay.url, &mailbox).await.ok();
    let code = item.map(|_| encode_code(&secret));
    if let Some(item) = item {
        let card = Card {
            handle: tokio::runtime::Handle::current(),
            secret: secret.clone(),
            relay_url: relay.url.clone(),
            mailbox,
            item,
        };
        let mut host = n.host();
        match host.cur.as_mut().filter(|h| h.gen == gen) {
            // Still live and unused: keep it so it can be deleted later.
            Some(h) if matches!(h.status, HostStatus::Showing { .. }) => h.card = Some(card),
            // Cancelled, replaced or already used while we were putting it.
            _ => card.retract(),
        }
    }
    if n.host().cur.as_ref().map(|h| h.gen) != Some(gen) {
        return Err(NetError::Cancelled);
    }
    Ok(ShowInfo {
        qr,
        code,
        expires_at,
        relay_url: relay.url,
    })
}

/// What the showing screen displays.
#[derive(Clone)]
pub struct ShowInfo {
    pub qr: String,
    /// `VW-…` (`None`: the relay couldn't be reached, so only the QR works).
    pub code: Option<String>,
    pub expires_at: UnixMillis,
    pub relay_url: String,
}

impl std::fmt::Debug for ShowInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShowInfo").finish_non_exhaustive()
    }
}

/// The joiner's state between screens.
#[derive(Default)]
pub struct JoinSlot {
    invite: Option<V2Invite>,
    joining: Option<Joining>,
    gen: u64,
}

/// What the joiner shows before connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub inviter_name: Option<String>,
    pub relay_url: String,
    pub relay: RelayCheck,
}

fn opened<N: Node2>(n: &N, inv: V2Invite) -> Opened {
    let out = Opened {
        inviter_name: inv.inviter_name().map(str::to_owned),
        relay_url: inv.relay.url.clone(),
        relay: check_relay(n, &inv.relay),
    };
    let mut slot = n.join_slot();
    if let Some(j) = slot.joining.take() {
        j.close();
    }
    slot.invite = Some(inv);
    slot.gen += 1;
    out
}

/// Joiner: a scanned `v=2` QR.
pub(crate) fn open_qr<N: Node2>(n: &N, uri: &str, now: Now) -> Result<Opened, NetError> {
    let inv = parse_qr(uri, now)?;
    if inv.inviter() == n.identity()?.0.device_id() {
        return Err(NetError::Rejected(RejectReason::FromSelf));
    }
    Ok(opened(n, inv))
}

/// Joiner: a typed code, fetched from `relay_url` (a saved relay).
pub(crate) async fn open_code<N: Node2>(
    n: &N,
    code: &str,
    relay_url: Option<&str>,
    now: Now,
) -> Result<Opened, NetError> {
    let secret = parse_code(code)?;
    let v = n.relay_view();
    let url = relay_url.unwrap_or(super::DEFAULT_RELAY_URL);
    let relay = find_saved(&v, url).ok_or(NetError::Rejected(RejectReason::RelayNotAdded))?;
    let inv = fetch_card(&secret, &relay.url, &mailbox_of(&relay), now).await?;
    // The card names the relay the pairing will use; it must be where we
    // found it (a card can't move the pairing to another relay).
    if inv.relay.url != relay.url {
        return Err(NetError::Rejected(RejectReason::SenderMismatch));
    }
    if inv.inviter() == n.identity()?.0.device_id() {
        return Err(NetError::Rejected(RejectReason::FromSelf));
    }
    Ok(opened(n, inv))
}

/// Joiner: the user chose [Add and pair].
pub(crate) fn add_pending_relay<N: Node2>(n: &N) -> Result<(), NetError> {
    let relay = {
        let slot = n.join_slot();
        slot.invite
            .as_ref()
            .map(|i| i.relay.clone())
            .ok_or(NetError::Rejected(RejectReason::NoSuchPrompt))?
    };
    match check_relay(n, &relay) {
        RelayCheck::Saved => Ok(()),
        RelayCheck::Full { .. } => Err(NetError::Rejected(RejectReason::RelayLimitReached)),
        RelayCheck::Ask { host } => {
            let nickname: String = host.chars().take(64).collect();
            n.save_relay(RelayEntry {
                nickname,
                relay,
                source: RelaySource::FromInvite,
                no_udp: false,
            })
        }
    }
}

/// Joiner: connect and prove; returns the SAS to show.
pub(crate) async fn join_begin<N: Node2>(n: &N, ep: &Endpoint) -> Result<String, NetError> {
    let (inv, gen) = {
        let mut slot = n.join_slot();
        let inv = slot
            .invite
            .take()
            .ok_or(NetError::Rejected(RejectReason::NoSuchPrompt))?;
        (inv, slot.gen)
    };
    if check_relay(n, &inv.relay) != RelayCheck::Saved {
        return Err(NetError::Rejected(match check_relay(n, &inv.relay) {
            RelayCheck::Full { .. } => RejectReason::RelayLimitReached,
            _ => RejectReason::RelayNotAdded,
        }));
    }
    n.has_room(&inv.relay)?;
    if crate::time::SystemClock.now().wall >= inv.expires_at() {
        return Err(NetError::Rejected(RejectReason::PairingSecretExpired));
    }
    let (_, cert) = n.identity()?;
    let conn = dial(ep, &inv).await?;
    let j = join_start(conn, &inv, &cert).await?;
    let sas = j.sas.clone();
    let mut slot = n.join_slot();
    if slot.gen != gen {
        j.close();
        return Err(NetError::Cancelled);
    }
    slot.joining = Some(j);
    Ok(sas)
}

/// Joiner: wait for the other device's user to type the SAS; keep the
/// pairing. Returns the new peer.
pub(crate) async fn join_wait<N: Node2>(n: &N) -> Result<Paired2, NetError> {
    let j = n
        .join_slot()
        .joining
        .take()
        .ok_or(NetError::Rejected(RejectReason::NoSuchPrompt))?;
    let addrs = remote_ip_addrs(&j.conn);
    let (me, _) = n.identity()?;
    let out = join_finish(j, &me, |p| n.keep(p, addrs)).await?;
    n.changed();
    Ok(out)
}

/// Joiner: the user closed the screen.
pub(crate) fn join_cancel<N: Node2>(n: &N) {
    let mut slot = n.join_slot();
    slot.invite = None;
    if let Some(j) = slot.joining.take() {
        j.close();
    }
    slot.gen += 1;
}

/// Inviter: the user typed the SAS; waits for the pairing to finish.
pub(crate) fn host_submit<N: Node2>(n: &N, sas: &str, now: Now) -> Result<Paired2, NetError> {
    let rx = n.host().submit(sas, now);
    n.changed();
    let rx = rx?;
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(r) => Ok(r?),
        Err(_) => Err(NetError::Timeout),
    }
}

pub(crate) async fn send_err(send: &mut SendStream, r: RejectReason) {
    let _ = write_frame(send, frame::ERROR, &super::error_payload(r)).await;
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(3), send.stopped()).await;
}

fn fail<I: Node2>(node: &I, gen: u64, r: RejectReason) {
    {
        let mut host = node.host();
        if let Some(h) = host.cur.as_mut().filter(|h| h.gen == gen) {
            h.session = None;
            h.status = HostStatus::Failed { reason: r };
        }
    }
    node.changed();
}

/// Is a v2 hello? (`HELLO` payload = secret id + version byte 2.)
pub(crate) fn is_v2_hello(p: &[u8]) -> Option<[u8; 8]> {
    (p.len() == 9 && p[8] == HELLO_V2).then(|| p[..8].try_into().expect("8"))
}

/// Inviter: serve one v2 pairing attempt (after its HELLO).
pub(crate) async fn serve<I: Node2>(
    node: &I,
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    sid: [u8; 8],
) {
    let Ok(joiner_transport) = super::device_id_of(&conn.remote_id()) else {
        return;
    };
    let now = || crate::time::SystemClock.now();
    // 1. Only a live, unspent invite gets our certificate.
    let gen = {
        let mut host = node.host();
        match host.cur.as_mut() {
            Some(h) if h.session.is_some() => Err(RejectReason::PairingSecretUsed),
            Some(h) => h.registry.check_pending(&sid, now()).map(|()| h.gen),
            None => Err(RejectReason::PairingSecretUnknown),
        }
    };
    let gen = match gen {
        Ok(g) => g,
        Err(r) => return send_err(&mut send, r).await,
    };
    let (me, my_cert) = match node.identity() {
        Ok(x) => x,
        Err(r) => return send_err(&mut send, r).await,
    };
    if write_frame(&mut send, frame::INVITER_CERT, my_cert.as_bytes())
        .await
        .is_err()
    {
        return;
    }
    // 2. The proof: hmac(32) || joiner rx(32) || joiner cert.
    let (proof, joiner_rx, joiner_cert) = match read_frame(&mut recv, IO_TIMEOUT).await {
        Ok((frame::PROOF, p)) if p.len() > 64 => {
            let proof: [u8; 32] = p[..32].try_into().expect("32");
            let rx = crate::keys::ReceivePublicKey(p[32..64].try_into().expect("32"));
            match DeviceCert::parse_verified(&p[64..]) {
                Ok(c) => (proof, rx, c),
                Err(r) => {
                    burn(node, gen);
                    return send_err(&mut send, r).await;
                }
            }
        }
        _ => {
            burn(node, gen);
            return send_err(&mut send, RejectReason::MalformedFrame).await;
        }
    };
    let Ok(exporter) = pairing_exporter(&conn, &sid) else {
        return;
    };
    let rx = {
        let mut host = node.host();
        let n = now();
        match host.cur.as_mut().filter(|h| h.gen == gen) {
            None => Err(RejectReason::PairingCancelled),
            Some(h) => {
                let hs = handshake_v2(
                    &exporter,
                    my_cert.as_bytes(),
                    joiner_cert.as_bytes(),
                    &h.relay,
                    &joiner_rx,
                );
                let req = PairingRequest {
                    secret_id: sid,
                    joiner: joiner_cert.device(),
                    joiner_name: joiner_cert.name().to_owned(),
                    proof,
                    joiner_cert: Some(joiner_cert.clone()),
                };
                // Consumes the secret whatever the outcome (single use),
                // so its card goes too.
                h.drop_card();
                match h.registry.redeem(&req, &hs, n) {
                    Ok(_) if joiner_cert.device() != joiner_transport => {
                        Err(RejectReason::SenderMismatch)
                    }
                    Ok(_) if joiner_cert.device() == me.device_id() => Err(RejectReason::FromSelf),
                    Ok(grant) => {
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        h.status = HostStatus::AwaitingCode {
                            device_name: grant.joiner_name().to_owned(),
                        };
                        h.session = Some((grant, tx));
                        Ok(rx)
                    }
                    Err(r) => Err(r),
                }
            }
        }
    };
    let rx = match rx {
        Ok(rx) => rx,
        Err(r) => {
            fail(node, gen, r);
            return send_err(&mut send, r).await;
        }
    };
    node.changed();
    if write_frame(&mut send, frame::PROOF_OK, &[]).await.is_err() {
        fail(node, gen, RejectReason::PairingCancelled);
        return;
    }
    // 3. Wait for the typed SAS (or the joiner giving up).
    let wait = Duration::from_millis(SAS_CONFIRM_TTL_MS + 5_000);
    let reply: Confirm = tokio::select! {
        r = tokio::time::timeout(wait, rx) => match r {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => {
                // A wrong SAS (status already says so) or a cancel.
                let r = match node.host().cur.as_ref().map(|h| h.status.clone()) {
                    Some(HostStatus::Failed { reason }) => reason,
                    _ => RejectReason::PairingCancelled,
                };
                fail(node, gen, r);
                return send_err(&mut send, r).await;
            }
            Err(_) => {
                fail(node, gen, RejectReason::SasTimeout);
                return send_err(&mut send, RejectReason::SasTimeout).await;
            }
        },
        _ = conn.closed() => {
            fail(node, gen, RejectReason::PairingCancelled);
            return;
        }
    };
    let out = finish_invite(
        node,
        &conn,
        &mut send,
        &mut recv,
        gen,
        &me,
        my_cert,
        joiner_cert,
        joiner_rx,
    )
    .await;
    match &out {
        Ok(p) => {
            {
                let mut host = node.host();
                if let Some(h) = host.cur.as_mut().filter(|h| h.gen == gen) {
                    h.status = HostStatus::Paired {
                        device_name: p.name.clone(),
                    };
                }
            }
            node.changed();
        }
        Err(r) => {
            fail(node, gen, *r);
            send_err(&mut send, *r).await;
        }
    }
    let _ = reply.send(out);
}

#[allow(clippy::too_many_arguments)]
async fn finish_invite<I: Node2>(
    node: &I,
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    gen: u64,
    me: &DeviceKeypair,
    my_cert: DeviceCert,
    joiner_cert: DeviceCert,
    joiner_rx: crate::keys::ReceivePublicKey,
) -> Result<Paired2, RejectReason> {
    let (pairing_id, relay) = {
        let host = node.host();
        let h = host
            .cur
            .as_ref()
            .filter(|h| h.gen == gen)
            .ok_or(RejectReason::PairingCancelled)?;
        (h.pairing_id, h.relay.clone())
    };
    node.has_room(&relay)?;
    let ts = crate::time::SystemClock.now().wall;
    let joiner = joiner_cert.device();
    let inv = crate::pairwise::v2::invite_with_id(
        me,
        pairing_id,
        my_cert,
        joiner_cert,
        joiner_rx,
        Some(relay),
        ts,
    )
    .map_err(|_| RejectReason::BadLogOp)?;
    let welcome = crate::envelope::seal(
        &joiner,
        &joiner_rx,
        &super::split::encode_offer(&inv.genesis, &inv.wrapped_gs),
    )?;
    write_frame(send, frame::WELCOME, &welcome)
        .await
        .map_err(|_| RejectReason::PairingCancelled)?;
    let (cosigned, caps) = match read_frame(recv, IO_TIMEOUT).await {
        Ok((frame::SPLIT_ACCEPT, p)) => super::split::decode_accept(&p)?,
        Ok((frame::ERROR, p)) => {
            return Err(match parse_error(&p) {
                NetError::Rejected(r) => r,
                _ => RejectReason::MalformedFrame,
            })
        }
        _ => return Err(RejectReason::PairingCancelled),
    };
    let (log, caps_done) = crate::pairwise::v2::finish_invite(me, &inv, cosigned, caps)
        .map_err(|_| RejectReason::BadLogOp)?;
    write_frame(send, frame::SPLIT_CAPS, &caps_done.encode())
        .await
        .map_err(|_| RejectReason::PairingCancelled)?;
    // Keep it only once the joiner has kept its copy.
    match read_frame(recv, IO_TIMEOUT).await {
        Ok((frame::RESULT, p)) if p == [0, 0, 0] => {}
        _ => return Err(RejectReason::PairingCancelled),
    }
    let my_rx = ReceiveKeypair::from_secret_bytes(&inv.my_rx.secret_bytes())
        .ok_or(RejectReason::Internal)?;
    let rec = crate::pairwise::v2::record(&me.device_id(), log, my_rx, inv.gs.clone())
        .map_err(|_| RejectReason::BadLogOp)?;
    let name = rec.peer.name.clone();
    let addrs = remote_ip_addrs(conn);
    let refreshed = node.keep(rec, addrs).map_err(|e| match e {
        NetError::Rejected(r) => r,
        _ => RejectReason::Internal,
    })?;
    Ok(Paired2 {
        peer: joiner,
        name,
        refreshed,
    })
}

fn remote_ip_addrs(conn: &Connection) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    for p in conn.paths().iter() {
        if let iroh::TransportAddr::Ip(sock) = p.remote_addr() {
            if !addrs.contains(sock) {
                addrs.push(*sock);
            }
        }
    }
    addrs
}

/// Keep a new v2 pairing: it replaces an older v2 pairing with the same
/// device (pairing again, e.g. after one side unpaired); a v0.4.x pairing
/// with it stays and the new one is refused. Returns the pairings it
/// replaced, for `undo_replace` if saving fails; `set` is unchanged on error.
pub(crate) fn replace_pairing(
    set: &mut crate::pairwise::PairingSet,
    p: Pairing,
) -> Result<Vec<Pairing>, NetError> {
    let old: Vec<(GroupId, bool)> = set
        .by_peer(&p.peer.id)
        .map(|x| (x.pairing_id, x.log.is_none()))
        .collect();
    if old.iter().any(|(_, legacy)| *legacy) {
        return Err(NetError::Rejected(RejectReason::AlreadyPaired));
    }
    let removed: Vec<Pairing> = old.iter().filter_map(|(id, _)| set.remove(id)).collect();
    let new_id = p.pairing_id;
    match set.add(p) {
        Ok(()) => Ok(removed),
        Err(e) => {
            undo_replace(set, &new_id, removed);
            Err(NetError::Rejected(match e {
                crate::pairwise::PairError::LimitReached => RejectReason::PairingLimitReached,
                _ => RejectReason::BadLogOp,
            }))
        }
    }
}

/// Put back what `replace_pairing` replaced (the state couldn't be saved).
pub(crate) fn undo_replace(
    set: &mut crate::pairwise::PairingSet,
    new_id: &GroupId,
    removed: Vec<Pairing>,
) {
    set.remove(new_id);
    for old in removed {
        let _ = set.add(old);
    }
}

/// A malformed proof burns the live secret (single use, no grinding).
fn burn<I: Node2>(node: &I, gen: u64) {
    let now = crate::time::SystemClock.now();
    let mut host = node.host();
    if let Some(h) = host.cur.as_mut().filter(|h| h.gen == gen) {
        h.registry.cancel_all(now);
        h.drop_card();
        h.status = HostStatus::Failed {
            reason: RejectReason::MalformedFrame,
        };
    }
}

/// The code's lifetime (for the UI's countdown).
pub const CODE_TTL_MS: u64 = PAIRING_CODE_TTL_MS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_url_round_trips() {
        for s in [
            "https://r.example:8443/x?a=b&c=d+e%f#g",
            "[fd00::1]:5,10.0.0.1:7",
            "\u{e9} @",
        ] {
            let e = enc_url(s);
            assert!(!e.contains(['&', '=', '+', '#', ' ', '?']), "{e}");
            let q = format!("k={e}");
            let (_, back) = url::form_urlencoded::parse(q.as_bytes()).next().unwrap();
            assert_eq!(back, s);
        }
    }

    /// The QR fixture the scanner and renderer tests use (testdata/qr): a
    /// real `qr_uri` at its realistic largest (6 addresses with long IPv6
    /// ones, a self-hosted relay and a different dial relay, a long name).
    /// `VOIDWIRE_UPDATE_FIXTURES=1` rewrites it.
    #[test]
    fn worst_case_pairing_qr_fixture_is_current() {
        let inviter = DeviceKeypair::from_secret_bytes(&[7; 32]).device_id();
        let mailbox = DeviceKeypair::from_secret_bytes(&[9; 32]).device_id();
        let relay = RelayRef {
            url: "https://relay.voidwire-selfhosted.example.net:8443".into(),
            mailbox_id: Some(mailbox),
        };
        let addrs: Vec<SocketAddr> = [
            "192.168.100.123:54321",
            "10.200.123.45:54321",
            "172.31.255.254:54321",
            "100.101.102.103:54321",
            "[2a02:8109:b6c0:1d00:4c3a:9eff:fe12:3456]:54321",
            "[fd7a:115c:a1e0:ab12:4843:cd96:6258:b240]:54321",
        ]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
        let uri = qr_uri(
            &inviter,
            &GroupId([0xab; 32]),
            &relay,
            &mailbox,
            Some("https://home-relay.voidwire-selfhosted.example.net"),
            &addrs,
            "Living room desktop PC",
            UnixMillis(4_102_444_800_000),
            &[0x5c; 16],
        );
        let now = crate::time::Now {
            wall: UnixMillis(1_800_000_000_000),
            mono: crate::time::MonoMillis(0),
        };
        assert!(parse_qr(&uri, now).is_ok());
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/qr/pair2-worst.uri"
        );
        if std::env::var("VOIDWIRE_UPDATE_FIXTURES").as_deref() == Ok("1") {
            std::fs::write(path, format!("{uri}\n")).unwrap();
        }
        let fixture = std::fs::read_to_string(path).expect("testdata/qr/pair2-worst.uri");
        assert_eq!(
            fixture.trim_end(),
            uri,
            "rerun with VOIDWIRE_UPDATE_FIXTURES=1"
        );
    }

    #[test]
    fn code_round_trips_and_catches_typos() {
        // Fixed secrets: a 10-bit check misses 1 typo in 1024, so random
        // ones would make this test flaky.
        for i in 0..64u8 {
            let s = [i.wrapping_mul(37) ^ 0x5a; 16];
            let c = encode_code(&s);
            assert!(c.starts_with("VW-"));
            assert_eq!(c.len(), 2 + 7 * 5);
            assert_eq!(*parse_code(&c).unwrap(), s);
            assert_eq!(*parse_code(&c.to_lowercase().replace('-', " ")).unwrap(), s);
            assert_eq!(*parse_code(&c[3..]).unwrap(), s);
            // One wrong character is caught (check characters or top bits).
            let mut b = c.clone().into_bytes();
            let i = 3 + 5; // second group, first char
            b[i] = if b[i] == b'7' { b'8' } else { b'7' };
            assert_eq!(
                parse_code(std::str::from_utf8(&b).unwrap()).unwrap_err(),
                RejectReason::PairingCodeInvalid
            );
        }
        assert!(parse_code("VW-1234").is_err());
        assert!(parse_code("").is_err());
        assert!(parse_code("VW-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU").is_err());
    }

    #[test]
    fn rendezvous_depends_only_on_the_secret() {
        let a = rendezvous(&[1; 16]);
        let b = rendezvous(&[1; 16]);
        let c = rendezvous(&[2; 16]);
        assert_eq!(a.keys.inbox_id.0, b.keys.inbox_id.0);
        assert_ne!(a.keys.inbox_id.0, c.keys.inbox_id.0);
        assert_eq!(a.id, b.id);
        assert_eq!(a.rx.public(), b.rx.public());
    }
}
