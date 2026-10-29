#![forbid(unsafe_code)]
//! Client-side blind mailbox transport (`docs/PROTOCOL.md` §7.1(e),
//! `docs/M2-PLAN.md` rev. 3 §2.1 & §8).
//!
//! Unlinkability invariant (`docs/M2-PLAN.md` §2.1 rev. 3):
//! Every mailbox session (`connect_throwaway`) binds a **fresh, ephemeral
//! iroh `Endpoint` with a newly generated random `SecretKey`** and
//! `.clear_ip_transports()`, closing it as soon as the session finishes.
//! A client's permanent `DeviceId` never dials `ALPN_MAILBOX`.

use std::time::Duration;

use iroh::{
    endpoint::{presets, Connection},
    Endpoint, EndpointAddr, PublicKey, SecretKey,
};

use crate::grouplog::SignedOp;
use crate::ids::DeviceId;
use crate::keys::DeviceKeypair;
use crate::mailbox::{
    mb_frame, mb_status, AdvertisedInboxCaps, AppendMailboxReq, CreateMailboxReq, DeviceInboxKeys,
    EpochKeys, InboxPullItem, InboxPullResp, MailboxId, MailboxRecord, MailboxSeal,
    OwnerEpochSealKey, ReadMailboxReq, ReadMailboxResp, RotateMailboxReq, SignedConfig,
    MAX_MAILBOX_RECORDS, MAX_MAILBOX_WIRE_FRAME,
};
use crate::net::{build_relay_mode, default_net_report_config, NetError};
use crate::protocol::ALPN_MAILBOX;
use crate::reject::RejectReason;
use crate::time::UnixMillis;

/// Environment variable overriding the mailbox service's iroh `DeviceId` (64-char hex).
pub const ENV_MAILBOX_ID: &str = "VOIDWIRE_MAILBOX_ID";

/// Production `voidwire-mailbox` Ed25519 `EndpointId` / `DeviceId` (`M2-H1`).
pub const DEFAULT_MAILBOX_ID: &str =
    "b080fe7101c968a6c827bad4e99d225343faa3bee18ee2a82b799c7a9d2f6840";

/// Maximum records returned in a single `READ_OK` response batch (`M2-H3`).
pub const MAX_READ_BATCH: usize = 64;

const MAILBOX_CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const MAILBOX_IO_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_FRAME_LEN: usize = MAX_MAILBOX_WIRE_FRAME;
const MAX_SEAL_CHAIN_HOPS: usize = 16;

/// Return the compiled-in production `DEFAULT_MAILBOX_ID` as a [`DeviceId`].
pub fn default_mailbox_device_id() -> DeviceId {
    DeviceId::from_hex(DEFAULT_MAILBOX_ID).expect("valid DEFAULT_MAILBOX_ID hex")
}

/// Resolve the configured mailbox service `DeviceId` from explicit config,
/// `VOIDWIRE_MAILBOX_ID`, or `DEFAULT_MAILBOX_ID` (`M2-H1`).
///
/// Passing `Some("")`, `Some("off")`, or `Some("none")` disables the mailbox (`None`).
pub fn resolve_mailbox_id(configured: Option<&str>) -> Option<DeviceId> {
    if let Some(raw) = configured {
        let trimmed = raw.trim();
        if trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("off")
            || trimmed.eq_ignore_ascii_case("none")
            || trimmed.eq_ignore_ascii_case("disabled")
        {
            return None;
        }
        return DeviceId::from_hex(trimmed);
    }
    if let Ok(val) = std::env::var(ENV_MAILBOX_ID) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            if trimmed.eq_ignore_ascii_case("off")
                || trimmed.eq_ignore_ascii_case("none")
                || trimmed.eq_ignore_ascii_case("disabled")
            {
                return None;
            }
            return DeviceId::from_hex(trimmed);
        }
    }
    Some(default_mailbox_device_id())
}

/// Parse an optional hex mailbox peer string (`None` -> `resolve_mailbox_id(None)`,
/// `Some("off" | "none" | "")` -> `Ok(None)`, invalid hex -> `Err(MalformedFrame)`).
pub fn parse_mailbox_peer_opt(peer_hex: Option<&str>) -> Result<Option<DeviceId>, RejectReason> {
    match peer_hex {
        None => Ok(resolve_mailbox_id(None)),
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("off")
                || trimmed.eq_ignore_ascii_case("none")
                || trimmed.eq_ignore_ascii_case("disabled")
            {
                Ok(None)
            } else {
                DeviceId::from_hex(trimmed)
                    .map(Some)
                    .ok_or(RejectReason::MalformedFrame)
            }
        }
    }
}

/// Whether the client should dial `peer` over the network right now.
/// In production builds, always `true`. In unit/integration test builds (`test` / `test-util`),
/// skips dialing the live production `DEFAULT_MAILBOX_ID` unless `explicit` is true or
/// `VOIDWIRE_MAILBOX_ID` is set, so offline tests without a local `MailboxServer` don't
/// block trying to reach production over the internet.
pub fn should_dial_mailbox_in_current_env(peer: &DeviceId, explicit: bool) -> bool {
    #[cfg(not(any(test, feature = "test-util")))]
    {
        let _ = (peer, explicit);
        true
    }
    #[cfg(any(test, feature = "test-util"))]
    {
        explicit || *peer != default_mailbox_device_id() || std::env::var(ENV_MAILBOX_ID).is_ok()
    }
}

/// Format the fail-open warning shown when a mailbox check fails (`docs/PROTOCOL.md` §7.1(e)):
/// `"Couldn't check for removals since <time>"`.
pub fn format_removal_warning(since: Option<UnixMillis>, failed_at: UnixMillis) -> String {
    let ts = since.unwrap_or(failed_at);
    let secs = ts.0 / 1000;
    let (y, m, d, hh, mm) = civil_utc_from_unix_secs(secs);
    format!("Couldn't check for removals since {y:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

fn civil_utc_from_unix_secs(secs: u64) -> (i32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hh = (rem / 3600) as u32;
    let mm = ((rem % 3600) / 60) as u32;
    // Howard Hinnant civil_from_days algorithm:
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d, hh, mm)
}

/// Ephemeral throwaway mailbox session (`Endpoint` + `Connection`).
/// Holds a freshly generated random secret key so the relay and mailbox server
/// never see the caller's permanent `DeviceId`.
pub struct ThrowawaySession {
    pub ephemeral_id: DeviceId,
    endpoint: Endpoint,
    conn: Connection,
}

impl ThrowawaySession {
    pub async fn connect(mailbox_peer: &DeviceId, relay_url: &str) -> Result<Self, NetError> {
        let ephemeral = DeviceKeypair::generate();
        let ephemeral_id = ephemeral.device_id();
        debug_assert_ne!(&ephemeral_id, mailbox_peer);

        let (relay_mode, parsed_url) = build_relay_mode(Some(relay_url))?;
        let relay_url_parsed = parsed_url
            .ok_or_else(|| NetError::Unreachable("mailbox requires a relay URL".into()))?;

        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&ephemeral.secret_bytes()))
            .relay_mode(relay_mode)
            .clear_address_lookup()
            .clear_ip_transports()
            .net_report_config(default_net_report_config())
            .bind()
            .await
            .map_err(|e| NetError::Unreachable(format!("throwaway bind: {e}")))?;

        let pk = PublicKey::from_bytes(mailbox_peer.as_bytes())
            .map_err(|_| NetError::Rejected(RejectReason::BadSignature))?;
        let addr = EndpointAddr::new(pk).with_relay_url(relay_url_parsed);

        let conn = match tokio::time::timeout(
            MAILBOX_CONNECT_TIMEOUT,
            endpoint.connect(addr, ALPN_MAILBOX),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                endpoint.close().await;
                return Err(NetError::Unreachable(format!("mailbox connect: {e}")));
            }
            Err(_) => {
                endpoint.close().await;
                return Err(NetError::Timeout);
            }
        };

        Ok(Self {
            ephemeral_id,
            endpoint,
            conn,
        })
    }

    pub async fn request(&self, ft: u8, payload: &[u8]) -> Result<(u8, Vec<u8>), NetError> {
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| NetError::Unreachable(format!("mailbox stream: {e}")))?;
        let mut hdr = [0u8; 5];
        hdr[0] = ft;
        hdr[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        tokio::time::timeout(MAILBOX_IO_TIMEOUT, async {
            send.write_all(&hdr).await?;
            send.write_all(payload).await?;
            send.finish()?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| NetError::Timeout)?
        .map_err(|e| NetError::Unreachable(format!("mailbox write: {e}")))?;

        let mut rhdr = [0u8; 5];
        tokio::time::timeout(MAILBOX_IO_TIMEOUT, recv.read_exact(&mut rhdr))
            .await
            .map_err(|_| NetError::Timeout)?
            .map_err(|e| NetError::Unreachable(format!("mailbox read hdr: {e}")))?;
        let rft = rhdr[0];
        let rlen = u32::from_be_bytes([rhdr[1], rhdr[2], rhdr[3], rhdr[4]]) as usize;
        if rlen > MAX_FRAME_LEN {
            return Err(NetError::Protocol("oversize mailbox response".into()));
        }
        let mut rbuf = vec![0u8; rlen];
        tokio::time::timeout(MAILBOX_IO_TIMEOUT, recv.read_exact(&mut rbuf))
            .await
            .map_err(|_| NetError::Timeout)?
            .map_err(|e| NetError::Unreachable(format!("mailbox read body: {e}")))?;
        Ok((rft, rbuf))
    }

    /// Enqueue one sealed HPKE envelope into a recipient's RAM-only blind device inbox
    /// (`M3-PLAN.md` §1.3.4).
    pub async fn put_device_inbox(
        &self,
        keys: &DeviceInboxKeys,
        item_id: [u8; 16],
        envelope: Vec<u8>,
    ) -> Result<(), NetError> {
        self.put_device_inbox_with_cap(keys, item_id, envelope)
            .await
            .map(|_| ())
    }

    /// Enqueue one sealed HPKE envelope into a recipient's RAM-only blind device inbox
    /// and return any `max_relay_file_bytes` advertised in the server's `STATUS` reply.
    pub async fn put_device_inbox_with_cap(
        &self,
        keys: &DeviceInboxKeys,
        item_id: [u8; 16],
        envelope: Vec<u8>,
    ) -> Result<Option<u64>, NetError> {
        let req = keys.build_put_req(item_id, envelope)?;
        self.put_device_inbox_raw(&req.encode()).await
    }

    /// PUT an already signed and encoded `INBOX_PUT` request (the durable
    /// outbox keeps those, never the inbox keys). Retrying the same item
    /// is idempotent on the server.
    pub(crate) async fn put_device_inbox_raw(&self, req: &[u8]) -> Result<Option<u64>, NetError> {
        let (rft, rp) = self.request(mb_frame::INBOX_PUT, req).await?;
        let (code, cap) = expect_ok_with_cap(rft, &rp)?;
        match code {
            mb_status::OK => Ok(cap),
            mb_status::QUOTA_EXCEEDED => Err(NetError::Protocol("device_inbox_full".into())),
            mb_status::BAD_AUTH => Err(NetError::Rejected(RejectReason::BadSignature)),
            mb_status::RATE_LIMITED => Err(NetError::Rejected(RejectReason::RateLimitedPeer)),
            mb_status::MALFORMED => Err(NetError::Rejected(RejectReason::MalformedFrame)),
            other => Err(NetError::Protocol(format!(
                "device_inbox_put_failed: status={other}"
            ))),
        }
    }

    /// Pull all pending envelopes from this device's RAM-only blind inbox (`M3-PLAN.md` §1.3.4).
    pub async fn pull_device_inbox(
        &self,
        keys: &DeviceInboxKeys,
    ) -> Result<Vec<InboxPullItem>, NetError> {
        self.pull_device_inbox_with_caps(keys)
            .await
            .map(|(items, _)| items)
    }

    /// Pull all pending envelopes from this device's RAM-only blind inbox and return any
    /// server-advertised limits (`AdvertisedInboxCaps`).
    pub async fn pull_device_inbox_with_caps(
        &self,
        keys: &DeviceInboxKeys,
    ) -> Result<(Vec<InboxPullItem>, Option<AdvertisedInboxCaps>), NetError> {
        let mut nonce = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let req = keys.build_pull_req(nonce);
        let (rft, rp) = self.request(mb_frame::INBOX_PULL, &req.encode()).await?;
        match rft {
            mb_frame::INBOX_PULL_OK => {
                let (resp, caps) = InboxPullResp::decode_with_caps(&rp)?;
                Ok((resp.items, caps))
            }
            mb_frame::STATUS => {
                let (code, _) = expect_ok_with_cap(rft, &rp)?;
                match code {
                    mb_status::NOT_FOUND => Ok((Vec::new(), None)),
                    mb_status::BAD_AUTH => Err(NetError::Rejected(RejectReason::BadSignature)),
                    mb_status::RATE_LIMITED => {
                        Err(NetError::Rejected(RejectReason::RateLimitedPeer))
                    }
                    other => Err(NetError::Protocol(format!(
                        "device_inbox_pull_failed: status={other}"
                    ))),
                }
            }
            _ => Err(NetError::Protocol(
                "unexpected device inbox pull response".into(),
            )),
        }
    }

    /// Acknowledge and zeroize delivered item IDs in this device's RAM-only blind inbox
    /// (`M3-PLAN.md` §1.3.4).
    #[allow(clippy::too_many_arguments)]
    pub async fn ack_device_inbox(
        &self,
        keys: &DeviceInboxKeys,
        item_ids: &[[u8; 16]],
    ) -> Result<(), NetError> {
        if item_ids.is_empty() {
            return Ok(());
        }
        for chunk in item_ids.chunks(64) {
            let req = keys.build_ack_req(chunk.to_vec())?;
            let (rft, rp) = self.request(mb_frame::INBOX_ACK, &req.encode()).await?;
            let (code, _) = expect_ok_with_cap(rft, &rp)?;
            match code {
                mb_status::OK | mb_status::NOT_FOUND => {}
                mb_status::BAD_AUTH => return Err(NetError::Rejected(RejectReason::BadSignature)),
                mb_status::RATE_LIMITED => {
                    return Err(NetError::Rejected(RejectReason::RateLimitedPeer))
                }
                other => {
                    return Err(NetError::Protocol(format!(
                        "device_inbox_ack_failed: status={other}"
                    )))
                }
            }
        }
        Ok(())
    }

    pub async fn close(self) {
        self.conn.close(0u32.into(), b"done");
        self.endpoint.close().await;
    }
}

fn expect_ok_with_cap(ft: u8, payload: &[u8]) -> Result<(u8, Option<u64>), NetError> {
    if ft != mb_frame::STATUS || (payload.len() != 1 && payload.len() != 9) {
        return Err(NetError::Protocol("unexpected mailbox status frame".into()));
    }
    let cap = if payload.len() == 9 {
        Some(u64::from_be_bytes(payload[1..9].try_into().expect("8")))
    } else {
        None
    };
    Ok((payload[0], cap))
}

#[allow(dead_code)]
fn expect_ok(ft: u8, payload: &[u8]) -> Result<u8, NetError> {
    expect_ok_with_cap(ft, payload).map(|(code, _)| code)
}

/// Paginate `READ` requests across batches of `MAX_READ_BATCH` (64) up to
/// `MAX_MAILBOX_RECORDS + 1` (513, including the quota-exempt sealing `RemoveDevice`
/// record per `PROTOCOL.md` §7.1(c), `M2-H3` / `M2-R3`).
/// Returns `Ok(None)` if the mailbox does not exist (`NOT_FOUND`).
pub async fn read_all_mailbox_records(
    sess: &ThrowawaySession,
    mailbox_id: MailboxId,
    start_seq: u64,
) -> Result<Option<ReadMailboxResp>, NetError> {
    read_all_mailbox_records_with_cap(sess, mailbox_id, start_seq)
        .await
        .map(|(resp, _)| resp)
}

/// Paginate `READ` requests and capture any `max_relay_file_bytes` advertised in
/// `READ_OK` (`PULL_RESP`) or `STATUS(NOT_FOUND)` (`M2.9`).
pub async fn read_all_mailbox_records_with_cap(
    sess: &ThrowawaySession,
    mailbox_id: MailboxId,
    start_seq: u64,
) -> Result<(Option<ReadMailboxResp>, Option<u64>), NetError> {
    const MAX_READ_RECORDS: usize = MAX_MAILBOX_RECORDS + 1;
    let mut from_seq = start_seq.max(1);
    let mut epoch = 0u64;
    let mut all_records: Vec<MailboxRecord> = Vec::new();
    let mut seal: Option<MailboxSeal> = None;
    let mut advertised_cap: Option<u64> = None;

    loop {
        let req = ReadMailboxReq {
            mailbox_id,
            from_seq,
        };
        let (rft, rp) = sess.request(mb_frame::READ, &req.encode()).await?;
        match rft {
            mb_frame::READ_OK => {
                let (page, page_cap) = ReadMailboxResp::decode_with_cap(&rp)?;
                if page_cap.is_some() {
                    advertised_cap = page_cap;
                }
                epoch = page.epoch;
                if page.seal.is_some() {
                    seal = page.seal;
                }
                let batch_len = page.records.len();
                let last_seq = page.records.last().map(|r| r.seq);
                for rec in page.records {
                    if all_records.len() < MAX_READ_RECORDS {
                        all_records.push(rec);
                    }
                }
                if batch_len < MAX_READ_BATCH || all_records.len() >= MAX_READ_RECORDS {
                    break;
                }
                match last_seq {
                    Some(seq) if seq >= from_seq => {
                        from_seq = seq.saturating_add(1);
                    }
                    _ => break,
                }
            }
            mb_frame::STATUS
                if !rp.is_empty()
                    && rp[0] == mb_status::NOT_FOUND
                    && (rp.len() == 1 || rp.len() == 9) =>
            {
                if rp.len() == 9 {
                    advertised_cap = Some(u64::from_be_bytes(rp[1..9].try_into().expect("8")));
                }
                if all_records.is_empty() && seal.is_none() {
                    return Ok((None, advertised_cap));
                }
                break;
            }
            _ => return Err(NetError::Protocol("unexpected mailbox read reply".into())),
        }
    }

    Ok((
        Some(ReadMailboxResp {
            epoch,
            records: all_records,
            seal,
        }),
        advertised_cap,
    ))
}

/// Owner (`PcNode`): ensure the current epoch mailbox exists and holds all ops in `signed_ops`,
/// re-seeding automatically if the mailbox is missing (`NOT_FOUND`, `docs/M2-PLAN.md` §8).
pub async fn owner_sync_or_reseed_mailbox(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    epoch: u64,
    keys: &EpochKeys,
    seal_verifier: [u8; 32],
    signed_ops: &[SignedOp],
) -> Result<DeviceId, NetError> {
    owner_sync_or_reseed_mailbox_with_cap(
        mailbox_peer,
        relay_url,
        epoch,
        keys,
        seal_verifier,
        signed_ops,
    )
    .await
    .map(|(eph_id, _)| eph_id)
}

/// Owner (`PcNode`): synchronize or reseed the current epoch mailbox and return any
/// `max_relay_file_bytes` advertised in `PULL_RESP` / `PUSH_ACK` (`M2.9`).
pub async fn owner_sync_or_reseed_mailbox_with_cap(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    epoch: u64,
    keys: &EpochKeys,
    seal_verifier: [u8; 32],
    signed_ops: &[SignedOp],
) -> Result<(DeviceId, Option<u64>), NetError> {
    let sess = ThrowawaySession::connect(mailbox_peer, relay_url).await?;
    let eph_id = sess.ephemeral_id;
    let res = async {
        // Check current state of our epoch mailbox (paginated across >64 records, M2-H3)
        let (existing_opt, mut adv_cap) =
            read_all_mailbox_records_with_cap(&sess, keys.mailbox_id, 1).await?;
        let existing_count = match existing_opt {
            Some(resp) => resp.records.len(),
            None => {
                // Mailbox missing (fresh or expired/lost -> owner re-seed per §8):
                let mut init_recs = Vec::with_capacity(signed_ops.len());
                for (i, op) in signed_ops.iter().enumerate() {
                    let seq = (i as u64) + 1;
                    init_recs.push(MailboxRecord::seal(keys, seq, op.as_bytes())?);
                }
                let create_req = CreateMailboxReq {
                    mailbox_id: keys.mailbox_id,
                    epoch,
                    write_verifier: keys.write_verifier,
                    seal_verifier,
                    initial_records: init_recs,
                };
                let (cft, cp) = sess.request(mb_frame::CREATE, &create_req.encode()).await?;
                let (code, cap) = expect_ok_with_cap(cft, &cp)?;
                if code != mb_status::OK {
                    return Err(NetError::Protocol("mailbox create failed".into()));
                }
                if cap.is_some() {
                    adv_cap = cap;
                }
                return Ok(adv_cap);
            }
        };

        // Append any ops not yet in the mailbox
        for (i, op) in signed_ops.iter().enumerate().skip(existing_count) {
            let seq = (i as u64) + 1;
            let rec = MailboxRecord::seal(keys, seq, op.as_bytes())?;
            let app = AppendMailboxReq {
                mailbox_id: keys.mailbox_id,
                record: rec,
            };
            let (aft, ap) = sess.request(mb_frame::APPEND, &app.encode()).await?;
            let (code, cap) = expect_ok_with_cap(aft, &ap)?;
            if code != mb_status::OK {
                return Err(NetError::Protocol("mailbox append failed".into()));
            }
            if cap.is_some() {
                adv_cap = cap;
            }
        }
        Ok(adv_cap)
    }
    .await;
    sess.close().await;
    res.map(|cap| (eph_id, cap))
}

/// Owner (`PcNode`): atomically append `RemoveDevice` to old mailbox, seal old mailbox
/// with `Rekey` op, and create new epoch mailbox seeded with the current signed log.
#[allow(clippy::too_many_arguments)]
pub async fn owner_rotate_mailbox(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    old_epoch: u64,
    old_keys: &EpochKeys,
    old_seal_key: &OwnerEpochSealKey,
    new_epoch: u64,
    new_keys: &EpochKeys,
    new_seal_verifier: [u8; 32],
    remove_op: &SignedOp,
    rekey_op: &SignedOp,
    all_signed_ops: &[SignedOp],
) -> Result<DeviceId, NetError> {
    owner_rotate_mailbox_with_cap(
        mailbox_peer,
        relay_url,
        old_epoch,
        old_keys,
        old_seal_key,
        new_epoch,
        new_keys,
        new_seal_verifier,
        remove_op,
        rekey_op,
        all_signed_ops,
    )
    .await
    .map(|(eph_id, _)| eph_id)
}

/// Owner (`PcNode`): rotate mailbox and return any `max_relay_file_bytes` advertised in `PUSH_ACK` (`M2.9`).
#[allow(clippy::too_many_arguments)]
pub async fn owner_rotate_mailbox_with_cap(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    old_epoch: u64,
    old_keys: &EpochKeys,
    old_seal_key: &OwnerEpochSealKey,
    new_epoch: u64,
    new_keys: &EpochKeys,
    new_seal_verifier: [u8; 32],
    remove_op: &SignedOp,
    rekey_op: &SignedOp,
    all_signed_ops: &[SignedOp],
) -> Result<(DeviceId, Option<u64>), NetError> {
    let sess = ThrowawaySession::connect(mailbox_peer, relay_url).await?;
    let eph_id = sess.ephemeral_id;
    let res = async {
        // Ensure old mailbox exists and find its next_seq (paginated past 64 records, M2-H3)
        let (old_opt, mut adv_cap) =
            read_all_mailbox_records_with_cap(&sess, old_keys.mailbox_id, 1).await?;
        let old_next_seq = match old_opt {
            Some(resp) => resp.records.last().map(|r| r.seq + 1).unwrap_or(1),
            None => {
                // Create old mailbox first so ROTATE has an unsealed old mailbox to seal
                let create_old = CreateMailboxReq {
                    mailbox_id: old_keys.mailbox_id,
                    epoch: old_epoch,
                    write_verifier: old_keys.write_verifier,
                    seal_verifier: old_seal_key.verifier,
                    initial_records: Vec::new(),
                };
                let (cft, cp) = sess.request(mb_frame::CREATE, &create_old.encode()).await?;
                let (code, cap) = expect_ok_with_cap(cft, &cp)?;
                if code != mb_status::OK {
                    return Err(NetError::Protocol("old mailbox create failed".into()));
                }
                if cap.is_some() {
                    adv_cap = cap;
                }
                1
            }
        };

        let final_old_rec = MailboxRecord::seal(old_keys, old_next_seq, remove_op.as_bytes())?;
        let seal = MailboxSeal::create(
            old_keys,
            old_seal_key,
            new_keys.mailbox_id,
            rekey_op.as_bytes(),
        )?;
        let seed_ops = if all_signed_ops.len() > MAX_MAILBOX_RECORDS {
            &all_signed_ops[all_signed_ops.len() - MAX_MAILBOX_RECORDS..]
        } else {
            all_signed_ops
        };
        let mut new_init_recs = Vec::with_capacity(seed_ops.len());
        for (i, op) in seed_ops.iter().enumerate() {
            new_init_recs.push(MailboxRecord::seal(
                new_keys,
                (i as u64) + 1,
                op.as_bytes(),
            )?);
        }
        let rot = RotateMailboxReq {
            old_mailbox_id: old_keys.mailbox_id,
            final_old_record: Some(final_old_rec),
            seal,
            create_new: CreateMailboxReq {
                mailbox_id: new_keys.mailbox_id,
                epoch: new_epoch,
                write_verifier: new_keys.write_verifier,
                seal_verifier: new_seal_verifier,
                initial_records: new_init_recs,
            },
        };
        let (ft, p) = sess.request(mb_frame::ROTATE, &rot.encode()).await?;
        let (code, cap) = expect_ok_with_cap(ft, &p)?;
        if code != mb_status::OK {
            return Err(NetError::Protocol("mailbox rotate failed".into()));
        }
        if cap.is_some() {
            adv_cap = cap;
        }
        Ok(adv_cap)
    }
    .await;
    sess.close().await;
    res.map(|cap| (eph_id, cap))
}

/// Fetch and verify a signed `voidwire-config` v1 from the mailbox server over a throwaway session.
pub async fn fetch_signed_config(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    verifying_key: &[u8; 32],
    current_day: Option<u32>,
) -> Result<(SignedConfig, DeviceId), NetError> {
    let sess = ThrowawaySession::connect(mailbox_peer, relay_url).await?;
    let eph_id = sess.ephemeral_id;
    let res = async {
        let (ft, p) = sess.request(mb_frame::CONFIG_GET, &[]).await?;
        if ft != mb_frame::CONFIG {
            return Err(NetError::Protocol("mailbox has no signed config".into()));
        }
        let cfg = SignedConfig::decode(&p)?;
        cfg.verify(verifying_key, current_day)?;
        Ok(cfg)
    }
    .await;
    sess.close().await;
    res.map(|c| (c, eph_id))
}

/// Pull signed ops from the mailbox starting at `(start_epoch, start_gs)`,
/// following `MailboxSeal` tombstones across epoch boundaries up to `MAX_SEAL_CHAIN_HOPS`.
pub async fn pull_mailbox_chain(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    my_id: &DeviceId,
    my_rx_kp: &crate::keys::ReceiveKeypair,
    group_id: &crate::ids::GroupId,
    start_epoch: u64,
    start_gs: &crate::mailbox::EpochSecret,
) -> Result<(DeviceId, u64, crate::mailbox::EpochSecret, Vec<SignedOp>), NetError> {
    let sess = ThrowawaySession::connect(mailbox_peer, relay_url).await?;
    let eph_id = sess.ephemeral_id;
    let mut cur_epoch = start_epoch;
    let mut cur_gs = start_gs.clone();
    let mut collected_ops: Vec<SignedOp> = Vec::new();

    let res = async {
        for _hop in 0..MAX_SEAL_CHAIN_HOPS {
            let keys = cur_gs.derive_keys();
            let Some(resp) = read_all_mailbox_records(&sess, keys.mailbox_id, 1).await? else {
                // Empty / not-yet-created mailbox: nothing new to pull
                break;
            };

            for rec in &resp.records {
                let pt = rec.open(&keys)?;
                let op = SignedOp::parse_verified(&pt)?;
                if !collected_ops
                    .iter()
                    .any(|existing| existing.as_bytes() == op.as_bytes())
                {
                    collected_ops.push(op);
                }
            }

            let Some(seal) = resp.seal else {
                break;
            };
            let rekey_bytes = seal.open_rekey_op(&keys)?;
            let rekey_op = SignedOp::parse_verified(&rekey_bytes)?;
            if !collected_ops
                .iter()
                .any(|existing| existing.as_bytes() == rekey_op.as_bytes())
            {
                collected_ops.push(rekey_op.clone());
            }

            // Inspect the Rekey payload to see if we were removed or can unwrap gs_{e+1}:
            if let Some(rekey_payload) = &rekey_op.rekey {
                if &rekey_payload.removed == my_id {
                    // We are the removed device; we have the signed Rekey/Remove op, stop here.
                    break;
                }
                if let Some(next_gs) = rekey_payload.unwrap_for(my_rx_kp, my_id, group_id)? {
                    let next_keys = next_gs.derive_keys();
                    if next_keys.mailbox_id != seal.next_mailbox_id {
                        return Err(NetError::Protocol(
                            "seal next_mailbox_id does not match unwrapped gs_{e+1}".into(),
                        ));
                    }
                    cur_epoch = rekey_payload.new_epoch;
                    cur_gs = next_gs;
                    continue;
                }
            }
            break;
        }
        Ok((eph_id, cur_epoch, cur_gs, collected_ops))
    }
    .await;
    sess.close().await;
    res
}

/// Pull signed ops from the mailbox starting at `(start_epoch, start_gs)` AND
/// best-effort fetch `CONFIG_GET` (`SignedConfig` v1) on the same throwaway session (`M26-M4`).
pub async fn pull_mailbox_chain_with_config(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    my_id: &DeviceId,
    my_rx_kp: &crate::keys::ReceiveKeypair,
    group_id: &crate::ids::GroupId,
    start_epoch: u64,
    start_gs: &crate::mailbox::EpochSecret,
) -> Result<
    (
        DeviceId,
        u64,
        crate::mailbox::EpochSecret,
        Vec<SignedOp>,
        Option<crate::mailbox::SignedConfig>,
        Option<u64>,
    ),
    NetError,
> {
    let sess = ThrowawaySession::connect(mailbox_peer, relay_url).await?;
    let eph_id = sess.ephemeral_id;
    let mut cur_epoch = start_epoch;
    let mut cur_gs = start_gs.clone();
    let mut collected_ops: Vec<SignedOp> = Vec::new();
    let mut advertised_cap: Option<u64> = None;

    let res = async {
        for _hop in 0..MAX_SEAL_CHAIN_HOPS {
            let keys = cur_gs.derive_keys();
            let (resp_opt, hop_cap) =
                read_all_mailbox_records_with_cap(&sess, keys.mailbox_id, 1).await?;
            if hop_cap.is_some() {
                advertised_cap = hop_cap;
            }
            let Some(resp) = resp_opt else {
                break;
            };

            for rec in &resp.records {
                let pt = rec.open(&keys)?;
                let op = SignedOp::parse_verified(&pt)?;
                if !collected_ops
                    .iter()
                    .any(|existing| existing.as_bytes() == op.as_bytes())
                {
                    collected_ops.push(op);
                }
            }

            let Some(seal) = resp.seal else {
                break;
            };
            let rekey_bytes = seal.open_rekey_op(&keys)?;
            let rekey_op = SignedOp::parse_verified(&rekey_bytes)?;
            if !collected_ops
                .iter()
                .any(|existing| existing.as_bytes() == rekey_op.as_bytes())
            {
                collected_ops.push(rekey_op.clone());
            }

            if let Some(rekey_payload) = &rekey_op.rekey {
                if &rekey_payload.removed == my_id {
                    break;
                }
                if let Some(next_gs) = rekey_payload.unwrap_for(my_rx_kp, my_id, group_id)? {
                    let next_keys = next_gs.derive_keys();
                    if next_keys.mailbox_id != seal.next_mailbox_id {
                        return Err(NetError::Protocol(
                            "seal next_mailbox_id does not match unwrapped gs_{e+1}".into(),
                        ));
                    }
                    cur_epoch = rekey_payload.new_epoch;
                    cur_gs = next_gs;
                    continue;
                }
            }
            break;
        }
        let maybe_cfg = match sess.request(mb_frame::CONFIG_GET, &[]).await {
            Ok((mb_frame::CONFIG, p)) => crate::mailbox::SignedConfig::decode(&p).ok(),
            _ => None,
        };
        Ok((
            eph_id,
            cur_epoch,
            cur_gs,
            collected_ops,
            maybe_cfg,
            advertised_cap,
        ))
    }
    .await;
    sess.close().await;
    res
}

/// Put one sealed envelope into a recipient's RAM-only blind device inbox over a fresh
/// throwaway session (`M3-PLAN.md` §1.3.4).
pub async fn put_device_inbox_item(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    keys: &DeviceInboxKeys,
    item_id: [u8; 16],
    envelope: Vec<u8>,
) -> Result<(DeviceId, Option<u64>), NetError> {
    let sess = ThrowawaySession::connect(mailbox_peer, relay_url).await?;
    let eph_id = sess.ephemeral_id;
    let res = sess
        .put_device_inbox_with_cap(keys, item_id, envelope)
        .await;
    sess.close().await;
    res.map(|cap| (eph_id, cap))
}

/// Pull all pending envelopes from this device's RAM-only blind inbox over a fresh
/// throwaway session and return any server-advertised limits (`M3-PLAN.md` §1.3.4).
pub async fn pull_device_inbox_with_caps(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    gs_e: &crate::mailbox::EpochSecret,
    group_id: &crate::ids::GroupId,
    epoch: u64,
    recipient: &DeviceId,
    recipient_rx_pk: &crate::keys::ReceivePublicKey,
) -> Result<(DeviceId, Vec<InboxPullItem>, Option<AdvertisedInboxCaps>), NetError> {
    let keys = gs_e.derive_device_inbox_keys(group_id, epoch, recipient, recipient_rx_pk);
    let sess = ThrowawaySession::connect(mailbox_peer, relay_url).await?;
    let eph_id = sess.ephemeral_id;
    let res = sess.pull_device_inbox_with_caps(&keys).await;
    sess.close().await;
    res.map(|(items, caps)| (eph_id, items, caps))
}

/// Acknowledge and zeroize delivered item IDs in this device's RAM-only blind inbox
/// over a fresh throwaway session (`M3-PLAN.md` §1.3.4).
#[allow(clippy::too_many_arguments)]
pub async fn ack_device_inbox(
    mailbox_peer: &DeviceId,
    relay_url: &str,
    gs_e: &crate::mailbox::EpochSecret,
    group_id: &crate::ids::GroupId,
    epoch: u64,
    recipient: &DeviceId,
    recipient_rx_pk: &crate::keys::ReceivePublicKey,
    item_ids: &[[u8; 16]],
) -> Result<DeviceId, NetError> {
    let keys = gs_e.derive_device_inbox_keys(group_id, epoch, recipient, recipient_rx_pk);
    let sess = ThrowawaySession::connect(mailbox_peer, relay_url).await?;
    let eph_id = sess.ephemeral_id;
    let res = sess.ack_device_inbox(&keys, item_ids).await;
    sess.close().await;
    res.map(|()| eph_id)
}
