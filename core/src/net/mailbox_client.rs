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

use crate::ids::DeviceId;
use crate::keys::DeviceKeypair;
use crate::mailbox::{
    mb_frame, mb_status, AdvertisedInboxCaps, DeviceInboxKeys, InboxPullItem, InboxPullResp,
    SignedConfig, MAX_MAILBOX_WIRE_FRAME,
};
use crate::net::{build_relay_mode, default_net_report_config, NetError};
use crate::protocol::ALPN_MAILBOX;
use crate::reject::RejectReason;

/// Environment variable overriding the mailbox service's iroh `DeviceId` (64-char hex).
pub const ENV_MAILBOX_ID: &str = "VOIDWIRE_MAILBOX_ID";

/// Production `voidwire-mailbox` Ed25519 `EndpointId` / `DeviceId` (`M2-H1`).
pub const DEFAULT_MAILBOX_ID: &str =
    "b080fe7101c968a6c827bad4e99d225343faa3bee18ee2a82b799c7a9d2f6840";

const MAILBOX_CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const MAILBOX_IO_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_FRAME_LEN: usize = MAX_MAILBOX_WIRE_FRAME;

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
