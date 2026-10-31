#![forbid(unsafe_code)]
//! One reason enum for every drop on the inbound and pairing paths (TEST-PLAN H-4).
//!
//! Every negative test asserts on the exact variant, so variants are never
//! merged or renamed casually; append new ones instead.

/// Why a frame, message, URL or pairing attempt was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum RejectReason {
    // --- transport / roster ------------------------------------------------
    #[error("transport peer is not in the roster")]
    NotInRoster,
    #[error("sender has been removed from the group")]
    Removed,
    #[error("no pairing session is active")]
    PairingNotActive,
    #[error("unexpected frame type for this connection")]
    UnexpectedFrame,
    // Codes 5 and 6 were the group-log head checks (stale / unknown head),
    // gone with message format 2. They stay reserved in `WIRE_CODES`.

    // --- envelope / frame --------------------------------------------------
    #[error("envelope could not be opened")]
    DecryptFailed,
    #[error("frame malformed")]
    MalformedFrame,
    #[error("unsupported protocol version")]
    UnsupportedVersion,

    // --- authentication / addressing ----------------------------------------
    #[error("signature invalid (or sender key weak/invalid)")]
    BadSignature,
    #[error("message sender differs from the transport peer")]
    SenderMismatch,
    #[error("message is for another device")]
    WrongRecipient,
    #[error("message is for another group")]
    WrongGroup,
    #[error("message claims to come from this device")]
    FromSelf,

    // --- freshness -----------------------------------------------------------
    #[error("message already received")]
    Replay,
    #[error("timestamp too old")]
    StaleTimestamp,
    #[error("timestamp too far in the future")]
    FutureTimestamp,
    #[error("replay cache full; refusing (fail closed)")]
    CacheFull,
    /// The on-disk replay cache was missing or damaged at startup: for one
    /// replay window only messages timestamped after startup are accepted.
    #[error("replay cache was lost; message predates startup (fail closed)")]
    ReplayStartupGuard,

    // --- rate limits -----------------------------------------------------------
    #[error("per-device rate limit exceeded")]
    RateLimitedDevice,
    #[error("global rate limit exceeded")]
    RateLimitedGlobal,
    /// D13: cheap per-peer budget keyed on the authenticated transport peer,
    /// charged *before* envelope decryption and signature verification.
    #[error("per-peer pre-decryption budget exceeded")]
    RateLimitedPeer,

    // --- URL policy --------------------------------------------------------------
    /// Unit variant on purpose (D11): the sender-chosen scheme string is never
    /// carried into rejection output, counters or logs.
    #[error("scheme not allowed (http/https only)")]
    SchemeNotAllowed,
    #[error("url contains user:password@")]
    UrlHasUserinfo,
    #[error("url exceeds the size cap")]
    UrlTooLong,
    #[error("url contains whitespace, control, bidi or non-RFC3986 characters")]
    UrlBadChars,
    #[error("url could not be parsed")]
    UrlParseError,
    #[error("url has no host")]
    UrlMissingHost,
    /// OQ-8: 127.0.0.0/8, ::1, `localhost`, `*.localhost` (and IPv4-mapped /
    /// odd encodings of them, normalized by the WHATWG parser first).
    #[error("url points at a loopback address")]
    HostLoopback,
    /// OQ-8: 169.254.0.0/16, fe80::/10.
    #[error("url points at a link-local address")]
    HostLinkLocal,
    /// OQ-8: 0.0.0.0/8 and ::.
    #[error("url points at an unspecified address")]
    HostUnspecified,
    /// N1: IPv4 224.0.0.0/4 and IPv6 ff00::/8.
    #[error("url points at a multicast address")]
    HostMulticast,
    /// N1: limited broadcast 255.255.255.255.
    #[error("url points at the broadcast address")]
    HostBroadcast,
    /// N1: deprecated IPv6 site-local fec0::/10.
    #[error("url points at a site-local address")]
    HostSiteLocal,

    // --- pairing -----------------------------------------------------------------
    #[error("pairing code unknown")]
    PairingSecretUnknown,
    #[error("pairing code already used")]
    PairingSecretUsed,
    #[error("pairing code expired")]
    PairingSecretExpired,
    #[error("pairing proof did not verify")]
    PairingHmacBad,
    #[error("security code rejected or mistyped")]
    SasRejected,
    #[error("security code not confirmed in time")]
    SasTimeout,
    #[error("device name empty, too long or containing control characters")]
    BadDeviceName,
    #[error("pairing cancelled (window closed, new QR, or the other side left)")]
    PairingCancelled,
    /// OQ-9 / PAIR-11: the device already belongs to a group and the user
    /// didn't confirm joining a different one.
    #[error("joining a different device group was not confirmed")]
    GroupChangeNotConfirmed,
    /// M4.1: a device keeps at most 16 pairings.
    #[error("pairing limit reached (16 paired devices)")]
    PairingLimitReached,
    /// M4.3: a typed pairing code with a typo (its check characters fail).
    #[error("pairing code mistyped")]
    PairingCodeInvalid,
    /// M4.3: the 4-relays-in-use or 8-saved-relays limit.
    #[error("relay limit reached (4 relays in use, 8 saved)")]
    RelayLimitReached,
    /// M4.3: the user didn't add the invite's relay.
    #[error("the pairing's relay was not added")]
    RelayNotAdded,
    /// M4.3: the other device is already paired over a v0.4.x pairing.
    #[error("already paired with this device")]
    AlreadyPaired,
    /// A signed message in an older Voidwire's format (B14, MSG_VERSION).
    #[error("message is from an older Voidwire")]
    OlderVoidwire,

    // --- group log ------------------------------------------------------------------
    #[error("group-log operation malformed, unsigned or not chained to our head")]
    BadLogOp,

    // --- open time ------------------------------------------------------------------
    /// D2: a VerifiedUrl minted by some other `Inbox` (i.e. against another
    /// roster) was handed to this inbox's deliver/confirm path.
    #[error("link was verified by a different inbox")]
    ForeignInbox,
    #[error("no such prompt (already decided or dismissed)")]
    NoSuchPrompt,
    #[error("prompt expired before it was answered")]
    PromptExpired,

    // --- everything else (fail closed) -----------------------------------------
    #[error("internal error (fail closed)")]
    Internal,
}

impl RejectReason {
    /// Stable short label for counters and logs (never includes URL/host/keys).
    pub fn label(&self) -> &'static str {
        use RejectReason::*;
        match self {
            NotInRoster => "not_in_roster",
            Removed => "removed",
            PairingNotActive => "pairing_not_active",
            UnexpectedFrame => "unexpected_frame",
            DecryptFailed => "decrypt_failed",
            MalformedFrame => "malformed_frame",
            UnsupportedVersion => "unsupported_version",
            BadSignature => "bad_signature",
            SenderMismatch => "sender_mismatch",
            WrongRecipient => "wrong_recipient",
            WrongGroup => "wrong_group",
            FromSelf => "from_self",
            Replay => "replay",
            StaleTimestamp => "stale_timestamp",
            FutureTimestamp => "future_timestamp",
            CacheFull => "cache_full",
            RateLimitedDevice => "rate_limited_device",
            RateLimitedGlobal => "rate_limited_global",
            RateLimitedPeer => "rate_limited_peer",
            SchemeNotAllowed => "scheme_not_allowed",
            UrlHasUserinfo => "url_has_userinfo",
            UrlTooLong => "url_too_long",
            UrlBadChars => "url_bad_chars",
            UrlParseError => "url_parse_error",
            UrlMissingHost => "url_missing_host",
            HostLoopback => "host_loopback",
            HostLinkLocal => "host_link_local",
            HostUnspecified => "host_unspecified",
            HostMulticast => "host_multicast",
            HostBroadcast => "host_broadcast",
            HostSiteLocal => "host_site_local",
            PairingSecretUnknown => "pairing_secret_unknown",
            PairingSecretUsed => "pairing_secret_used",
            PairingSecretExpired => "pairing_secret_expired",
            PairingHmacBad => "pairing_hmac_bad",
            SasRejected => "sas_rejected",
            SasTimeout => "sas_timeout",
            BadDeviceName => "bad_device_name",
            BadLogOp => "bad_log_op",
            PairingCancelled => "pairing_cancelled",
            ForeignInbox => "foreign_inbox",
            Internal => "internal",
            GroupChangeNotConfirmed => "group_change_not_confirmed",
            ReplayStartupGuard => "replay_startup_guard",
            NoSuchPrompt => "no_such_prompt",
            PromptExpired => "prompt_expired",
            PairingLimitReached => "pairing_limit_reached",
            PairingCodeInvalid => "pairing_code_invalid",
            RelayLimitReached => "relay_limit_reached",
            RelayNotAdded => "relay_not_added",
            AlreadyPaired => "already_paired",
            OlderVoidwire => "older_voidwire",
        }
    }
}

/// Wire-code table: position + 1 is the status code (`code()`), shared by
/// every app version. **Append only.** A retired reason leaves `None` in its
/// slot so later codes never move.
const WIRE_CODES: &[Option<RejectReason>] = {
    use RejectReason::*;
    &[
        Some(NotInRoster),
        Some(Removed),
        Some(PairingNotActive),
        Some(UnexpectedFrame),
        None, // 5: reserved (was the stale group-log head, message format 1)
        None, // 6: reserved (was the unknown group-log head, message format 1)
        Some(DecryptFailed),
        Some(MalformedFrame),
        Some(UnsupportedVersion),
        Some(BadSignature),
        Some(SenderMismatch),
        Some(WrongRecipient),
        Some(WrongGroup),
        Some(FromSelf),
        Some(Replay),
        Some(StaleTimestamp),
        Some(FutureTimestamp),
        Some(CacheFull),
        Some(RateLimitedDevice),
        Some(RateLimitedGlobal),
        Some(SchemeNotAllowed),
        Some(UrlHasUserinfo),
        Some(UrlTooLong),
        Some(UrlBadChars),
        Some(UrlParseError),
        Some(UrlMissingHost),
        Some(HostLoopback),
        Some(HostLinkLocal),
        Some(HostUnspecified),
        Some(PairingSecretUnknown),
        Some(PairingSecretUsed),
        Some(PairingSecretExpired),
        Some(PairingHmacBad),
        Some(SasRejected),
        Some(SasTimeout),
        Some(ForeignInbox),
        Some(Internal),
        Some(RateLimitedPeer),
        Some(HostMulticast),
        Some(HostBroadcast),
        Some(HostSiteLocal),
        Some(BadDeviceName),
        Some(BadLogOp),
        Some(PairingCancelled),
        Some(GroupChangeNotConfirmed),
        Some(ReplayStartupGuard),
        Some(NoSuchPrompt),
        Some(PromptExpired),
        Some(PairingLimitReached),
        Some(PairingCodeInvalid),
        Some(RelayLimitReached),
        Some(RelayNotAdded),
        Some(AlreadyPaired),
        Some(OlderVoidwire),
    ]
};

/// Every live variant, in wire-code order.
pub const ALL_REASONS: &[RejectReason] = &{
    let mut out = [RejectReason::Internal; WIRE_CODES.len() - RESERVED_CODES];
    let (mut i, mut j) = (0, 0);
    while i < WIRE_CODES.len() {
        if let Some(r) = WIRE_CODES[i] {
            out[j] = r;
            j += 1;
        }
        i += 1;
    }
    out
};

/// How many slots in `WIRE_CODES` are reserved (`None`).
const RESERVED_CODES: usize = 2;

impl RejectReason {
    /// Stable wire status code (1-based position in `WIRE_CODES`).
    pub fn code(&self) -> u16 {
        WIRE_CODES
            .iter()
            .position(|r| *r == Some(*self))
            .map(|i| i as u16 + 1)
            .unwrap_or(0)
    }

    /// Inverse of [`code`](Self::code); unknown codes map to `Internal`.
    pub fn from_code(code: u16) -> RejectReason {
        WIRE_CODES
            .get((code as usize).wrapping_sub(1))
            .copied()
            .flatten()
            .unwrap_or(RejectReason::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codes_are_stable_unique_and_cover_every_variant() {
        let mut labels = std::collections::HashSet::new();
        for (i, slot) in WIRE_CODES.iter().enumerate() {
            let Some(r) = slot else { continue };
            assert_eq!(r.code() as usize, i + 1);
            assert_eq!(RejectReason::from_code(r.code()), *r);
            assert!(labels.insert(r.label()), "duplicate {r:?}");
        }
        assert_eq!(
            WIRE_CODES.iter().filter(|r| r.is_none()).count(),
            RESERVED_CODES
        );
        assert_eq!(ALL_REASONS.len(), WIRE_CODES.len() - RESERVED_CODES);
        // Retired codes 5 and 6 stay reserved: nothing decodes to them and
        // the codes after them keep their numbers.
        assert_eq!(RejectReason::from_code(5), RejectReason::Internal);
        assert_eq!(RejectReason::from_code(6), RejectReason::Internal);
        assert_eq!(RejectReason::DecryptFailed.code(), 7);
        // Pinned codes that apps of different versions rely on.
        assert_eq!(RejectReason::NotInRoster.code(), 1);
        assert_eq!(RejectReason::Replay.code(), 15);
        assert_eq!(RejectReason::SchemeNotAllowed.code(), 21);
        assert_eq!(RejectReason::UrlTooLong.code(), 23);
        assert_eq!(RejectReason::Internal.code(), 37);
        assert_eq!(RejectReason::from_code(0), RejectReason::Internal);
        assert_eq!(RejectReason::from_code(9999), RejectReason::Internal);
    }

    // Exhaustiveness: adding a variant without listing it in ALL_REASONS
    // fails to compile here.
    #[allow(dead_code)]
    fn exhaustive(r: RejectReason) -> usize {
        use RejectReason::*;
        match r {
            NotInRoster
            | Removed
            | PairingNotActive
            | UnexpectedFrame
            | DecryptFailed
            | MalformedFrame
            | UnsupportedVersion
            | BadSignature
            | SenderMismatch
            | WrongRecipient
            | WrongGroup
            | FromSelf
            | Replay
            | StaleTimestamp
            | FutureTimestamp
            | CacheFull
            | RateLimitedDevice
            | RateLimitedGlobal
            | SchemeNotAllowed
            | UrlHasUserinfo
            | UrlTooLong
            | UrlBadChars
            | UrlParseError
            | UrlMissingHost
            | HostLoopback
            | HostLinkLocal
            | HostUnspecified
            | PairingSecretUnknown
            | PairingSecretUsed
            | PairingSecretExpired
            | PairingHmacBad
            | SasRejected
            | SasTimeout
            | ForeignInbox
            | Internal
            | RateLimitedPeer
            | HostMulticast
            | HostBroadcast
            | HostSiteLocal
            | BadDeviceName
            | BadLogOp
            | PairingCancelled
            | GroupChangeNotConfirmed
            | ReplayStartupGuard
            | NoSuchPrompt
            | PromptExpired
            | PairingLimitReached
            | PairingCodeInvalid
            | RelayLimitReached
            | RelayNotAdded
            | AlreadyPaired
            | OlderVoidwire => 0,
        }
    }
}
