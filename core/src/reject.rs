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
    #[error("sender's group-log head is behind ours (needs sync)")]
    StaleGroupHead,
    #[error("sender's group-log head is unknown to us (needs sync)")]
    UnknownGroupHead,

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
            StaleGroupHead => "stale_group_head",
            UnknownGroupHead => "unknown_group_head",
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
        }
    }
}

/// Every variant, in wire-code order. **Append only**: a variant's position is
/// its status code on the wire (`code()`), shared by every app version.
pub const ALL_REASONS: &[RejectReason] = {
    use RejectReason::*;
    &[
        NotInRoster,
        Removed,
        PairingNotActive,
        UnexpectedFrame,
        StaleGroupHead,
        UnknownGroupHead,
        DecryptFailed,
        MalformedFrame,
        UnsupportedVersion,
        BadSignature,
        SenderMismatch,
        WrongRecipient,
        WrongGroup,
        FromSelf,
        Replay,
        StaleTimestamp,
        FutureTimestamp,
        CacheFull,
        RateLimitedDevice,
        RateLimitedGlobal,
        SchemeNotAllowed,
        UrlHasUserinfo,
        UrlTooLong,
        UrlBadChars,
        UrlParseError,
        UrlMissingHost,
        HostLoopback,
        HostLinkLocal,
        HostUnspecified,
        PairingSecretUnknown,
        PairingSecretUsed,
        PairingSecretExpired,
        PairingHmacBad,
        SasRejected,
        SasTimeout,
        ForeignInbox,
        Internal,
        RateLimitedPeer,
        HostMulticast,
        HostBroadcast,
        HostSiteLocal,
        BadDeviceName,
        BadLogOp,
        PairingCancelled,
        GroupChangeNotConfirmed,
        ReplayStartupGuard,
        NoSuchPrompt,
        PromptExpired,
        PairingLimitReached,
        PairingCodeInvalid,
        RelayLimitReached,
        RelayNotAdded,
        AlreadyPaired,
    ]
};

impl RejectReason {
    /// Stable wire status code (1-based position in [`ALL_REASONS`]).
    pub fn code(&self) -> u16 {
        ALL_REASONS
            .iter()
            .position(|r| r == self)
            .map(|i| i as u16 + 1)
            .unwrap_or(0)
    }

    /// Inverse of [`code`](Self::code); unknown codes map to `Internal`.
    pub fn from_code(code: u16) -> RejectReason {
        ALL_REASONS
            .get((code as usize).wrapping_sub(1))
            .cloned()
            .unwrap_or(RejectReason::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codes_are_stable_unique_and_cover_every_variant() {
        let mut labels = std::collections::HashSet::new();
        for (i, r) in ALL_REASONS.iter().enumerate() {
            assert_eq!(r.code() as usize, i + 1);
            assert_eq!(RejectReason::from_code(r.code()), *r);
            assert!(labels.insert(r.label()), "duplicate {r:?}");
        }
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
            | StaleGroupHead
            | UnknownGroupHead
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
            | AlreadyPaired => 0,
        }
    }
}
