#![forbid(unsafe_code)]
//! Clocks are injected (TEST-PLAN H-2). Verification code never reads the
//! system clock itself: it receives a [`Now`] from the caller. The only
//! system-clock reads in core are in [`SystemClock`] (CI greps for this).

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Wall-clock milliseconds since the Unix epoch (UTC). Used for message
/// timestamps and anything compared with another device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixMillis(pub u64);

impl UnixMillis {
    pub fn saturating_add(self, ms: u64) -> Self {
        UnixMillis(self.0.saturating_add(ms))
    }
    pub fn abs_diff(self, other: UnixMillis) -> u64 {
        self.0.abs_diff(other.0)
    }
}

/// Monotonic milliseconds since an arbitrary process-local origin. Used for
/// local timers (pairing expiry, rate-limit refill, cache eviction) so a wall
/// clock jump can't extend or shorten them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoMillis(pub u64);

impl MonoMillis {
    pub fn saturating_add(self, ms: u64) -> Self {
        MonoMillis(self.0.saturating_add(ms))
    }
    pub fn saturating_sub(self, other: MonoMillis) -> u64 {
        self.0.saturating_sub(other.0)
    }
}

/// One reading of both clocks, passed into every time-dependent call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    pub wall: UnixMillis,
    pub mono: MonoMillis,
}

impl Now {
    /// Both clocks advanced by `ms` (test convenience).
    pub fn plus(self, ms: u64) -> Now {
        Now {
            wall: self.wall.saturating_add(ms),
            mono: self.mono.saturating_add(ms),
        }
    }
}

pub trait Clock {
    fn now(&self) -> Now;
}

/// The real clocks. Apps call `SystemClock.now()` at the edge and pass the
/// result down.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[allow(clippy::disallowed_methods)] // the one sanctioned clock read (H-2)
    fn now(&self) -> Now {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        let origin = *ORIGIN.get_or_init(Instant::now);
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Now {
            wall: UnixMillis(wall),
            mono: MonoMillis(origin.elapsed().as_millis() as u64),
        }
    }
}

/// Elapsed-time measurement for reporting only (send latency shown to the
/// user and in tests). Never used for a security decision; those use the
/// injected `Now`.
#[derive(Debug, Clone, Copy)]
pub struct Stopwatch(Instant);

impl Stopwatch {
    #[allow(clippy::disallowed_methods)] // sanctioned clock read (H-2), reporting only
    pub fn start() -> Self {
        Stopwatch(Instant::now())
    }
    #[allow(clippy::disallowed_methods)]
    pub fn elapsed_us(&self) -> u64 {
        self.0.elapsed().as_micros() as u64
    }
}
