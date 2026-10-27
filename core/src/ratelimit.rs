#![forbid(unsafe_code)]
//! Token-bucket rate limiting on the monotonic clock (integer arithmetic).

use crate::time::MonoMillis;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Max messages accepted back-to-back.
    pub burst: u32,
    /// Sustained refill rate.
    pub per_minute: u32,
}

/// Classic token bucket. Tokens are tracked in milli-tokens to avoid floats.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    limit: RateLimit,
    milli_tokens: u64,
    last: MonoMillis,
}

impl TokenBucket {
    pub fn new(limit: RateLimit, now: MonoMillis) -> Self {
        TokenBucket {
            limit,
            milli_tokens: limit.burst as u64 * 1000,
            last: now,
        }
    }

    fn refill(&mut self, now: MonoMillis) {
        if now > self.last {
            let elapsed = now.saturating_sub(self.last);
            // per_minute tokens per 60_000 ms == per_minute milli-tokens per 60 ms.
            let add = elapsed.saturating_mul(self.limit.per_minute as u64) / 60;
            let cap = self.limit.burst as u64 * 1000;
            self.milli_tokens = self.milli_tokens.saturating_add(add).min(cap);
            self.last = now;
        }
    }

    /// Consume one token. Returns false (and consumes nothing) if empty.
    pub fn try_take(&mut self, now: MonoMillis) -> bool {
        self.refill(now);
        if self.milli_tokens >= 1000 {
            self.milli_tokens -= 1000;
            true
        } else {
            false
        }
    }

    /// Refund one previously-consumed token (capped at burst).
    pub fn refund_one(&mut self) {
        let cap = self.limit.burst as u64 * 1000;
        self.milli_tokens = self.milli_tokens.saturating_add(1000).min(cap);
    }

    /// Whole tokens currently available (for visible counters).
    pub fn available(&mut self, now: MonoMillis) -> u32 {
        self.refill(now);
        (self.milli_tokens / 1000) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn burst_then_refill() {
        let t0 = MonoMillis(1_000_000);
        let mut b = TokenBucket::new(
            RateLimit {
                burst: 3,
                per_minute: 60,
            },
            t0,
        );
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0));
        assert!(!b.try_take(t0.saturating_add(999)));
        assert!(b.try_take(t0.saturating_add(1000)));
        let later = t0.saturating_add(3_600_000);
        assert_eq!(b.available(later), 3, "idle never exceeds burst");
    }
}
