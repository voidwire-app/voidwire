//! Test-only work counters: how many envelopes were HPKE-opened and how many
//! app streams a node accepted. They prove that an unpaired peer costs no
//! parse and no decrypt. Every hook compiles to nothing outside tests.

#[cfg(any(test, feature = "test-util"))]
mod imp {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    static OPENS: AtomicU64 = AtomicU64::new(0);
    static APP_STREAMS: AtomicU64 = AtomicU64::new(0);
    thread_local! {
        static OPENS_HERE: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn envelope_open() {
        OPENS.fetch_add(1, Ordering::SeqCst);
        OPENS_HERE.with(|c| c.set(c.get() + 1));
    }
    pub(crate) fn app_stream_accepted() {
        APP_STREAMS.fetch_add(1, Ordering::SeqCst);
    }
    /// HPKE opens in this process (all threads).
    pub fn envelope_opens() -> u64 {
        OPENS.load(Ordering::SeqCst)
    }
    /// HPKE opens on the calling thread (for unit tests running in parallel).
    pub fn envelope_opens_on_this_thread() -> u64 {
        OPENS_HERE.with(|c| c.get())
    }
    /// App-ALPN streams accepted by any PC or phone node in this process.
    pub fn app_streams_accepted() -> u64 {
        APP_STREAMS.load(Ordering::SeqCst)
    }
}

#[cfg(any(test, feature = "test-util"))]
pub use imp::{app_streams_accepted, envelope_opens, envelope_opens_on_this_thread};

#[cfg(any(test, feature = "test-util"))]
pub(crate) use imp::{app_stream_accepted, envelope_open};

#[cfg(not(any(test, feature = "test-util")))]
#[inline(always)]
pub(crate) fn envelope_open() {}

#[cfg(not(any(test, feature = "test-util")))]
#[inline(always)]
#[allow(dead_code)]
pub(crate) fn app_stream_accepted() {}
