//! Test seam (test-util only): hold one device's unpair notice between its
//! pairing check and the erase, so a re-pairing can land in that gap (S27).

use crate::ids::DeviceId;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Idle,
    Armed(DeviceId),
    Held,
    Open,
    Passed,
}

static STEP: Mutex<Step> = Mutex::new(Step::Idle);
static CV: Condvar = Condvar::new();

fn wait_for(want: impl Fn(Step) -> bool, timeout: Duration) -> bool {
    let g = STEP.lock().unwrap_or_else(|p| p.into_inner());
    let (g, _) = CV
        .wait_timeout_while(g, timeout, |s| !want(*s))
        .unwrap_or_else(|p| p.into_inner());
    want(*g)
}

fn set(s: Step) {
    *STEP.lock().unwrap_or_else(|p| p.into_inner()) = s;
    CV.notify_all();
}

/// Hold the next unpair notice `device` acts on.
pub fn arm(device: DeviceId) {
    set(Step::Armed(device));
}

/// Wait until the armed device is holding a notice.
pub fn wait_held(timeout: Duration) -> bool {
    wait_for(|s| s == Step::Held, timeout)
}

/// Let the held notice go on; returns once it has been acted on.
pub fn release(timeout: Duration) -> bool {
    set(Step::Open);
    let done = wait_for(|s| s == Step::Passed, timeout);
    set(Step::Idle);
    done
}

/// Called by `me`'s notice handler in the gap; blocks while armed for `me`.
pub(crate) fn hold(me: &DeviceId) {
    {
        let mut g = STEP.lock().unwrap_or_else(|p| p.into_inner());
        if *g != Step::Armed(*me) {
            return;
        }
        *g = Step::Held;
        CV.notify_all();
    }
    let wait = || {
        wait_for(|s| s == Step::Open, Duration::from_secs(30));
    };
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(wait);
    } else {
        wait();
    }
}

/// Called by the handler once the erase step has run.
pub(crate) fn passed() {
    let mut g = STEP.lock().unwrap_or_else(|p| p.into_inner());
    if *g == Step::Open {
        *g = Step::Passed;
        CV.notify_all();
    }
}
