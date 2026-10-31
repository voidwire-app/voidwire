//! Test seam (test-util only): hold one device at a named point so another
//! step can land in that gap. [`Point::Notice`]: an unpair notice between its
//! pairing check and the erase (S27). [`Point::Keep`]: the phone keeping a new
//! pairing, just after its save (S33).

use crate::ids::DeviceId;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Where a device can be held.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Point {
    Notice,
    Keep,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Idle,
    Armed(Point, DeviceId),
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
    arm_at(Point::Notice, device);
}

/// Hold `device` the next time it reaches `point`.
pub fn arm_at(point: Point, device: DeviceId) {
    set(Step::Armed(point, device));
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
    hold_at(Point::Notice, me);
}

/// Called by `me` at `point`; blocks while armed for that point and `me`.
pub(crate) fn hold_at(point: Point, me: &DeviceId) {
    {
        let mut g = STEP.lock().unwrap_or_else(|p| p.into_inner());
        if *g != Step::Armed(point, *me) {
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
