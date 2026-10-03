//! Signal handling for `run` (ADR 0010).
//!
//! Scanners lead their own process group, so a terminal Ctrl-C reaches only this
//! process. The first SIGINT or SIGTERM sets the flag that backs the run's
//! [`CancelToken`]; the executor then kills every scanner process tree, removes
//! its scratch directories and the run exits with status 8 (`cancelled`) without
//! committing anything. A second signal while the first is being handled ends
//! the process at once with status 8: nothing is cleaned in that case, the
//! scanner trees may be left running, and the custodian must contain the run.
//!
//! No first-party `unsafe`: the handlers come from `signal-hook` (flag
//! handlers only; docs/dependency-policy.md).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::exec::CancelToken;

/// Status of the immediate exit on a second signal (the `cancelled` status).
const SECOND_SIGNAL_STATUS: i32 = 8;

/// Install the SIGINT and SIGTERM handlers and return the token they cancel.
#[cfg(unix)]
pub fn install() -> CancelToken {
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::flag;

    let flag_value = Arc::new(AtomicBool::new(false));
    for signal in [SIGINT, SIGTERM] {
        // Order matters: the conditional shutdown fires only when the flag is
        // already set, i.e. on the second signal; registering the flag setter
        // second keeps the first signal graceful.
        let _ = flag::register_conditional_shutdown(
            signal,
            SECOND_SIGNAL_STATUS,
            Arc::clone(&flag_value),
        );
        let _ = flag::register(signal, Arc::clone(&flag_value));
    }
    CancelToken::from_flag(flag_value)
}

/// Windows: scanner execution is refused, so there is nothing to cancel.
#[cfg(not(unix))]
pub fn install() -> CancelToken {
    let _ = SECOND_SIGNAL_STATUS;
    CancelToken::from_flag(Arc::new(AtomicBool::new(false)))
}
