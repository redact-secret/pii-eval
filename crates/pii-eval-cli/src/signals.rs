//! Signal handling for `run` (ADR 0010).
//!
//! Scanners lead their own process group, so a terminal Ctrl-C reaches only this
//! process. The first SIGINT or SIGTERM sets the flag that backs the run's
//! [`CancelToken`]; the executor then kills every scanner process tree, removes
//! its scratch directories and the run exits with status 8 (`cancelled`) without
//! committing anything. A second signal while the first is being handled ends
//! the process at once with status 8: nothing is cleaned in that case, the
//! scanner trees may be left running, scratch directories and writer temporaries
//! (`.pii-eval-tmp.*`) may remain, files already renamed into place may exist
//! without `run-artifact.json` (an incomplete run by definition), and the
//! custodian must contain the run.
//!
//! No first-party `unsafe`: the handlers come from `signal-hook` (flag
//! handlers only; docs/dependency-policy.md).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::exec::CancelToken;
use crate::status::Failure;

/// Status of the immediate exit on a second signal (the `cancelled` status).
const SECOND_SIGNAL_STATUS: i32 = 8;

/// Install the SIGINT, SIGTERM and SIGHUP handlers and return the token they
/// cancel. SIGHUP (a closed terminal or session) is treated like SIGTERM: a run
/// must not outlive its terminal with scanners attached. A handler that cannot
/// be registered fails closed (`signal-handler-unavailable`, exit 6): a run that
/// could not be cancelled is not started.
#[cfg(unix)]
pub fn install() -> Result<CancelToken, Failure> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::flag;

    use crate::status::{Exit, reason};

    let unavailable = |_| Failure::new(Exit::Execution, reason::SIGNAL_HANDLER_UNAVAILABLE);
    let flag_value = Arc::new(AtomicBool::new(false));
    for signal in [SIGINT, SIGTERM, SIGHUP] {
        // Order matters: the conditional shutdown fires only when the flag is
        // already set, i.e. on the second signal; registering the flag setter
        // second keeps the first signal graceful.
        flag::register_conditional_shutdown(signal, SECOND_SIGNAL_STATUS, Arc::clone(&flag_value))
            .map_err(unavailable)?;
        flag::register(signal, Arc::clone(&flag_value)).map_err(unavailable)?;
    }
    Ok(CancelToken::from_flag(flag_value))
}

/// Windows: scanner execution is refused, so there is nothing to cancel.
#[cfg(not(unix))]
pub fn install() -> Result<CancelToken, Failure> {
    let _ = SECOND_SIGNAL_STATUS;
    Ok(CancelToken::from_flag(Arc::new(AtomicBool::new(false))))
}
