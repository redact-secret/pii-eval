//! `pii-eval worker-job --job FILE` (docs/worker-job.md): the production entry.
//! It always uses [`Adapters::production`] and the production policy, so the
//! binary cannot be told to use a test adapter.

use std::path::Path;

use crate::args::WorkerJobArgs;
use crate::exec::CancelToken;
use crate::status::Failure;
use crate::worker::contract::{AdapterPolicy, Adapters};
use crate::worker::launch::{WorkerOutput, WorkerRequest, run_worker_job};

/// Execute `worker-job`. `cancel` installs the signal handlers; it runs only
/// after the adapter check, so a refusal because the contract is not final has
/// no side effect at all.
pub fn worker_job(
    args: &WorkerJobArgs,
    cancel: impl FnOnce() -> Result<CancelToken, Failure>,
) -> Result<WorkerOutput, Failure> {
    let adapters = Adapters::production();
    adapters.resolve(AdapterPolicy::Production)?;
    let token = cancel()?;
    run_worker_job(
        &WorkerRequest {
            job: Path::new(&args.job),
            adapters: &adapters,
            policy: AdapterPolicy::Production,
        },
        &token,
    )
}
