//! The service's boundaries to the outside world, as traits.
//!
//! The core never imports an HTTP client or a GitHub type. A deployment
//! supplies a [`ChecksApi`] and a [`HeadResolver`] backed by the GitHub REST
//! API (not implemented in this repository, ADR 0011 D3), a [`JobRunner`]
//! (the CLI library runner in [`crate::cli_runner`]) and, for protected
//! profiles, a [`CustodianRouter`]. No credential type appears in any
//! signature: a transport mints installation tokens itself, so a runner, a
//! worker or a job specification cannot receive one.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::checks::{CheckRunCreate, CheckRunId, CheckRunUpdate, RunnerOutcome};
use crate::request::{CommitSha, JobId, JobIdentity, Subject};

/// A transport or upstream failure. Fixed variants, no message: an upstream
/// error body could contain anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// Network or upstream failure; retrying may succeed.
    Unavailable,
    /// The installation lacks permission or the object is gone.
    Denied,
}

/// Time source (seconds since the Unix epoch).
pub trait Clock: Send + Sync {
    /// Now.
    fn now_secs(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// The current head of a subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadInfo {
    /// The head commit.
    pub sha: CommitSha,
    /// The repository that holds that commit (differs from the base repository
    /// for a pull request from a fork).
    pub head_repository_id: u64,
}

/// Resolve the current head of a pull request or branch. Called at admission
/// and again before and after a run, so a result for a commit that is no
/// longer the head is never published as current.
pub trait HeadResolver: Send + Sync {
    /// The head now.
    fn resolve(&self, repository_id: u64, subject: &Subject) -> Result<HeadInfo, PortError>;
}

/// The minimal GitHub Checks surface.
pub trait ChecksApi: Send + Sync {
    /// Find a run on `head_sha` whose `external_id` is `external_id` (so a retry
    /// after an unknown outcome does not create a duplicate).
    fn find(
        &self,
        installation_id: u64,
        repository_id: u64,
        head_sha: &CommitSha,
        external_id: &JobId,
    ) -> Result<Option<CheckRunId>, PortError>;
    /// Create a run.
    fn create(&self, request: &CheckRunCreate) -> Result<CheckRunId, PortError>;
    /// Update a run.
    fn update(&self, request: &CheckRunUpdate) -> Result<(), PortError>;
}

/// A cooperative cancellation flag shared with a running job.
#[derive(Clone, Debug, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
    /// A flag that is not set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set it.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether it is set.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What a runner is told about a job: identities only. There is no repository
/// content, no token, no secret and no free text here.
#[derive(Clone, Debug)]
pub struct JobSpec {
    /// The job.
    pub job_id: JobId,
    /// What is measured (profile, pins, class).
    pub identity: JobIdentity,
    /// Attempt number, starting at 1.
    pub attempt: u32,
}

/// Why a runner produced no outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerError {
    /// Unknown profile or an unusable host.
    Refused,
    /// The pinned configuration is not the one the profile names.
    ProfileChanged,
    /// The time limit was exceeded.
    Timeout,
    /// Cancelled.
    Cancelled,
    /// The runner's own output failed the projection.
    SummaryRejected,
    /// Anything else.
    Internal,
}

/// Executes a public/synthetic job with pinned inputs and returns a validated
/// outcome. Implementations must enforce the time limit and kill what they
/// started when `cancel` is set or the limit passes.
pub trait JobRunner: Send + Sync {
    /// Run one job.
    fn run(&self, spec: &JobSpec, cancel: &CancelFlag) -> Result<RunnerOutcome, RunnerError>;
}

/// A protected job handed to private-custodian. It carries identities only: this
/// repository never authorizes a protected run, holds no protected input and
/// learns no result.
#[derive(Clone, Debug)]
pub struct CustodianSubmission {
    /// The job.
    pub job_id: JobId,
    /// What is requested.
    pub identity: JobIdentity,
    /// Requesting user id (for the custodian's own authorization).
    pub requester_id: u64,
}

/// The seam to private-custodian. Acceptance of a submission is not an
/// approval; the custodian decides.
pub trait CustodianRouter: Send + Sync {
    /// Submit a request for the custodian to evaluate.
    fn submit(&self, submission: &CustodianSubmission) -> Result<(), PortError>;
}

/// A router for deployments without a custodian: every submission fails, so a
/// protected profile can never run.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCustodian;

impl CustodianRouter for NoCustodian {
    fn submit(&self, _: &CustodianSubmission) -> Result<(), PortError> {
        Err(PortError::Unavailable)
    }
}
