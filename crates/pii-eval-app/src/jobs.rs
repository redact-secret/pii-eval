//! Job state machine and the bounded job store.
//!
//! A job is identified by its [`JobId`], derived from the immutable commit,
//! profile and pinned identities. The store gives idempotent admission:
//! the same identity requested again is coalesced, an already published result
//! stands, and a failed or stale job may be retried up to a limit.
//!
//! ```text
//! Queued -> Running -> Completed            (result published)
//!                   -> Failed(reason)       (retryable)
//!                   -> Stale                (head moved; retryable)
//!                   -> RoutedToCustodian    (protected profile; terminal)
//! Failed | Stale -> Queued                  (retry, attempts + 1)
//! ```

use std::collections::{BTreeMap, HashMap};

use crate::checks::{CheckReport, CheckRunId};
use crate::request::{EvaluationRequest, JobId, JobIdentity};

/// Why a job failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailReason {
    /// The runner refused.
    RunnerRefused,
    /// Time limit.
    Timeout,
    /// Cancelled.
    Cancelled,
    /// The run or its output was not acceptable.
    RunFailed,
    /// The result did not match the profile's pinned identity.
    IdentityMismatch,
    /// Posting the Check failed (the sanitized result is kept for a retry).
    PublishFailed,
    /// The current head could not be determined.
    HeadUnverifiable,
    /// The custodian did not accept the submission.
    CustodianUnavailable,
    /// Unexpected error or panic.
    Internal,
}

impl FailReason {
    /// Stable code.
    pub const fn code(self) -> &'static str {
        match self {
            FailReason::RunnerRefused => "runner-refused",
            FailReason::Timeout => "timeout",
            FailReason::Cancelled => "cancelled",
            FailReason::RunFailed => "run-failed",
            FailReason::IdentityMismatch => "identity-mismatch",
            FailReason::PublishFailed => "publish-failed",
            FailReason::HeadUnverifiable => "head-unverifiable",
            FailReason::CustodianUnavailable => "custodian-unavailable",
            FailReason::Internal => "internal-error",
        }
    }
}

/// Job state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    /// Waiting in the queue.
    Queued,
    /// A worker is on it.
    Running,
    /// The sanitized result was published.
    Completed,
    /// Failed; may be retried.
    Failed(FailReason),
    /// The head moved; no result was published as current.
    Stale,
    /// Handed to the custodian (terminal; the custodian owns what follows).
    RoutedToCustodian,
}

impl JobState {
    /// Stable name.
    pub const fn name(self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Running => "running",
            JobState::Completed => "completed",
            JobState::Failed(_) => "failed",
            JobState::Stale => "stale",
            JobState::RoutedToCustodian => "routed-to-custodian",
        }
    }

    /// Whether no worker will touch the job again unless it is retried.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, JobState::Queued | JobState::Running)
    }

    /// Whether the state machine allows `self -> next`.
    pub fn can_become(self, next: JobState) -> bool {
        use JobState::*;
        matches!(
            (self, next),
            (Queued, Running)
                | (Running, Completed)
                | (Running, Failed(_))
                | (Running, Stale)
                | (Running, RoutedToCustodian)
                | (Failed(_), Queued)
                | (Stale, Queued)
        )
    }
}

/// A sanitized result that has not been published yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingResult {
    /// What to publish.
    pub report: CheckReport,
    /// The failure the job ends in once published (`None`: completed).
    pub fail: Option<FailReason>,
}

/// One job.
#[derive(Clone, Debug)]
pub struct Job {
    /// Deterministic id.
    pub id: JobId,
    /// Immutable identity.
    pub identity: JobIdentity,
    /// The request that created it (later identical requests are coalesced).
    pub request: EvaluationRequest,
    /// State.
    pub state: JobState,
    /// Runs started so far.
    pub attempts: u32,
    /// The Check, once found or created.
    pub check_run_id: Option<CheckRunId>,
    /// The sanitized result awaiting publication (kept across a publish failure
    /// so a retry publishes it without running again).
    pub pending: Option<PendingResult>,
    /// Requests folded into this job.
    pub coalesced: u32,
    seq: u64,
}

/// The state change was not allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionError;

impl Job {
    /// Move to `next` if the state machine allows it.
    pub fn transition(&mut self, next: JobState) -> Result<(), TransitionError> {
        if self.state.can_become(next) {
            self.state = next;
            Ok(())
        } else {
            Err(TransitionError)
        }
    }
}

/// What admission did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// A new job; the caller must enqueue it (or call [`JobStore::rollback_new`]).
    New,
    /// A retry of a failed or stale job; the caller must enqueue it (or call
    /// [`JobStore::rollback_requeue`] with the previous state).
    Requeued {
        /// State before the retry.
        previous: JobState,
    },
    /// Queued or running already.
    Coalesced,
    /// Completed already.
    AlreadyComplete,
    /// Routed to the custodian already.
    AlreadyRouted,
    /// A failed or stale job that has used all its attempts.
    RetryLimit,
    /// No room: every stored job is in flight.
    Full,
}

/// Bounded job store.
#[derive(Debug)]
pub struct JobStore {
    capacity: usize,
    max_attempts: u32,
    next_seq: u64,
    jobs: HashMap<JobId, Job>,
    by_seq: BTreeMap<u64, JobId>,
}

impl JobStore {
    /// An empty store.
    pub fn new(capacity: usize, max_attempts: u32) -> Self {
        Self {
            capacity: capacity.max(1),
            max_attempts: max_attempts.max(1),
            next_seq: 0,
            jobs: HashMap::new(),
            by_seq: BTreeMap::new(),
        }
    }

    /// Admit a request for `identity`.
    pub fn admit(&mut self, identity: &JobIdentity, request: &EvaluationRequest) -> Admission {
        let id = JobId::derive(identity);
        if let Some(job) = self.jobs.get_mut(&id) {
            return match job.state {
                JobState::Queued | JobState::Running => {
                    job.coalesced = job.coalesced.saturating_add(1);
                    Admission::Coalesced
                }
                JobState::Completed => Admission::AlreadyComplete,
                JobState::RoutedToCustodian => Admission::AlreadyRouted,
                JobState::Failed(_) | JobState::Stale => {
                    if job.attempts >= self.max_attempts {
                        Admission::RetryLimit
                    } else {
                        let previous = job.state;
                        job.state = JobState::Queued;
                        job.request = request.clone();
                        Admission::Requeued { previous }
                    }
                }
            };
        }
        if self.jobs.len() >= self.capacity && !self.evict_oldest_terminal() {
            return Admission::Full;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.by_seq.insert(seq, id.clone());
        self.jobs.insert(
            id.clone(),
            Job {
                id,
                identity: identity.clone(),
                request: request.clone(),
                state: JobState::Queued,
                attempts: 0,
                check_run_id: None,
                pending: None,
                coalesced: 0,
                seq,
            },
        );
        Admission::New
    }

    fn evict_oldest_terminal(&mut self) -> bool {
        let victim = self
            .by_seq
            .iter()
            .find(|(_, id)| self.jobs.get(*id).is_some_and(|j| j.state.is_terminal()))
            .map(|(seq, id)| (*seq, id.clone()));
        match victim {
            Some((seq, id)) => {
                self.by_seq.remove(&seq);
                self.jobs.remove(&id);
                true
            }
            None => false,
        }
    }

    /// Undo [`Admission::New`] when the queue refused the job.
    pub fn rollback_new(&mut self, id: &JobId) {
        if let Some(job) = self.jobs.remove(id) {
            self.by_seq.remove(&job.seq);
        }
    }

    /// Undo [`Admission::Requeued`] when the queue refused the job.
    pub fn rollback_requeue(&mut self, id: &JobId, previous: JobState) {
        if let Some(job) = self.jobs.get_mut(id) {
            job.state = previous;
        }
    }

    /// A job.
    pub fn get(&self, id: &JobId) -> Option<&Job> {
        self.jobs.get(id)
    }

    /// A job, mutable.
    pub fn get_mut(&mut self, id: &JobId) -> Option<&mut Job> {
        self.jobs.get_mut(id)
    }

    /// Start a queued job: `Queued -> Running`, attempts + 1. A snapshot is
    /// returned; `None` if the job is missing or not queued.
    pub fn start(&mut self, id: &JobId) -> Option<Job> {
        let job = self.jobs.get_mut(id)?;
        job.transition(JobState::Running).ok()?;
        job.attempts = job.attempts.saturating_add(1);
        Some(job.clone())
    }

    /// Stored jobs.
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{CommitSha, EventKind, ProfileClass, Subject};

    fn identity(n: u64) -> JobIdentity {
        JobIdentity {
            repository_id: n,
            commit: CommitSha::parse(&"a".repeat(40)).unwrap(),
            profile_id: "p".into(),
            engine_version: "0.0.0".into(),
            protocol_revision: 2,
            config_digest: "1".repeat(64),
            population_digest: "2".repeat(64),
            class: ProfileClass::PublicSynthetic,
        }
    }

    fn request(n: u64) -> EvaluationRequest {
        EvaluationRequest {
            installation_id: 1,
            repository_id: n,
            repository_name: "o/r".into(),
            commit: CommitSha::parse(&"a".repeat(40)).unwrap(),
            subject: Subject::PullRequest(1),
            profile_id: "p".into(),
            requester_id: 5,
            delivery_id: "d".into(),
            event: EventKind::IssueComment,
        }
    }

    #[test]
    fn the_state_machine_allows_only_the_documented_edges() {
        use FailReason::*;
        use JobState::*;
        let states = [
            Queued,
            Running,
            Completed,
            Failed(Timeout),
            Stale,
            RoutedToCustodian,
        ];
        let allowed = [
            (Queued, Running),
            (Running, Completed),
            (Running, Failed(Timeout)),
            (Running, Stale),
            (Running, RoutedToCustodian),
            (Failed(Timeout), Queued),
            (Stale, Queued),
        ];
        for a in states {
            for b in states {
                let expected = allowed.iter().any(|(x, y)| {
                    std::mem::discriminant(x) == std::mem::discriminant(&a)
                        && std::mem::discriminant(y) == std::mem::discriminant(&b)
                });
                assert_eq!(a.can_become(b), expected, "{a:?} -> {b:?}");
            }
        }
    }

    #[test]
    fn admission_is_idempotent_and_retries_are_bounded() {
        let mut s = JobStore::new(10, 2);
        let (i, r) = (identity(1), request(1));
        let id = JobId::derive(&i);
        assert_eq!(s.admit(&i, &r), Admission::New);
        assert_eq!(s.admit(&i, &r), Admission::Coalesced);
        assert_eq!(s.get(&id).unwrap().coalesced, 1);
        s.start(&id).unwrap();
        assert_eq!(s.admit(&i, &r), Admission::Coalesced, "running");
        s.get_mut(&id)
            .unwrap()
            .transition(JobState::Failed(FailReason::Timeout))
            .unwrap();
        assert!(matches!(s.admit(&i, &r), Admission::Requeued { .. }));
        s.start(&id).unwrap();
        s.get_mut(&id)
            .unwrap()
            .transition(JobState::Failed(FailReason::Timeout))
            .unwrap();
        assert_eq!(s.admit(&i, &r), Admission::RetryLimit, "two attempts used");
    }

    #[test]
    fn completed_and_routed_jobs_are_not_rerun() {
        let mut s = JobStore::new(10, 3);
        let (i, r) = (identity(1), request(1));
        let id = JobId::derive(&i);
        s.admit(&i, &r);
        s.start(&id).unwrap();
        s.get_mut(&id)
            .unwrap()
            .transition(JobState::Completed)
            .unwrap();
        assert_eq!(s.admit(&i, &r), Admission::AlreadyComplete);
        let (i2, r2) = (identity(2), request(2));
        let id2 = JobId::derive(&i2);
        s.admit(&i2, &r2);
        s.start(&id2).unwrap();
        s.get_mut(&id2)
            .unwrap()
            .transition(JobState::RoutedToCustodian)
            .unwrap();
        assert_eq!(s.admit(&i2, &r2), Admission::AlreadyRouted);
    }

    #[test]
    fn the_store_is_bounded_and_evicts_only_terminal_jobs() {
        let mut s = JobStore::new(2, 3);
        let ids: Vec<JobId> = (1..=3).map(|n| JobId::derive(&identity(n))).collect();
        assert_eq!(s.admit(&identity(1), &request(1)), Admission::New);
        assert_eq!(s.admit(&identity(2), &request(2)), Admission::New);
        assert_eq!(
            s.admit(&identity(3), &request(3)),
            Admission::Full,
            "both stored jobs are in flight"
        );
        s.start(&ids[0]).unwrap();
        s.get_mut(&ids[0])
            .unwrap()
            .transition(JobState::Completed)
            .unwrap();
        assert_eq!(s.admit(&identity(3), &request(3)), Admission::New);
        assert!(s.get(&ids[0]).is_none(), "oldest terminal job evicted");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn rollbacks_restore_the_previous_state() {
        let mut s = JobStore::new(4, 3);
        let (i, r) = (identity(1), request(1));
        let id = JobId::derive(&i);
        assert_eq!(s.admit(&i, &r), Admission::New);
        s.rollback_new(&id);
        assert!(s.is_empty());
        s.admit(&i, &r);
        s.start(&id).unwrap();
        s.get_mut(&id).unwrap().transition(JobState::Stale).unwrap();
        let Admission::Requeued { previous } = s.admit(&i, &r) else {
            panic!("requeued")
        };
        s.rollback_requeue(&id, previous);
        assert_eq!(s.get(&id).unwrap().state, JobState::Stale);
    }
}
