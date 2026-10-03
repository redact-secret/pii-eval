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
    /// When the job last reached a terminal state (clock seconds); the retry
    /// cooldown counts from here.
    pub last_terminal_at: u64,
    /// A conclusion (stale, internal error) that could not be written to the
    /// Check yet; the reconciliation tick retries it so a Check is not left
    /// "running" forever.
    pub unconcluded: Option<PendingResult>,
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
    /// A failed or stale job that ended too recently to be retried.
    Cooldown,
    /// No room: every stored job is in flight.
    Full,
}

/// Bounded job store.
#[derive(Debug)]
pub struct JobStore {
    capacity: usize,
    max_attempts: u32,
    cooldown_secs: u64,
    next_seq: u64,
    jobs: HashMap<JobId, Job>,
    by_seq: BTreeMap<u64, JobId>,
    /// Attempts and end time of evicted failed or stale jobs, so that eviction
    /// cannot reset `max_attempts` or the cooldown. Bounded at four times the
    /// job capacity (oldest dropped first): the retry limit is therefore exact
    /// for as long as an identity is among the most recent `4 * capacity`
    /// failed or stale identities, and approximate beyond that.
    tombstones: HashMap<JobId, (u32, u64)>,
    tomb_order: BTreeMap<u64, JobId>,
    tomb_seq: u64,
}

impl JobStore {
    /// An empty store.
    pub fn new(capacity: usize, max_attempts: u32, cooldown_secs: u64) -> Self {
        Self {
            capacity: capacity.max(1),
            max_attempts: max_attempts.max(1),
            cooldown_secs,
            next_seq: 0,
            jobs: HashMap::new(),
            by_seq: BTreeMap::new(),
            tombstones: HashMap::new(),
            tomb_order: BTreeMap::new(),
            tomb_seq: 0,
        }
    }

    /// Admit a request for `identity` at clock time `now`.
    pub fn admit(
        &mut self,
        identity: &JobIdentity,
        request: &EvaluationRequest,
        now: u64,
    ) -> Admission {
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
                    } else if now < job.last_terminal_at.saturating_add(self.cooldown_secs) {
                        Admission::Cooldown
                    } else {
                        let previous = job.state;
                        job.state = JobState::Queued;
                        job.request = request.clone();
                        Admission::Requeued { previous }
                    }
                }
            };
        }
        let carried = self.tombstones.get(&id).copied();
        if let Some((attempts, ended)) = carried {
            if attempts >= self.max_attempts {
                return Admission::RetryLimit;
            }
            if now < ended.saturating_add(self.cooldown_secs) {
                return Admission::Cooldown;
            }
        }
        if self.jobs.len() >= self.capacity && !self.evict_oldest_terminal() {
            return Admission::Full;
        }
        if carried.is_some() {
            self.tombstones.remove(&id);
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
                attempts: carried.map_or(0, |c| c.0),
                check_run_id: None,
                pending: None,
                coalesced: 0,
                last_terminal_at: 0,
                unconcluded: None,
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
                if let Some(job) = self.jobs.remove(&id) {
                    if matches!(job.state, JobState::Failed(_) | JobState::Stale) {
                        self.remember(id, job.attempts, job.last_terminal_at);
                    }
                }
                true
            }
            None => false,
        }
    }

    fn remember(&mut self, id: JobId, attempts: u32, ended: u64) {
        let limit = self.capacity.saturating_mul(4);
        let seq = self.tomb_seq;
        self.tomb_seq += 1;
        self.tombstones.insert(id.clone(), (attempts, ended));
        self.tomb_order.insert(seq, id);
        while self.tomb_order.len() > limit {
            if let Some((_, old)) = self.tomb_order.pop_first() {
                self.tombstones.remove(&old);
            }
        }
    }

    /// Jobs with a result or conclusion that still has to be written to its
    /// Check: an `unconcluded` conclusion, or a `publish-failed` job holding its
    /// sanitized result. At most `limit`.
    pub fn awaiting_check_update(&self, limit: usize) -> Vec<Job> {
        let mut jobs: Vec<&Job> = self
            .jobs
            .values()
            .filter(|j| {
                j.unconcluded.is_some()
                    || (j.state == JobState::Failed(FailReason::PublishFailed)
                        && j.pending.is_some())
            })
            .collect();
        jobs.sort_by_key(|j| j.seq);
        jobs.into_iter().take(limit).cloned().collect()
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
        let mut s = JobStore::new(10, 2, 0);
        let (i, r) = (identity(1), request(1));
        let id = JobId::derive(&i);
        assert_eq!(s.admit(&i, &r, 0), Admission::New);
        assert_eq!(s.admit(&i, &r, 0), Admission::Coalesced);
        assert_eq!(s.get(&id).unwrap().coalesced, 1);
        s.start(&id).unwrap();
        assert_eq!(s.admit(&i, &r, 0), Admission::Coalesced, "running");
        s.get_mut(&id)
            .unwrap()
            .transition(JobState::Failed(FailReason::Timeout))
            .unwrap();
        assert!(matches!(s.admit(&i, &r, 0), Admission::Requeued { .. }));
        s.start(&id).unwrap();
        s.get_mut(&id)
            .unwrap()
            .transition(JobState::Failed(FailReason::Timeout))
            .unwrap();
        assert_eq!(
            s.admit(&i, &r, 0),
            Admission::RetryLimit,
            "two attempts used"
        );
    }

    #[test]
    fn completed_and_routed_jobs_are_not_rerun() {
        let mut s = JobStore::new(10, 3, 0);
        let (i, r) = (identity(1), request(1));
        let id = JobId::derive(&i);
        s.admit(&i, &r, 0);
        s.start(&id).unwrap();
        s.get_mut(&id)
            .unwrap()
            .transition(JobState::Completed)
            .unwrap();
        assert_eq!(s.admit(&i, &r, 0), Admission::AlreadyComplete);
        let (i2, r2) = (identity(2), request(2));
        let id2 = JobId::derive(&i2);
        s.admit(&i2, &r2, 0);
        s.start(&id2).unwrap();
        s.get_mut(&id2)
            .unwrap()
            .transition(JobState::RoutedToCustodian)
            .unwrap();
        assert_eq!(s.admit(&i2, &r2, 0), Admission::AlreadyRouted);
    }

    #[test]
    fn the_store_is_bounded_and_evicts_only_terminal_jobs() {
        let mut s = JobStore::new(2, 3, 0);
        let ids: Vec<JobId> = (1..=3).map(|n| JobId::derive(&identity(n))).collect();
        assert_eq!(s.admit(&identity(1), &request(1), 0), Admission::New);
        assert_eq!(s.admit(&identity(2), &request(2), 0), Admission::New);
        assert_eq!(
            s.admit(&identity(3), &request(3), 0),
            Admission::Full,
            "both stored jobs are in flight"
        );
        s.start(&ids[0]).unwrap();
        s.get_mut(&ids[0])
            .unwrap()
            .transition(JobState::Completed)
            .unwrap();
        assert_eq!(s.admit(&identity(3), &request(3), 0), Admission::New);
        assert!(s.get(&ids[0]).is_none(), "oldest terminal job evicted");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn eviction_does_not_reset_attempts_and_the_cooldown_applies() {
        let mut s = JobStore::new(1, 3, 100);
        let (i1, r1) = (identity(1), request(1));
        let id1 = JobId::derive(&i1);
        assert_eq!(s.admit(&i1, &r1, 0), Admission::New);
        s.start(&id1).unwrap();
        {
            let j = s.get_mut(&id1).unwrap();
            j.transition(JobState::Failed(FailReason::Timeout)).unwrap();
            j.last_terminal_at = 10;
        }
        assert_eq!(s.admit(&i1, &r1, 50), Admission::Cooldown);
        // Another identity evicts the failed job (capacity 1).
        let (i2, r2) = (identity(2), request(2));
        assert_eq!(s.admit(&i2, &r2, 50), Admission::New);
        assert!(s.get(&id1).is_none());
        // Its attempts and end time survive in the tombstone.
        s.start(&JobId::derive(&i2)).unwrap();
        s.get_mut(&JobId::derive(&i2))
            .unwrap()
            .transition(JobState::Completed)
            .unwrap();
        assert_eq!(s.admit(&i1, &r1, 50), Admission::Cooldown);
        assert_eq!(s.admit(&i1, &r1, 110), Admission::New);
        assert_eq!(s.get(&id1).unwrap().attempts, 1, "attempts carried over");
    }

    #[test]
    fn rollbacks_restore_the_previous_state() {
        let mut s = JobStore::new(4, 3, 0);
        let (i, r) = (identity(1), request(1));
        let id = JobId::derive(&i);
        assert_eq!(s.admit(&i, &r, 0), Admission::New);
        s.rollback_new(&id);
        assert!(s.is_empty());
        s.admit(&i, &r, 0);
        s.start(&id).unwrap();
        s.get_mut(&id).unwrap().transition(JobState::Stale).unwrap();
        let Admission::Requeued { previous } = s.admit(&i, &r, 0) else {
            panic!("requeued")
        };
        s.rollback_requeue(&id, previous);
        assert_eq!(s.get(&id).unwrap().state, JobState::Stale);
    }
}
