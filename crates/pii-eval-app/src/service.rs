//! The GitHub-independent service: delivery handling, admission, the bounded
//! queue, limited workers and Check publication (ADR 0011).
//!
//! `App::handle_delivery` is what an HTTP adapter calls with the raw request.
//! It authenticates, deduplicates, parses, authorizes, resolves the head and
//! enqueues, and returns; it never runs a job and never calls the runner. Jobs
//! run on the worker threads of [`WorkerPool`], which are the only callers of
//! the runner, the custodian router and the Checks API.

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use crate::checks::{
    CHECK_NAME, CheckReport, CheckRunCreate, CheckRunId, CheckRunUpdate, CheckStatus, FailureKind,
    ReportContext, RunnerOutcome, report_failure, report_measured, report_stale, report_started,
};
use crate::dedupe::{Begin, DeliveryStore};
use crate::jobs::{Admission, FailReason, Job, JobState, JobStore, PendingResult};
use crate::policy::{AppPolicy, PolicyError, Profile, RepositoryPolicy};
use crate::ports::{
    CancelFlag, ChecksApi, Clock, CustodianRouter, CustodianSubmission, HeadResolver, JobRunner,
    JobSpec, RunnerError,
};
use crate::queue::{JobQueue, PushError};
use crate::reason::{Decision, Disposition, Meta, Outcome, Reason};
use crate::request::{CommandParse, EvaluationRequest, JobId, JobIdentity, ProfileClass, Subject};
use crate::secret::Secret;
use crate::webhook::{
    EventClass, Parsed, ParsedEvent, RawDelivery, Trigger, classify_event, parse_payload,
    valid_delivery_id, verify_signature,
};

/// The collaborators of the service.
#[derive(Clone)]
pub struct Services {
    /// Head lookup.
    pub heads: Arc<dyn HeadResolver>,
    /// Checks API.
    pub checks: Arc<dyn ChecksApi>,
    /// Public/synthetic job runner.
    pub runner: Arc<dyn JobRunner>,
    /// Protected job router.
    pub custodian: Arc<dyn CustodianRouter>,
    /// Time.
    pub clock: Arc<dyn Clock>,
}

struct Inner {
    policy: AppPolicy,
    secret: Secret,
    services: Services,
    deliveries: Mutex<DeliveryStore>,
    jobs: Mutex<JobStore>,
    queue: JobQueue,
    cancel: CancelFlag,
    workers_started: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The service.
#[derive(Clone)]
pub struct App {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App").finish_non_exhaustive()
    }
}

impl App {
    /// Build the service. The policy is validated; the secret is moved in and
    /// stays inside (it is used only by the signature check).
    pub fn new(
        policy: AppPolicy,
        webhook_secret: Secret,
        services: Services,
    ) -> Result<Self, PolicyError> {
        policy.validate()?;
        let l = &policy.limits;
        let inner = Inner {
            deliveries: Mutex::new(DeliveryStore::new(
                l.delivery_capacity,
                l.delivery_ttl.as_secs(),
            )),
            jobs: Mutex::new(JobStore::new(l.job_capacity, l.max_attempts)),
            queue: JobQueue::new(l.queue_capacity),
            cancel: CancelFlag::new(),
            workers_started: AtomicBool::new(false),
            policy,
            secret: webhook_secret,
            services,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Handle one webhook delivery. Cheap and non-blocking apart from the head
    /// lookup of the [`HeadResolver`]; never executes a job.
    pub fn handle_delivery(&self, raw: &RawDelivery<'_>) -> Decision {
        let mut meta = Meta::default();
        let mut begun = false;
        let outcome = self.inner.decide(raw, &mut meta, &mut begun);
        if let Outcome::Rejected(r) = &outcome {
            // A transient failure must not consume the delivery id, so that
            // GitHub's redelivery (same id) is processed.
            if begun && r.is_transient() {
                if let Some(id) = &meta.delivery_id {
                    lock(&self.inner.deliveries).forget(id);
                }
            }
        }
        Decision { outcome, meta }
    }

    /// Start the worker threads (once). Each runs one job at a time, so at most
    /// `limits.workers` jobs run concurrently.
    pub fn start_workers(&self) -> io::Result<WorkerPool> {
        if self.inner.workers_started.swap(true, Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "workers already started",
            ));
        }
        let mut handles = Vec::new();
        for n in 0..self.inner.policy.limits.workers {
            let inner = Arc::clone(&self.inner);
            let spawned = std::thread::Builder::new()
                .name(format!("pii-eval-app-worker-{n}"))
                .spawn(move || {
                    while let Some(id) = inner.queue.pop_blocking() {
                        inner.process(&id);
                    }
                });
            match spawned {
                Ok(h) => handles.push(h),
                Err(e) => {
                    self.inner.shutdown();
                    for h in handles {
                        let _ = h.join();
                    }
                    return Err(e);
                }
            }
        }
        Ok(WorkerPool {
            inner: Arc::clone(&self.inner),
            handles,
        })
    }

    /// A snapshot of a job.
    pub fn job(&self, id: &JobId) -> Option<Job> {
        lock(&self.inner.jobs).get(id).cloned()
    }

    /// A job's state.
    pub fn job_state(&self, id: &JobId) -> Option<JobState> {
        lock(&self.inner.jobs).get(id).map(|j| j.state)
    }

    /// Pending (queued, not yet started) jobs.
    pub fn queue_len(&self) -> usize {
        self.inner.queue.len()
    }

    /// Cancel running jobs and stop accepting work. Pending jobs are dropped:
    /// state is in memory, a restart forgets it, and a later request or GitHub
    /// redelivery re-admits the work.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

/// The worker threads. Dropping the pool shuts the service down and joins them.
pub struct WorkerPool {
    inner: Arc<Inner>,
    handles: Vec<JoinHandle<()>>,
}

impl WorkerPool {
    /// Number of worker threads.
    pub fn size(&self) -> usize {
        self.handles.len()
    }

    /// Cancel running jobs, drop pending ones and join every worker.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.inner.shutdown();
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Inner {
    fn shutdown(&self) {
        self.cancel.cancel();
        self.queue.close();
    }

    fn decide(&self, raw: &RawDelivery<'_>, meta: &mut Meta, begun: &mut bool) -> Outcome {
        // 1. Size, then authenticity, before anything is parsed.
        if raw.body.len() > self.policy.limits.max_body_bytes {
            return Outcome::Rejected(Reason::PayloadTooLarge);
        }
        if let Err(r) = verify_signature(&self.secret, raw.signature, raw.body) {
            return Outcome::Rejected(r);
        }
        // 2. Authentic from here: headers, replay.
        let Some(delivery_id) = raw.delivery_id.filter(|d| valid_delivery_id(d)) else {
            return Outcome::Rejected(Reason::DeliveryIdInvalid);
        };
        meta.delivery_id = Some(delivery_id.to_owned());
        let class = match classify_event(raw.event) {
            Ok(c) => c,
            Err(r) => return Outcome::Rejected(r),
        };
        let now = self.services.clock.now_secs();
        if lock(&self.deliveries).begin(delivery_id, now) == Begin::Duplicate {
            return Outcome::Rejected(Reason::DuplicateDelivery);
        }
        *begun = true;
        let EventClass::Approved(kind) = class else {
            return Outcome::Ignored(Reason::EventNotApproved);
        };
        // 3. Strict typed parsing.
        let event = match parse_payload(kind, raw.body) {
            Ok(Parsed::Event(e)) => *e,
            Ok(Parsed::Ignored(r)) => return Outcome::Ignored(r),
            Err(r) => return Outcome::Rejected(r),
        };
        meta.installation_id = Some(event.installation_id);
        meta.repository_id = Some(event.repository_id);
        // 4. Authorization against the allowlist, by numeric id.
        let repo = match self.authorize(&event) {
            Ok(r) => r,
            Err(r) => return Outcome::Rejected(r),
        };
        // 5. Request, head, admission.
        let (request, profile) = match self.build_request(&event, repo, delivery_id) {
            Ok(x) => x,
            Err(r) => return Outcome::Rejected(r),
        };
        let identity = JobIdentity {
            repository_id: repo.id,
            commit: request.commit.clone(),
            profile_id: profile.id.clone(),
            engine_version: profile.engine_version.clone(),
            protocol_revision: profile.protocol_revision,
            config_digest: profile.config_digest.clone(),
            population_digest: profile.population_digest.clone(),
            class: profile.class,
        };
        let job_id = JobId::derive(&identity);
        meta.job_id = Some(job_id.clone());
        let admission = lock(&self.jobs).admit(&identity, &request);
        let disposition = match admission {
            Admission::New => match self.queue.try_push(job_id.clone()) {
                Ok(()) => Disposition::Queued,
                Err(e) => {
                    lock(&self.jobs).rollback_new(&job_id);
                    return Outcome::Rejected(push_reason(e));
                }
            },
            Admission::Requeued { previous } => match self.queue.try_push(job_id.clone()) {
                Ok(()) => Disposition::Requeued,
                Err(e) => {
                    lock(&self.jobs).rollback_requeue(&job_id, previous);
                    return Outcome::Rejected(push_reason(e));
                }
            },
            Admission::Coalesced => Disposition::Coalesced,
            Admission::AlreadyComplete => Disposition::AlreadyComplete,
            Admission::AlreadyRouted => Disposition::AlreadyRouted,
            Admission::RetryLimit => return Outcome::Rejected(Reason::RetryLimit),
            Admission::Full => return Outcome::Rejected(Reason::JobStoreFull),
        };
        Outcome::Accepted {
            job_id,
            disposition,
        }
    }

    /// Installation, repository (by id) and actor must all be allowlisted, and
    /// the repository must belong to *this* installation.
    fn authorize(&self, e: &ParsedEvent) -> Result<&RepositoryPolicy, Reason> {
        let installation = self
            .policy
            .installation(e.installation_id)
            .ok_or(Reason::InstallationNotAllowlisted)?;
        let repo = installation
            .repositories
            .iter()
            .find(|r| r.id == e.repository_id)
            .ok_or_else(|| {
                if self.policy.repository_known(e.repository_id) {
                    Reason::InstallationRepositoryMismatch
                } else {
                    Reason::RepositoryNotAllowlisted
                }
            })?;
        if !repo.full_name.eq_ignore_ascii_case(&e.repository_name) {
            return Err(Reason::RepositoryNameMismatch);
        }
        if !repo.actors.contains(&e.sender_id) {
            return Err(Reason::ActorNotAuthorized);
        }
        Ok(repo)
    }

    fn build_request(
        &self,
        e: &ParsedEvent,
        repo: &RepositoryPolicy,
        delivery_id: &str,
    ) -> Result<(EvaluationRequest, &Profile), Reason> {
        let default_profile = repo.profiles[0].as_str();
        let (profile_id, subject, expected) = match &e.trigger {
            Trigger::Comment { pr_number, command } => {
                let CommandParse::Run { profile } = command else {
                    return Err(Reason::CommandMalformed);
                };
                (
                    profile
                        .clone()
                        .unwrap_or_else(|| default_profile.to_owned()),
                    Subject::PullRequest(*pr_number),
                    None,
                )
            }
            Trigger::Suite {
                head_sha,
                head_branch,
                pr_number,
            } => (
                default_profile.to_owned(),
                subject_of(*pr_number, head_branch)?,
                Some(head_sha.clone()),
            ),
            Trigger::Run {
                head_sha,
                external_id,
                head_branch,
                pr_number,
            } => {
                // A rerun of one of our own Checks keeps its profile.
                let previous = external_id
                    .as_deref()
                    .and_then(JobId::parse)
                    .and_then(|id| {
                        lock(&self.jobs).get(&id).and_then(|j| {
                            (j.identity.repository_id == repo.id && j.identity.commit == *head_sha)
                                .then(|| j.identity.profile_id.clone())
                        })
                    });
                (
                    previous.unwrap_or_else(|| default_profile.to_owned()),
                    subject_of(*pr_number, head_branch)?,
                    Some(head_sha.clone()),
                )
            }
        };
        if !repo.profiles.contains(&profile_id) {
            return Err(Reason::ProfileNotAllowed);
        }
        let profile = self
            .policy
            .profile(&profile_id)
            .ok_or(Reason::ProfileNotAllowed)?;
        let head = self
            .services
            .heads
            .resolve(repo.id, &subject)
            .map_err(|_| Reason::HeadUnresolvable)?;
        if let Some(expected) = expected {
            if head.sha != expected {
                return Err(Reason::StaleHead);
            }
        }
        if head.head_repository_id != repo.id && !repo.allow_fork_heads {
            return Err(Reason::ForkHeadNotAllowed);
        }
        Ok((
            EvaluationRequest {
                installation_id: e.installation_id,
                repository_id: repo.id,
                repository_name: repo.full_name.clone(),
                commit: head.sha,
                subject,
                profile_id,
                requester_id: e.sender_id,
                delivery_id: delivery_id.to_owned(),
                event: e.kind,
            },
            profile,
        ))
    }

    // ---- worker side -------------------------------------------------------

    fn process(&self, id: &JobId) {
        let Some(job) = lock(&self.jobs).start(id) else {
            return;
        };
        let state = match catch_unwind(AssertUnwindSafe(|| self.execute(&job))) {
            Ok(state) => state,
            Err(_) => {
                // The panic payload is dropped unread (it could hold anything).
                // Do not leave a Check in progress forever.
                let _ = catch_unwind(AssertUnwindSafe(|| self.conclude_internal(&job)));
                JobState::Failed(FailReason::Internal)
            }
        };
        if let Some(j) = lock(&self.jobs).get_mut(id) {
            if j.transition(state).is_err() {
                // Unreachable by construction (execute returns only states the
                // machine allows from Running); fail closed if it ever happens.
                j.state = JobState::Failed(FailReason::Internal);
            }
        }
    }

    fn conclude_internal(&self, job: &Job) {
        let (Some(profile), Some(check_run_id)) = (
            self.policy.profile(&job.identity.profile_id),
            self.check_id(&job.id),
        ) else {
            return;
        };
        let ctx = ReportContext {
            job_id: &job.id,
            commit: &job.identity.commit,
            profile,
        };
        let r = report_failure(&ctx, FailureKind::Internal);
        let _ = self.services.checks.update(&CheckRunUpdate {
            installation_id: job.request.installation_id,
            repository_id: job.request.repository_id,
            check_run_id,
            status: CheckStatus::Completed,
            conclusion: Some(r.conclusion),
            output: Some(r.output),
            details_url: self.details_url(&job.id),
        });
    }

    fn with_job<R>(&self, id: &JobId, f: impl FnOnce(&mut Job) -> R) -> Option<R> {
        lock(&self.jobs).get_mut(id).map(f)
    }

    fn execute(&self, job: &Job) -> JobState {
        let Some(profile) = self.policy.profile(&job.identity.profile_id) else {
            return JobState::Failed(FailReason::Internal);
        };
        if profile.class == ProfileClass::Protected {
            return self.route(job);
        }
        let ctx = ReportContext {
            job_id: &job.id,
            commit: &job.identity.commit,
            profile,
        };
        match self.head_is_current(job) {
            Ok(true) => {}
            Ok(false) => return self.stale(job, &ctx),
            Err(()) => return JobState::Failed(FailReason::HeadUnverifiable),
        }
        let pending = match job.pending.clone() {
            // A previous attempt produced a result but could not publish it.
            Some(p) => p,
            None => {
                if self.ensure_check(job, &ctx).is_err() {
                    return JobState::Failed(FailReason::PublishFailed);
                }
                self.run_to_result(job, profile, &ctx)
            }
        };
        match self.head_is_current(job) {
            Ok(true) => {}
            Ok(false) => return self.stale(job, &ctx),
            Err(()) => {
                self.with_job(&job.id, |j| j.pending = Some(pending));
                return JobState::Failed(FailReason::HeadUnverifiable);
            }
        }
        let Some(check_run_id) = self.check_id(&job.id) else {
            // A pending result of an earlier attempt always has a Check; a job
            // without one is created now.
            return match self
                .ensure_check(job, &ctx)
                .ok()
                .and_then(|_| self.check_id(&job.id))
            {
                Some(id) => self.publish(job, id, pending),
                None => {
                    self.with_job(&job.id, |j| j.pending = Some(pending));
                    JobState::Failed(FailReason::PublishFailed)
                }
            };
        };
        self.publish(job, check_run_id, pending)
    }

    fn publish(&self, job: &Job, check_run_id: CheckRunId, pending: PendingResult) -> JobState {
        let update = CheckRunUpdate {
            installation_id: job.request.installation_id,
            repository_id: job.request.repository_id,
            check_run_id,
            status: CheckStatus::Completed,
            conclusion: Some(pending.report.conclusion),
            output: Some(pending.report.output.clone()),
            details_url: self.details_url(&job.id),
        };
        match self.services.checks.update(&update) {
            Ok(()) => {
                self.with_job(&job.id, |j| j.pending = None);
                match pending.fail {
                    None => JobState::Completed,
                    Some(r) => JobState::Failed(r),
                }
            }
            Err(_) => {
                self.with_job(&job.id, |j| j.pending = Some(pending));
                JobState::Failed(FailReason::PublishFailed)
            }
        }
    }

    fn run_to_result(
        &self,
        job: &Job,
        profile: &Profile,
        ctx: &ReportContext<'_>,
    ) -> PendingResult {
        let spec = JobSpec {
            job_id: job.id.clone(),
            identity: job.identity.clone(),
            attempt: job.attempts,
        };
        let failed = |kind: FailureKind, fail: FailReason| PendingResult {
            report: report_failure(ctx, kind),
            fail: Some(fail),
        };
        match self.services.runner.run(&spec, &self.cancel) {
            Ok(RunnerOutcome::Measured(m)) => {
                if !m.matches_profile(profile) {
                    return failed(FailureKind::IdentityMismatch, FailReason::IdentityMismatch);
                }
                let report: CheckReport = report_measured(ctx, &m);
                let fail = (m.exit_code != 0).then_some(FailReason::RunFailed);
                PendingResult { report, fail }
            }
            Ok(RunnerOutcome::Failed { exit_code, .. }) => {
                if exit_code == 8 {
                    failed(FailureKind::Cancelled, FailReason::Cancelled)
                } else {
                    failed(FailureKind::RunFailed, FailReason::RunFailed)
                }
            }
            Err(RunnerError::Timeout) => failed(FailureKind::Timeout, FailReason::Timeout),
            Err(RunnerError::Cancelled) => failed(FailureKind::Cancelled, FailReason::Cancelled),
            Err(RunnerError::Refused) => {
                failed(FailureKind::RunnerRefused, FailReason::RunnerRefused)
            }
            Err(RunnerError::ProfileChanged) => {
                failed(FailureKind::IdentityMismatch, FailReason::IdentityMismatch)
            }
            Err(RunnerError::SummaryRejected) => {
                failed(FailureKind::SummaryRejected, FailReason::RunFailed)
            }
            Err(RunnerError::Internal) => failed(FailureKind::Internal, FailReason::Internal),
        }
    }

    fn route(&self, job: &Job) -> JobState {
        let submission = CustodianSubmission {
            job_id: job.id.clone(),
            identity: job.identity.clone(),
            requester_id: job.request.requester_id,
        };
        match self.services.custodian.submit(&submission) {
            Ok(()) => JobState::RoutedToCustodian,
            Err(_) => JobState::Failed(FailReason::CustodianUnavailable),
        }
    }

    /// The commit is the head, as resolved now. `Err` when it cannot be told
    /// (fail closed: nothing is published as current).
    fn head_is_current(&self, job: &Job) -> Result<bool, ()> {
        let head = self
            .services
            .heads
            .resolve(job.identity.repository_id, &job.request.subject)
            .map_err(|_| ())?;
        Ok(head.sha == job.identity.commit)
    }

    /// The head moved: nothing the run produced is published. An existing Check
    /// is concluded `neutral` with the superseded text.
    fn stale(&self, job: &Job, ctx: &ReportContext<'_>) -> JobState {
        if let Some(check_run_id) = self.check_id(&job.id) {
            let r = report_stale(ctx);
            let _ = self.services.checks.update(&CheckRunUpdate {
                installation_id: job.request.installation_id,
                repository_id: job.request.repository_id,
                check_run_id,
                status: CheckStatus::Completed,
                conclusion: Some(r.conclusion),
                output: Some(r.output),
                details_url: self.details_url(&job.id),
            });
        }
        self.with_job(&job.id, |j| j.pending = None);
        JobState::Stale
    }

    fn check_id(&self, id: &JobId) -> Option<CheckRunId> {
        self.with_job(id, |j| j.check_run_id).flatten()
    }

    fn details_url(&self, id: &JobId) -> Option<String> {
        self.policy
            .details_base_url
            .as_ref()
            .map(|b| format!("{}/{}", b.trim_end_matches('/'), id))
    }

    /// Make sure a Check exists for the job and is in progress: the stored id,
    /// else one found by `external_id` (a retry after an unknown outcome), else
    /// a new one.
    fn ensure_check(&self, job: &Job, ctx: &ReportContext<'_>) -> Result<(), ()> {
        let started = report_started(ctx);
        let existing = match self.check_id(&job.id) {
            Some(id) => Some(id),
            None => self
                .services
                .checks
                .find(
                    job.request.installation_id,
                    job.request.repository_id,
                    &job.identity.commit,
                    &job.id,
                )
                .map_err(|_| ())?,
        };
        let id = match existing {
            Some(id) => {
                self.services
                    .checks
                    .update(&CheckRunUpdate {
                        installation_id: job.request.installation_id,
                        repository_id: job.request.repository_id,
                        check_run_id: id,
                        status: CheckStatus::InProgress,
                        conclusion: None,
                        output: Some(started),
                        details_url: self.details_url(&job.id),
                    })
                    .map_err(|_| ())?;
                id
            }
            None => self
                .services
                .checks
                .create(&CheckRunCreate {
                    installation_id: job.request.installation_id,
                    repository_id: job.request.repository_id,
                    head_sha: job.identity.commit.clone(),
                    name: CHECK_NAME,
                    external_id: job.id.clone(),
                    status: CheckStatus::InProgress,
                    conclusion: None,
                    output: Some(started),
                    details_url: self.details_url(&job.id),
                })
                .map_err(|_| ())?,
        };
        self.with_job(&job.id, |j| j.check_run_id = Some(id));
        Ok(())
    }
}

fn subject_of(pr: Option<u64>, branch: &Option<String>) -> Result<Subject, Reason> {
    match (pr, branch) {
        (Some(n), _) => Ok(Subject::PullRequest(n)),
        (None, Some(b)) => Ok(Subject::Branch(b.clone())),
        (None, None) => Err(Reason::PayloadMalformed),
    }
}

fn push_reason(e: PushError) -> Reason {
    match e {
        PushError::Full => Reason::QueueFull,
        PushError::Closed => Reason::ShuttingDown,
    }
}
