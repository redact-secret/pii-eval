//! In-memory fakes and builders for the tests (and for local experiments).
//! Synthetic data only; nothing here touches the network or the file system.
//! Not for production: a production deployment implements the [`crate::ports`]
//! traits against GitHub.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::checks::{
    CheckOutput, CheckRunCreate, CheckRunId, CheckRunUpdate, CheckStatus, Conclusion, RunnerOutcome,
};
use crate::hmac::{hex, hmac_sha256};
use crate::policy::{AppPolicy, InstallationPolicy, Limits, Profile, RepositoryPolicy};
use crate::ports::{
    CancelFlag, ChecksApi, Clock, CustodianRouter, CustodianSubmission, HeadInfo, HeadResolver,
    JobRunner, JobSpec, PortError, RunnerError,
};
use crate::request::{CommitSha, JobId, JobIdentity, ProfileClass, Subject};
use crate::secret::Secret;
use crate::service::{App, Services};
use crate::webhook::RawDelivery;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Poll `cond` until it holds. The deadline is generous (two minutes) because a
/// loaded machine must not turn a slow worker into a failure; it is a bound on
/// a hang, not a measurement.
pub fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The fake clock's start (2027-01-15T08:00:00Z).
pub const BASE_TIME: u64 = 1_800_000_000;

/// Conformance helper for transports: run `call` (for example a [`HeadResolver`]
/// lookup against a server that accepts the connection and never answers) and
/// assert that it returns within `limit` (use [`crate::ports::MAX_PORT_CALL_SECS`]
/// plus slack). It measures after the fact, so a call that really hangs hangs the
/// test: run it with a watchdog in the transport's own test suite.
pub fn assert_port_call_bounded<T>(what: &str, limit: Duration, call: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = call();
    assert!(
        start.elapsed() <= limit,
        "{what} took {:?}, over the {limit:?} port-call bound",
        start.elapsed()
    );
    out
}

/// A clock the test moves. It starts at [`BASE_TIME`].
#[derive(Debug)]
pub struct FakeClock(AtomicU64);

impl Default for FakeClock {
    fn default() -> Self {
        Self(AtomicU64::new(BASE_TIME))
    }
}

impl FakeClock {
    /// Advance by `secs`.
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Heads the test sets.
#[derive(Default)]
pub struct FakeHeads {
    heads: Mutex<HashMap<(u64, Subject), HeadInfo>>,
    fail: AtomicBool,
    calls: AtomicUsize,
}

impl FakeHeads {
    /// Set the head of a subject.
    pub fn set(&self, repository_id: u64, subject: Subject, sha: &CommitSha, head_repo: u64) {
        lock(&self.heads).insert(
            (repository_id, subject),
            HeadInfo {
                sha: sha.clone(),
                head_repository_id: head_repo,
            },
        );
    }

    /// Make every lookup fail (or succeed again).
    pub fn set_failing(&self, failing: bool) {
        self.fail.store(failing, Ordering::SeqCst);
    }

    /// Lookups so far.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl HeadResolver for FakeHeads {
    fn resolve(&self, repository_id: u64, subject: &Subject) -> Result<HeadInfo, PortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(PortError::Unavailable);
        }
        lock(&self.heads)
            .get(&(repository_id, subject.clone()))
            .cloned()
            .ok_or(PortError::Denied)
    }
}

/// One check run as the fake GitHub holds it.
#[derive(Clone, Debug)]
pub struct RecordedRun {
    /// Id.
    pub id: CheckRunId,
    /// Installation used.
    pub installation_id: u64,
    /// Repository.
    pub repository_id: u64,
    /// Commit.
    pub head_sha: CommitSha,
    /// `external_id`.
    pub external_id: JobId,
    /// Status.
    pub status: CheckStatus,
    /// Conclusion.
    pub conclusion: Option<Conclusion>,
    /// Output.
    pub output: Option<CheckOutput>,
    /// Details link.
    pub details_url: Option<String>,
}

/// The fake Checks API: records everything, can fail on demand.
#[derive(Default)]
pub struct FakeChecks {
    runs: Mutex<Vec<RecordedRun>>,
    fail_find: AtomicU32,
    fail_create: AtomicU32,
    fail_update: AtomicU32,
    /// When set, a `create` stores the run and then reports failure (the
    /// outcome-unknown case that reconciliation by `external_id` must handle).
    create_lost_response: AtomicBool,
}

fn take_failure(counter: &AtomicU32) -> bool {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
}

impl FakeChecks {
    /// All runs.
    pub fn runs(&self) -> Vec<RecordedRun> {
        lock(&self.runs).clone()
    }

    /// Fail the next `n` finds.
    pub fn fail_next_finds(&self, n: u32) {
        self.fail_find.store(n, Ordering::SeqCst);
    }

    /// Fail the next `n` creates.
    pub fn fail_next_creates(&self, n: u32) {
        self.fail_create.store(n, Ordering::SeqCst);
    }

    /// Fail the next `n` updates.
    pub fn fail_next_updates(&self, n: u32) {
        self.fail_update.store(n, Ordering::SeqCst);
    }

    /// The next create stores the run but reports failure.
    pub fn lose_next_create_response(&self) {
        self.create_lost_response.store(true, Ordering::SeqCst);
    }
}

impl ChecksApi for FakeChecks {
    fn find(
        &self,
        installation_id: u64,
        repository_id: u64,
        head_sha: &CommitSha,
        external_id: &JobId,
    ) -> Result<Option<CheckRunId>, PortError> {
        if take_failure(&self.fail_find) {
            return Err(PortError::Unavailable);
        }
        Ok(lock(&self.runs)
            .iter()
            .find(|r| {
                r.installation_id == installation_id
                    && r.repository_id == repository_id
                    && r.head_sha == *head_sha
                    && r.external_id == *external_id
            })
            .map(|r| r.id))
    }

    fn create(&self, c: &CheckRunCreate) -> Result<CheckRunId, PortError> {
        if take_failure(&self.fail_create) {
            return Err(PortError::Unavailable);
        }
        let mut runs = lock(&self.runs);
        let id = CheckRunId(runs.len() as u64 + 1);
        runs.push(RecordedRun {
            id,
            installation_id: c.installation_id,
            repository_id: c.repository_id,
            head_sha: c.head_sha.clone(),
            external_id: c.external_id.clone(),
            status: c.status,
            conclusion: c.conclusion,
            output: c.output.clone(),
            details_url: c.details_url.clone(),
        });
        if self.create_lost_response.swap(false, Ordering::SeqCst) {
            return Err(PortError::Unavailable);
        }
        Ok(id)
    }

    fn update(&self, u: &CheckRunUpdate) -> Result<(), PortError> {
        if take_failure(&self.fail_update) {
            return Err(PortError::Unavailable);
        }
        let mut runs = lock(&self.runs);
        let run = runs
            .iter_mut()
            .find(|r| r.id == u.check_run_id && r.repository_id == u.repository_id)
            .ok_or(PortError::Denied)?;
        run.status = u.status;
        run.conclusion = u.conclusion;
        run.output = u.output.clone();
        run.details_url = u.details_url.clone();
        Ok(())
    }
}

/// A gate the test opens to let blocked runners continue.
#[derive(Default)]
pub struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    /// Open it.
    pub fn open(&self) {
        *lock(&self.open) = true;
        self.changed.notify_all();
    }

    fn wait(&self) {
        let mut g = lock(&self.open);
        while !*g {
            g = self.changed.wait(g).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

type RunnerScript = dyn Fn(&JobSpec) -> Result<RunnerOutcome, RunnerError> + Send + Sync;

/// A scriptable runner that tracks concurrency.
pub struct FakeRunner {
    script: Box<RunnerScript>,
    gate: Option<Arc<Gate>>,
    running: AtomicUsize,
    max_running: AtomicUsize,
    calls: AtomicUsize,
    specs: Mutex<Vec<JobSpec>>,
}

impl FakeRunner {
    /// A runner that returns a complete measurement matching the job's pins.
    pub fn complete() -> Self {
        Self::scripted(|spec| Ok(measured_for(&spec.identity, 0)))
    }

    /// A runner with a custom script.
    pub fn scripted(
        f: impl Fn(&JobSpec) -> Result<RunnerOutcome, RunnerError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            script: Box::new(f),
            gate: None,
            running: AtomicUsize::new(0),
            max_running: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            specs: Mutex::new(Vec::new()),
        }
    }

    /// Block every run until the gate opens.
    pub fn with_gate(mut self, gate: Arc<Gate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Runs started.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Runs in progress now.
    pub fn running(&self) -> usize {
        self.running.load(Ordering::SeqCst)
    }

    /// Highest number of simultaneous runs seen.
    pub fn max_running(&self) -> usize {
        self.max_running.load(Ordering::SeqCst)
    }

    /// Every spec the runner received.
    pub fn specs(&self) -> Vec<JobSpec> {
        lock(&self.specs).clone()
    }
}

impl JobRunner for FakeRunner {
    fn run(&self, spec: &JobSpec, _cancel: &CancelFlag) -> Result<RunnerOutcome, RunnerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.specs).push(spec.clone());
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_running.fetch_max(now, Ordering::SeqCst);
        if let Some(g) = &self.gate {
            g.wait();
        }
        let result = (self.script)(spec);
        self.running.fetch_sub(1, Ordering::SeqCst);
        result
    }
}

/// A custodian that records submissions.
#[derive(Default)]
pub struct FakeCustodian {
    submissions: Mutex<Vec<CustodianSubmission>>,
    unavailable: AtomicBool,
}

impl FakeCustodian {
    /// Make submissions fail.
    pub fn set_unavailable(&self, v: bool) {
        self.unavailable.store(v, Ordering::SeqCst);
    }

    /// What was submitted.
    pub fn submissions(&self) -> Vec<CustodianSubmission> {
        lock(&self.submissions).clone()
    }
}

impl CustodianRouter for FakeCustodian {
    fn submit(&self, s: &CustodianSubmission) -> Result<(), PortError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(PortError::Unavailable);
        }
        lock(&self.submissions).push(s.clone());
        Ok(())
    }
}

/// A CLI `pii-eval-summary/1` line for a complete (exit 0) or incomplete (exit 5)
/// run that reports exactly the identities of `identity`.
pub fn summary_line_for(identity: &JobIdentity, exit_code: u8) -> String {
    let state = if exit_code == 0 {
        "complete"
    } else {
        "incomplete"
    };
    json!({
        "schema": "pii-eval-summary/1",
        "command": "run",
        "engine": {"name": "pii-eval", "version": identity.engine_version},
        "exit": {"code": exit_code, "name": "x"},
        "state": state,
        "semantic": {
            "runClass": "public-synthetic",
            "protocol": {"id": "pii-v1", "revision": identity.protocol_revision},
            "populationDigest": identity.population_digest,
            "manifestDigest": "3".repeat(64),
            "runArtifactDigest": "5".repeat(64),
            "publicArtifactDigest": "4".repeat(64),
            "populationCounts": {"authoredCases": 3, "variants": 9},
            "completeness": "full",
            "failureCodes": [],
            "scanners": [{"scannerId": "redact-secret-core", "status": "complete",
                          "observationDigest": "6".repeat(64)}],
        }
    })
    .to_string()
}

/// [`summary_line_for`], projected.
pub fn measured_for(identity: &JobIdentity, exit_code: u8) -> RunnerOutcome {
    RunnerOutcome::from_summary_line(&summary_line_for(identity, exit_code))
        .expect("the test summary projects")
}

// ---- the standard test world ------------------------------------------------

/// Webhook secret of the test world.
pub const SECRET: &[u8] = b"synthetic-webhook-secret-for-tests-only-0123456789";
/// Installation of the main repository.
pub const INSTALLATION: u64 = 7;
/// Main repository id.
pub const REPO: u64 = 42;
/// Main repository name.
pub const REPO_NAME: &str = "example/repo";
/// An allowlisted actor of the main repository.
pub const ACTOR: u64 = 1001;
/// A second installation and its repository (cross-repository tests).
pub const OTHER_INSTALLATION: u64 = 8;
/// The second repository.
pub const OTHER_REPO: u64 = 43;
/// The second repository's actor.
pub const OTHER_ACTOR: u64 = 2002;
/// A pull request number.
pub const PR: u64 = 5;
/// Public synthetic profile.
pub const PUBLIC_PROFILE: &str = "public-default";
/// A second public profile.
pub const PUBLIC_PROFILE_B: &str = "public-alt";
/// Protected profile (routed only).
pub const PROTECTED_PROFILE: &str = "protected-main";

/// A commit id made of one repeated hex digit.
pub fn sha(c: char) -> CommitSha {
    CommitSha::parse(&c.to_string().repeat(40)).expect("valid test sha")
}

/// The test policy.
pub fn test_policy(limits: Limits) -> AppPolicy {
    let profile = |id: &str, class, d: char, pop: char| Profile {
        id: id.to_owned(),
        class,
        engine_version: "0.0.0".to_owned(),
        protocol_revision: 2,
        config_digest: d.to_string().repeat(64),
        population_digest: pop.to_string().repeat(64),
    };
    AppPolicy {
        installations: vec![
            InstallationPolicy {
                id: INSTALLATION,
                repositories: vec![RepositoryPolicy {
                    id: REPO,
                    full_name: REPO_NAME.to_owned(),
                    actors: BTreeSet::from([ACTOR]),
                    profiles: vec![
                        PUBLIC_PROFILE.to_owned(),
                        PUBLIC_PROFILE_B.to_owned(),
                        PROTECTED_PROFILE.to_owned(),
                    ],
                    allow_fork_heads: false,
                }],
            },
            InstallationPolicy {
                id: OTHER_INSTALLATION,
                repositories: vec![RepositoryPolicy {
                    id: OTHER_REPO,
                    full_name: "example/other".to_owned(),
                    actors: BTreeSet::from([OTHER_ACTOR]),
                    profiles: vec![PUBLIC_PROFILE.to_owned()],
                    allow_fork_heads: false,
                }],
            },
        ],
        profiles: vec![
            profile(PUBLIC_PROFILE, ProfileClass::PublicSynthetic, 'a', 'd'),
            profile(PUBLIC_PROFILE_B, ProfileClass::PublicSynthetic, 'b', 'e'),
            profile(PROTECTED_PROFILE, ProfileClass::Protected, 'c', 'f'),
        ],
        limits,
        details_base_url: Some("https://ci.example.invalid/pii-eval/jobs".to_owned()),
    }
}

/// Sign `body` as GitHub would.
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    format!("sha256={}", hex(&hmac_sha256(secret, body)))
}

/// `YYYY-MM-DDTHH:MM:SSZ` for Unix seconds (Howard Hinnant's civil-from-days).
pub fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

static COMMENT_IDS: AtomicU64 = AtomicU64::new(1000);

/// An `issue_comment` payload with a fresh comment id, created at [`BASE_TIME`].
pub fn comment_payload(
    installation: u64,
    repo: u64,
    repo_name: &str,
    sender: u64,
    pr: u64,
    text: &str,
) -> Vec<u8> {
    let id = COMMENT_IDS.fetch_add(1, Ordering::SeqCst);
    comment_payload_full(
        installation,
        repo,
        repo_name,
        sender,
        pr,
        text,
        id,
        BASE_TIME,
    )
}

/// An `issue_comment` payload with an explicit comment id and creation time.
#[allow(clippy::too_many_arguments)]
pub fn comment_payload_full(
    installation: u64,
    repo: u64,
    repo_name: &str,
    sender: u64,
    pr: u64,
    text: &str,
    comment_id: u64,
    created_at: u64,
) -> Vec<u8> {
    json!({
        "action": "created",
        "installation": {"id": installation},
        "repository": {"id": repo, "full_name": repo_name, "private": true},
        "sender": {"id": sender, "login": "someone", "type": "User"},
        "issue": {"number": pr, "pull_request": {"url": "https://example.invalid/pr"}},
        "comment": {"id": comment_id, "created_at": format_utc(created_at), "body": text, "user": {"id": sender}, "author_association": "NONE"},
    })
    .to_string()
    .into_bytes()
}

/// A `check_suite` payload.
pub fn suite_payload(
    action: &str,
    installation: u64,
    repo: u64,
    repo_name: &str,
    sender: u64,
    head_sha: &CommitSha,
    pr: Option<u64>,
) -> Vec<u8> {
    let prs: Vec<Value> = pr.map(|n| json!({"number": n})).into_iter().collect();
    json!({
        "action": action,
        "installation": {"id": installation},
        "repository": {"id": repo, "full_name": repo_name},
        "sender": {"id": sender},
        "check_suite": {"head_sha": head_sha.as_str(), "head_branch": "feature", "pull_requests": prs},
    })
    .to_string()
    .into_bytes()
}

/// A `check_run` payload.
#[allow(clippy::too_many_arguments)]
pub fn run_payload(
    action: &str,
    installation: u64,
    repo: u64,
    repo_name: &str,
    sender: u64,
    head_sha: &CommitSha,
    pr: Option<u64>,
    external_id: Option<&str>,
) -> Vec<u8> {
    let prs: Vec<Value> = pr.map(|n| json!({"number": n})).into_iter().collect();
    json!({
        "action": action,
        "installation": {"id": installation},
        "repository": {"id": repo, "full_name": repo_name},
        "sender": {"id": sender},
        "check_run": {"head_sha": head_sha.as_str(), "external_id": external_id,
                      "check_suite": {"head_branch": "feature"}, "pull_requests": prs},
    })
    .to_string()
    .into_bytes()
}

/// The service with all fakes wired in. Workers are not started.
pub struct TestEnv {
    /// The service.
    pub app: App,
    /// Heads.
    pub heads: Arc<FakeHeads>,
    /// Checks.
    pub checks: Arc<FakeChecks>,
    /// Runner.
    pub runner: Arc<FakeRunner>,
    /// Custodian.
    pub custodian: Arc<FakeCustodian>,
    /// Clock.
    pub clock: Arc<FakeClock>,
    counter: AtomicU64,
}

impl TestEnv {
    /// Default limits, a runner that completes.
    pub fn new() -> Self {
        Self::build(Limits::default(), FakeRunner::complete())
    }

    /// Custom limits and runner. The main pull request's head is `sha('1')`.
    pub fn build(limits: Limits, runner: FakeRunner) -> Self {
        let heads = Arc::new(FakeHeads::default());
        heads.set(REPO, Subject::PullRequest(PR), &sha('1'), REPO);
        heads.set(OTHER_REPO, Subject::PullRequest(PR), &sha('2'), OTHER_REPO);
        let checks = Arc::new(FakeChecks::default());
        let runner = Arc::new(runner);
        let custodian = Arc::new(FakeCustodian::default());
        let clock = Arc::new(FakeClock::default());
        let services = Services {
            heads: Arc::clone(&heads) as Arc<dyn HeadResolver>,
            checks: Arc::clone(&checks) as Arc<dyn ChecksApi>,
            runner: Arc::clone(&runner) as Arc<dyn JobRunner>,
            custodian: Arc::clone(&custodian) as Arc<dyn CustodianRouter>,
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
        };
        let secret = Secret::new(SECRET.to_vec()).expect("test secret");
        let app = App::new(test_policy(limits), secret, services).expect("test policy");
        Self {
            app,
            heads,
            checks,
            runner,
            custodian,
            clock,
            counter: AtomicU64::new(0),
        }
    }

    /// A fresh delivery id.
    pub fn next_delivery_id(&self) -> String {
        format!("delivery-{}", self.counter.fetch_add(1, Ordering::SeqCst))
    }

    /// Deliver a correctly signed payload with a fresh delivery id.
    pub fn deliver(&self, event: &str, body: &[u8]) -> crate::reason::Decision {
        let id = self.next_delivery_id();
        self.deliver_with_id(event, &id, body)
    }

    /// Deliver a correctly signed payload with a given delivery id.
    pub fn deliver_with_id(&self, event: &str, id: &str, body: &[u8]) -> crate::reason::Decision {
        let signature = sign(SECRET, body);
        self.app.handle_delivery(&RawDelivery {
            event: Some(event),
            delivery_id: Some(id),
            signature: Some(&signature),
            body,
        })
    }

    /// A `/pii-eval run` comment by the allowlisted actor on the main PR.
    pub fn comment(&self, text: &str) -> crate::reason::Decision {
        self.deliver(
            "issue_comment",
            &comment_payload(INSTALLATION, REPO, REPO_NAME, ACTOR, PR, text),
        )
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}
