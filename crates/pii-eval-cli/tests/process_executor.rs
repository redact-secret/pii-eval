//! The executor over real scanner processes: the inert Node fake of the adapters
//! crate misbehaves on demand (crash, hang, flood, descendants, memory, scratch
//! files, instability) and the executor must record each as a distinct,
//! sanitized failure, bound its resources, and leave nothing running.
//! Synthetic only. Unix and Node required (CI sets `PII_EVAL_REQUIRE_NODE=1`).
#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use pii_eval_adapters::redact_secret::RedactSecretVocabulary;
use pii_eval_adapters::{
    AdapterLimits, ArtifactPin, ProcessAdapter, ProcessAdapterSpec, ScannerAdapter, sha256_of_file,
    sha256_of_tree,
};
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunOutput, RunRequest, run};
use pii_eval_contracts::{
    ActionCapability, ActionExpectation, ActivationSelector, AdapterIdentity, ByteRange, Case,
    ConfigKey, ConfigParameter, ConfigValue, ContextClass, ContextObligation, CorpusSnapshot,
    CorpusSnapshotBody, Derivation, ExecutionLimits, Expectation, ExpectedType, FailureCode,
    FamilyId, GenerationRules, Id, LanguageTag, Lineage, MethodId, Population, ProductIdentity,
    ScannerConfiguration, ScannerId, ScannerStatus, SensitivityExpectation, Strategy, Variant,
    VersionString, Visibility, seal, validate,
};
use pii_eval_kernel::{OffsetUnit, verify_run_artifact_accounting};

fn node() -> Option<PathBuf> {
    let found = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join("node"))
            .find(|p| p.is_file())
    });
    if found.is_none() {
        assert!(
            std::env::var("PII_EVAL_REQUIRE_NODE").as_deref() != Ok("1"),
            "node is required (PII_EVAL_REQUIRE_NODE=1) but was not found"
        );
        eprintln!("SKIPPED: node not found on PATH");
    }
    found
}

fn adapters_fixtures() -> PathBuf {
    // The adapter refuses `..` components in pinned paths.
    std::fs::canonicalize(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pii-eval-adapters/tests/fixtures"),
    )
    .expect("adapter fixtures exist")
}

fn adapter(node: &Path, call_timeout: Duration, startup: &str) -> Arc<ProcessAdapter> {
    let shim = adapters_fixtures().join("fake-scanner.mjs");
    let core = adapters_fixtures().join("fake-core");
    let spec = ProcessAdapterSpec {
        executable: node.to_path_buf(),
        shim: ArtifactPin::file(&shim, sha256_of_file(&shim).unwrap()),
        scanner_artifact: ArtifactPin::tree(&core, sha256_of_tree(&core).unwrap()),
        scanner_entry: core.join("lib/index.js"),
        extra_artifacts: Vec::new(),
        scanner_id: ScannerId::new("fake-scanner").unwrap(),
        scanner_version: VersionString::new("1.0.0").unwrap(),
        product: ProductIdentity::Released,
        adapter: AdapterIdentity {
            adapter_id: ScannerId::new("fake-adapter").unwrap(),
            adapter_version: VersionString::new("0.0.1").unwrap(),
            normalization_version: 1,
        },
        runtime_name: "node".to_owned(),
        runtime_version_prefix: None,
        offset_unit: OffsetUnit::Utf16CodeUnits,
        inherit_env: Vec::new(),
        allowed_parameters: vec![ConfigParameter {
            key: ConfigKey::new("startup").unwrap(),
            value: ConfigValue::Text(startup.to_owned()),
        }],
        return_output: true,
        limits: AdapterLimits {
            startup_timeout: Duration::from_secs(20),
            call_timeout,
            ..AdapterLimits::default()
        },
        vocabulary: Arc::new(RedactSecretVocabulary),
    };
    Arc::new(ProcessAdapter::new(spec).expect("valid spec"))
}

/// One authored case whose variants carry the given texts (directives for the fake).
fn directive_snapshot(texts: &[String]) -> CorpusSnapshot {
    let variants: Vec<Variant> = texts
        .iter()
        .enumerate()
        .map(|(i, text)| Variant {
            variant_id: Id::new(format!("v{i:02}")).unwrap(),
            derivation: Derivation {
                strategy: Strategy::Authored,
                operator: None,
                seed: None,
            },
            text: text.clone(),
            text_digest: pii_eval_contracts::Sha256Digest::of_bytes(text.as_bytes()),
            expectations: vec![Expectation {
                occurrence_id: Id::new("occurrence-1").unwrap(),
                range: Some(ByteRange { start: 0, end: 1 }),
                family: FamilyId::new("pii:global:email").unwrap(),
                type_expectation: ExpectedType::Valid,
                validator: None,
                sensitivity: SensitivityExpectation::Sensitive,
                context_class: ContextClass::Sensitive,
                context_obligation: ContextObligation::None,
                action: ActionExpectation::Redact,
            }],
        })
        .collect();
    let case = Case {
        case_id: Id::new("directive-case").unwrap(),
        method: MethodId::TypeValidation,
        lineage: Lineage {
            source_id: Id::new("synthetic-source").unwrap(),
            source_digest: digest_of("synthetic-source"),
        },
        language: LanguageTag::new("en").unwrap(),
        jurisdiction: None,
        collision: None,
        variants,
    };
    let mut snapshot = pii_eval_contracts::CorpusSnapshot::unsealed(CorpusSnapshotBody {
        population: Population {
            population_id: Id::new("synthetic-directives").unwrap(),
            population_version: 1,
            visibility: Visibility::PublicSynthetic,
        },
        generation: GenerationRules {
            generator: Id::new("synthetic-generator").unwrap(),
            generator_version: 1,
            seed_derivation: pii_eval_contracts::Seed::new("seed-v1").unwrap(),
        },
        cases: vec![case],
    });
    seal(&mut snapshot).unwrap();
    validate(&snapshot).expect("synthetic snapshot is valid");
    snapshot
}

struct Scenario {
    texts: Vec<String>,
    limits: ExecutionLimits,
    replays: u32,
    call_timeout: Duration,
    sample: Duration,
    startup: &'static str,
}

impl Scenario {
    fn new(texts: &[&str]) -> Self {
        Scenario {
            texts: texts.iter().map(|t| (*t).to_owned()).collect(),
            limits: limits(2, 1, 1, 2),
            replays: 2,
            call_timeout: Duration::from_secs(20),
            sample: Duration::from_millis(50),
            startup: "normal",
        }
    }

    fn run(&self, node: &Path, cancel: &CancelToken, scratch: &Path) -> RunOutput {
        let snapshot = directive_snapshot(&self.texts);
        let adapter = adapter(node, self.call_timeout, self.startup);
        let plan = adapter
            .plan(ScannerConfiguration {
                parameters: vec![ConfigParameter {
                    key: ConfigKey::new("startup").unwrap(),
                    value: ConfigValue::Text(self.startup.to_owned()),
                }],
                activation: vec![ActivationSelector::new("pii:global").unwrap()],
            })
            .expect("plan");
        let manifest = manifest(&snapshot, vec![plan], self.limits, mechanics(self.replays));
        run(
            &RunRequest {
                snapshot: &snapshot,
                manifest: &manifest,
                adapters: vec![adapter as Arc<dyn ScannerAdapter>],
            },
            &RunConfig {
                executor: ExecutorConfig {
                    max_workers: 4,
                    sample_interval: self.sample,
                    scratch_root: Some(scratch.to_path_buf()),
                    resources: ResourcePolicy::Enforce,
                    ..ExecutorConfig::default()
                },
                diagnostics: true,
                commit_cancelled: false,
            },
            cancel,
        )
        .expect("the run starts")
    }
}

fn failure(out: &RunOutput) -> (ScannerStatus, Option<FailureCode>) {
    let s = &out.assembled.artifact.semantic;
    (s.scanners[0].status, s.failures.first().map(|f| f.code))
}

fn assert_artifact_ok(out: &RunOutput, texts: &[String]) {
    validate(&out.assembled.artifact).unwrap();
    let snapshot = directive_snapshot(texts);
    verify_run_artifact_accounting(&out.assembled.artifact, &snapshot).unwrap();
}

fn pid_alive(pid: i32) -> bool {
    let out = Command::new(if Path::new("/bin/ps").exists() {
        "/bin/ps"
    } else {
        "/usr/bin/ps"
    })
    .args(["-o", "stat=", "-p", &pid.to_string()])
    .output()
    .unwrap();
    let state = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    out.status.success() && !state.is_empty() && !state.starts_with('Z')
}

fn wait_dead(pid: i32) {
    let start = Instant::now();
    while pid_alive(pid) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "pid {pid} is still running"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

/// The scanner creates the file and then writes the pid, so the file can exist
/// while still empty. Wait for a parseable pid instead of reading once.
fn try_read_pid(file: &Path) -> Option<i32> {
    std::fs::read_to_string(file).ok()?.trim().parse().ok()
}

fn read_pid(file: &Path) -> i32 {
    let start = Instant::now();
    loop {
        if let Some(pid) = try_read_pid(file) {
            return pid;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "no pid was written to {}",
            file.display()
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn no_scratch_left(root: &Path) {
    let left: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "scratch directories left behind: {left:?}");
}

#[test]
fn a_normal_run_records_the_runtime_and_a_sampled_peak_and_cleans_its_scratch() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-ok");
    // One slow input so the 50 ms sampler sees the process at least once.
    let s = Scenario::new(&["ok one", "#slow 400", "ok three"]);
    let out = s.run(&node, &CancelToken::new(), &scratch.0);
    assert_artifact_ok(&out, &s.texts);
    assert_eq!(failure(&out), (ScannerStatus::Complete, None));
    let diag = out.assembled.observations[0].diagnostics.as_ref().unwrap();
    let runtime = diag.runtime.as_ref().expect("runtime provenance");
    assert_eq!(runtime.runtime_name.as_str(), "node");
    assert!(out.runs[0].timing.peak_rss_bytes > 1024 * 1024);
    no_scratch_left(&scratch.0);
    // The scanner was told about the action capability it really has.
    assert_eq!(
        out.assembled.observations[0].semantic.capabilities.action,
        ActionCapability::SanitizedOutput
    );
}

#[test]
fn crashed_oversized_malformed_and_noisy_scanners_are_distinct_failures() {
    let Some(node) = node() else { return };
    let cases: [(&str, ScannerStatus, Option<FailureCode>); 4] = [
        (
            "#crash",
            ScannerStatus::Error,
            Some(FailureCode::ExecutionError),
        ),
        (
            "#huge",
            ScannerStatus::Error,
            Some(FailureCode::OutputLimitExceeded),
        ),
        (
            "#malformed",
            ScannerStatus::Error,
            Some(FailureCode::MalformedOutput),
        ),
        // 40,000 lines on stderr: drained and counted, never an error.
        ("#stderr", ScannerStatus::Complete, None),
    ];
    for (directive, status, code) in cases {
        let scratch = TempDir::new("proc-fail");
        let s = Scenario::new(&["ok one", directive, "ok three"]);
        let out = s.run(&node, &CancelToken::new(), &scratch.0);
        assert_artifact_ok(&out, &s.texts);
        assert_eq!(failure(&out), (status, code), "{directive}");
        if code.is_some() {
            // Every input is unmeasured: a failure is never a clean scan.
            assert!(out.assembled.observations[0].semantic.inputs.is_empty());
            assert_eq!(
                out.assembled.artifact.semantic.failures[0].affected_inputs,
                3
            );
        }
        no_scratch_left(&scratch.0);
    }
}

#[test]
fn a_descendant_left_by_a_crashing_scanner_does_not_survive_the_run() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-descendant");
    let dir = TempDir::new("proc-descendant-pid");
    let pidfile = dir.0.join("pid");
    let directive = format!("#spawncrash {}", pidfile.display());
    let s = Scenario::new(&["ok one", &directive]);
    let out = s.run(&node, &CancelToken::new(), &scratch.0);
    assert_eq!(
        failure(&out),
        (ScannerStatus::Error, Some(FailureCode::ExecutionError))
    );
    wait_dead(read_pid(&pidfile));
    no_scratch_left(&scratch.0);
}

#[test]
fn the_scanner_deadline_kills_a_hung_scanner_and_its_descendant() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-deadline");
    let dir = TempDir::new("proc-deadline-pid");
    let pidfile = dir.0.join("pid");
    let directive = format!("#spawnhang {}", pidfile.display());
    let mut s = Scenario::new(&[&directive]);
    s.limits.scanner_timeout_ms = 1500; // total budget for the scanner
    s.call_timeout = Duration::from_secs(120); // so only the deadline can end the call
    let started = Instant::now();
    let out = s.run(&node, &CancelToken::new(), &scratch.0);
    assert_artifact_ok(&out, &s.texts);
    assert_eq!(
        failure(&out),
        (ScannerStatus::Error, Some(FailureCode::Timeout))
    );
    assert!(started.elapsed() < Duration::from_secs(60));
    wait_dead(read_pid(&pidfile));
    no_scratch_left(&scratch.0);
}

#[test]
fn a_cancel_kills_the_running_scanner_and_is_recorded_as_cancelled() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-cancel");
    let dir = TempDir::new("proc-cancel-pid");
    let pidfile = dir.0.join("pid");
    let directive = format!("#spawnhang {}", pidfile.display());
    let mut s = Scenario::new(&[&directive]);
    s.call_timeout = Duration::from_secs(120);
    let cancel = CancelToken::new();
    let canceller = thread::spawn({
        let cancel = cancel.clone();
        let pidfile = pidfile.clone();
        move || {
            // Cancel once the scanner is demonstrably running its descendant.
            let start = Instant::now();
            while try_read_pid(&pidfile).is_none() && start.elapsed() < Duration::from_secs(30) {
                thread::sleep(Duration::from_millis(25));
            }
            cancel.cancel();
        }
    });
    let started = Instant::now();
    let out = s.run(&node, &cancel, &scratch.0);
    canceller.join().unwrap();
    assert_artifact_ok(&out, &s.texts);
    assert_eq!(
        failure(&out),
        (ScannerStatus::Error, Some(FailureCode::Cancelled))
    );
    assert!(started.elapsed() < Duration::from_secs(60));
    wait_dead(read_pid(&pidfile));
    no_scratch_left(&scratch.0);
}

#[test]
fn a_scanner_over_its_memory_share_is_stopped_with_a_resource_failure() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-memory");
    let mut s = Scenario::new(&["#mem 400"]);
    s.limits = limits(1, 1, 1, 1);
    s.limits.max_memory_bytes = 200 << 20; // one session: the whole budget is its share
    let out = s.run(&node, &CancelToken::new(), &scratch.0);
    assert_artifact_ok(&out, &s.texts);
    assert_eq!(
        failure(&out),
        (
            ScannerStatus::Error,
            Some(FailureCode::ResourceLimitExceeded)
        )
    );
    no_scratch_left(&scratch.0);
}

#[test]
fn a_scanner_that_fills_its_scratch_directory_is_stopped_and_the_scratch_removed() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-scratch");
    let mut s = Scenario::new(&["#tmpwrite 20"]);
    s.limits = limits(1, 1, 1, 1);
    s.limits.max_temporary_bytes = 5 << 20;
    let out = s.run(&node, &CancelToken::new(), &scratch.0);
    assert_artifact_ok(&out, &s.texts);
    assert_eq!(
        failure(&out),
        (
            ScannerStatus::Error,
            Some(FailureCode::ResourceLimitExceeded)
        )
    );
    no_scratch_left(&scratch.0);
}

#[test]
fn real_processes_give_the_same_digests_for_one_worker_and_many() {
    let Some(node) = node() else { return };
    let texts = [
        "mail a@example.invalid please",
        "#slow 300",
        "plain text",
        "#slow 150",
        "ssn 000-12-3456 here",
        "last one",
    ];
    let mut digests = Vec::new();
    for (workers, per, max_workers) in [(1u32, 1u32, 1usize), (4, 4, 4)] {
        let scratch = TempDir::new("proc-jobs");
        let mut s = Scenario::new(&texts);
        s.limits = limits(workers, per, 1, 4);
        // Same manifest limits in both runs would differ in the manifest digest, so
        // compare the measured parts: observation digests, rows and metrics.
        let snapshot = directive_snapshot(&s.texts);
        let adapter = adapter(&node, s.call_timeout, "normal");
        let plan = adapter
            .plan(ScannerConfiguration {
                parameters: vec![ConfigParameter {
                    key: ConfigKey::new("startup").unwrap(),
                    value: ConfigValue::Text("normal".to_owned()),
                }],
                activation: vec![ActivationSelector::new("pii:global").unwrap()],
            })
            .unwrap();
        // One manifest for both runs; only the host cap changes.
        let manifest = manifest(&snapshot, vec![plan], limits(4, 4, 1, 4), mechanics(2));
        let out = run(
            &RunRequest {
                snapshot: &snapshot,
                manifest: &manifest,
                adapters: vec![adapter as Arc<dyn ScannerAdapter>],
            },
            &RunConfig {
                executor: ExecutorConfig {
                    max_workers,
                    sample_interval: s.sample,
                    scratch_root: Some(scratch.0.clone()),
                    resources: ResourcePolicy::Enforce,
                    ..ExecutorConfig::default()
                },
                diagnostics: false,
                commit_cancelled: false,
            },
            &CancelToken::new(),
        )
        .unwrap();
        assert_artifact_ok(&out, &s.texts);
        assert_eq!(failure(&out), (ScannerStatus::Complete, None));
        digests.push((
            out.assembled.artifact.semantic_digest.clone(),
            out.assembled.observations[0].semantic_digest.clone(),
        ));
    }
    assert_eq!(digests[0], digests[1]);
}

#[test]
fn a_scanner_whose_answers_change_between_processes_is_unstable() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-flaky");
    let dir = TempDir::new("proc-flaky-counter");
    let counter = dir.0.join("count");
    let directive = format!("#flaky {}", counter.display());
    let s = Scenario::new(&[&directive]);
    let out = s.run(&node, &CancelToken::new(), &scratch.0);
    assert_artifact_ok(&out, &s.texts);
    assert_eq!(
        failure(&out),
        (
            ScannerStatus::Unstable,
            Some(FailureCode::ReplayDisagreement)
        )
    );
    assert!(!out.assembled.artifact.semantic.scanners[0].replays.agreed);
    no_scratch_left(&scratch.0);
}

#[test]
fn a_deadline_during_startup_kills_a_scanner_that_never_becomes_ready() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-startup-deadline");
    let mut s = Scenario::new(&["ok one"]);
    s.startup = "hang"; // the fake never answers `init`
    s.limits.scanner_timeout_ms = 1500;
    let started = Instant::now();
    let out = s.run(&node, &CancelToken::new(), &scratch.0);
    assert_artifact_ok(&out, &s.texts);
    assert_eq!(
        failure(&out),
        (ScannerStatus::Error, Some(FailureCode::Timeout))
    );
    // The adapter's own startup timeout is 20 s: the deadline ended it earlier.
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );
    no_scratch_left(&scratch.0);
}

#[test]
fn a_cancel_during_startup_kills_a_scanner_that_never_becomes_ready() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-startup-cancel");
    let mut s = Scenario::new(&["ok one"]);
    s.startup = "hang";
    let cancel = CancelToken::new();
    let canceller = thread::spawn({
        let cancel = cancel.clone();
        move || {
            thread::sleep(Duration::from_millis(700));
            cancel.cancel();
        }
    });
    let started = Instant::now();
    let out = s.run(&node, &cancel, &scratch.0);
    canceller.join().unwrap();
    assert_artifact_ok(&out, &s.texts);
    assert_eq!(
        failure(&out),
        (ScannerStatus::Error, Some(FailureCode::Cancelled))
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );
    no_scratch_left(&scratch.0);
}

#[test]
fn a_flood_of_non_protocol_stdout_lines_is_a_malformed_output_failure() {
    let Some(node) = node() else { return };
    let scratch = TempDir::new("proc-floodlines");
    let s = Scenario::new(&["ok one", "#floodlines"]);
    let out = s.run(&node, &CancelToken::new(), &scratch.0);
    assert_artifact_ok(&out, &s.texts);
    assert_eq!(
        failure(&out),
        (ScannerStatus::Error, Some(FailureCode::MalformedOutput))
    );
    no_scratch_left(&scratch.0);
}

#[test]
fn the_recorded_failure_is_the_lowest_index_with_real_processes_whatever_the_jobs() {
    let Some(node) = node() else { return };
    // Index 2 crashes (execution-error), index 4 is malformed: the crash is
    // always the recorded cause, with one worker or several.
    let texts = ["ok 0", "ok 1", "#crash", "ok 3", "#malformed", "ok 5"];
    let mut seen = Vec::new();
    for (workers, per) in [(1u32, 1u32), (4, 4)] {
        let scratch = TempDir::new("proc-lowest");
        let mut s = Scenario::new(&texts);
        s.limits = limits(workers, per, 1, 4);
        s.replays = 2;
        let out = s.run(&node, &CancelToken::new(), &scratch.0);
        assert_artifact_ok(&out, &s.texts);
        seen.push(failure(&out));
        no_scratch_left(&scratch.0);
    }
    assert_eq!(
        seen,
        vec![(ScannerStatus::Error, Some(FailureCode::ExecutionError)); 2]
    );
}
