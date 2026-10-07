//! Performance measurement harness (P10, issue #11, ADR 0013). Test support
//! shared by `examples/perf.rs` (the measurement driver, run in release mode by
//! `tools/perf/run.mjs`) and `tests/perf_harness.rs` (smoke and semantic-equality
//! tests at tiny sizes). Synthetic data only.
//!
//! One process measures one thing. Every function here times PHASES with
//! `Instant` (wall time) and returns plain data; process-level CPU time and
//! peak RSS are measured from outside by the orchestrator (`/usr/bin/time`),
//! because a process cannot report its own peak RSS without `unsafe` or a
//! dependency (the workspace forbids both, ADR 0013).
//!
//! The workload is the one the TypeScript oracle also runs: authored cases and
//! frozen scanner findings from `tools/perf/make-workload.mjs`, the oracle's
//! generated variants and findings from `tools/perf/oracle-bench.mjs --export`.
#![allow(dead_code, clippy::too_many_arguments, clippy::type_complexity)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use pii_eval_adapters::error::{MissingCapability, StartupStage};
use pii_eval_adapters::{
    AbortHandle, AdapterError, RuntimeRecord, ScanOutput, ScanSession, ScannerAdapter,
    SessionStats, StartFailure,
};
use pii_eval_cli::assemble::{AssembleOptions, assemble, variant_tasks};
use pii_eval_cli::exec::ScannerTiming;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ObservedInput, ResourcePolicy, ScannerRun};
use pii_eval_cli::run::{RunConfig, RunRequest, run};
use pii_eval_cli::write::{ArtifactWriter, OverwritePolicy};
use pii_eval_compat::legacy::{LegacyExpectation, LegacyScanner, interpret};
use pii_eval_compat::legacy_accounting::{LegacyMechanics, LegacyRow, Quirks, account_rows};
use pii_eval_contracts::axes::OutcomeRow;
use pii_eval_contracts::{
    ActionCapability, ActionOutcome, CapabilityState, CorpusSnapshot, FamilyCapability, FamilyId,
    Finding, JurisdictionCapability, JurisdictionCode, ObservationSet, ProtocolIdentity,
    ReplayRecord, RunArtifact, RunManifest, ScannerCapabilities, ScannerConfiguration, ScannerPlan,
    ScannerStatus, Sha256Digest, parse_default, seal, to_pretty_json, validate,
};
use pii_eval_kernel::methods::apply_review_strategy;
use pii_eval_kernel::{OffsetUnit, verify_run_artifact_accounting};
use serde_json::{Value, json};

use crate::parity::engine::manifest as parity_manifest;
use crate::parity::json::*;
use crate::parity::model::*;

/// Hard limits of the harness itself (it is bounded like everything else).
pub const MAX_REPEAT: usize = 50;
pub const MAX_WORKERS: u32 = 256;

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256Digest::of_bytes(bytes).as_str().to_owned()
}

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn time<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let t = Instant::now();
    let v = f();
    (v, ms(t))
}

// ---------------------------------------------------------------------------
// The workload
// ---------------------------------------------------------------------------

/// The frozen input and the oracle's observations of it, bound by digest.
pub struct Workload {
    pub input: Value,
    pub export: Value,
    pub input_sha256: String,
    pub params: Value,
}

/// Load and VALIDATE a workload before anything is measured: schemas, the digest
/// binding of the observations to the input, and the counts the parameters promise.
pub fn load(workload: &Path, observations: &Path) -> Result<Workload, String> {
    let input_bytes = std::fs::read(workload).map_err(|_| "workload unreadable".to_owned())?;
    let export_bytes =
        std::fs::read(observations).map_err(|_| "observations unreadable".to_owned())?;
    let input: Value =
        serde_json::from_slice(&input_bytes).map_err(|_| "workload is not JSON".to_owned())?;
    let export: Value = serde_json::from_slice(&export_bytes)
        .map_err(|_| "observations are not JSON".to_owned())?;
    if text(&input, "schema") != "pii-eval-parity-input/1"
        || text(get(&input, "workload"), "schema") != "pii-eval-perf-workload/1"
    {
        return Err("not a perf workload".to_owned());
    }
    if text(&export, "schema") != "pii-eval-perf-observations/1" {
        return Err("not a perf observations file".to_owned());
    }
    let input_sha256 = sha256_hex(&input_bytes);
    if text(&export, "workloadSha256") != input_sha256 {
        return Err("the observations were produced for another workload".to_owned());
    }
    let params = get(&input, "workload").clone();
    if uint(&params, "cases") as usize != list(&input, "cases").len()
        || uint(&params, "scanners") as usize != list(&input, "scanners").len()
        || list(&export, "scanners").len() != list(&input, "scanners").len()
        || list(&export, "cases").len() != list(&input, "cases").len()
    {
        return Err("workload counts disagree with its parameters".to_owned());
    }
    Ok(Workload {
        input,
        export,
        input_sha256,
        params,
    })
}

/// The counts that describe the size of a workload (all exact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub cases: u64,
    pub variants: u64,
    pub scanners: u64,
    pub findings: u64,
    pub text_bytes: u64,
}

pub struct Prepared {
    pub corpus: RustCorpus,
    pub snapshot: CorpusSnapshot,
    pub scanner_ids: Vec<String>,
    pub plans: Vec<ScannerPlan>,
    /// Per scanner: variant id -> findings in the order the scanner emitted them
    /// (the oracle's order; the engine paths sort a copy into canonical order).
    pub findings: Vec<HashMap<String, Vec<Finding>>>,
    pub counts: Counts,
}

fn capabilities() -> ScannerCapabilities {
    let fam = |s: &str| FamilyCapability {
        family: FamilyId::new(s).unwrap(),
        state: CapabilityState::Supported,
    };
    ScannerCapabilities {
        ranges: CapabilityState::Supported,
        family_classification: CapabilityState::Supported,
        sensitivity_classification: CapabilityState::Supported,
        jurisdiction_reporting: CapabilityState::Supported,
        action: ActionCapability::ReportedAction,
        families: vec![fam("pii:global:email"), fam("pii:us:ssn")],
        jurisdictions: vec![JurisdictionCapability {
            jurisdiction: JurisdictionCode::new("US").unwrap(),
            state: CapabilityState::Supported,
        }],
    }
}

fn plan_of(name: &str, salt: i64) -> ScannerPlan {
    use pii_eval_contracts::{
        ActivationSelector, AdapterIdentity, ConfigKey, ConfigParameter, ConfigValue,
        ProductIdentity, ScannerId, ScannerIdentity, VersionString,
    };
    let configuration = ScannerConfiguration {
        parameters: vec![ConfigParameter {
            key: ConfigKey::new("contextWindow").unwrap(),
            value: ConfigValue::Integer(salt),
        }],
        activation: vec![
            ActivationSelector::new("pii:global").unwrap(),
            ActivationSelector::new("pii:us").unwrap(),
        ],
    };
    ScannerPlan {
        identity: ScannerIdentity {
            scanner_id: ScannerId::new(name).unwrap(),
            scanner_version: Some(VersionString::new("1.0.0").unwrap()),
            artifact_digest: Some(Sha256Digest::of_bytes(
                format!("artifact-{name}").as_bytes(),
            )),
            adapter: AdapterIdentity {
                adapter_id: ScannerId::new("frozen-adapter").unwrap(),
                adapter_version: VersionString::new("0.0.1").unwrap(),
                normalization_version: 1,
            },
            product: ProductIdentity::Released,
            configuration_digest: configuration.configuration_digest().unwrap(),
            activation_digest: configuration.activation_digest().unwrap(),
        },
        configuration,
    }
}

/// Generate the corpus with the kernel's methods and bind the oracle's frozen
/// findings to the generated variants. Panics on a defect of the workload (the
/// harness validates before it measures; a defect must stop the run).
pub fn prepare(w: &Workload) -> Prepared {
    let corpus = rust_corpus(&w.input, &w.export);
    assert!(
        corpus.refused.is_empty(),
        "the kernel refused authored cases: {:?}",
        corpus.refused.len()
    );
    let snapshot = corpus.snapshot();
    let scanners = list(&w.export, "scanners");
    let mut ids: Vec<(String, usize)> = scanners
        .iter()
        .enumerate()
        .map(|(i, s)| (text(s, "id").to_owned(), i))
        .collect();
    // The manifest lists scanners ascending by id.
    ids.sort();
    let by_key: HashMap<(String, String), String> = corpus
        .variants
        .iter()
        .map(|v| (v.key(), v.variant.variant_id.as_str().to_owned()))
        .collect();
    let mut plans = Vec::new();
    let mut findings = Vec::new();
    let mut scanner_ids = Vec::new();
    let mut total = 0u64;
    for (n, (id, at)) in ids.iter().enumerate() {
        let mut per: HashMap<String, Vec<Finding>> = HashMap::new();
        for (key, f) in findings_of(&scanners[*at]) {
            total += f.len() as u64;
            let vid = by_key
                .get(&key)
                .unwrap_or_else(|| panic!("a frozen observation names no generated variant"));
            per.insert(vid.clone(), f);
        }
        findings.push(per);
        plans.push(plan_of(id, n as i64 + 1));
        scanner_ids.push(id.clone());
    }
    let text_bytes = corpus
        .variants
        .iter()
        .map(|v| v.variant.text.len() as u64)
        .sum();
    let counts = Counts {
        cases: list(&w.input, "cases").len() as u64,
        variants: corpus.variants.len() as u64,
        scanners: scanner_ids.len() as u64,
        findings: total,
        text_bytes,
    };
    Prepared {
        corpus,
        snapshot,
        scanner_ids,
        plans,
        findings,
        counts,
    }
}

/// The manifest for `p` with `workers` and `batch_variants` (a plan field, so it
/// is digested; the harness reseals it).
pub fn manifest_of(
    p: &Prepared,
    workers: u32,
    batch_variants: u32,
    per_scanner: u32,
    replays: u32,
) -> RunManifest {
    let mut manifest = parity_manifest(&p.snapshot, p.plans.clone(), workers);
    let per_scanner = per_scanner.clamp(1, workers);
    if manifest.semantic.limits.batch_variants != batch_variants
        || manifest.semantic.limits.per_scanner_parallelism != per_scanner
        || manifest.semantic.mechanics.replays != replays
    {
        manifest.semantic.limits.batch_variants = batch_variants;
        manifest.semantic.limits.per_scanner_parallelism = per_scanner;
        manifest.semantic.mechanics.replays = replays;
        seal(&mut manifest).expect("manifest seals");
    }
    manifest
}

fn zero_timing() -> ScannerTiming {
    ScannerTiming {
        startup: std::time::Duration::ZERO,
        scan: std::time::Duration::ZERO,
        wall: std::time::Duration::ZERO,
        started_at: SystemTime::UNIX_EPOCH,
        finished_at: SystemTime::UNIX_EPOCH,
        peak_rss_bytes: 0,
    }
}

fn canonical(f: Option<&Vec<Finding>>) -> Vec<Finding> {
    let mut v = f.cloned().unwrap_or_default();
    v.sort();
    v
}

/// Frozen results as the executor would deliver them (no scanner runs).
pub fn frozen_runs(p: &Prepared, replays: u32) -> Vec<ScannerRun> {
    let tasks = variant_tasks(&p.snapshot);
    let digests: Vec<Sha256Digest> = p
        .snapshot
        .semantic
        .cases
        .iter()
        .flat_map(|c| &c.variants)
        .map(|v| Sha256Digest::of_bytes(v.text.as_bytes()))
        .collect();
    p.plans
        .iter()
        .enumerate()
        .map(|(s, plan)| ScannerRun {
            plan: plan.clone(),
            status: ScannerStatus::Complete,
            capabilities: capabilities(),
            replays: ReplayRecord {
                count: replays,
                agreed: true,
            },
            inputs: tasks
                .iter()
                .enumerate()
                .map(|(index, t)| ObservedInput {
                    index,
                    input_digest: digests[index].clone(),
                    sanitized_output_digest: None,
                    findings: canonical(p.findings[s].get(t.variant_id.as_str())),
                    verification: None,
                })
                .collect(),
            failure: None,
            runtime: None,
            timing: zero_timing(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// An in-process adapter that replays frozen findings and counts its own time
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ReplayAdapter {
    plan: ScannerPlan,
    by_text: Arc<HashMap<String, Vec<Finding>>>,
    /// Nanoseconds spent inside `scan` over all sessions: the stand-in scanner's
    /// own time, so evaluator overhead can be told apart from it.
    pub scan_nanos: Arc<AtomicU64>,
    pub scans: Arc<AtomicU64>,
    /// Sessions started, sessions alive now and the most alive at once: deterministic bounds
    /// (never timings) that a work-counter test can assert.
    pub sessions: Arc<AtomicU64>,
    pub live: Arc<AtomicU64>,
    pub max_live: Arc<AtomicU64>,
}

struct Session {
    by_text: Arc<HashMap<String, Vec<Finding>>>,
    nanos: Arc<AtomicU64>,
    total_scans: Arc<AtomicU64>,
    live: Arc<AtomicU64>,
    runtime: RuntimeRecord,
    scans: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ScanSession for Session {
    fn runtime(&self) -> &RuntimeRecord {
        &self.runtime
    }

    fn capabilities(&self) -> &ScannerCapabilities {
        // One static value for every session.
        static CAPS: std::sync::OnceLock<ScannerCapabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(capabilities)
    }

    fn scan(&mut self, text: &str) -> Result<ScanOutput, AdapterError> {
        let t = Instant::now();
        self.scans += 1;
        let findings = self.by_text.get(text).cloned().unwrap_or_default();
        let out = ScanOutput {
            findings,
            input_digest: Sha256Digest::of_bytes(text.as_bytes()),
            sanitized_output_digest: None,
            sanitized_output: None,
            skipped_findings: 0,
        };
        self.nanos
            .fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        Ok(out)
    }

    fn finish(&mut self) -> SessionStats {
        SessionStats {
            scans: self.scans,
            stderr_bytes: 0,
            peak_rss_bytes: 0,
            pin_check: None,
        }
    }

    fn abort_handle(&self) -> AbortHandle {
        AbortHandle::inert()
    }
}

impl ScannerAdapter for ReplayAdapter {
    fn plan(&self, _configuration: ScannerConfiguration) -> Result<ScannerPlan, AdapterError> {
        Ok(self.plan.clone())
    }

    fn start(&self, plan: &ScannerPlan) -> Result<Box<dyn ScanSession>, StartFailure> {
        if *plan != self.plan {
            return Err(StartFailure {
                error: AdapterError::MissingCapability(MissingCapability::SelectorUnsupported),
                capabilities: capabilities(),
            });
        }
        let _ = StartupStage::Spawn;
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let now = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_live.fetch_max(now, Ordering::SeqCst);
        Ok(Box::new(Session {
            by_text: Arc::clone(&self.by_text),
            nanos: Arc::clone(&self.scan_nanos),
            total_scans: Arc::clone(&self.scans),
            live: Arc::clone(&self.live),
            scans: 0,
            runtime: RuntimeRecord {
                scanner_version: "1.0.0".to_owned(),
                runtime_name: "frozen-observation".to_owned(),
                runtime_version: "v1".to_owned(),
                activation_identity: "frozen".to_owned(),
                activation_identity_digest: Sha256Digest::of_bytes(b"frozen"),
                offset_unit: OffsetUnit::Utf8Bytes,
                protocol: "pii-eval-adapter/1",
                shim_digest: Sha256Digest::of_bytes(b"shim"),
                artifact_digest: Sha256Digest::of_bytes(b"artifact"),
            },
        }))
    }
}

pub fn replay_adapters(p: &Prepared) -> Vec<ReplayAdapter> {
    p.plans
        .iter()
        .enumerate()
        .map(|(s, plan)| {
            let mut by_text = HashMap::new();
            for v in &p.corpus.variants {
                if let Some(f) = p.findings[s].get(v.variant.variant_id.as_str()) {
                    assert!(
                        by_text
                            .insert(v.variant.text.clone(), canonical(Some(f)))
                            .is_none(),
                        "variant texts must be unique"
                    );
                }
            }
            ReplayAdapter {
                plan: plan.clone(),
                by_text: Arc::new(by_text),
                scan_nanos: Arc::new(AtomicU64::new(0)),
                scans: Arc::new(AtomicU64::new(0)),
                sessions: Arc::new(AtomicU64::new(0)),
                live: Arc::new(AtomicU64::new(0)),
                max_live: Arc::new(AtomicU64::new(0)),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Measurements (one JSON object each)
// ---------------------------------------------------------------------------

fn counts_json(c: &Counts) -> Value {
    json!({
        "cases": c.cases, "variants": c.variants, "scanners": c.scanners,
        "findings": c.findings, "textBytes": c.text_bytes,
    })
}

fn phases(map: BTreeMap<&str, Vec<f64>>) -> Value {
    Value::Object(
        map.into_iter()
            .map(|(k, v)| (k.to_owned(), json!(v)))
            .collect(),
    )
}

/// Digest of everything semantic a run produced (snapshot, manifest, observation
/// sets and artifact digests), so before/after and jobs=1 versus N compare by one string.
pub fn semantic_fingerprint(
    snapshot: &CorpusSnapshot,
    manifest: &RunManifest,
    observations: &[ObservationSet],
    artifact: &RunArtifact,
) -> String {
    let mut text = format!(
        "{}\n{}\n{}\n",
        snapshot.semantic_digest.as_str(),
        manifest.semantic_digest.as_str(),
        artifact.semantic_digest.as_str()
    );
    for o in observations {
        text.push_str(o.semantic_digest.as_str());
        text.push('\n');
    }
    sha256_hex(text.as_bytes())
}

/// Corpus generation and snapshot sealing from the authored cases.
pub fn measure_generate(w: &Workload, repeat: usize) -> Value {
    let mut ph: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    let mut digest = String::new();
    let mut variants = 0u64;
    for _ in 0..repeat {
        let (rc, t_gen) = time(|| rust_corpus(&w.input, &w.export));
        let (snapshot, t_seal) = time(|| rc.snapshot());
        let (r, t_validate) = time(|| validate(&snapshot));
        r.expect("snapshot validates");
        ph.entry("generate").or_default().push(t_gen);
        ph.entry("seal").or_default().push(t_seal);
        ph.entry("validate").or_default().push(t_validate);
        digest = snapshot.semantic_digest.as_str().to_owned();
        variants = rc.variants.len() as u64;
    }
    json!({ "mode": "generate", "variants": variants, "snapshotDigest": digest, "phasesMs": phases(ph) })
}

/// Kernel replay: accounting and verification over frozen observations, no scanner.
pub fn measure_replay(w: &Workload, repeat: usize, tmp: &Path) -> Value {
    let p = prepare(w);
    let manifest = manifest_of(&p, 4, 2, 2, 2);
    let runs = frozen_runs(&p, manifest.semantic.mechanics.replays);
    let tasks = variant_tasks(&p.snapshot);
    let mut ph: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    let mut fingerprint = String::new();
    let mut rows = 0u64;
    let mut bytes = (0u64, 0u64);
    let mut writer_refusal: Option<String> = None;
    let mut parse_refusal: Option<String> = None;
    for r in 0..repeat {
        let (assembled, t_assemble) = time(|| {
            assemble(
                &p.snapshot,
                &manifest,
                &tasks,
                &runs,
                AssembleOptions {
                    diagnostics: false,
                    run_started_at: SystemTime::now(),
                },
            )
            .expect("assembles")
        });
        ph.entry("assemble").or_default().push(t_assemble);
        ph.entry("assembleKernel")
            .or_default()
            .push(assembled.kernel_time.as_secs_f64() * 1000.0);
        let (v, t_verify) =
            time(|| verify_run_artifact_accounting(&assembled.artifact, &p.snapshot));
        v.expect("artifact verifies");
        ph.entry("verify").or_default().push(t_verify);
        let (v, t_validate) = time(|| validate(&assembled.artifact));
        v.expect("artifact validates");
        ph.entry("validate").or_default().push(t_validate);
        let (text, t_serialize) = time(|| to_pretty_json(&assembled.artifact).expect("serializes"));
        ph.entry("serialize").or_default().push(t_serialize);
        let (back, t_parse) = time(|| parse_default::<RunArtifact>(text.as_bytes()));
        // A document over the 32 MiB cap is refused by the parser: that is a measurement (a
        // ceiling), recorded, and the parse phases that need the parse to work are skipped.
        if back.is_ok() {
            ph.entry("parse").or_default().push(t_parse);
            // Where the parse and the digest go: the strict tree, the typed deserialization.
            let (tree, t_strict) =
                time(|| pii_eval_contracts::parse_strict(text.as_bytes(), &Default::default()));
            assert!(tree.is_ok());
            drop(tree);
            ph.entry("parseStrictTree").or_default().push(t_strict);
            let (typed, t_typed) = time(|| serde_json::from_slice::<RunArtifact>(text.as_bytes()));
            assert!(typed.is_ok());
            drop(typed);
            ph.entry("parseTyped").or_default().push(t_typed);
        } else {
            parse_refusal =
                Some("the artifact exceeds the document cap and does not parse".to_owned());
        }
        drop(back);
        let (d, t_digest) = time(|| pii_eval_contracts::compute_digest(&assembled.artifact));
        assert!(d.is_ok());
        ph.entry("digest").or_default().push(t_digest);
        rows = assembled.artifact.semantic.outcomes.len() as u64;
        bytes.0 = text.len() as u64;
        bytes.1 = assembled
            .observations
            .iter()
            .map(|o| to_pretty_json(o).expect("serializes").len() as u64)
            .sum();
        fingerprint = semantic_fingerprint(
            &p.snapshot,
            &manifest,
            &assembled.observations,
            &assembled.artifact,
        );
        // The full writer once (validate + verify + serialize + round trip + fsync + rename). A
        // document over the 32 MiB cap cannot round-trip: the writer refuses, and that is a
        // measurement (a ceiling), not a harness failure.
        if r == 0 {
            let mut assembled = assembled;
            let dir = tmp.join(format!("replay-writer-{}", std::process::id()));
            let writer = ArtifactWriter::new(&dir, OverwritePolicy::Replace);
            let (written, t_write) =
                time(|| writer.write_run(&p.snapshot, &manifest, &mut assembled, Instant::now()));
            match written {
                Ok(written) => {
                    ph.entry("writer").or_default().push(t_write);
                    // Validate, verify, serialize and round-trip every document (CPU) versus the
                    // atomic file commit (fsync and rename).
                    let ser = written.serialization.as_secs_f64() * 1000.0;
                    ph.entry("writerSerialize").or_default().push(ser);
                    ph.entry("writerCommit").or_default().push(t_write - ser);
                }
                Err(e) => writer_refusal = Some(format!("{e}")),
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    json!({
        "mode": "replay", "counts": counts_json(&p.counts), "rows": rows,
        "artifactBytes": bytes.0, "observationBytes": bytes.1, "writerRefusal": writer_refusal, "parseRefusal": parse_refusal,
        "fingerprint": fingerprint, "phasesMs": phases(ph),
    })
}

/// The oracle-faithful path: the legacy first-overlap rule and the oracle's
/// accounting port (`pii-eval-compat`), compared with the oracle's own counts.
pub fn measure_compat(w: &Workload, repeat: usize) -> Value {
    let p = prepare(w);
    let mut ph: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    // `None` when the observations carry no oracle counts (an export that skipped the oracle's evaluation).
    let has_counts = list(&w.export, "scanners")
        .iter()
        .all(|s| get(s, "metricCounts").is_object());
    let mut equal = true;
    for r in 0..repeat {
        let mut interpret_ms = 0.0;
        let mut account_ms = 0.0;
        let mut per_scanner = Vec::new();
        for (s, _) in p.scanner_ids.iter().enumerate() {
            let (rows, t) = time(|| {
                p.corpus
                    .variants
                    .iter()
                    .map(|v| {
                        let e = &v.variant.expectations[0];
                        let findings: &[Finding] = p.findings[s]
                            .get(v.variant.variant_id.as_str())
                            .map_or(&[], Vec::as_slice);
                        // Legacy rule over findings in emission order is the oracle's; the
                        // frozen lists are canonical-ordered here, so first-overlap may pick
                        // differently from the oracle when several findings overlap. The
                        // comparison below says whether that happened.
                        let outcome = interpret(
                            &LegacyExpectation {
                                candidate: e.range.unwrap(),
                                expected_type: e.type_expectation,
                                family: &e.family,
                                jurisdiction: v.case_jurisdiction.as_ref(),
                                sensitivity: e.sensitivity,
                            },
                            &LegacyScanner {
                                status: ScannerStatus::Complete,
                                findings,
                            },
                        );
                        let gated = apply_review_strategy(
                            OutcomeRow {
                                type_identity: outcome.type_identity,
                                sensitivity_context: outcome.sensitivity_context,
                                range: outcome.range,
                                action: ActionOutcome::NotMeasured,
                            },
                            v.variant.derivation.strategy,
                        );
                        LegacyRow {
                            case_id: v.case_id.clone(),
                            method: v.method,
                            variant: v.slot.clone(),
                            jurisdictional: v.case_jurisdiction.is_some(),
                            expected_type: e.type_expectation,
                            sensitivity: e.sensitivity,
                            context_class: e.context_class,
                            type_state: gated.type_identity,
                            sensitivity_state: outcome.sensitivity_context,
                            range: outcome.range,
                        }
                    })
                    .collect::<Vec<_>>()
            });
            interpret_ms += t;
            let (metrics, t) = time(|| {
                account_rows(&rows, &LegacyMechanics::PII_V1, Quirks::ORACLE).expect("accounts")
            });
            account_ms += t;
            per_scanner.push(metrics);
        }
        ph.entry("interpret").or_default().push(interpret_ms);
        ph.entry("account").or_default().push(account_ms);
        if r == 0 && has_counts {
            // Compare with the oracle's counts (frozen findings are in canonical order here,
            // the oracle saw emission order; equality is expected for one-finding behaviours
            // and not promised for dense overlaps, which is why it is reported, not asserted).
            let scanners = list(&w.export, "scanners");
            for (s, id) in p.scanner_ids.iter().enumerate() {
                let oracle = scanners
                    .iter()
                    .find(|x| text(x, "id") == id)
                    .expect("scanner");
                let want = get(get(oracle, "metricCounts"), "metrics");
                for (metric, m) in &per_scanner[s] {
                    let key = serde_json::to_value(metric)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default();
                    let o = get(want, &key);
                    let c = get(o, "counts");
                    let got = [
                        m.counts.eligible,
                        m.counts.measured,
                        m.counts.numerator,
                        m.counts.unresolved,
                        m.counts.not_measured,
                        m.counts.not_applicable,
                        m.counts.total,
                        m.effective_n,
                    ];
                    let exp = [
                        uint(c, "eligible"),
                        uint(c, "measured"),
                        uint(c, "numerator"),
                        uint(c, "unresolved"),
                        uint(c, "notMeasured"),
                        uint(c, "notApplicable"),
                        uint(c, "total"),
                        uint(o, "effectiveN"),
                    ];
                    equal &= got == exp;
                }
            }
        }
    }
    json!({ "mode": "compat", "counts": counts_json(&p.counts), "equalToOracleCounts": if has_counts { Value::Bool(equal) } else { Value::Null }, "phasesMs": phases(ph) })
}

/// The in-process pipeline: executor (worker pool, replays, batching), assembly
/// and kernel, with a stand-in scanner whose own time is counted.
pub fn measure_engine(
    w: &Workload,
    repeat: usize,
    workers: u32,
    batch: u32,
    per_scanner: u32,
    replays: u32,
) -> Value {
    let p = prepare(w);
    let manifest = manifest_of(&p, workers, batch, per_scanner, replays);
    let mut ph: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    let mut fingerprint = String::new();
    for _ in 0..repeat {
        let adapters = replay_adapters(&p);
        let counters: Vec<(Arc<AtomicU64>, Arc<AtomicU64>)> = adapters
            .iter()
            .map(|a| (Arc::clone(&a.scan_nanos), Arc::clone(&a.scans)))
            .collect();
        let request = RunRequest {
            snapshot: &p.snapshot,
            manifest: &manifest,
            adapters: adapters
                .into_iter()
                .map(|a| Arc::new(a) as Arc<dyn ScannerAdapter>)
                .collect(),
        };
        let (out, t_run) = time(|| {
            run(
                &request,
                &RunConfig {
                    executor: ExecutorConfig {
                        max_workers: workers.clamp(1, MAX_WORKERS) as usize,
                        resources: ResourcePolicy::Unenforced,
                        ..ExecutorConfig::default()
                    },
                    diagnostics: false,
                    commit_cancelled: false,
                },
                &CancelToken::new(),
            )
            .expect("the run")
        });
        ph.entry("run").or_default().push(t_run);
        ph.entry("kernel")
            .or_default()
            .push(out.assembled.kernel_time.as_secs_f64() * 1000.0);
        let nanos: u64 = counters.iter().map(|c| c.0.load(Ordering::Relaxed)).sum();
        let scans: u64 = counters.iter().map(|c| c.1.load(Ordering::Relaxed)).sum();
        // Summed over all workers (so it can exceed wall time when workers overlap).
        ph.entry("standInScannerSum")
            .or_default()
            .push(nanos as f64 / 1e6);
        ph.entry("scanCalls").or_default().push(scans as f64);
        fingerprint = semantic_fingerprint(
            &p.snapshot,
            &manifest,
            &out.assembled.observations,
            &out.assembled.artifact,
        );
    }
    json!({
        "mode": "engine", "counts": counts_json(&p.counts), "workers": workers, "batchVariants": batch,
        "perScannerParallelism": manifest.semantic.limits.per_scanner_parallelism,
        "replays": manifest.semantic.mechanics.replays,
        "fingerprint": fingerprint, "phasesMs": phases(ph),
    })
}

/// Load and prepare only: the baseline whose process cost (RSS, CPU) the other modes subtract.
pub fn measure_prepare(w: &Workload) -> Value {
    let (p, t) = time(|| prepare(w));
    json!({ "mode": "prepare", "counts": counts_json(&p.counts), "phasesMs": phases(BTreeMap::from([("prepare", vec![t])])) })
}

/// Write the documents of one in-process run (observation sets, artifacts, snapshot, manifest).
pub fn emit_documents(w: &Workload, dir: &Path, workers: u32) -> Value {
    let p = prepare(w);
    let manifest = manifest_of(&p, workers, 2, workers.min(2), 2);
    std::fs::create_dir_all(dir).expect("dir");
    std::fs::write(
        dir.join("snapshot.json"),
        to_pretty_json(&p.snapshot).expect("snapshot"),
    )
    .expect("write");
    let adapters = replay_adapters(&p)
        .into_iter()
        .map(|a| Arc::new(a) as Arc<dyn ScannerAdapter>)
        .collect();
    let writer = ArtifactWriter::new(dir.join("run"), OverwritePolicy::Replace).with_manifest();
    let (out, written) = pii_eval_cli::run::run_and_write(
        &RunRequest {
            snapshot: &p.snapshot,
            manifest: &manifest,
            adapters,
        },
        &RunConfig {
            executor: ExecutorConfig {
                max_workers: workers.clamp(1, MAX_WORKERS) as usize,
                resources: ResourcePolicy::Unenforced,
                ..ExecutorConfig::default()
            },
            diagnostics: false,
            commit_cancelled: false,
        },
        &CancelToken::new(),
        &writer,
    )
    .expect("the run");
    json!({
        "mode": "emit", "counts": counts_json(&p.counts),
        "files": written.files.iter().map(|f| json!({"name": f.name, "bytes": f.bytes, "sha256": f.sha256.as_str()})).collect::<Vec<_>>(),
        "fingerprint": semantic_fingerprint(&p.snapshot, &manifest, &out.assembled.observations, &out.assembled.artifact),
    })
}

/// Parse one document with `parse_default` (the strict tree, then the typed parse).
///
/// `stage`: `full` is `parse_default` (strict tree, typed parse, validation, digest); `strict`
/// is the strict value tree alone, `typed` the typed deserialization alone and `validate` the
/// typed parse followed by validation and the digest recomputation, so the memory
/// of the stages can be told apart (ADR 0008 section 6 measured only `full`).
pub fn measure_parse(doc: &Path, kind: &str, stage: &str, repeat: usize) -> Value {
    let bytes = std::fs::read(doc).expect("document");
    let mut ph: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    for _ in 0..repeat {
        let (ok, t) = time(|| match (stage, kind) {
            ("strict", _) => pii_eval_contracts::parse_strict(&bytes, &Default::default()).is_ok(),
            ("typed", "snapshot") => serde_json::from_slice::<CorpusSnapshot>(&bytes).is_ok(),
            ("typed", "observation") => serde_json::from_slice::<ObservationSet>(&bytes).is_ok(),
            ("typed", "artifact") => serde_json::from_slice::<RunArtifact>(&bytes).is_ok(),
            ("typed", "manifest") => serde_json::from_slice::<RunManifest>(&bytes).is_ok(),
            // typed parse, then structural validation and the digest recomputation (the stages after the strict tree)
            ("validate", "snapshot") => {
                serde_json::from_slice::<CorpusSnapshot>(&bytes).is_ok_and(|d| validate(&d).is_ok())
            }
            ("validate", "observation") => {
                serde_json::from_slice::<ObservationSet>(&bytes).is_ok_and(|d| validate(&d).is_ok())
            }
            ("validate", "artifact") => {
                serde_json::from_slice::<RunArtifact>(&bytes).is_ok_and(|d| validate(&d).is_ok())
            }
            ("validate", "manifest") => {
                serde_json::from_slice::<RunManifest>(&bytes).is_ok_and(|d| validate(&d).is_ok())
            }
            ("full", "snapshot") => parse_default::<CorpusSnapshot>(&bytes).is_ok(),
            ("full", "observation") => parse_default::<ObservationSet>(&bytes).is_ok(),
            ("full", "artifact") => parse_default::<RunArtifact>(&bytes).is_ok(),
            ("full", "manifest") => parse_default::<RunManifest>(&bytes).is_ok(),
            _ => panic!("unknown document kind or stage"),
        });
        assert!(ok, "the document parses");
        ph.entry("parse").or_default().push(t);
    }
    json!({ "mode": "parse", "kind": kind, "stage": stage, "bytes": bytes.len(), "phasesMs": phases(ph) })
}

pub fn protocol() -> ProtocolIdentity {
    ProtocolIdentity::CANONICAL_V2
}

/// Where the harness keeps scratch files.
pub fn scratch_dir() -> PathBuf {
    std::env::var_os("PII_EVAL_PERF_TMP").map_or_else(std::env::temp_dir, PathBuf::from)
}
