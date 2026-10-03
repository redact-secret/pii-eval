//! Synthetic custodian round trip (P12, docs/custodian-boundary.md).
//!
//! `SyntheticCustodian` below is a STUB written for this repository's tests. It
//! is NOT private-custodian and imports none of its code: it re-implements, from
//! that repository's published documents (`docs/contracts.md`,
//! `docs/worker-isolation.md`, `docs/benchmarks-integration.md`), only the few
//! checks this boundary needs, so that OUR side of the contract can be exercised
//! end to end: the stub authorizes a synthetic job, writes the job context, runs
//! the real `pii-eval` binary on SYNTHETIC data classed as protected, verifies
//! the internal artifact's domain, candidate, activation and population
//! bindings, and releases only a custodian-side projection (never the
//! engine's artifact). The projection format (`worker-result/1`, `aggregates/1`)
//! is what private-custodian documents as its input; this engine does not
//! emit it, so the mapping here is a PROPOSAL (docs/custodian-boundary.md).
//! Nothing here authorizes anything real.
#![cfg(unix)]

mod cli_support;
mod common;

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use cli_support::*;
use pii_eval_contracts::{
    ActivationSelector, CorpusSnapshot, ENGINE_VERSION, RunArtifact, RunClass, RunManifest,
    ScannerConfiguration, Visibility, parse_default, seal, to_pretty_json,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// The stub custodian
// ---------------------------------------------------------------------------

/// What the stub approved for one job. The real custodian binds more (budget,
/// approval ids, policy activation state); only what the engine boundary needs
/// is modelled.
#[derive(Clone)]
struct Approval {
    job_id: String,
    /// `pii` or `credential`; this engine serves only `pii` (protocol `pii-v1`).
    domain: &'static str,
    population_digest: String,
    manifest_digest: String,
    candidate_digest: String,
    activation_digest: String,
    /// Unix seconds after which the stub refuses to start or to release.
    not_after: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    WrongDomain,
    Expired,
    Revoked,
}

#[derive(Debug, PartialEq, Eq)]
enum Mismatch {
    Domain,
    Candidate,
    Activation,
    Population,
    Manifest,
    RunClass,
    Incomplete,
    /// The engine's own verifier (digest, bindings, accounting) refused the artifact.
    EngineVerification,
    /// A run measures exactly one scanner; another count is not supported.
    ScannerCount,
}

struct SyntheticCustodian {
    approval: Approval,
    revoked: Cell<bool>,
}

/// A verified internal result. It exists only after every binding matched.
struct Verified {
    artifact: Value,
}

/// What may leave the (stub) custodian: counters and integers per allowlisted
/// label, never case identities.
struct Projection {
    worker_result: Value,
    aggregates: Value,
}

impl SyntheticCustodian {
    fn new(approval: Approval) -> Self {
        Self {
            approval,
            revoked: Cell::new(false),
        }
    }

    fn revoke(&self) {
        self.revoked.set(true);
    }

    /// The custodian authorizes (or refuses) BEFORE the engine runs: freshness
    /// and revocation are its state, the engine has no clock authority.
    fn issue_job_context(
        &self,
        requested_domain: &str,
        now: u64,
        job: &Job,
    ) -> Result<PathBuf, Refusal> {
        if requested_domain != self.approval.domain || self.approval.domain != "pii" {
            return Err(Refusal::WrongDomain);
        }
        if self.revoked.get() {
            return Err(Refusal::Revoked);
        }
        if now > self.approval.not_after {
            return Err(Refusal::Expired);
        }
        let text = serde_json::to_string_pretty(&json!({
            "schema": "pii-eval-job-context/1",
            "jobId": self.approval.job_id,
            "custodian": "synthetic-custodian-stub",
            "runClass": "protected",
            "populationDigest": self.approval.population_digest,
            "manifestDigest": self.approval.manifest_digest,
            "candidateDigest": self.approval.candidate_digest,
            "inputRoot": s(&std::fs::canonicalize(&job.input_root).unwrap()),
            "outputRoot": s(&std::fs::canonicalize(&job.output_root).unwrap()),
        }))
        .unwrap();
        let path = job
            .ws
            .tmp
            .0
            .join(format!("{}.job-context.json", self.approval.job_id));
        write_private(&path, &text);
        Ok(path)
    }

    /// Verify the engine's INTERNAL artifact: cheap binding checks against the
    /// approval, then the engine's own verifier (strict parse, digest, bindings
    /// to the snapshot and manifest, accounting recomputed from the rows) run
    /// inside a validation context. A `Verified` value exists only after both,
    /// and `release` takes nothing else, so an artifact edited after the run
    /// (re-sealed or not) cannot reach release even if the caller skips a step.
    fn verify_internal(&self, job: &Job, out: &Path) -> Result<Verified, Mismatch> {
        let bytes = std::fs::read(out.join("run-artifact.json")).unwrap();
        let artifact: Value =
            serde_json::from_slice(&bytes).map_err(|_| Mismatch::EngineVerification)?;
        self.check_bindings(&artifact)?;
        self.engine_validate(job, out, &bytes, &artifact)?;
        Ok(Verified { artifact })
    }

    fn check_bindings(&self, artifact: &Value) -> Result<(), Mismatch> {
        let a = &self.approval;
        let sem = &artifact["semantic"];
        // Domain: the protocol the artifact claims must be the one the approved
        // domain maps to.
        let protocol = if a.domain == "pii" {
            "pii-v1"
        } else {
            "credential-v1"
        };
        if sem["protocol"]["id"] != protocol {
            return Err(Mismatch::Domain);
        }
        if sem["runClass"] != "protected" || sem["population"]["visibility"] != "protected" {
            return Err(Mismatch::RunClass);
        }
        if sem["population"]["populationDigest"] != a.population_digest {
            return Err(Mismatch::Population);
        }
        if sem["manifestDigest"] != a.manifest_digest {
            return Err(Mismatch::Manifest);
        }
        // Exactly one scanner per run (docs/cli.md known limits); every scanner
        // block present is bound, and a different count is refused.
        let scanners = sem["scanners"].as_array().map_or(0, Vec::len);
        if scanners != 1 || sem["scannerMetrics"].as_array().map_or(0, Vec::len) != 1 {
            return Err(Mismatch::ScannerCount);
        }
        let identity = &sem["scanners"][0]["identity"];
        if identity["product"]["candidateDigest"] != a.candidate_digest {
            return Err(Mismatch::Candidate);
        }
        if identity["activationDigest"] != a.activation_digest {
            return Err(Mismatch::Activation);
        }
        if sem["scannerMetrics"][0]["scannerId"] != identity["scannerId"] {
            return Err(Mismatch::ScannerCount);
        }
        if sem["completeness"] != "complete" || sem["scanners"][0]["status"] != "complete" {
            return Err(Mismatch::Incomplete);
        }
        Ok(())
    }

    fn engine_validate(
        &self,
        job: &Job,
        out: &Path,
        artifact_bytes: &[u8],
        artifact: &Value,
    ) -> Result<(), Mismatch> {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let staging = job.ws.tmp.0.join(format!("validate-in-{n}"));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::copy(&job.snapshot, staging.join("snapshot.json")).unwrap();
        std::fs::copy(out.join("manifest.json"), staging.join("manifest.json")).unwrap();
        std::fs::write(staging.join("run-artifact.json"), artifact_bytes).unwrap();
        let context = job.ws.tmp.0.join(format!("validate-{n}.job-context.json"));
        let text = serde_json::to_string_pretty(&json!({
            "schema": "pii-eval-job-context/1",
            "jobId": self.approval.job_id,
            "custodian": "synthetic-custodian-stub",
            "runClass": "protected",
            "populationDigest": self.approval.population_digest,
            "manifestDigest": self.approval.manifest_digest,
            "candidateDigest": self.approval.candidate_digest,
            "inputRoot": s(&std::fs::canonicalize(&staging).unwrap()),
            "outputRoot": s(&std::fs::canonicalize(&job.output_root).unwrap()),
        }))
        .unwrap();
        write_private(&context, &text);
        let checked = run_cli(&[
            "validate",
            s(&staging.join("run-artifact.json")),
            "--snapshot",
            s(&staging.join("snapshot.json")),
            "--manifest",
            s(&staging.join("manifest.json")),
            "--job-context",
            s(&context),
        ]);
        if code(&checked) != 0 {
            return Err(Mismatch::EngineVerification);
        }
        let v = summary(&checked);
        // The engine verified exactly the document that is being released.
        if v["semantic"]["verification"] != "verified"
            || v["semantic"]["semanticDigest"] != artifact["semanticDigest"]
        {
            return Err(Mismatch::EngineVerification);
        }
        Ok(())
    }

    /// Release decision, taken at release time against CURRENT state: a prior
    /// success is evidence, never permission.
    fn release(&self, verified: &Verified, now: u64) -> Result<Projection, Refusal> {
        if self.revoked.get() {
            return Err(Refusal::Revoked);
        }
        if now > self.approval.not_after {
            return Err(Refusal::Expired);
        }
        Ok(project(&verified.artifact))
    }
}

/// PROPOSED mapping of the internal artifact to the two documents
/// private-custodian takes as input (docs/custodian-boundary.md, section 6).
fn project(artifact: &Value) -> Projection {
    let sem = &artifact["semantic"];
    let rows = sem["outcomes"].as_array().unwrap().len() as u64;
    let protocol =
        json!({"name": sem["protocol"]["id"], "version": sem["protocol"]["version"].to_string()});
    let roster = json!({"expected": rows, "observed": rows, "failed": 0});
    let cells: Vec<Value> = sem["scannerMetrics"][0]["metrics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            json!({
                "stratum": "overall",
                "metric": m["metric"]["id"],
                "numerator": m["counts"]["numerator"],
                "denominator": m["counts"]["measured"],
            })
        })
        .collect();
    Projection {
        worker_result: json!({
            "schema": "private-custodian.worker-result/1",
            "domain": "pii",
            "protocol": protocol,
            "status": "complete",
            "roster": roster,
        }),
        aggregates: json!({
            "schema": "private-custodian.aggregates/1",
            "domain": "pii",
            "protocol": protocol,
            "roster": roster,
            "cells": cells,
        }),
    }
}

fn label_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c))
}

/// The documented custodian rules for the two documents (re-implemented from
/// its docs, not imported): closed shapes, bounded size, consistent counters.
fn check_projection(p: &Projection, authorized_roster: u64) {
    let wr = serde_json::to_string(&p.worker_result).unwrap();
    assert!(wr.len() <= 64 * 1024);
    let w = p.worker_result.as_object().unwrap();
    assert_eq!(
        w.keys().map(String::as_str).collect::<Vec<_>>(),
        ["domain", "protocol", "roster", "schema", "status"]
    );
    let r = &w["roster"];
    assert_eq!(r["expected"], authorized_roster);
    assert!(r["observed"].as_u64() <= r["expected"].as_u64());
    assert!(r["failed"].as_u64() <= r["observed"].as_u64());
    assert_eq!(w["status"] == "complete", r["observed"] == r["expected"]);
    let ag = serde_json::to_string(&p.aggregates).unwrap();
    assert!(ag.len() <= 64 * 1024);
    let a = p.aggregates.as_object().unwrap();
    assert_eq!(
        a.keys().map(String::as_str).collect::<Vec<_>>(),
        ["cells", "domain", "protocol", "roster", "schema"]
    );
    assert_eq!(a["roster"], *r);
    let cells = a["cells"].as_array().unwrap();
    assert!(!cells.is_empty() && cells.len() <= 256);
    let mut seen = std::collections::BTreeSet::new();
    for c in cells {
        let c = c.as_object().unwrap();
        assert_eq!(
            c.keys().map(String::as_str).collect::<Vec<_>>(),
            ["denominator", "metric", "numerator", "stratum"]
        );
        assert!(label_ok(c["stratum"].as_str().unwrap()));
        assert!(label_ok(c["metric"].as_str().unwrap()));
        let (n, d) = (
            c["numerator"].as_u64().unwrap(),
            c["denominator"].as_u64().unwrap(),
        );
        assert!(n <= d && d <= r["observed"].as_u64().unwrap(), "{c:?}");
        assert!(
            seen.insert((c["stratum"].to_string(), c["metric"].to_string())),
            "duplicate cell"
        );
    }
}

// ---------------------------------------------------------------------------
// A protected workspace: SYNTHETIC data, classed as protected for the test
// ---------------------------------------------------------------------------

struct Job {
    ws: Workspace,
    input_root: PathBuf,
    output_root: PathBuf,
    snapshot: PathBuf,
    config: PathBuf,
    population_digest: String,
    manifest_digest: String,
    candidate_digest: String,
}

fn write_private(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn protected_job(label: &str, node: &Path) -> Job {
    let ws = Workspace::new(label, node);
    let input_root = ws.tmp.0.join("custodian-in");
    let output_root = ws.tmp.0.join("custodian-out");
    std::fs::create_dir_all(&input_root).unwrap();
    std::fs::create_dir_all(&output_root).unwrap();
    let mut snapshot: CorpusSnapshot = read_snapshot(&ws.snapshot);
    snapshot.semantic.population.visibility = Visibility::Protected;
    seal(&mut snapshot).unwrap();
    let snapshot_path = input_root.join("snapshot.json");
    std::fs::write(&snapshot_path, to_pretty_json(&snapshot).unwrap()).unwrap();
    let mut manifest: RunManifest = parse_default(&std::fs::read(&ws.manifest).unwrap()).unwrap();
    manifest.semantic.run_class = RunClass::Protected;
    manifest.semantic.population.visibility = Visibility::Protected;
    manifest.semantic.population.population_digest = snapshot.semantic_digest.clone();
    seal(&mut manifest).unwrap();
    let manifest_path = input_root.join("manifest.json");
    std::fs::write(&manifest_path, to_pretty_json(&manifest).unwrap()).unwrap();
    let mut spec = ConfigSpec::new(&snapshot_path, &manifest_path, &ws.package);
    spec.mode = "official";
    spec.run_class = "protected";
    spec.snapshot_digest = Some(snapshot.semantic_digest.as_str());
    spec.manifest_digest = Some(manifest.semantic_digest.as_str());
    let extra = format!(
        r#","engineVersion": "{ENGINE_VERSION}","protocol": {{"id": "pii-v1", "revision": 2}}"#
    );
    spec.extra_top = &extra;
    let config = ws.tmp.0.join("protected.json");
    std::fs::write(&config, spec.json()).unwrap();
    let candidate_digest = pii_eval_adapters::sha256_of_tree(&ws.package)
        .unwrap()
        .as_str()
        .to_owned();
    Job {
        population_digest: snapshot.semantic_digest.as_str().to_owned(),
        manifest_digest: manifest.semantic_digest.as_str().to_owned(),
        candidate_digest,
        ws,
        input_root,
        output_root,
        snapshot: snapshot_path,
        config,
    }
}

impl Job {
    fn approval(&self, activation_digest: &str) -> Approval {
        Approval {
            job_id: "job-0001".into(),
            domain: "pii",
            population_digest: self.population_digest.clone(),
            manifest_digest: self.manifest_digest.clone(),
            candidate_digest: self.candidate_digest.clone(),
            activation_digest: activation_digest.to_owned(),
            not_after: 2_000,
        }
    }

    fn run(&self, context: Option<&Path>, out: &Path) -> Output {
        let mut args = vec![
            "run",
            "--config",
            s(&self.config),
            "--node",
            s(&self.ws.node),
            "--out",
            s(out),
        ];
        if let Some(c) = context {
            args.push("--job-context");
            args.push(s(c));
        }
        run_cli(&args)
    }
}

fn reason(v: &Value) -> &str {
    v["error"]["reason"].as_str().unwrap_or_default()
}

/// The approved scanner activation, derived INDEPENDENTLY of any run from the
/// activation selectors the custodian approved (the contracts' own activation
/// digest function), so the binding check is not a comparison of the engine's
/// output with itself.
fn approved_activation() -> String {
    activation_of(&["pii:global", "pii:us"])
}

fn activation_of(selectors: &[&str]) -> String {
    ScannerConfiguration {
        parameters: core_configuration().parameters,
        activation: selectors
            .iter()
            .map(|s| ActivationSelector::new(*s).unwrap())
            .collect(),
    }
    .activation_digest()
    .unwrap()
    .as_str()
    .to_owned()
}

/// Case ids, variant ids, texts, digests and source identities of the population.
fn collect_values(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                let wanted = [
                    "caseId",
                    "variantId",
                    "occurrenceId",
                    "text",
                    "textDigest",
                    "sourceId",
                    "sourceDigest",
                ];
                if let (true, Value::String(s)) = (wanted.contains(&k.as_str()), x) {
                    out.push(s.clone());
                }
                collect_values(x, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_values(x, out)),
        _ => {}
    }
}

fn collect_seeds(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if let (true, Value::String(s)) = (k.to_lowercase().contains("seed"), x) {
                    // `seedDerivation` names a rule, not a seed value.
                    if k != "seedDerivation" {
                        out.push(s.clone());
                    }
                }
                collect_seeds(x, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_seeds(x, out)),
        _ => {}
    }
}

fn consume(args: &[&str]) -> (i32, Value) {
    let consumer = repo_root().join("examples/consumer/consume.mjs");
    let out = Command::new(node().expect("node"))
        .arg(consumer)
        .args(args)
        .output()
        .expect("node runs");
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn a_protected_job_round_trips_and_only_the_custodian_projection_may_leave() {
    let node = node_or_return!();
    let job = protected_job("rt-ok", &node);
    let activation = approved_activation();
    let custodian = SyntheticCustodian::new(job.approval(&activation));
    let context = custodian.issue_job_context("pii", 1_000, &job).unwrap();
    let out = job.output_root.join("run");
    let result = job.run(Some(&context), &out);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    let summary = summary(&result);
    assert_eq!(summary["semantic"]["runClass"], "protected");
    // The engine wrote the INTERNAL documents only: no public projection, no
    // counts in the summary.
    assert_eq!(
        list_dir(&out),
        [
            "manifest.json",
            "observation-redact-secret-core.json",
            "run-artifact.json"
        ]
    );
    assert!(summary["semantic"].get("populationCounts").is_none());

    // The custodian verifies every binding AND runs the engine's verifier on the
    // exact document before it believes the result.
    let verified = custodian
        .verify_internal(&job, &out)
        .expect("bindings match and the engine verifies");

    // Release: custodian-side projection, within the documented bounds.
    let projection = custodian.release(&verified, 1_500).expect("release");
    let roster = projection.worker_result["roster"]["expected"]
        .as_u64()
        .unwrap();
    check_projection(&projection, roster);
    // It carries no case identity, text, seed or range from the population.
    let leaked = serde_json::to_string(&projection.aggregates).unwrap()
        + &serde_json::to_string(&projection.worker_result).unwrap();
    let snapshot: Value =
        serde_json::from_str(&std::fs::read_to_string(&job.snapshot).unwrap()).unwrap();
    let mut protected_values = Vec::new();
    collect_values(&snapshot, &mut protected_values);
    assert!(
        protected_values.len() > 20,
        "the check has population values to look for"
    );
    for value in &protected_values {
        assert!(
            !leaked.contains(value.as_str()),
            "a population value reached the projection"
        );
    }
    // Seeds too: from every document of the run that records one (a snapshot of
    // authored cases records none; the check is that no `seed` string, wherever
    // the population or the artifact keeps one, appears in the projection).
    let mut seeds = Vec::new();
    for name in [
        "manifest.json",
        "observation-redact-secret-core.json",
        "run-artifact.json",
    ] {
        let doc: Value = serde_json::from_slice(&std::fs::read(out.join(name)).unwrap()).unwrap();
        collect_seeds(&doc, &mut seeds);
    }
    collect_seeds(&snapshot, &mut seeds);
    for seed in &seeds {
        assert!(
            !leaked.contains(seed.as_str()),
            "a seed reached the projection"
        );
    }
    // The consumer example never reads the internal artifact: the benchmarks
    // side receives only what the custodian releases.
    let pins = job.ws.tmp.0.join("pins.json");
    std::fs::write(
        &pins,
        std::fs::read_to_string(repo_root().join("examples/consumer/fixtures/pins.json")).unwrap(),
    )
    .unwrap();
    let (status, report) = consume(&["--pins", s(&pins), s(&out.join("run-artifact.json"))]);
    assert_eq!(status, 1);
    assert!(
        report
            .to_string()
            .contains("internal-artifact-not-consumable")
    );

    // The documented determinism: the same job gives byte-identical documents.
    let again = job.output_root.join("run-again");
    assert_eq!(code(&job.run(Some(&context), &again)), 0);
    for name in [
        "manifest.json",
        "run-artifact.json",
        "observation-redact-secret-core.json",
    ] {
        assert_eq!(
            std::fs::read(out.join(name)).unwrap(),
            std::fs::read(again.join(name)).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn the_public_synthetic_path_needs_no_custodian_and_reaches_the_consumer() {
    // The same engine, a public synthetic population, no context: the public
    // projection exists and the consumer verifies it against exact pins.
    let node = node_or_return!();
    let ws = Workspace::new("rt-public", &node);
    let out = ws.out("public");
    let result = ws.run(&out);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    let public: Value =
        serde_json::from_slice(&std::fs::read(out.join("public-synthetic-artifact.json")).unwrap())
            .unwrap();
    let sem = &public["semantic"];
    let pins = json!({
        "schema": "pii-eval-consumer-pins/1",
        "engine": sem["engine"],
        "protocol": sem["protocol"],
        "artifactSchema": {"id": public["schema"], "version": public["schemaVersion"]},
        "requireComplete": true,
        "populations": [{
            "label": "demo",
            "population": sem["population"],
            "runClass": sem["runClass"],
            "artifactDigest": public["semanticDigest"],
            "manifestDigest": sem["manifestDigest"],
            "scanners": [sem["scanners"][0]["identity"]],
        }],
    });
    let pins_path = ws.tmp.0.join("pins.json");
    std::fs::write(&pins_path, pins.to_string()).unwrap();
    let (status, report) = consume(&[
        "--pins",
        s(&pins_path),
        s(&out.join("public-synthetic-artifact.json")),
    ]);
    assert_eq!(status, 0, "{report}");
    assert_eq!(report["populations"][0]["status"], "accepted");
}

#[test]
fn a_missing_context_is_refused_before_any_input_is_read() {
    let node = node_or_return!();
    let job = protected_job("rt-missing", &node);
    let out = job.output_root.join("run");
    let result = job.run(None, &out);
    assert_eq!(code(&result), 9);
    assert_eq!(reason(&summary(&result)), "protected-context-required");
    assert!(!out.exists());
}

#[test]
fn wrong_population_candidate_or_manifest_in_the_context_is_refused_by_the_engine() {
    let node = node_or_return!();
    let job = protected_job("rt-bindings", &node);
    let zero = "0".repeat(64);
    let cases = [
        (
            "population",
            Approval {
                population_digest: zero.clone(),
                ..job.approval(&zero)
            },
        ),
        (
            "candidate",
            Approval {
                candidate_digest: zero.clone(),
                ..job.approval(&zero)
            },
        ),
        (
            "manifest",
            Approval {
                manifest_digest: zero.clone(),
                ..job.approval(&zero)
            },
        ),
    ];
    for (name, approval) in cases {
        let context = SyntheticCustodian::new(approval)
            .issue_job_context("pii", 1, &job)
            .unwrap();
        let out = job.output_root.join(format!("run-{name}"));
        let result = job.run(Some(&context), &out);
        assert_eq!(code(&result), 9, "{name}");
        assert_eq!(
            reason(&summary(&result)),
            "protected-context-mismatch",
            "{name}"
        );
        assert!(!out.exists(), "{name}: nothing is written");
    }
}

#[test]
fn the_custodian_rejects_a_result_whose_activation_domain_or_other_binding_differs() {
    let node = node_or_return!();
    let job = protected_job("rt-verify", &node);
    let activation = approved_activation();
    let context = SyntheticCustodian::new(job.approval(&activation))
        .issue_job_context("pii", 1, &job)
        .unwrap();
    let out = job.output_root.join("run");
    assert_eq!(code(&job.run(Some(&context), &out)), 0);

    let other = "f".repeat(64);
    let wrong = |edit: &dyn Fn(&mut Approval)| {
        let mut a = job.approval(&activation);
        edit(&mut a);
        SyntheticCustodian::new(a).verify_internal(&job, &out).err()
    };
    assert_eq!(wrong(&|_| {}), None, "the unedited approval verifies");
    assert_eq!(
        wrong(&|a| a.activation_digest = other.clone()),
        Some(Mismatch::Activation)
    );
    assert_eq!(
        wrong(&|a| a.candidate_digest = other.clone()),
        Some(Mismatch::Candidate)
    );
    assert_eq!(
        wrong(&|a| a.population_digest = other.clone()),
        Some(Mismatch::Population)
    );
    assert_eq!(
        wrong(&|a| a.manifest_digest = other.clone()),
        Some(Mismatch::Manifest)
    );
    assert_eq!(wrong(&|a| a.domain = "credential"), Some(Mismatch::Domain));
    // An activation the custodian approved that is a REAL, different one (derived
    // from other selectors), not just a random digest.
    let narrower = activation_of(&["pii:global"]);
    assert_ne!(narrower, activation);
    assert_eq!(
        wrong(&|a| a.activation_digest = narrower.clone()),
        Some(Mismatch::Activation)
    );
    // Exactly one scanner per run: a second block is refused, not silently ignored.
    let custodian = SyntheticCustodian::new(job.approval(&activation));
    let mut artifact: Value =
        serde_json::from_slice(&std::fs::read(out.join("run-artifact.json")).unwrap()).unwrap();
    let scanner = artifact["semantic"]["scanners"][0].clone();
    artifact["semantic"]["scanners"]
        .as_array_mut()
        .unwrap()
        .push(scanner);
    assert_eq!(
        custodian.check_bindings(&artifact),
        Err(Mismatch::ScannerCount)
    );

    // A public-synthetic artifact is not a protected result.
    let public = Workspace::new("rt-verify-public", &node);
    let public_out = public.out("p");
    assert_eq!(code(&public.run(&public_out)), 0);
    assert_eq!(
        SyntheticCustodian::new(job.approval(&activation))
            .verify_internal(&job, &public_out)
            .err(),
        Some(Mismatch::RunClass)
    );
}

#[test]
fn an_expired_wrong_domain_or_revoked_job_is_never_started_and_a_revoked_result_is_never_released()
{
    let node = node_or_return!();
    let job = protected_job("rt-state", &node);
    let activation = approved_activation();
    let custodian = SyntheticCustodian::new(job.approval(&activation));
    // Expired: the stub writes no context, so the engine, run anyway, refuses.
    assert_eq!(
        custodian.issue_job_context("pii", 2_001, &job),
        Err(Refusal::Expired)
    );
    let out = job.output_root.join("no-context");
    let result = job.run(None, &out);
    assert_eq!(code(&result), 9);
    assert_eq!(reason(&summary(&result)), "protected-context-required");
    // Another domain is refused before any context exists.
    assert_eq!(
        custodian.issue_job_context("credential", 1, &job),
        Err(Refusal::WrongDomain)
    );

    // Revocation between execution and release: the verified result stays
    // private; nothing is projected.
    let context = custodian.issue_job_context("pii", 1_000, &job).unwrap();
    let run_out = job.output_root.join("run");
    assert_eq!(code(&job.run(Some(&context), &run_out)), 0);
    let verified = custodian.verify_internal(&job, &run_out).unwrap();
    custodian.revoke();
    assert_eq!(
        custodian.release(&verified, 1_001).err(),
        Some(Refusal::Revoked)
    );
    assert_eq!(
        custodian.issue_job_context("pii", 1, &job),
        Err(Refusal::Revoked)
    );
    // Expiry at release time is enforced too, independently of revocation.
    let fresh = SyntheticCustodian::new(job.approval(&activation));
    let verified = fresh.verify_internal(&job, &run_out).unwrap();
    assert_eq!(
        fresh.release(&verified, 2_001).err(),
        Some(Refusal::Expired)
    );
}

#[test]
fn a_tampered_internal_artifact_never_reaches_release() {
    let node = node_or_return!();
    let job = protected_job("rt-tamper", &node);
    let activation = approved_activation();
    let custodian = SyntheticCustodian::new(job.approval(&activation));
    let context = custodian.issue_job_context("pii", 1, &job).unwrap();
    let out = job.output_root.join("run");
    assert_eq!(code(&job.run(Some(&context), &out)), 0);
    assert!(custodian.verify_internal(&job, &out).is_ok());

    let tamper_dir = |name: &str, artifact: &[u8]| {
        let dir = job.output_root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(out.join("manifest.json"), dir.join("manifest.json")).unwrap();
        std::fs::write(dir.join("run-artifact.json"), artifact).unwrap();
        dir
    };
    let text = std::fs::read_to_string(out.join("run-artifact.json")).unwrap();

    // 1. A metric count edited after the fact, digest left alone: the engine's
    //    strict parse refuses it.
    let edited = text.replacen("\"numerator\": 1", "\"numerator\": 2", 1);
    assert_ne!(edited, text, "the fixture has a numerator to edit");
    let dir = tamper_dir("tamper-stale-digest", edited.as_bytes());
    assert_eq!(
        custodian.verify_internal(&job, &dir).err(),
        Some(Mismatch::EngineVerification)
    );

    // 2. The same edit RE-SEALED with a correct digest: the document is
    //    well-formed, so only the accounting verifier (metrics recomputed from
    //    the rows against the snapshot) can refuse it.
    let mut doc: RunArtifact = parse_default(text.as_bytes()).unwrap();
    // A metric with room in its numerator, so the edit stays structurally valid.
    let metric = doc.semantic.scanner_metrics[0]
        .metrics
        .iter_mut()
        .find(|m| m.counts.numerator < m.counts.measured)
        .expect("a metric with a non-numerator sample");
    metric.counts.numerator += 1;
    seal(&mut doc).unwrap();
    let resealed = to_pretty_json(&doc).unwrap();
    assert!(
        parse_default::<RunArtifact>(resealed.as_bytes()).is_ok(),
        "a valid, re-sealed document"
    );
    let dir = tamper_dir("tamper-resealed", resealed.as_bytes());
    assert_eq!(
        custodian.verify_internal(&job, &dir).err(),
        Some(Mismatch::EngineVerification)
    );
    // Without a Verified value there is nothing to pass to release().
}
