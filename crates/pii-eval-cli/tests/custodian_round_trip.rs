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
    CorpusSnapshot, ENGINE_VERSION, RunClass, RunManifest, Visibility, parse_default, seal,
    to_pretty_json,
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

    /// Verify the engine's INTERNAL artifact against the approval.
    fn verify_internal(&self, out: &Path) -> Result<Verified, Mismatch> {
        let a = &self.approval;
        let artifact: Value =
            serde_json::from_slice(&std::fs::read(out.join("run-artifact.json")).unwrap()).unwrap();
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
        let identity = &sem["scanners"][0]["identity"];
        if identity["product"]["candidateDigest"] != a.candidate_digest {
            return Err(Mismatch::Candidate);
        }
        if identity["activationDigest"] != a.activation_digest {
            return Err(Mismatch::Activation);
        }
        if sem["completeness"] != "complete" || sem["scanners"][0]["status"] != "complete" {
            return Err(Mismatch::Incomplete);
        }
        Ok(Verified { artifact })
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

/// The activation digest the run records, learned from a first successful run of
/// the same inputs (the approval of a real custodian carries it from its
/// activation record; the stub has none, so it reads it from a rehearsal).
fn approved_activation(job: &Job) -> String {
    let rehearsal_context = SyntheticCustodian::new(job.approval("0".repeat(64).as_str()))
        .issue_job_context("pii", 0, job)
        .unwrap();
    let out = job.output_root.join("rehearsal");
    let result = job.run(Some(&rehearsal_context), &out);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    let artifact: Value =
        serde_json::from_slice(&std::fs::read(out.join("run-artifact.json")).unwrap()).unwrap();
    artifact["semantic"]["scanners"][0]["identity"]["activationDigest"]
        .as_str()
        .unwrap()
        .to_owned()
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
    let activation = approved_activation(&job);
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

    // The custodian verifies every binding before it believes the result.
    let verified = custodian.verify_internal(&out).expect("bindings match");
    // The engine's own verifier agrees (custodian re-runs it inside the context).
    let staging = job.ws.tmp.0.join("validate-in");
    std::fs::create_dir_all(&staging).unwrap();
    for (from, to) in [
        (&job.snapshot, "snapshot.json"),
        (&out.join("manifest.json"), "manifest.json"),
        (&out.join("run-artifact.json"), "run-artifact.json"),
    ] {
        std::fs::copy(from, staging.join(to)).unwrap();
    }
    let validation = job.ws.tmp.0.join("validate.job-context.json");
    let ctx_text = std::fs::read_to_string(&context).unwrap().replace(
        s(&std::fs::canonicalize(&job.input_root).unwrap()),
        s(&std::fs::canonicalize(&staging).unwrap()),
    );
    write_private(&validation, &ctx_text);
    let checked = run_cli(&[
        "validate",
        s(&staging.join("run-artifact.json")),
        "--snapshot",
        s(&staging.join("snapshot.json")),
        "--manifest",
        s(&staging.join("manifest.json")),
        "--job-context",
        s(&validation),
    ]);
    assert_eq!(code(&checked), 0, "{}", stderr(&checked));
    assert_eq!(
        self::summary(&checked)["semantic"]["verification"],
        "verified"
    );

    // Release: custodian-side projection, within the documented bounds.
    let projection = custodian.release(&verified, 1_500).expect("release");
    let roster = projection.worker_result["roster"]["expected"]
        .as_u64()
        .unwrap();
    check_projection(&projection, roster);
    // It carries no case identity, text, seed or range from the population.
    let leaked = serde_json::to_string(&projection.aggregates).unwrap()
        + &serde_json::to_string(&projection.worker_result).unwrap();
    let snapshot_text = std::fs::read_to_string(&job.snapshot).unwrap();
    let snapshot: Value = serde_json::from_str(&snapshot_text).unwrap();
    for case in snapshot["semantic"]["cases"].as_array().unwrap() {
        assert!(!leaked.contains(case["caseId"].as_str().unwrap()));
        for v in case["variants"].as_array().unwrap() {
            assert!(!leaked.contains(v["variantId"].as_str().unwrap()));
            assert!(!leaked.contains(v["text"].as_str().unwrap()));
        }
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
    let activation = approved_activation(&job);
    let context = SyntheticCustodian::new(job.approval(&activation))
        .issue_job_context("pii", 1, &job)
        .unwrap();
    let out = job.output_root.join("run");
    assert_eq!(code(&job.run(Some(&context), &out)), 0);

    let other = "f".repeat(64);
    let wrong = |edit: &dyn Fn(&mut Approval)| {
        let mut a = job.approval(&activation);
        edit(&mut a);
        SyntheticCustodian::new(a).verify_internal(&out).err()
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

    // A public-synthetic artifact is not a protected result.
    let public = Workspace::new("rt-verify-public", &node);
    let public_out = public.out("p");
    assert_eq!(code(&public.run(&public_out)), 0);
    assert_eq!(
        SyntheticCustodian::new(job.approval(&activation))
            .verify_internal(&public_out)
            .err(),
        Some(Mismatch::RunClass)
    );
}

#[test]
fn an_expired_wrong_domain_or_revoked_job_is_never_started_and_a_revoked_result_is_never_released()
{
    let node = node_or_return!();
    let job = protected_job("rt-state", &node);
    let activation = approved_activation(&job);
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
    let verified = custodian.verify_internal(&run_out).unwrap();
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
    let verified = fresh.verify_internal(&run_out).unwrap();
    assert_eq!(
        fresh.release(&verified, 2_001).err(),
        Some(Refusal::Expired)
    );
}

#[test]
fn a_tampered_internal_artifact_does_not_survive_the_engine_verifier() {
    let node = node_or_return!();
    let job = protected_job("rt-tamper", &node);
    let activation = approved_activation(&job);
    let context = SyntheticCustodian::new(job.approval(&activation))
        .issue_job_context("pii", 1, &job)
        .unwrap();
    let out = job.output_root.join("run");
    assert_eq!(code(&job.run(Some(&context), &out)), 0);
    let staging = job.ws.tmp.0.join("tamper-in");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::copy(&job.snapshot, staging.join("snapshot.json")).unwrap();
    std::fs::copy(out.join("manifest.json"), staging.join("manifest.json")).unwrap();
    let text = std::fs::read_to_string(out.join("run-artifact.json")).unwrap();
    // A metric count edited after the fact, digest left alone.
    let tampered = text.replacen("\"numerator\": 1", "\"numerator\": 2", 1);
    assert_ne!(tampered, text, "the fixture has a numerator to edit");
    std::fs::write(staging.join("run-artifact.json"), tampered).unwrap();
    let ctx = std::fs::read_to_string(&context).unwrap().replace(
        s(&std::fs::canonicalize(&job.input_root).unwrap()),
        s(&std::fs::canonicalize(&staging).unwrap()),
    );
    let ctx_path = job.ws.tmp.0.join("tamper.job-context.json");
    write_private(&ctx_path, &ctx);
    let checked = run_cli(&[
        "validate",
        s(&staging.join("run-artifact.json")),
        "--snapshot",
        s(&staging.join("snapshot.json")),
        "--manifest",
        s(&staging.join("manifest.json")),
        "--job-context",
        s(&ctx_path),
    ]);
    assert_eq!(
        code(&checked),
        3,
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );
    assert_eq!(reason(&summary(&checked)), "document-invalid");
}
