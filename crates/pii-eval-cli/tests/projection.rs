//! The product projection (schema 1.2, ADR 0016) end to end: the real executor,
//! assembler, writer and kernel with the in-process fake scanners (no Node), and
//! the built binary's `validate` and `replay`.
//!
//! Proves: determinism (equal bytes and semantic digest across runs and worker
//! counts), additivity (every other document is byte-identical to a run with no
//! roster), and the rejections the benchmarks request names (#664): duplicate
//! family/view rows, absent required views, pooled denominators, unknown modes,
//! and a row whose scanner/configuration/activation/candidate/population binding
//! differs from the artifact.
#![cfg(unix)]

mod cli_support;
mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cli_support::{code, run_cli, s, stderr, summary};
use common::*;
use pii_eval_cli::assemble::ProjectionRequest;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run_and_write_with_projection};
use pii_eval_cli::write::{ArtifactWriter, OverwritePolicy};
use pii_eval_contracts::{
    CorpusSnapshot, Id, ProductIdentity, ProjectionMode, ProjectionView, PublicSyntheticArtifact,
    RunManifest, SchemaVersion, compute_digest, parse_default, serialize_public_synthetic,
    to_pretty_json,
};
use pii_eval_kernel::{ProjectionRoster, verify_public_projection};
use serde_json::Value;

const ROSTER_JSON: &str = r#"{
  "schema": "pii-eval-projection-roster/1",
  "requiredViews": ["oracle-plan", "qualification-plan"],
  "views": [
    {"view": "oracle-plan", "cases": ["collision-us-ssn-demo"]},
    {"view": "qualification-plan", "cases": ["context-email-ko-demo", "type-card-demo"]}
  ],
  "controlClasses": [{"class": "test-value", "cases": ["type-card-demo"]}]
}
"#;

fn id(text: &str) -> Id {
    Id::new(text).unwrap()
}

fn roster(snapshot: &CorpusSnapshot) -> ProjectionRoster {
    let views = [
        ("collision-us-ssn-demo", ProjectionView::OraclePlan),
        ("context-email-ko-demo", ProjectionView::QualificationPlan),
        ("type-card-demo", ProjectionView::QualificationPlan),
    ]
    .map(|(case, view)| (id(case), view));
    ProjectionRoster::new(
        &snapshot.semantic,
        &[
            ProjectionView::OraclePlan,
            ProjectionView::QualificationPlan,
        ],
        &views,
        &[(id("type-card-demo"), id("test-value"))],
    )
    .unwrap()
}

fn generate(out: &Path, workers: usize, projection: Option<ProjectionRequest>) -> RunManifest {
    let snapshot = snapshot();
    let mut beta = FakeAdapter::new("beta-scan", 3);
    beta.unsupported = true;
    let adapters = vec![FakeAdapter::new("alpha-scan", 5), beta];
    let manifest = manifest(
        &snapshot,
        adapters.iter().map(|a| a.plan.clone()).collect(),
        limits(4, 2, 2, 8),
        mechanics(2),
    );
    run_and_write_with_projection(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: adapters
                .into_iter()
                .map(|a| Arc::new(a) as Arc<dyn pii_eval_adapters::ScannerAdapter>)
                .collect(),
        },
        &RunConfig {
            executor: ExecutorConfig {
                max_workers: workers,
                resources: ResourcePolicy::Unenforced,
                ..ExecutorConfig::default()
            },
            diagnostics: false,
            commit_cancelled: false,
        },
        &CancelToken::new(),
        &ArtifactWriter::new(out, OverwritePolicy::Refuse),
        projection.as_ref(),
    )
    .expect("run and write");
    std::fs::write(
        out.join("manifest.json"),
        to_pretty_json(&manifest).unwrap(),
    )
    .unwrap();
    manifest
}

fn request(mode: ProjectionMode) -> ProjectionRequest {
    ProjectionRequest {
        roster: roster(&snapshot()),
        mode,
    }
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap()
}

fn public(dir: &Path) -> PublicSyntheticArtifact {
    parse_default(&read(dir, "public-synthetic-artifact.json")).unwrap()
}

struct Case {
    _tmp: TempDir,
    dir: PathBuf,
    snapshot: PathBuf,
    roster: PathBuf,
}

/// One run with the projection, plus the snapshot and roster files for the CLI.
fn with_projection(label: &str, mode: ProjectionMode) -> Case {
    let tmp = TempDir::new(label);
    let dir = tmp.0.join("out");
    generate(&dir, 4, Some(request(mode)));
    let snapshot_path = tmp.0.join("snapshot.json");
    std::fs::write(&snapshot_path, to_pretty_json(&snapshot()).unwrap()).unwrap();
    let roster_path = tmp.0.join("roster.json");
    std::fs::write(&roster_path, ROSTER_JSON).unwrap();
    Case {
        _tmp: tmp,
        dir,
        snapshot: snapshot_path,
        roster: roster_path,
    }
}

/// Validate `artifact` through the built binary with the snapshot and roster.
fn validate(case: &Case, artifact: &Path, with_roster: bool) -> (i32, Value) {
    let mut args = vec!["validate", s(artifact), "--snapshot", s(&case.snapshot)];
    if with_roster {
        args.extend(["--projection-roster", s(&case.roster)]);
    }
    let out = run_cli(&args);
    (code(&out), summary(&out))
}

/// Edit the typed public artifact, reseal WITHOUT validating, write it next to
/// the others so that the validator, not the builder, judges it.
fn tampered(case: &Case, name: &str, edit: impl FnOnce(&mut PublicSyntheticArtifact)) -> PathBuf {
    let mut doc = public(&case.dir);
    edit(&mut doc);
    let digest = compute_digest(&doc).unwrap();
    doc.semantic_digest = digest;
    let path = case.dir.join(name);
    std::fs::write(&path, serialize_public_synthetic(&doc).unwrap()).unwrap();
    path
}

fn codes(summary: &Value) -> String {
    summary["error"]["codes"].to_string()
}

// ---------------------------------------------------------------------------
// Additivity and determinism
// ---------------------------------------------------------------------------

#[test]
fn a_roster_changes_only_the_public_artifact_everything_else_is_byte_identical() {
    let tmp = TempDir::new("projection-additive");
    let (plain, with) = (tmp.0.join("plain"), tmp.0.join("with"));
    generate(&plain, 4, None);
    generate(&with, 4, Some(request(ProjectionMode::Official)));
    for name in [
        "manifest.json",
        "observation-alpha-scan.json",
        "observation-beta-scan.json",
        "run-artifact.json",
    ] {
        assert_eq!(read(&plain, name), read(&with, name), "{name}");
    }
    let (before, after) = (public(&plain), public(&with));
    // No roster: the 1.1 artifact the repository has always written, byte for byte.
    assert_eq!(before.schema_version, SchemaVersion::V1_1);
    assert_eq!(
        read(&plain, "public-synthetic-artifact.json"),
        std::fs::read(fixtures_dir().join("rev2/public-synthetic-artifact.json")).unwrap()
    );
    // With a roster: 1.2, the block, and nothing else changed in the body.
    assert_eq!(after.schema_version, SchemaVersion::V1_2);
    let mut stripped = after.clone();
    stripped.semantic.product_projection = None;
    assert_eq!(stripped.semantic, before.semantic);
    assert_ne!(after.semantic_digest, before.semantic_digest);
}

#[test]
fn the_projected_artifact_is_deterministic_across_runs_and_worker_counts() {
    let tmp = TempDir::new("projection-determinism");
    let mut digests = Vec::new();
    let mut bytes = Vec::new();
    for (i, workers) in [1usize, 2, 4, 4].into_iter().enumerate() {
        let dir = tmp.0.join(format!("run-{i}"));
        generate(&dir, workers, Some(request(ProjectionMode::Exploratory)));
        digests.push(public(&dir).semantic_digest);
        bytes.push(read(&dir, "public-synthetic-artifact.json"));
    }
    assert!(digests.windows(2).all(|w| w[0] == w[1]), "{digests:?}");
    assert!(bytes.windows(2).all(|w| w[0] == w[1]));
    // The mode is part of the digest: an exploratory run is not an official one.
    let official = tmp.0.join("official");
    generate(&official, 4, Some(request(ProjectionMode::Official)));
    assert_ne!(public(&official).semantic_digest, digests[0]);
}

#[test]
fn the_block_is_a_hand_checked_restatement_of_one_population() {
    let case = with_projection("projection-shape", ProjectionMode::Official);
    let doc = public(&case.dir);
    let block = doc.semantic.product_projection.as_ref().unwrap();
    // 2 scanners x (oracle/ssn, qualification/email, qualification/card).
    let keys: Vec<(&str, &str, &str)> = block
        .rows
        .iter()
        .map(|r| {
            (
                r.binding.scanner_id.as_str(),
                r.view.as_str(),
                r.family.as_str(),
            )
        })
        .collect();
    assert_eq!(
        keys,
        [
            ("alpha-scan", "oracle-plan", "pii:us:ssn"),
            ("alpha-scan", "qualification-plan", "pii:global:email"),
            (
                "alpha-scan",
                "qualification-plan",
                "pii:global:payment-card"
            ),
            ("beta-scan", "oracle-plan", "pii:us:ssn"),
            ("beta-scan", "qualification-plan", "pii:global:email"),
            ("beta-scan", "qualification-plan", "pii:global:payment-card"),
        ]
    );
    // Cases/variants per cell: collision 1/1, context 1/3, type-validation 1/2.
    let counts: Vec<(u64, u64)> = block
        .rows
        .iter()
        .take(3)
        .map(|r| (r.counts.authored_cases, r.counts.variants))
        .collect();
    assert_eq!(counts, [(1, 1), (1, 3), (1, 2)]);
    // Every row has the ten metrics and the artifact's own population binding.
    for row in &block.rows {
        assert_eq!(row.metrics.len(), 10);
        assert_eq!(row.binding.population, doc.semantic.population);
        assert_eq!(row.mode, ProjectionMode::Official);
    }
    // Language strata: the context case is Korean, the other two English.
    let email = &block.rows[1];
    assert_eq!(email.by_language.len(), 1);
    assert_eq!(email.by_language[0].language.as_str(), "ko");
    // The control class was assigned to the type-validation case only.
    assert_eq!(block.rows[2].by_control_class.len(), 1);
    assert_eq!(
        block.rows[2].by_control_class[0].control_class.as_str(),
        "test-value"
    );
    assert!(block.rows[0].by_control_class.is_empty());
    // A scanner that did not run is unmeasured in every cell.
    for row in block
        .rows
        .iter()
        .filter(|r| r.binding.scanner_id.as_str() == "beta-scan")
    {
        assert!(row.metrics.iter().all(|m| m.counts.measured == 0));
    }
    assert!(matches!(
        doc.semantic.scanners[0].identity.product,
        ProductIdentity::Released | ProductIdentity::Candidate { .. }
    ));
}

// ---------------------------------------------------------------------------
// The binary: validate recomputes the block; replay reproduces it
// ---------------------------------------------------------------------------

#[test]
fn validate_checks_the_block_structurally_and_recomputes_it_with_the_roster() {
    let case = with_projection("projection-validate", ProjectionMode::Official);
    let artifact = case.dir.join("public-synthetic-artifact.json");
    let (c, v) = validate(&case, &artifact, false);
    assert_eq!(c, 0, "{v}");
    assert_eq!(v["semantic"]["productProjection"], "structural");
    assert_eq!(v["semantic"]["schemaVersion"], "1.2");
    let (c, v) = validate(&case, &artifact, true);
    assert_eq!(c, 0, "{v}");
    assert_eq!(v["semantic"]["productProjection"], "recomputed");
    assert_eq!(v["semantic"]["verification"], "verified");
    // A document without a block is refused when a roster says it should have one.
    let plain = TempDir::new("projection-plain");
    generate(&plain.0.join("o"), 4, None);
    let (c, v) = validate(
        &case,
        &plain.0.join("o/public-synthetic-artifact.json"),
        true,
    );
    assert_eq!(c, 3, "{v}");
    assert!(codes(&v).contains("projection-invalid"));
    // The roster applies to a public artifact only.
    let out = run_cli(&[
        "validate",
        s(&case.dir.join("run-artifact.json")),
        "--projection-roster",
        s(&case.roster),
    ]);
    assert_eq!(code(&out), 2);
}

#[test]
fn replay_with_a_roster_reproduces_the_projected_artifact_byte_for_byte() {
    let case = with_projection("projection-replay", ProjectionMode::Exploratory);
    let out = case.dir.parent().unwrap().join("replayed");
    let run = run_cli(&[
        "replay",
        "--snapshot",
        s(&case.snapshot),
        "--manifest",
        s(&case.dir.join("manifest.json")),
        "--observation",
        s(&case.dir.join("observation-alpha-scan.json")),
        "--observation",
        s(&case.dir.join("observation-beta-scan.json")),
        "--original",
        s(&case.dir.join("run-artifact.json")),
        "--out",
        s(&out),
        "--projection-roster",
        s(&case.roster),
        "--projection-mode",
        "exploratory",
    ]);
    assert_eq!(
        code(&run),
        5,
        "{} {}",
        stderr(&run),
        String::from_utf8_lossy(&run.stdout)
    ); // beta did not complete
    let v = summary(&run);
    assert_eq!(v["semantic"]["productProjection"]["mode"], "exploratory");
    assert_eq!(v["semantic"]["productProjection"]["rows"], 6);
    assert_eq!(
        read(&out, "public-synthetic-artifact.json"),
        read(&case.dir, "public-synthetic-artifact.json")
    );
    // A roster needs a stated mode, and a mode needs a roster.
    let manifest_path = case.dir.join("manifest.json");
    let observation = case.dir.join("observation-alpha-scan.json");
    let refused = case.dir.parent().unwrap().join("refused");
    for extra in [
        vec!["--projection-roster", s(&case.roster)],
        vec!["--projection-mode", "official"],
    ] {
        let mut args = vec![
            "replay",
            "--snapshot",
            s(&case.snapshot),
            "--manifest",
            s(&manifest_path),
            "--observation",
            s(&observation),
            "--out",
            s(&refused),
        ];
        args.extend(extra);
        assert_eq!(code(&run_cli(&args)), 2);
    }
}

// ---------------------------------------------------------------------------
// The rejections of benchmarks #664, through the binary
// ---------------------------------------------------------------------------

#[test]
fn duplicate_family_view_rows_are_rejected() {
    let case = with_projection("projection-duplicate", ProjectionMode::Official);
    let path = tampered(&case, "duplicate.json", |d| {
        let rows = &mut d.semantic.product_projection.as_mut().unwrap().rows;
        let again = rows[1].clone();
        rows.insert(2, again);
    });
    let (c, v) = validate(&case, &path, false);
    assert_eq!(c, 3, "{v}");
    assert!(codes(&v).contains("duplicate-identity"), "{v}");
}

#[test]
fn an_absent_required_view_is_rejected() {
    let case = with_projection("projection-view-absent", ProjectionMode::Official);
    let path = tampered(&case, "absent-view.json", |d| {
        d.semantic
            .product_projection
            .as_mut()
            .unwrap()
            .rows
            .retain(|r| r.view != ProjectionView::OraclePlan);
    });
    let (c, v) = validate(&case, &path, false);
    assert_eq!(c, 3, "{v}");
    assert!(codes(&v).contains("projection-view-missing"), "{v}");
}

#[test]
fn pooled_denominators_are_rejected_structurally_and_by_recomputation() {
    let case = with_projection("projection-pooled", ProjectionMode::Official);
    // (1) A row that counts more than the cases of its cell, on top of the
    // others: the artifact's cells add up to more than the population.
    let extra = tampered(&case, "pooled-extra.json", |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        let mut all = block.rows[0].clone();
        all.family = pii_eval_contracts::FamilyId::new("pii:global:phone").unwrap();
        all.counts = d.semantic.population_counts;
        all.method_coverage = d.semantic.method_coverage.clone();
        block.rows.push(all);
        block.rows.sort_by_key(|r| {
            (
                r.binding.scanner_id.as_str().to_owned(),
                r.view.as_str(),
                r.family.as_str().to_owned(),
            )
        });
    });
    let (c, v) = validate(&case, &extra, false);
    assert_eq!(c, 3, "{v}");
    assert!(codes(&v).contains("projection-pooled-denominator"), "{v}");

    // (2) Two cells merged into one row that keeps the first cell's metrics: the
    // totals still add up, so only recomputation from the authored population
    // (the roster) can tell. Structural validation passes, recomputation refuses.
    let merged = tampered(&case, "pooled-merged.json", |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        // alpha-scan: qualification email (row 1) absorbs qualification card (row 2).
        let card = block.rows.remove(2);
        let email = &mut block.rows[1];
        email.counts.authored_cases += card.counts.authored_cases;
        email.counts.variants += card.counts.variants;
        email.counts.occurrences += card.counts.occurrences;
        email.method_coverage.extend(card.method_coverage);
        email.method_coverage.sort_by_key(|m| m.method.id.as_str());
        email.by_language.clear();
        email.by_control_class.clear();
        // The beta rows keep their own cells, so the merged scanner still
        // sums to the population only if the card row is gone: it is.
    });
    let (c, v) = validate(&case, &merged, false);
    // Structural: the merged row's metrics counts are its old ones (inside its
    // new cases), the sums add up; the typed parse accepts it.
    assert_eq!(c, 0, "{v}");
    let (c, v) = validate(&case, &merged, true);
    assert_eq!(c, 3, "{v}");
    assert!(codes(&v).contains("verification") || v["error"]["reason"] == "verification-failed");
    assert!(
        codes(&v).contains("projection-pooled-denominator") || codes(&v).contains("count-mismatch"),
        "{v}"
    );
}

#[test]
fn an_unknown_mode_or_view_is_rejected() {
    let case = with_projection("projection-unknown", ProjectionMode::Official);
    let text = String::from_utf8(read(&case.dir, "public-synthetic-artifact.json")).unwrap();
    for (from, to, name) in [
        (
            "\"mode\": \"official\"",
            "\"mode\": \"pilot\"",
            "unknown-mode.json",
        ),
        (
            "\"view\": \"oracle-plan\"",
            "\"view\": \"everything\"",
            "unknown-view.json",
        ),
    ] {
        assert!(text.contains(from));
        let path = case.dir.join(name);
        std::fs::write(&path, text.replacen(from, to, 1)).unwrap();
        let (c, v) = validate(&case, &path, false);
        assert_eq!(c, 3, "{name}: {v}");
        assert!(codes(&v).contains("schema-violation"), "{name}: {v}");
    }
    // Mixing modes in one artifact is refused as well.
    let mixed = tampered(&case, "mixed-modes.json", |d| {
        d.semantic.product_projection.as_mut().unwrap().rows[0].mode = ProjectionMode::Exploratory;
    });
    let (c, v) = validate(&case, &mixed, false);
    assert_eq!(c, 3, "{v}");
    assert!(codes(&v).contains("projection-invalid"));
}

#[test]
fn a_row_bound_to_another_scanner_configuration_activation_candidate_or_population_is_rejected() {
    let case = with_projection("projection-binding", ProjectionMode::Official);
    type Edit = Box<dyn Fn(&mut pii_eval_contracts::ProjectionRow)>;
    let edits: Vec<(&str, Edit)> = vec![
        (
            "configuration",
            Box::new(|r| r.binding.configuration_digest = digest_of("other-configuration")),
        ),
        (
            "activation",
            Box::new(|r| r.binding.activation_digest = digest_of("other-activation")),
        ),
        (
            "candidate",
            Box::new(|r| {
                r.binding.product = ProductIdentity::Candidate {
                    candidate_digest: digest_of("other-candidate"),
                }
            }),
        ),
        (
            "population",
            Box::new(|r| r.binding.population.population_digest = digest_of("other-population")),
        ),
        (
            "scanner",
            Box::new(|r| r.binding.scanner_id = sid("gamma-scan")),
        ),
    ];
    for (name, edit) in edits {
        let path = tampered(&case, &format!("binding-{name}.json"), |d| {
            edit(&mut d.semantic.product_projection.as_mut().unwrap().rows[0]);
        });
        let (c, v) = validate(&case, &path, false);
        assert_eq!(c, 3, "{name}: {v}");
        assert!(
            codes(&v).contains("projection-binding-mismatch"),
            "{name}: {v}"
        );
    }
}

#[test]
fn a_tampered_value_inside_a_row_is_found_by_recomputation_only() {
    let case = with_projection("projection-value", ProjectionMode::Official);
    let path = tampered(&case, "value.json", |d| {
        // A self-consistent but different count set: one measured sample that
        // did not count is made to count. Structural checks cannot know.
        let row = d
            .semantic
            .product_projection
            .as_mut()
            .unwrap()
            .rows
            .iter_mut()
            .find(|r| {
                r.binding.scanner_id.as_str() == "alpha-scan"
                    && r.metrics
                        .iter()
                        .any(|m| m.counts.measured >= 1 && m.counts.numerator == 0)
            })
            .expect("a row with a measured sample outside the numerator");
        row.by_control_class.clear();
        let m = row
            .metrics
            .iter_mut()
            .find(|m| m.counts.measured >= 1 && m.counts.numerator == 0)
            .unwrap();
        m.counts.numerator = 1;
    });
    let (c, _) = validate(&case, &path, false);
    assert_eq!(c, 0, "structurally the row is still consistent");
    let (c, v) = validate(&case, &path, true);
    assert_eq!(c, 3, "{v}");
}

#[test]
fn the_kernel_verifier_accepts_the_written_artifact_and_names_a_wrong_roster() {
    let case = with_projection("projection-library", ProjectionMode::Official);
    let snapshot = snapshot();
    let doc = public(&case.dir);
    verify_public_projection(&doc, &snapshot, &roster(&snapshot)).unwrap();
    // Another roster (everything in one view) is another artifact.
    let views: Vec<(Id, ProjectionView)> = snapshot
        .semantic
        .cases
        .iter()
        .map(|c| (c.case_id.clone(), ProjectionView::OraclePlan))
        .collect();
    let other = ProjectionRoster::new(
        &snapshot.semantic,
        &[ProjectionView::OraclePlan],
        &views,
        &[],
    )
    .unwrap();
    assert!(verify_public_projection(&doc, &snapshot, &other).is_err());
}
