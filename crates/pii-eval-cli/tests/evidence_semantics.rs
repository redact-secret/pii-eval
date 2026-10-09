//! The pinned public-synthetic population, mapping revision 3. Fake scanner
//! execution is conformance evidence, never a product measurement.
mod common;
use common::*;
use pii_eval_cli::assemble::{AssembleOptions, assemble, variant_tasks};
use pii_eval_cli::evidence::{
    files::read_dir,
    map::{map, map_semantic},
    pin::SnapshotPin,
    plan,
    verify::verify,
};
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::replay::runs_from_observations;
use pii_eval_cli::run::{RunConfig, RunRequest, run};
use pii_eval_contracts::*;
use pii_eval_kernel::{verify_public_artifact_accounting, verify_run_artifact_accounting};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn mapped() -> pii_eval_cli::evidence::map::Mapped {
    let pin =
        SnapshotPin::parse(&std::fs::read(root().join("fixtures/pii-evidence/pin.json")).unwrap())
            .unwrap();
    let files = read_dir(&root().join("fixtures/pii-evidence/snapshots").join(&pin.id)).unwrap();
    let v = verify(&files, &pin).unwrap();
    map_semantic(&v, &pin).unwrap()
}

#[test]
fn mapping_reduces_every_representable_loss_and_retains_exact_authored_metadata() {
    let pin =
        SnapshotPin::parse(&std::fs::read(root().join("fixtures/pii-evidence/pin.json")).unwrap())
            .unwrap();
    let files = read_dir(&root().join("fixtures/pii-evidence/snapshots").join(&pin.id)).unwrap();
    let v = verify(&files, &pin).unwrap();
    let old = map(&v, &pin).unwrap();
    let new = map_semantic(&v, &pin).unwrap();
    assert_eq!(new.snapshot.schema_version, SchemaVersion::V1_5);
    assert_eq!(new.snapshot.semantic.population.population_version, 3);
    assert_eq!(new.binding["semantic"]["mappingRule"]["revision"], 3);
    let authored: BTreeMap<_, _> = v.fixtures.iter().map(|f| (f.id.as_str(), f)).collect();
    let cases: BTreeMap<_, _> = v.cases.iter().map(|c| (c.id.as_str(), c)).collect();
    let by_variant: BTreeMap<_, _> = new
        .snapshot
        .semantic
        .cases
        .iter()
        .flat_map(|c| &c.variants)
        .map(|v| (v.variant_id.as_str(), v))
        .collect();
    let rows = new.binding["semantic"]["rows"].as_array().unwrap();
    for row in rows {
        let f = authored[row["evidenceFixture"].as_str().unwrap()];
        let c = cases[f.case.as_str()];
        let variant = by_variant[row["variantId"].as_str().unwrap()];
        assert_eq!(variant.text, f.content);
        let e = &variant.expectations[0];
        let metadata = e.evidence.as_ref().unwrap();
        let mut contexts = c.contexts.clone();
        contexts.sort();
        assert_eq!(metadata.contexts, contexts);
        assert_eq!(
            metadata.domains.contains(&EvidenceDomain::Phi),
            f.expectation.domains.iter().any(|d| d == "phi")
        );
        if f.expectation.sensitivity.as_str() == "context-dependent" {
            assert_eq!(e.sensitivity, SensitivityExpectation::ContextDependent);
        }
    }
    let loss = &new.binding["semantic"]["losses"];
    for code in [
        "contexts-not-carried",
        "phi-domain-not-carried",
        "sensitivity-context-dependent-flattened",
    ] {
        assert!(loss.get(code).is_none());
    }
    assert_eq!(new.snapshot.semantic.variant_count(), 139);
    assert_eq!(new.snapshot.semantic.occurrence_count(), 139);
    let report = json!({
        "schema": "pii-eval-semantic-mapping-delta/1", "snapshotId": pin.id,
        "visibility": "public-synthetic", "productMode": "not-applicable-mapping-only",
        "before": {"mappingRevision": 1, "populationDigest": old.snapshot.semantic_digest,
            "losses": old.binding["semantic"]["losses"]},
        "after": {"mappingRevision": 3, "populationDigest": new.snapshot.semantic_digest,
            "bindingDigest": new.binding["semanticDigest"], "losses": loss,
            "textNegativeExpectations": by_variant.values().filter(|v| v.expectations[0].is_text_negative()).count(),
            "contextDependentExpectations": by_variant.values().filter(|v| v.expectations[0].sensitivity == SensitivityExpectation::ContextDependent).count()},
        "remainingLossReason": "None of the five recorded losses remains on this pin. Future unlocated positive assertions still need an authored span; no occurrence is fabricated.",
        "resultChanges": "Only new text-negative rows can change verdicts; located context-dependent rows retain unresolved sensitivity. Evidence metadata changes digests, not scanner behavior."
    });
    let path = root().join("docs/migration/phi-context-mapping-delta-37.json");
    let bytes = serde_json::to_string_pretty(&report).unwrap() + "\n";
    if std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1") {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), bytes);
    assert_eq!(new.binding, map_semantic(&v, &pin).unwrap().binding);
}

#[test]
fn fresh_execution_replay_worker_counts_and_public_projection_preserve_semantics() {
    let m = mapped();
    let s = &m.snapshot;
    let adapter = FakeAdapter::new("semantic-test", 5);
    let manifest = plan::manifest(s, vec![adapter.plan.clone()], limits(4, 4, 8, 16), 2).unwrap();
    assert_eq!(manifest.schema_version, SchemaVersion::V1_5);
    assert_eq!(manifest.semantic.protocol, ProtocolIdentity::CANONICAL_V3);
    let mut old_plan = manifest.clone();
    old_plan.semantic.protocol = ProtocolIdentity::CANONICAL_V2;
    old_plan.schema_version = SchemaVersion::V1_1;
    seal(&mut old_plan).unwrap();
    validate(&old_plan).unwrap();
    assert!(validate_manifest_against_snapshot(&old_plan, s).is_err());
    let mut reference = None;
    for workers in [1, 2, 4, 1] {
        let output = run(
            &RunRequest {
                snapshot: s,
                manifest: &manifest,
                adapters: vec![Arc::new(adapter.clone())],
            },
            &RunConfig {
                executor: ExecutorConfig {
                    max_workers: workers,
                    resources: ResourcePolicy::Unenforced,
                    ..ExecutorConfig::default()
                },
                ..RunConfig::default()
            },
            &CancelToken::new(),
        )
        .unwrap();
        let a = output.assembled;
        let public = a.public.as_ref().unwrap();
        assert_eq!(a.artifact.schema_version, SchemaVersion::V1_5);
        assert_eq!(public.schema_version, SchemaVersion::V1_5);
        verify_run_artifact_accounting(&a.artifact, s).unwrap();
        verify_public_artifact_accounting(public, s).unwrap();
        for (i, o) in public.semantic.outcomes.iter().enumerate() {
            assert!(o.evidence.is_some());
            assert_eq!(o.evidence, a.artifact.semantic.outcomes[i].evidence);
        }
        let bytes = to_pretty_json(&a.artifact).unwrap();
        if let Some(want) = &reference {
            assert_eq!(&bytes, want);
        } else {
            reference = Some(bytes.clone());
        }
        let mut observations = a.observations.clone();
        for o in &mut observations {
            validate_observation_against_manifest(o, &manifest).unwrap();
            validate_observation_against_snapshot(o, s).unwrap();
            o.semantic.inputs.reverse();
        }
        // Library replay indexes inputs by identity. Persisted documents must be
        // canonical, so restore order and seal before validating their wire form.
        for o in &mut observations {
            o.semantic
                .inputs
                .sort_by(|a, b| a.variant_id.cmp(&b.variant_id));
            seal(o).unwrap();
            validate(o).unwrap();
        }
        let runs = runs_from_observations(s, &manifest, &observations, Some(&a.artifact)).unwrap();
        let replay = assemble(
            s,
            &manifest,
            &variant_tasks(s),
            &runs,
            AssembleOptions {
                diagnostics: false,
                run_started_at: SystemTime::UNIX_EPOCH,
            },
        )
        .unwrap();
        assert_eq!(to_pretty_json(&replay.artifact).unwrap(), bytes);
        assert_eq!(
            to_pretty_json(replay.public.as_ref().unwrap()).unwrap(),
            to_pretty_json(public).unwrap()
        );
        if workers == 2 {
            let tmp = TempDir::new("semantic-consumer");
            let artifact_path = tmp.0.join("public.json");
            std::fs::write(&artifact_path, to_pretty_json(public).unwrap()).unwrap();
            let p = &public.semantic;
            let pins = json!({"schema": "pii-eval-consumer-pins/1", "engine": p.engine,
                "protocol": p.protocol, "artifactSchema": {"id": "pii-eval.public-synthetic-artifact", "version": "1.5"},
                "requireComplete": true, "populations": [{"label": "semantic-conformance",
                    "population": p.population, "runClass": "public-synthetic",
                    "artifactDigest": public.semantic_digest, "manifestDigest": p.manifest_digest,
                    "scanners": p.scanners.iter().map(|s| &s.identity).collect::<Vec<_>>() }]});
            let pins_path = tmp.0.join("pins.json");
            std::fs::write(&pins_path, serde_json::to_vec(&pins).unwrap()).unwrap();
            let result = std::process::Command::new("node")
                .arg(root().join("examples/consumer/consume.mjs"))
                .arg("--pins")
                .arg(&pins_path)
                .arg(&artifact_path)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stdout)
            );
            let mut older = pins;
            older["artifactSchema"]["version"] = json!("1.2");
            std::fs::write(&pins_path, serde_json::to_vec(&older).unwrap()).unwrap();
            let result = std::process::Command::new("node")
                .arg(root().join("examples/consumer/consume.mjs"))
                .arg("--pins")
                .arg(&pins_path)
                .arg(&artifact_path)
                .output()
                .unwrap();
            assert!(!result.status.success());
            assert!(String::from_utf8_lossy(&result.stdout).contains("schema-version-unsupported"));
        }
        let mut altered = a.artifact.clone();
        altered.semantic.outcomes[0]
            .evidence
            .as_mut()
            .unwrap()
            .contexts
            .push("extra-context".into());
        seal(&mut altered).unwrap();
        assert!(validate_artifact_against_snapshot(&altered, s).is_err());
    }
}

#[test]
fn named_revision_same_observation_delta_classifies_every_changed_axis() {
    let pin =
        SnapshotPin::parse(&std::fs::read(root().join("fixtures/pii-evidence/pin.json")).unwrap())
            .unwrap();
    let files = read_dir(&root().join("fixtures/pii-evidence/snapshots").join(&pin.id)).unwrap();
    let v = verify(&files, &pin).unwrap();
    let old = map(&v, &pin).unwrap();
    let new = map_semantic(&v, &pin).unwrap();
    let dir = root().join("docs/measurements/pii-evidence-public-pii-phi-2026-10-07-9d4e8e036bbb");
    let original: RunArtifact =
        parse_default(&std::fs::read(dir.join("run-artifact.json")).unwrap()).unwrap();
    let manifest: RunManifest =
        parse_default(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let observation: ObservationSet =
        parse_default(&std::fs::read(dir.join("observation-redact-secret-core.json")).unwrap())
            .unwrap();
    validate_manifest_against_snapshot(&manifest, &old.snapshot).unwrap();
    validate_observation_against_manifest(&observation, &manifest).unwrap();
    validate_observation_against_snapshot(&observation, &old.snapshot).unwrap();
    let runs = runs_from_observations(
        &old.snapshot,
        &manifest,
        std::slice::from_ref(&observation),
        Some(&original),
    )
    .unwrap();
    let migrated = plan::manifest(
        &new.snapshot,
        manifest.semantic.scanners.clone(),
        manifest.semantic.limits,
        manifest.semantic.mechanics.replays,
    )
    .unwrap();
    let candidate = assemble(
        &new.snapshot,
        &migrated,
        &variant_tasks(&new.snapshot),
        &runs,
        AssembleOptions {
            diagnostics: false,
            run_started_at: SystemTime::UNIX_EPOCH,
        },
    )
    .unwrap();
    let by_variant: BTreeMap<_, _> = new
        .snapshot
        .semantic
        .cases
        .iter()
        .flat_map(|c| &c.variants)
        .map(|v| (v.variant_id.as_str(), &v.expectations[0]))
        .collect();
    let mut changed = Vec::new();
    let mut unchanged = 0;
    for (before, after) in original
        .semantic
        .outcomes
        .iter()
        .zip(&candidate.artifact.semantic.outcomes)
    {
        assert_eq!(before.variant_id, after.variant_id);
        let mut axes = Vec::new();
        if before.type_identity != after.type_identity {
            axes.push("typeIdentity");
        }
        if before.sensitivity_context != after.sensitivity_context {
            axes.push("sensitivityContext");
        }
        if before.range != after.range {
            axes.push("range");
        }
        if before.action != after.action {
            axes.push("action");
        }
        if axes.is_empty() {
            unchanged += 1;
            continue;
        }
        assert!(
            by_variant[after.variant_id.as_str()].is_text_negative(),
            "unexplained delta"
        );
        changed.push(json!({"variantId": after.variant_id, "axes": axes,
            "classification": "protocol-3-text-negative-expectation",
            "before": {"typeIdentity": before.type_identity, "sensitivityContext": before.sensitivity_context,
                "range": before.range, "action": before.action},
            "after": {"typeIdentity": after.type_identity, "sensitivityContext": after.sensitivity_context,
                "range": after.range, "action": after.action}}));
    }
    let report = json!({"schema": "pii-eval-semantic-outcome-delta/1", "snapshotId": pin.id,
        "visibility": "public-synthetic", "productMode": "released",
        "kind": "same-observation-protocol-migration-replay", "scannersLaunched": 0,
        "scanner": observation.semantic.scanner, "observationDigest": observation.semantic_digest,
        "beforeProtocol": manifest.semantic.protocol, "afterProtocol": migrated.semantic.protocol,
        "beforeArtifactDigest": original.semantic_digest, "afterArtifactDigest": candidate.artifact.semantic_digest,
        "unchangedOutcomeRows": unchanged, "changedOutcomeRows": changed.len(), "unexplainedDeltas": 0,
        "changed": changed,
        "beforeMetrics": original.semantic.scanner_metrics, "afterMetrics": candidate.artifact.semantic.scanner_metrics});
    let path = root().join("docs/migration/phi-context-outcome-delta-37.json");
    let bytes = serde_json::to_string_pretty(&report).unwrap() + "\n";
    if std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1") {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), bytes);
}

#[test]
fn cli_requires_explicit_mapping_revision_and_refuses_unknown_revisions() {
    let tmp = TempDir::new("semantic-import-cli");
    let snapshot =
        root().join("fixtures/pii-evidence/snapshots/public-pii-phi/2026-10-07/9d4e8e036bbb");
    let pin = root().join("fixtures/pii-evidence/pin.json");
    let out = tmp.0.join("out");
    for (revision, expected) in [("4", 2), ("3", 0)] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_pii-eval-evidence"))
            .arg("import")
            .arg("--snapshot-dir")
            .arg(&snapshot)
            .arg("--pin")
            .arg(&pin)
            .arg("--out")
            .arg(&out)
            .arg("--mapping-revision")
            .arg(revision)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(expected));
    }
    let s: CorpusSnapshot =
        parse_default(&std::fs::read(out.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(s.schema_version, SchemaVersion::V1_5);
}
