//! Adapter records conform to the frozen contracts: the scanner plan embeds in
//! a run manifest and the observations (complete, and failed) validate and bind
//! to it. Uses the committed synthetic contract fixtures.

mod common;

use std::path::PathBuf;

use common::*;
use pii_eval_adapters::ScannerAdapter;
use pii_eval_contracts::{
    InputObservation, ObservationSet, ObservationSetBody, ReplayRecord, RunManifest, ScannerStatus,
    document, validate_observation_against_manifest,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/contracts/v1")
        .join(name);
    std::fs::read(path).expect("fixture")
}

fn manifest_with(plan: pii_eval_contracts::ScannerPlan) -> RunManifest {
    let mut manifest: RunManifest =
        document::parse_default(&fixture("manifest.json")).expect("fixture manifest");
    manifest.semantic.scanners = vec![plan];
    document::seal(&mut manifest).unwrap();
    manifest
}

#[test]
fn plan_observation_and_failure_records_validate_and_bind() {
    let Some(node) = node_or_skip("contracts") else {
        return;
    };
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let plan = adapter
        .plan(configuration("normal", &["pii:global", "pii:us"]))
        .unwrap();
    let manifest = manifest_with(plan.clone());
    document::validate(&manifest).expect("manifest with the adapter's plan is valid");

    let template: ObservationSet =
        document::parse_default(&fixture("observation-alpha.json")).unwrap();
    let mut session = adapter.start(&plan).map_err(|f| f.error).unwrap();
    let texts = ["x ann@ex.org y", "ssn 123-45-6789 z", "nothing"];
    let mut inputs: Vec<InputObservation> = Vec::new();
    for (i, text) in texts.iter().enumerate() {
        let out = session.scan(text).unwrap();
        inputs.push(out.to_input_observation(
            pii_eval_contracts::Id::new(format!("synthetic-variant-{i}")).unwrap(),
        ));
    }
    let body = ObservationSetBody {
        engine: template.semantic.engine.clone(),
        protocol: template.semantic.protocol,
        population_digest: template.semantic.population_digest.clone(),
        scanner: plan.identity.clone(),
        status: ScannerStatus::Complete,
        capabilities: session.capabilities().clone(),
        replays: ReplayRecord {
            count: 2,
            agreed: true,
        },
        inputs,
    };
    let mut observation = ObservationSet::unsealed(body);
    document::seal(&mut observation).unwrap();
    document::validate(&observation).expect("complete observation is valid");
    validate_observation_against_manifest(&observation, &manifest).expect("binds to the plan");
    // The serialized observation holds digests and byte ranges, not text.
    let json = document::to_pretty_json(&observation).unwrap();
    assert!(!json.contains("ann@ex.org") && !json.contains("123-45-6789"));
    assert_no_sentinel(&json);

    // A failed start is recorded as a status with no inputs, never as a clean scan.
    let kr_plan = adapter.plan(configuration("normal", &["pii:kr"])).unwrap();
    let Err(failure) = adapter.start(&kr_plan) else {
        panic!("must fail")
    };
    assert_eq!(
        failure.error.scanner_status(),
        Some(ScannerStatus::Unsupported)
    );
    let mut failed = ObservationSet::unsealed(ObservationSetBody {
        scanner: kr_plan.identity.clone(),
        status: ScannerStatus::Unsupported,
        capabilities: failure.capabilities,
        inputs: Vec::new(),
        ..observation.semantic.clone()
    });
    document::seal(&mut failed).unwrap();
    document::validate(&failed).expect("unsupported observation is valid");
    // The failure code is one the contract allows for that status.
    assert!(
        failure
            .error
            .failure_code()
            .unwrap()
            .allowed_for(ScannerStatus::Unsupported)
    );
}
