//! Same-pinned-scanner parity (P9, ADR 0011): the real `@redact-secret/core`
//! 0.1.0-beta.12.
//!
//! Two tests:
//!
//! * `committed_real_scanner_observations_*` runs in CI. It feeds the COMMITTED
//!   synthetic observation export of the real scanner (what the oracle's own
//!   adapter observed through a hermetic install,
//!   `tools/oracle-parity/real-scanner/run.sh`) through the same comparator and
//!   the real engine pipeline as the synthetic scanners. No scanner runs.
//! * `live_rust_run_*` is opt-in (`PII_EVAL_REDACT_SECRET_CORE_DIR`, an extracted
//!   package directory installed by `run.sh`; skipped with a printed reason
//!   otherwise). It runs the Rust adapter, shim and engine over the same package
//!   and requires the observed findings to equal the oracle adapter's, then the
//!   engine's metrics to equal the comparator's.

mod cli_support;
mod common;
mod parity;

use std::path::PathBuf;
use std::sync::Arc;

use cli_support::{core_configuration, node, shim_path};
use parity::compare::{Class, compare};
use parity::engine::{manifest, run_engine, view_of_result};
use parity::json::*;
use parity::model::*;
use pii_eval_adapters::redact_secret::{
    CoreAdapterConfig, CorePin, NPM_INTEGRITY, REAL_ENTRY_RELATIVE, SHIM_SHA256, core_adapter,
};
use pii_eval_adapters::{AdapterLimits, ScannerAdapter};
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run};
use pii_eval_contracts::{ScannerStatus, Sha256Digest};

const REAL_ID: &str = "redact-secret-core";

#[test]
fn committed_real_scanner_observations_have_no_unexplained_difference() {
    let ds = Dataset::load_real();
    let provenance = Dataset::real_provenance();
    // Identity of what ran: the pinned package, its integrity from the oracle lockfile,
    // a hermetic install of exactly the oracle lockfile's @redact-secret entries.
    assert_eq!(text(&provenance, "package"), "@redact-secret/core");
    assert_eq!(text(&provenance, "version"), "0.1.0-beta.12");
    let core = list(&provenance, "packages")
        .iter()
        .find(|p| text(p, "name") == "@redact-secret/core")
        .expect("core is in the lock");
    assert_eq!(text(core, "integrity"), NPM_INTEGRITY);
    assert_eq!(text(core, "installedVersion"), "0.1.0-beta.12");
    assert!(
        list(&provenance, "packages")
            .iter()
            .all(|p| text(p, "lockVersion") == "0.1.0-beta.12"
                && text(p, "integrity").starts_with("sha512-"))
    );
    assert_eq!(text(&provenance, "lockSha256").len(), 64);
    assert_eq!(
        text(get(&ds.input, "population"), "visibility"),
        "public-synthetic"
    );

    let cmp = compare(&ds);
    assert_eq!(cmp.scanners.len(), 1);
    assert_eq!(cmp.scanners[0].id, REAL_ID);
    assert_eq!(cmp.scanners[0].status, "complete");
    assert!(cmp.scanners[0].canonical_accounted && cmp.scanners[0].variants >= 50);
    assert!(
        cmp.compat_differences().is_empty(),
        "{:#?}",
        cmp.compat_differences()
    );
    assert!(cmp.unexplained().is_empty(), "{:#?}", cmp.unexplained());
    // The real scanner reports findings (the comparison is not over an empty observation).
    let export = &list(&ds.export, "scanners")[0];
    let observed: usize = list(export, "returned")
        .iter()
        .map(|r| list(r, "findings").len())
        .sum();
    assert!(observed >= 8, "{observed}");
    // Only PII findings with a family are observations; every one reports sensitivity (the oracle's
    // adapter reads a PII finding as the product's redaction decision).
    for r in list(export, "returned") {
        for f in list(r, "findings") {
            assert!(text(f, "family").starts_with("pii:"));
            assert_eq!(get(f, "sensitive").as_bool(), Some(true));
        }
    }
    // Every difference is classified, and none is a new bug.
    for d in &cmp.differences {
        assert_ne!(d.class(), Class::Unexplained);
        assert_ne!(d.class(), Class::NewBug);
    }

    // The engine's real pipeline over the same frozen observation equals the comparator's canonical
    // accounting, bit for bit.
    let rc = rust_corpus(&ds.input, &ds.export);
    let one = run_engine(&ds, &rc, 1);
    let four = run_engine(&ds, &rc, 4);
    assert_eq!(one.artifact.semantic_digest, four.artifact.semantic_digest);
    assert_eq!(one.metrics[REAL_ID], cmp.canonical[REAL_ID]);
    assert_eq!(one.statuses[REAL_ID], "complete");
}

#[test]
fn live_rust_run_over_the_real_package_reproduces_the_oracles_observations() {
    let Some(dir) = std::env::var_os("PII_EVAL_REDACT_SECRET_CORE_DIR") else {
        eprintln!(
            "SKIPPED live_rust_run_over_the_real_package: set PII_EVAL_REDACT_SECRET_CORE_DIR to the \
             package directory installed by tools/oracle-parity/real-scanner/run.sh"
        );
        return;
    };
    let node = node_or_skip();
    let ds = Dataset::load_real();
    let rc = rust_corpus(&ds.input, &ds.export);
    let snapshot = rc.snapshot();
    let adapter = core_adapter(CoreAdapterConfig {
        node,
        shim: shim_path(),
        package_dir: PathBuf::from(dir),
        entry_relative: REAL_ENTRY_RELATIVE.into(),
        pin: CorePin::released_beta12(),
        shim_sha256: Sha256Digest::new(SHIM_SHA256).unwrap(),
        extra_artifacts: Vec::new(),
        limits: AdapterLimits::default(),
    })
    .expect("adapter specification");
    let plan = adapter.plan(core_configuration()).expect("plan");
    let manifest = manifest(&snapshot, vec![plan], 2);
    let output = run(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: vec![Arc::new(adapter)],
        },
        &RunConfig {
            executor: ExecutorConfig {
                max_workers: 2,
                resources: ResourcePolicy::Unenforced,
                ..ExecutorConfig::default()
            },
            diagnostics: false,
            commit_cancelled: false,
        },
        &CancelToken::new(),
    )
    .expect("the run");
    let observation = &output.assembled.observations[0].semantic;
    assert_eq!(
        observation.status,
        ScannerStatus::Complete,
        "the real scanner did not complete: {:?}",
        output.runs.iter().map(|r| r.failure).collect::<Vec<_>>()
    );

    // 1. Observation parity: the Rust adapter saw what the oracle's adapter saw (range, family,
    //    jurisdiction, sensitivity; the Rust adapter also keeps the reported action, which the
    //    oracle's adapter does not read).
    let export = &list(&ds.export, "scanners")[0];
    let oracle = findings_of(export);
    let key = |f: &pii_eval_contracts::Finding| {
        (
            f.range.start,
            f.range.end,
            f.family.as_ref().map(|x| x.as_str().to_owned()),
            f.jurisdiction.as_ref().map(|x| x.as_str().to_owned()),
            f.sensitive,
        )
    };
    let mut compared = 0;
    let mut with_findings = 0;
    for v in &rc.variants {
        let rust = observation
            .inputs
            .iter()
            .find(|i| i.variant_id == v.variant.variant_id)
            .unwrap_or_else(|| panic!("no observation of {}/{}", v.case_id, v.slot));
        let mut got: Vec<_> = rust.findings.iter().map(key).collect();
        let mut want: Vec<_> = oracle[&v.key()].iter().map(key).collect();
        got.sort();
        want.sort();
        assert_eq!(
            got, want,
            "{}/{}: the Rust adapter and the oracle's adapter observed different findings",
            v.case_id, v.slot
        );
        compared += 1;
        with_findings += usize::from(!got.is_empty());
    }
    assert_eq!(compared, rc.variants.len());
    assert!(with_findings >= 8, "{with_findings}");

    // 2. Metrics: the engine's artifact equals the comparator's canonical accounting over the oracle's
    //    frozen observation of the same package.
    let cmp = compare(&ds);
    let artifact = &output.assembled.artifact;
    let metrics: Vec<_> = artifact.semantic.scanner_metrics[0]
        .metrics
        .iter()
        .map(|m| (m.metric.id, view_of_result(m)))
        .collect();
    let mut metrics = metrics;
    metrics.sort_by_key(|(m, _)| word(m));
    assert_eq!(metrics, cmp.canonical[REAL_ID]);
    assert!(cmp.unexplained().is_empty());
}

fn node_or_skip() -> PathBuf {
    node().unwrap_or_else(|| panic!("node is required for the live run"))
}
