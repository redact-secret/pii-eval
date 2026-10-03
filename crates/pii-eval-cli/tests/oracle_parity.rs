//! Oracle parity (P9, issue #10, ADR 0011): the Rust engine against the pinned
//! TypeScript oracle's own output on frozen synthetic input.
//!
//! The oracle side is committed (`fixtures/oracle-parity/oracle-export.json`,
//! produced by `tools/oracle-parity/regenerate.sh`); CI has no access to the
//! oracle repository and never regenerates it. The tests below run the
//! comparison from that committed export, check that the export manifest and the
//! oracle pin are unchanged, prove that the comparator finds injected
//! differences (so it cannot pass vacuously) and check determinism, input-order
//! and worker-count invariance where the canonical protocol promises them.
//!
//! Regenerate the report after an intentional, reviewed change with
//! `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test oracle_parity`.

mod parity;

use std::collections::{BTreeMap, BTreeSet};

use parity::compare::{Class, Comparison, Difference, EXPLANATIONS, attribute, class_of, compare};
use parity::engine::run_engine;
use parity::json::*;
use parity::model::*;
use parity::report;
use parity::rows::{canonical_assessment, canonical_row, legacy_row};
use pii_eval_contracts::{
    Finding, ScannerStatus, Sha256Digest, validate_artifact_against_snapshot,
};
use pii_eval_kernel::verify_run_artifact_accounting;
use serde_json::Value;

const ORACLE_PIN: &str = "4b846967346505baca11e0b98cab1475fbce6773";
/// Second, independent record of the digest of the oracle files the export was
/// produced from. Changing the oracle file list or any file makes this test fail
/// until the change is made on purpose, here and in `oracle-files.json`.
const ORACLE_TREE_DIGEST: &str = "6f35613cc5a6a827f19609d8c3d22a56362c0f7f526553f17cc1bc4e9ec8a83b";

fn read_repo(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path)).unwrap_or_else(|_| panic!("missing {path}"))
}

fn updating() -> bool {
    std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1")
}

// ---------------------------------------------------------------------------
// The export manifest and the pin
// ---------------------------------------------------------------------------

#[test]
fn the_export_manifest_and_the_oracle_pin_are_unchanged() {
    let ds = Dataset::load();
    let provenance = get(&ds.export, "provenance");
    let oracle = get(provenance, "oracle");
    assert_eq!(text(&ds.export, "schema"), "pii-eval-oracle-export/1");
    assert_eq!(text(&ds.input, "schema"), "pii-eval-parity-input/1");
    assert_eq!(text(oracle, "commit"), ORACLE_PIN);
    assert_eq!(
        text(oracle, "repository"),
        "redact-secret/redact-secret-benchmarks"
    );
    for doc in [
        "docs/adr/0001-rust-first-and-oracle-pin.md",
        "docs/migration/ownership-map.md",
    ] {
        let body = String::from_utf8(read_repo(doc)).unwrap();
        assert!(body.contains(ORACLE_PIN), "{doc} records the pin");
    }
    // The file list, its tree digest and the export agree.
    let spec: Value =
        serde_json::from_slice(&read_repo("tools/oracle-parity/oracle-files.json")).unwrap();
    assert_eq!(text(&spec, "pin"), ORACLE_PIN);
    assert_eq!(text(&spec, "treeDigest"), ORACLE_TREE_DIGEST);
    assert_eq!(text(oracle, "filesTreeDigest"), ORACLE_TREE_DIGEST);
    assert_eq!(
        uint(oracle, "fileCount") as usize,
        list(&spec, "files").len()
    );
    // The tooling that produced the export is the tooling in the repository.
    let scripts = get(provenance, "scripts")
        .as_object()
        .expect("script digests");
    assert!(scripts.len() >= 8);
    for (name, digest) in scripts {
        let file = read_repo(&format!("tools/oracle-parity/{name}"));
        assert_eq!(
            digest.as_str().unwrap(),
            Sha256Digest::of_bytes(&file).as_str(),
            "tools/oracle-parity/{name} changed since the export was produced; regenerate the export"
        );
    }
    assert_eq!(
        text(provenance, "inputSha256"),
        Sha256Digest::of_bytes(&ds.input_bytes).as_str(),
        "the parity input changed since the export was produced"
    );
    assert!(text(get(provenance, "runtime"), "node").starts_with("v22."));
    // The oracle versions the comparison is about.
    assert_eq!(text(oracle, "engineVersion"), "1.0.0");
    assert_eq!(text(get(oracle, "profile"), "id"), "pii-v1");
    // The export holds only integers and strings: nothing a strict parser rejects.
    fn no_floats_or_nulls(v: &Value) {
        match v {
            Value::Number(n) => assert!(n.is_u64() || n.is_i64(), "float in the export"),
            Value::Null => panic!("null in the export"),
            Value::Array(a) => a.iter().for_each(no_floats_or_nulls),
            Value::Object(o) => o.values().for_each(no_floats_or_nulls),
            _ => {}
        }
    }
    no_floats_or_nulls(&ds.export);
}

// ---------------------------------------------------------------------------
// The compatibility protocol and the census
// ---------------------------------------------------------------------------

fn variant_count(ds: &Dataset) -> u64 {
    list(&ds.export, "cases")
        .iter()
        .map(|c| list(c, "variants").len() as u64)
        .sum()
}

#[test]
fn the_compatibility_protocol_reproduces_the_oracle_with_zero_differences() {
    let ds = Dataset::load();
    let cmp = compare(&ds);
    assert!(
        cmp.compat_differences().is_empty(),
        "compatibility layers differ: {:#?}",
        cmp.compat_differences()
            .into_iter()
            .take(5)
            .collect::<Vec<_>>()
    );
    // The comparison is not vacuous: every layer compared exactly the items the data holds.
    let scanners = list(&ds.export, "scanners").len() as u64;
    let vectors = list(&ds.export, "accountingVectors").len() as u64;
    let throws = list(&ds.export, "accountingVectors")
        .iter()
        .filter(|v| v.get("throws").is_some())
        .count() as u64;
    let variants = variant_count(&ds);
    let stats = get(&ds.export, "statistics");
    let n_stats = (list(stats, "grid").len() + list(stats, "singles").len()) as u64;
    let accounted = cmp
        .scanners
        .iter()
        .filter(|s| s.canonical_accounted)
        .count() as u64;
    let expect =
        |layer: &str, n: u64| assert_eq!(cmp.compared.get(layer).copied(), Some(n), "{layer}");
    expect("variant", variants);
    expect("outcome-compat", scanners * variants);
    // One matching comparison per variant and scanner, plus the scanner-level check of a scanner the
    // oracle failed although it was declared complete (the rejected-range scanner).
    let failed_declared_complete = list(&ds.export, "scanners")
        .iter()
        .filter(|s| text(s, "declaredStatus") == "complete" && text(s, "status") != "complete")
        .count() as u64;
    assert_eq!(failed_declared_complete, 1);
    expect("outcome", scanners * variants + failed_declared_complete);
    expect("accounting-compat", (scanners + vectors) * 10 + throws);
    expect("accounting-rule", (scanners + vectors) * 10);
    expect("accounting-canonical", accounted * 10);
    expect("statistics-compat", n_stats);
    expect("statistics", n_stats);
    expect("population", scanners * 2);
    assert!(scanners >= 10 && vectors >= 8 && variants >= 50 && n_stats >= 600);
    // The seven methods, ten metrics and every scanner status are represented.
    let methods: BTreeSet<&str> = list(&ds.export, "cases")
        .iter()
        .map(|c| text(c, "method"))
        .collect();
    assert_eq!(methods.len(), 7);
    let statuses: BTreeSet<&str> = list(&ds.export, "scanners")
        .iter()
        .map(|s| text(s, "status"))
        .collect();
    assert_eq!(
        statuses,
        BTreeSet::from([
            "complete",
            "error",
            "unavailable",
            "unstable",
            "unsupported"
        ])
    );
    // Withheld states of both kinds occur in the oracle's own output.
    let mut kinds = BTreeSet::new();
    for s in list(&ds.export, "scanners") {
        for (_, m) in get(get(s, "accounting"), "metrics").as_object().unwrap() {
            kinds.insert(text(get(m, "rate"), "kind").to_owned());
        }
    }
    assert_eq!(
        kinds,
        BTreeSet::from([
            "insufficient-evidence".to_owned(),
            "null".to_owned(),
            "value".to_owned()
        ])
    );
}

#[test]
fn every_difference_of_the_canonical_revision_is_classified() {
    let ds = Dataset::load();
    let cmp = compare(&ds);
    let unexplained: Vec<&Difference> = cmp.unexplained();
    assert!(
        unexplained.is_empty(),
        "unexplained: {:#?}",
        unexplained.into_iter().take(5).collect::<Vec<_>>()
    );
    // Ids are the registry's; classes are never `new-bug` or `unresolved` here: a
    // difference that needed either would have been a finding to fix or to record.
    let known: BTreeSet<&str> = EXPLANATIONS.iter().map(|(i, _, _)| *i).collect();
    for d in &cmp.differences {
        for id in &d.ids {
            assert!(known.contains(id), "{id}");
        }
        assert_ne!(d.class(), Class::NewBug);
        assert_ne!(d.class(), Class::Unresolved);
        // Compatibility layers never carry a classified difference.
        assert!(!d.layer.ends_with("-compat"));
    }
    // Every id of the registry occurs: the list is neither stale nor padded.
    let exercised = cmp.ids_exercised();
    let expected: BTreeSet<&str> = [
        "0004/D1", "0004/D3", "0004/D6", "0005/A2", "0005/A3", "0005/S1", "0007/D1", "0007/D4",
        "0008/R3",
    ]
    .into_iter()
    .collect();
    assert_eq!(exercised.keys().copied().collect::<BTreeSet<_>>(), expected);
    assert_eq!(known, expected);
    // Hand-checked anchors: the A8 vector (3 of 4 in the oracle, 2 of 4 canonical) and the
    // A2 vector (the oracle's eligibility follows the first variant by id).
    let a8 = cmp
        .differences
        .iter()
        .find(|d| {
            d.subject == "a8-collision-any-versus-all" && d.aspect == "jurisdiction-collision-rate"
        })
        .expect("A8 difference");
    assert_eq!(a8.ids, ["0008/R3"]);
    assert!(a8.oracle.contains("numerator=3") && a8.rust.contains("numerator=2"));
    assert!(
        a8.oracle.contains("point=750000 bound=300636")
            && a8.rust.contains("point=500000 bound=150036")
    );
    let a2 = cmp
        .differences
        .iter()
        .find(|d| d.subject == "a2-invalid-variant-sorts-first" && d.aspect == "type-miss-rate")
        .expect("A2 difference");
    assert_eq!(a2.ids, ["0005/A2"]);
    // The S1 tie vectors: 3/20 and 7/20 at one place round differently (ADR 0005 S1).
    let s1: Vec<_> = cmp
        .differences
        .iter()
        .filter(|d| d.layer == "statistics")
        .collect();
    assert_eq!(s1.len(), 2);
    assert!(s1.iter().all(|d| d.ids == ["0005/S1"]));
    // Classes of every id come from the registry.
    assert_eq!(class_of("0004/D1"), Class::OldBug);
    assert_eq!(class_of("0008/R3"), Class::IntendedRevision);
    assert_eq!(class_of("0007/D1"), Class::Compatibility);
    assert_eq!(class_of("not-an-id"), Class::Unexplained);
}

// ---------------------------------------------------------------------------
// The committed report
// ---------------------------------------------------------------------------

#[test]
fn the_report_is_deterministic_and_equals_the_committed_report() {
    let ds = Dataset::load();
    let real = Dataset::load_real();
    let first = report::build(&ds, &compare(&ds), Some((&real, &compare(&real))));
    let second = report::build(&ds, &compare(&ds), Some((&real, &compare(&real))));
    assert_eq!(
        first, second,
        "two runs of the comparison give different reports"
    );
    let json = report::pretty(&first);
    let markdown = report::markdown(&first);
    assert_eq!(markdown, report::markdown(&second));
    let json_path = data_dir().join("report.json");
    let md_path = repo_root().join("docs/migration/oracle-parity-report.md");
    if updating() {
        std::fs::write(&json_path, &json).unwrap();
        std::fs::write(&md_path, &markdown).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&json_path)
            .expect("missing report.json; run with PII_EVAL_UPDATE_FIXTURES=1"),
        json,
        "fixtures/oracle-parity/report.json is stale"
    );
    assert_eq!(
        std::fs::read_to_string(&md_path)
            .expect("missing report; run with PII_EVAL_UPDATE_FIXTURES=1"),
        markdown,
        "docs/migration/oracle-parity-report.md is stale"
    );
    // Sanitized: only synthetic ids, enumerated states and integers. No authored text appears.
    for case in list(&ds.input, "cases") {
        let value = text(case, "value");
        assert!(
            !json.contains(value) && !markdown.contains(value),
            "a matched value appears in the report"
        );
    }
    assert!(json.contains("\"unexplained\": 0"));
}

// ---------------------------------------------------------------------------
// The comparator finds injected differences
// ---------------------------------------------------------------------------

fn corrupted(f: impl FnOnce(&mut Value)) -> Comparison {
    let mut ds = Dataset::load();
    f(&mut ds.export);
    compare(&ds)
}

fn detected(cmp: &Comparison, layer: &str, aspect: &str) -> bool {
    cmp.differences
        .iter()
        .any(|d| d.layer == layer && d.aspect == aspect && d.class() == Class::Unexplained)
}

fn set(export: &mut Value, pointer: &str, value: Value) {
    *export
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("no {pointer}")) = value;
}

#[test]
fn a_changed_count_is_found() {
    let cmp = corrupted(|e| {
        let n = e
            .pointer("/scanners/0/accounting/metrics/type-miss-rate/counts/numerator")
            .unwrap()
            .as_u64()
            .unwrap();
        set(
            e,
            "/scanners/0/accounting/metrics/type-miss-rate/counts/numerator",
            Value::from(n + 1),
        );
    });
    assert!(
        detected(&cmp, "accounting-compat", "type-miss-rate"),
        "{:?}",
        cmp.compat_differences().len()
    );
    let cmp = corrupted(|e| {
        let n = e
            .pointer("/scanners/1/accounting/metrics/measurable-share/effectiveN")
            .unwrap()
            .as_u64()
            .unwrap();
        set(
            e,
            "/scanners/1/accounting/metrics/measurable-share/effectiveN",
            Value::from(n + 1),
        );
    });
    assert!(detected(&cmp, "accounting-compat", "measurable-share"));
}

#[test]
fn a_changed_range_state_is_found() {
    let cmp = corrupted(|e| {
        let was = e
            .pointer("/scanners/1/outcomes/0/range")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        set(
            e,
            "/scanners/1/outcomes/0/range",
            Value::from(if was == "miss" { "exact" } else { "miss" }),
        );
    });
    assert!(detected(&cmp, "outcome-compat", "range"));
}

#[test]
fn a_changed_axis_state_and_observed_summary_are_found() {
    let cmp = corrupted(|e| {
        set(
            e,
            "/scanners/1/outcomes/1/type/state",
            Value::from("wrong-family"),
        );
        set(
            e,
            "/scanners/1/outcomes/2/sensitivity/state",
            Value::from("false-positive"),
        );
        set(
            e,
            "/scanners/1/outcomes/3/observed/findingCount",
            Value::from(99),
        );
    });
    assert!(detected(&cmp, "outcome-compat", "type"));
    assert!(detected(&cmp, "outcome-compat", "sensitivity"));
    assert!(detected(&cmp, "outcome-compat", "observed.count"));
}

#[test]
fn a_changed_interval_is_found() {
    let cmp = corrupted(|e| {
        let bound = e
            .pointer("/scanners/0/accounting/metrics/measurable-share/rate/bound")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let mut chars: Vec<char> = bound.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '9' { '8' } else { '9' };
        set(
            e,
            "/scanners/0/accounting/metrics/measurable-share/rate/bound",
            Value::from(chars.into_iter().collect::<String>()),
        );
    });
    assert!(detected(&cmp, "accounting-compat", "measurable-share"));
    let cmp = corrupted(|e| {
        set(
            e,
            "/scanners/0/accounting/metrics/measurable-share/rate/point",
            Value::from("0.000001"),
        );
    });
    assert!(detected(&cmp, "accounting-compat", "measurable-share"));
    let cmp = corrupted(|e| {
        let rate = e
            .pointer("/statistics/grid/100/rate/bound")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let tweaked = if rate.ends_with('1') {
            format!("{}2", &rate[..rate.len() - 1])
        } else {
            format!("{}1", &rate[..rate.len() - 1])
        };
        set(e, "/statistics/grid/100/rate/bound", Value::from(tweaked));
    });
    assert!(detected(&cmp, "statistics-compat", "rate"));
}

#[test]
fn a_changed_withheld_state_is_found() {
    // A published value becomes withheld.
    let cmp = corrupted(|e| {
        set(
            e,
            "/scanners/0/accounting/metrics/measurable-share/rate",
            serde_json::json!({"kind": "insufficient-evidence"}),
        );
    });
    assert!(detected(&cmp, "accounting-compat", "measurable-share"));
    // An insufficient-evidence metric becomes a zero denominator.
    let ds = Dataset::load();
    let baseline = &list(&ds.export, "scanners")[0];
    let m = get(
        get(get(baseline, "accounting"), "metrics"),
        "context-discrimination-rate",
    );
    assert_eq!(
        text(get(m, "rate"), "kind"),
        "insufficient-evidence",
        "the anchor metric is withheld in the oracle"
    );
    let cmp = corrupted(|e| {
        set(
            e,
            "/scanners/0/accounting/metrics/context-discrimination-rate/rate",
            serde_json::json!({"kind": "null"}),
        );
    });
    assert!(detected(
        &cmp,
        "accounting-compat",
        "context-discrimination-rate"
    ));
    // A changed status.
    let cmp = corrupted(|e| {
        set(
            e,
            "/scanners/0/accounting/metrics/type-miss-rate/status",
            Value::from("not-measured"),
        );
    });
    assert!(detected(&cmp, "accounting-compat", "type-miss-rate"));
    // A scanner failure state changed: the rows it produced no longer follow.
    let cmp = corrupted(|e| {
        set(e, "/scanners/5/status", Value::from("complete"));
    });
    assert!(detected(&cmp, "outcome-compat", "type") || detected(&cmp, "outcome-compat", "range"));
}

#[test]
fn a_changed_identity_or_population_binding_is_found() {
    // A variant renamed in the oracle export no longer matches the Rust variant.
    let cmp = corrupted(|e| set(e, "/cases/0/variants/0/slot", Value::from("renamed")));
    assert!(detected(&cmp, "variant", "variant"));
    // A case's family, scope and text.
    let cmp = corrupted(|e| set(e, "/cases/1/family", Value::from("pii:global:phone")));
    assert!(detected(&cmp, "variant", "family"));
    let cmp = corrupted(|e| set(e, "/cases/1/variants/0/text", Value::from("other text")));
    assert!(detected(&cmp, "variant", "text"));
    let cmp = corrupted(|e| set(e, "/cases/2/variants/0/strategy", Value::from("derived")));
    assert!(detected(&cmp, "variant", "strategy"));
    // An outcome row filed under another variant.
    let cmp = corrupted(|e| set(e, "/scanners/0/outcomes/0/slot", Value::from("renamed")));
    assert!(detected(&cmp, "outcome-compat", "row"));
    // Population counts.
    let cmp = corrupted(|e| set(e, "/scanners/0/accounting/sourceCaseCount", Value::from(35)));
    assert!(detected(&cmp, "population", "sourceCaseCount"));
    let cmp = corrupted(|e| set(e, "/scanners/0/accounting/rowCount", Value::from(52)));
    assert!(detected(&cmp, "population", "rowCount"));
}

#[test]
fn a_changed_observation_or_a_missing_vector_is_found() {
    // The frozen findings no longer produce the oracle's outcome.
    let cmp = corrupted(|e| {
        let list = e
            .pointer_mut("/scanners/0/returned/0/findings")
            .unwrap()
            .as_array_mut()
            .unwrap();
        list.clear();
    });
    assert!(
        cmp.compat_differences()
            .iter()
            .any(|d| d.layer == "outcome-compat")
    );
    let cmp = corrupted(|e| {
        e.pointer_mut("/accountingVectors")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .remove(0);
    });
    assert!(detected(&cmp, "accounting-compat", "vector"));
    // An oracle refusal that is no longer a refusal.
    let cmp = corrupted(|e| {
        let vectors = e
            .pointer_mut("/accountingVectors")
            .unwrap()
            .as_array_mut()
            .unwrap();
        let i = vectors
            .iter()
            .position(|v| v.get("throws").is_some())
            .unwrap();
        vectors[i] =
            serde_json::json!({"id": vectors[i]["id"].clone(), "throws": "some other message"});
    });
    assert!(detected(&cmp, "accounting-compat", "throws"));
}

#[test]
fn an_unattributable_matching_difference_is_unexplained() {
    // Take a real variant and tamper with the canonical row: no counterfactual removes the difference.
    let ds = Dataset::load();
    let rc = rust_corpus(&ds.input, &ds.export);
    let multi = list(&ds.export, "scanners")
        .iter()
        .find(|s| text(s, "id") == "parity-multi")
        .unwrap();
    let findings = findings_of(multi);
    let caps = parity::capabilities();
    let mut attributed = 0;
    let mut tampered = 0;
    for v in &rc.variants {
        let emission = findings.get(&v.key()).cloned().unwrap_or_default();
        let a = canonical_assessment(v, ScannerStatus::Complete, &caps, &emission).unwrap();
        let legacy = legacy_row(v, ScannerStatus::Complete, &emission);
        let canonical = canonical_row(v, &a);
        // Untampered: attributable (possibly with no id at all).
        assert!(
            attribute(
                v,
                ScannerStatus::Complete,
                &emission,
                &a,
                &legacy,
                &canonical
            )
            .is_ok()
        );
        attributed += 1;
        // Tampered: a range state no rule produces.
        let mut wrong = canonical.clone();
        wrong.range = if canonical.range == pii_eval_contracts::RangeState::Partial {
            pii_eval_contracts::RangeState::Exact
        } else {
            pii_eval_contracts::RangeState::Partial
        };
        assert!(
            attribute(v, ScannerStatus::Complete, &emission, &a, &legacy, &wrong).is_err(),
            "{}/{}",
            v.case_id,
            v.slot
        );
        // Tampered: a changed observed count.
        let mut wrong = canonical.clone();
        wrong.finding_count += 1;
        assert!(attribute(v, ScannerStatus::Complete, &emission, &a, &legacy, &wrong).is_err());
        tampered += 1;
    }
    assert_eq!(attributed, tampered);
    assert!(attributed >= 50);
    // The D3 attribution needs its cause: a sensitivity difference with a primary that DID report sensitivity is not D3.
    let mut checked = false;
    for v in &rc.variants {
        let emission = findings.get(&v.key()).cloned().unwrap_or_default();
        let a = canonical_assessment(v, ScannerStatus::Complete, &caps, &emission).unwrap();
        let legacy = legacy_row(v, ScannerStatus::Complete, &emission);
        let canonical = canonical_row(v, &a);
        if canonical.sensitivity_state == pii_eval_contracts::SensitivityState::Correct
            && a.occurrences[0].primary.is_some()
        {
            let mut wrong = canonical.clone();
            wrong.sensitivity_state = pii_eval_contracts::SensitivityState::NotMeasured;
            assert!(attribute(v, ScannerStatus::Complete, &emission, &a, &legacy, &wrong).is_err());
            checked = true;
            break;
        }
    }
    assert!(checked);
}

// ---------------------------------------------------------------------------
// Determinism and invariance
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, (self.next() % (i as u64 + 1)) as usize);
        }
    }
}

fn shuffle_array(v: &mut Value, rng: &mut Rng) {
    if let Some(a) = v.as_array_mut() {
        rng.shuffle(a);
    }
}

#[test]
fn canonical_results_are_invariant_to_input_order_and_legacy_results_are_not() {
    let base = Dataset::load();
    let reference = compare(&base);
    assert!(!reference.canonical.is_empty());
    for seed in 1..=6u64 {
        let mut rng = Rng(seed);
        let mut ds = base.clone();
        // Case order, scanner order, row order and the order of every finding list.
        shuffle_array(ds.input.get_mut("cases").unwrap(), &mut rng);
        shuffle_array(ds.export.get_mut("cases").unwrap(), &mut rng);
        shuffle_array(ds.export.get_mut("scanners").unwrap(), &mut rng);
        for s in ds
            .export
            .get_mut("scanners")
            .unwrap()
            .as_array_mut()
            .unwrap()
        {
            shuffle_array(s.get_mut("returned").unwrap(), &mut rng);
            shuffle_array(s.get_mut("outcomes").unwrap(), &mut rng);
            for r in s.get_mut("returned").unwrap().as_array_mut().unwrap() {
                shuffle_array(r.get_mut("findings").unwrap(), &mut rng);
            }
        }
        let cmp = compare(&ds);
        assert_eq!(
            cmp.canonical, reference.canonical,
            "canonical metrics depend on input order (seed {seed})"
        );
        // The canonical rows too: the differences against the oracle that do not involve the
        // legacy mode (the accounting layers over canonical rows) are identical.
        let canonical_layer = |c: &Comparison| -> Vec<(String, String, String)> {
            c.differences
                .iter()
                .filter(|d| d.layer == "accounting-canonical")
                .map(|d| (d.scanner.clone(), d.aspect.clone(), d.rust.clone()))
                .collect()
        };
        let mut a = canonical_layer(&cmp);
        let mut b = canonical_layer(&reference);
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    // Per variant: reversing the findings changes the legacy row for at least one
    // multi-finding variant (the compatibility mode keeps the oracle's emission-order
    // dependence, D1) and never changes the canonical row.
    let rc = rust_corpus(&base.input, &base.export);
    let caps = parity::capabilities();
    let multi = list(&base.export, "scanners")
        .iter()
        .find(|s| text(s, "id") == "parity-multi")
        .unwrap();
    let findings = findings_of(multi);
    let mut legacy_changed = 0;
    for v in &rc.variants {
        let emission = findings.get(&v.key()).cloned().unwrap_or_default();
        let mut reversed: Vec<Finding> = emission.clone();
        reversed.reverse();
        let canonical = |f: &[Finding]| {
            canonical_row(
                v,
                &canonical_assessment(v, ScannerStatus::Complete, &caps, f).unwrap(),
            )
        };
        assert_eq!(
            canonical(&emission),
            canonical(&reversed),
            "{}/{}",
            v.case_id,
            v.slot
        );
        if legacy_row(v, ScannerStatus::Complete, &emission)
            != legacy_row(v, ScannerStatus::Complete, &reversed)
        {
            legacy_changed += 1;
        }
    }
    assert!(
        legacy_changed >= 5,
        "the legacy mode must show its order dependence on this corpus ({legacy_changed})"
    );
}

#[test]
fn the_engine_run_matches_the_comparator_and_is_invariant_to_workers_and_repeats() {
    let ds = Dataset::load();
    let cmp = compare(&ds);
    let rc = rust_corpus(&ds.input, &ds.export);
    let one = run_engine(&ds, &rc, 1);
    let four = run_engine(&ds, &rc, 4);
    let again = run_engine(&ds, &rc, 4);
    // Jobs and repeat invariance: the same semantic digest and the same documents.
    assert_eq!(one.artifact.semantic_digest, four.artifact.semantic_digest);
    assert_eq!(
        four.artifact.semantic_digest,
        again.artifact.semantic_digest
    );
    assert_eq!(one.artifact.semantic, four.artifact.semantic);
    // The engine's artifact verifies against the snapshot and binds to the population.
    let snapshot = rc.snapshot();
    validate_artifact_against_snapshot(&one.artifact, &snapshot).expect("binds to the snapshot");
    verify_run_artifact_accounting(&one.artifact, &snapshot).expect("accounting verifies");
    let population = get(&ds.input, "population");
    let binding = &one.artifact.semantic.population;
    assert_eq!(binding.population_id.as_str(), text(population, "id"));
    assert_eq!(
        u64::from(binding.population_version),
        uint(population, "version")
    );
    assert_eq!(word(&binding.visibility), text(population, "visibility"));
    assert_eq!(binding.population_digest, snapshot.semantic_digest);
    // Statuses are the oracle's; metrics are the comparator's canonical metrics, bit for bit.
    let mut compared = 0;
    for s in list(&ds.export, "scanners") {
        let id = text(s, "id");
        let Some(metrics) = one.metrics.get(id) else {
            assert!(id == "parity-midchar" || id == "parity-badrange", "{id}");
            continue;
        };
        assert_eq!(one.statuses[id], text(s, "status"), "{id}");
        assert_eq!(
            metrics, &cmp.canonical[id],
            "{id}: the engine's metrics differ from the comparator's canonical accounting"
        );
        compared += 1;
    }
    assert_eq!(compared, 8);
    // The per-scanner failure and instability states are recorded, not hidden.
    let by_status: BTreeMap<&str, usize> =
        one.statuses.values().fold(BTreeMap::new(), |mut m, s| {
            *m.entry(s.as_str()).or_default() += 1;
            m
        });
    assert_eq!(by_status.get("unstable"), Some(&1));
    assert_eq!(by_status.get("unsupported"), Some(&1));
    assert_eq!(by_status.get("unavailable"), Some(&1));
    assert_eq!(by_status.get("error"), Some(&1));
}
