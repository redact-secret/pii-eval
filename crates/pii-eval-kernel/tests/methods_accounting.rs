//! Generated variants through the real matcher (P3) and accounting (P4):
//! denominator and variant conservation, explicit not-measured states, the two
//! population views, bounded generation, and invariance under input order,
//! worker completion order, batching, repetition and seed changes.
//!
//! Counts in the conservation tests are derived by hand from the authored
//! cases (see the comments); nothing is read back from the code under test.

mod meth_common;

use std::cell::Cell;
use std::rc::Rc;

use meth_common::*;
use pii_eval_contracts::axes::OutcomeRow;
use pii_eval_contracts::{
    ActionCapability, ActionOutcome, ByteRange, CapabilityState, CorpusSnapshot,
    CorpusSnapshotBody, ExpectedType, Finding, Mechanics, MetricId, PopulationCounts, RangeState,
    ScannerCapabilities, ScannerId, ScannerStatus, SensitivityExpectation, SensitivityState,
    TypeState, seal,
};
use pii_eval_kernel::methods::{
    AuthoredCase, GenerateError, GenerationLimit, GenerationLimits, GenerationOutput, Generator,
    PopulationView, RefusalReason, SEED_RULE_LEGACY, SEED_RULE_V1, ValidatorRegistry,
    ViewAssignment, ViewError, ViewRoster, apply_review, assemble_body, assemble_cases,
};
use pii_eval_kernel::{
    Accounting, AuthoredIndex, OutcomeRef, ScannerInput, ScannerView, VariantInput, account,
    assess_variant,
};

fn capabilities() -> ScannerCapabilities {
    ScannerCapabilities {
        ranges: CapabilityState::Supported,
        family_classification: CapabilityState::Supported,
        sensitivity_classification: CapabilityState::Supported,
        jurisdiction_reporting: CapabilityState::Supported,
        action: ActionCapability::ReportedAction,
        families: vec![],
        jurisdictions: vec![],
    }
}

struct Row {
    case: String,
    variant: String,
    occurrence: String,
    method: pii_eval_contracts::MethodId,
    row: OutcomeRow,
}

/// Rows of a scanner that reports exactly the authored valid-type occurrences,
/// with the right family, jurisdiction and sensitivity flag, through the
/// canonical matcher. `reviews` gates the type axis as `apply_review` says.
fn perfect_rows(out: &GenerationOutput, gate: bool) -> Vec<Row> {
    let caps = capabilities();
    let mut rows = Vec::new();
    for g in &out.generated {
        for (variant, prov) in g.case.variants.iter().zip(&g.provenance) {
            let findings: Vec<Finding> = variant
                .expectations
                .iter()
                .filter(|e| e.type_expectation == ExpectedType::Valid)
                .map(|e| Finding {
                    range: e.range,
                    family: Some(e.family.clone()),
                    jurisdiction: g.case.jurisdiction.clone(),
                    sensitive: Some(e.sensitivity == SensitivityExpectation::Sensitive),
                    action: None,
                })
                .collect();
            let a = assess_variant(
                &VariantInput {
                    text: &variant.text,
                    case_jurisdiction: g.case.jurisdiction.as_ref(),
                    expectations: &variant.expectations,
                },
                &ScannerView {
                    status: ScannerStatus::Complete,
                    capabilities: &caps,
                    findings: &findings,
                },
            )
            .unwrap();
            for o in a.occurrences {
                rows.push(Row {
                    case: g.case.case_id.as_str().to_owned(),
                    variant: variant.variant_id.as_str().to_owned(),
                    occurrence: o.occurrence_id.as_str().to_owned(),
                    method: g.case.method,
                    row: if gate {
                        apply_review(o.row, prov.review)
                    } else {
                        o.row
                    },
                });
            }
        }
    }
    rows
}

/// Rows of a scanner that finds nothing.
fn blind_rows(out: &GenerationOutput) -> Vec<Row> {
    let mut rows = Vec::new();
    for g in &out.generated {
        for variant in &g.case.variants {
            for e in &variant.expectations {
                let (type_identity, range) = match e.type_expectation {
                    ExpectedType::Valid => (TypeState::Miss, RangeState::Miss),
                    ExpectedType::Invalid => (TypeState::InvalidCorrect, RangeState::Miss),
                };
                let sensitivity_context = match e.sensitivity {
                    SensitivityExpectation::Sensitive => SensitivityState::Miss,
                    SensitivityExpectation::NonSensitive => SensitivityState::Correct,
                    SensitivityExpectation::NotEstablished => SensitivityState::Unresolved,
                };
                rows.push(Row {
                    case: g.case.case_id.as_str().to_owned(),
                    variant: variant.variant_id.as_str().to_owned(),
                    occurrence: e.occurrence_id.as_str().to_owned(),
                    method: g.case.method,
                    row: OutcomeRow {
                        type_identity,
                        sensitivity_context,
                        range,
                        action: ActionOutcome::NotMeasured,
                    },
                });
            }
        }
    }
    rows
}

fn unmeasured_rows(rows: &[Row]) -> Vec<Row> {
    rows.iter()
        .map(|r| Row {
            case: r.case.clone(),
            variant: r.variant.clone(),
            occurrence: r.occurrence.clone(),
            method: r.method,
            row: OutcomeRow {
                type_identity: TypeState::NotMeasured,
                sensitivity_context: SensitivityState::NotMeasured,
                range: RangeState::NotApplicable,
                action: ActionOutcome::NotMeasured,
            },
        })
        .collect()
}

fn account_rows(body: &CorpusSnapshotBody, rows: &[Row], status: ScannerStatus) -> Accounting {
    let index = AuthoredIndex::new(body).unwrap();
    let scanner = ScannerId::new("scanner-a").unwrap();
    account(
        &index,
        &[ScannerInput {
            id: &scanner,
            status,
        }],
        rows.iter().map(|r| OutcomeRef {
            scanner_id: "scanner-a",
            case_id: &r.case,
            variant_id: &r.variant,
            occurrence_id: &r.occurrence,
            method: r.method,
            row: r.row,
        }),
        &Mechanics::PII_V1,
    )
    .unwrap()
}

fn generate_all(cases: &[AuthoredCase], rule: &str) -> GenerationOutput {
    let reg = ValidatorRegistry::builtin();
    let g = Generator::new(&rules(rule), &reg, GenerationLimits::DEFAULT).unwrap();
    g.generate_all(cases).unwrap()
}

fn body_of(out: GenerationOutput, rule: &str) -> CorpusSnapshotBody {
    assemble_body(population(), rules(rule), out.generated).unwrap()
}

fn counts(acc: &Accounting, metric: MetricId) -> (u64, u64, u64, u64, u64, u64, u64) {
    let c = acc.scanners[0].overall.metric(metric).unwrap().counts;
    (
        c.eligible,
        c.measured,
        c.numerator,
        c.unresolved,
        c.not_measured,
        c.not_applicable,
        c.total,
    )
}

// ---------------------------------------------------------------------------
// Conservation through accounting
// ---------------------------------------------------------------------------

#[test]
fn generated_variants_are_conserved_by_accounting() {
    // Seven cases, nine variants (the context case has three), nine occurrences.
    let out = generate_all(&one_of_each(), SEED_RULE_V1);
    assert!(out.report.is_conserved());
    assert_eq!(out.report.cases_in, 7);
    assert_eq!(out.report.cases_generated, 7);
    assert_eq!(out.report.variants_generated, 9);
    assert_eq!(out.report.cases_refused(), 0);
    let body = body_of(out.clone(), SEED_RULE_V1);
    let rows = perfect_rows(&out, false);
    assert_eq!(rows.len(), 9);

    let acc = account_rows(&body, &rows, ScannerStatus::Complete);
    assert_eq!(
        acc.authored,
        PopulationCounts {
            authored_cases: 7,
            variants: 9,
            occurrences: 9
        }
    );
    assert_eq!(acc.resources.rows_visited, 9);

    // (eligible, measured, numerator, unresolved, not_measured, not_applicable, total)
    // Valid-type cases: all but the mutation case (type invalid) -> 6 of 7.
    assert_eq!(counts(&acc, MetricId::TypeMissRate), (6, 6, 0, 0, 0, 1, 7));
    assert_eq!(
        counts(&acc, MetricId::WrongFamilyRate),
        (6, 6, 0, 0, 0, 1, 7)
    );
    // Jurisdictional: only the SSN collision case.
    assert_eq!(
        counts(&acc, MetricId::WrongJurisdictionRate),
        (1, 1, 0, 0, 0, 6, 7)
    );
    // Authored sensitive occurrences: the context case (one frame) and the collision case.
    assert_eq!(
        counts(&acc, MetricId::SensitiveMissRate),
        (2, 2, 0, 0, 0, 5, 7)
    );
    // Authored non-sensitive occurrences: schema-only, one context frame, the benign control.
    assert_eq!(
        counts(&acc, MetricId::NonSensitiveFlagRate),
        (3, 3, 0, 0, 0, 4, 7)
    );
    // Restricted metrics: only their own method's cases are in the population.
    assert_eq!(
        counts(&acc, MetricId::ContextDiscriminationRate),
        (1, 1, 1, 0, 0, 0, 1)
    );
    assert_eq!(
        counts(&acc, MetricId::BenignSuppressionRate),
        (1, 1, 1, 0, 0, 6, 7)
    );
    assert_eq!(
        counts(&acc, MetricId::JurisdictionCollisionRate),
        (1, 1, 1, 0, 0, 6, 7)
    );
    // Reported spans of valid-type occurrences: six cases, all exact.
    assert_eq!(
        counts(&acc, MetricId::RangeCollateralRate),
        (6, 6, 0, 0, 0, 1, 7)
    );
    // Two axis assertions per case: 14. The type axis resolves everywhere (7); the sensitivity
    // axis is unresolved for the four cases with a not-established occurrence (type-validation,
    // context, mutation, reference) and resolved for the other three.
    let (eligible, measured, numerator, unresolved, ..) = counts(&acc, MetricId::MeasurableShare);
    assert_eq!((eligible, measured, numerator, unresolved), (14, 10, 10, 4));

    // By-method strata partition the cases: one stratum per method, and each holds its own cases.
    let by_method = &acc.scanners[0].by_method;
    assert_eq!(by_method.len(), 7);
    assert_eq!(
        by_method
            .iter()
            .map(|(_, s)| s.authored.authored_cases)
            .sum::<u64>(),
        7
    );
    assert_eq!(
        by_method
            .iter()
            .map(|(_, s)| s.authored.variants)
            .sum::<u64>(),
        9
    );
}

#[test]
fn a_blind_scanner_changes_numerators_but_not_denominators() {
    let out = generate_all(&one_of_each(), SEED_RULE_V1);
    let body = body_of(out.clone(), SEED_RULE_V1);
    let perfect = account_rows(&body, &perfect_rows(&out, false), ScannerStatus::Complete);
    let blind = account_rows(&body, &blind_rows(&out), ScannerStatus::Complete);
    assert_eq!(perfect.authored, blind.authored);
    for metric in [
        MetricId::TypeMissRate,
        MetricId::SensitiveMissRate,
        MetricId::NonSensitiveFlagRate,
        MetricId::ContextDiscriminationRate,
        MetricId::BenignSuppressionRate,
        MetricId::JurisdictionCollisionRate,
    ] {
        let (pe, pm, ..) = counts(&perfect, metric);
        let (be, bm, ..) = counts(&blind, metric);
        assert_eq!(
            (pe, pm),
            (be, bm),
            "{metric:?}: denominators move with outcomes"
        );
    }
    // The blind scanner misses every valid-type occurrence and every sensitive one.
    assert_eq!(counts(&blind, MetricId::TypeMissRate).2, 6);
    assert_eq!(counts(&blind, MetricId::SensitiveMissRate).2, 2);
    // It flags nothing, so the non-sensitive controls pass: suppression is 1 of 1.
    assert_eq!(counts(&blind, MetricId::NonSensitiveFlagRate).2, 0);
    assert_eq!(counts(&blind, MetricId::BenignSuppressionRate).2, 1);
    // The sensitive context endpoint failed, so the trio's numerator is 0 of 1.
    assert_eq!(counts(&blind, MetricId::ContextDiscriminationRate).2, 0);
}

#[test]
fn a_scanner_that_did_not_complete_measures_nothing_and_says_so() {
    let out = generate_all(&one_of_each(), SEED_RULE_V1);
    let body = body_of(out.clone(), SEED_RULE_V1);
    let rows = unmeasured_rows(&perfect_rows(&out, false));
    let acc = account_rows(&body, &rows, ScannerStatus::Error);
    for metric in [
        MetricId::TypeMissRate,
        MetricId::SensitiveMissRate,
        MetricId::ContextDiscriminationRate,
        MetricId::BenignSuppressionRate,
        MetricId::JurisdictionCollisionRate,
    ] {
        let (eligible, measured, numerator, _, not_measured, ..) = counts(&acc, metric);
        assert!(eligible > 0, "{metric:?}");
        assert_eq!(
            (measured, numerator, not_measured),
            (0, 0, eligible),
            "{metric:?}"
        );
    }
}

#[test]
fn an_unavailable_validator_leaves_its_case_unmeasured_never_clean() {
    let mut cases = one_of_each();
    cases.push(with(
        mod10_case(
            "case-typeval-unavailable",
            "SYNTHETIC-1236",
            ExpectedType::Valid,
        ),
        |c| c.validator = Some(vref("no-such-validator", 1)),
    ));
    let out = generate_all(&cases, SEED_RULE_V1);
    assert_eq!(out.report.cases_generated, 8);
    let body = body_of(out.clone(), SEED_RULE_V1);

    let gated = account_rows(&body, &perfect_rows(&out, true), ScannerStatus::Complete);
    // Seven valid-type cases; the held one is not measured on the type axis.
    assert_eq!(
        counts(&gated, MetricId::TypeMissRate),
        (7, 6, 0, 0, 1, 1, 8)
    );
    // Without the review gate the perfect scanner would have produced a clean pass.
    let ungated = account_rows(&body, &perfect_rows(&out, false), ScannerStatus::Complete);
    assert_eq!(
        counts(&ungated, MetricId::TypeMissRate),
        (7, 7, 0, 0, 0, 1, 8)
    );
}

#[test]
fn a_reference_disagreement_is_recorded_without_changing_any_count() {
    let mut cases = one_of_each();
    cases.push(reference_case(
        "case-reference-disagrees",
        "SYNTHETIC-1237",
        vref("synthetic-mod10", 1),
    ));
    let out = generate_all(&cases, SEED_RULE_V1);
    let body = body_of(out.clone(), SEED_RULE_V1);
    let gated = account_rows(&body, &perfect_rows(&out, true), ScannerStatus::Complete);
    let ungated = account_rows(&body, &perfect_rows(&out, false), ScannerStatus::Complete);
    assert_eq!(gated, ungated);
    // The disagreeing case stays valid-type and is measured.
    assert_eq!(
        counts(&gated, MetricId::TypeMissRate),
        (7, 7, 0, 0, 0, 1, 8)
    );
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

fn assignments(body: &CorpusSnapshotBody) -> Vec<ViewAssignment> {
    body.cases
        .iter()
        .map(|c| ViewAssignment {
            case_id: c.case_id.clone(),
            view: if matches!(
                c.case_id.as_str(),
                "case-benign" | "case-schema" | "case-context"
            ) {
                PopulationView::BenignHeavyStress
            } else {
                PopulationView::DiagnosticBalanced
            },
        })
        .collect()
}

#[test]
fn the_two_views_are_kept_separate_and_partition_the_population() {
    let out = generate_all(&one_of_each(), SEED_RULE_V1);
    let body = body_of(out.clone(), SEED_RULE_V1);
    let roster = ViewRoster::new(&body, &assignments(&body)).unwrap();
    let rows = perfect_rows(&out, false);

    let mut cases = 0;
    let mut variants = 0;
    let mut accounted = Vec::new();
    for view in PopulationView::ALL {
        let restricted = roster.restrict(&body, view);
        let in_view: Vec<&Row> = rows
            .iter()
            .filter(|r| roster.view_of(&id(&r.case)) == Some(view))
            .collect();
        let owned: Vec<Row> = in_view
            .iter()
            .map(|r| Row {
                case: r.case.clone(),
                variant: r.variant.clone(),
                occurrence: r.occurrence.clone(),
                method: r.method,
                row: r.row,
            })
            .collect();
        let acc = account_rows(&restricted, &owned, ScannerStatus::Complete);
        let comp = roster.composition(&body, view);
        assert_eq!(comp.cases, acc.authored.authored_cases);
        assert_eq!(comp.variants, acc.authored.variants);
        assert_eq!(comp.occurrences, acc.authored.occurrences);
        assert_eq!(
            comp.sensitive + comp.non_sensitive + comp.not_established,
            comp.occurrences
        );
        cases += comp.cases;
        variants += comp.variants;
        accounted.push((view, comp));
    }
    assert_eq!((cases, variants), (7, 9));

    // Diagnostic: typeval, collision, mutation, reference (4 cases, 4 variants).
    // Stress: benign, schema, context (3 cases, 5 variants): non-sensitive occurrences are
    // schema, benign and one context frame (3) against one sensitive context frame.
    let diag = accounted[0].1;
    let stress = accounted[1].1;
    assert_eq!((diag.cases, diag.variants), (4, 4));
    assert_eq!((stress.cases, stress.variants), (3, 5));
    assert_eq!(
        (
            stress.sensitive,
            stress.non_sensitive,
            stress.not_established
        ),
        (1, 3, 1)
    );
    assert!(stress.benign_dominant());
    assert!(!diag.benign_dominant());
}

#[test]
fn a_roster_must_assign_every_case_exactly_once() {
    let out = generate_all(&one_of_each(), SEED_RULE_V1);
    let body = body_of(out, SEED_RULE_V1);
    let all = assignments(&body);
    assert!(ViewRoster::new(&body, &all).is_ok());
    assert_eq!(
        ViewRoster::new(&body, &all[1..]).unwrap_err(),
        ViewError::UnassignedCase
    );
    let mut dup = all.clone();
    dup.push(all[0].clone());
    assert_eq!(
        ViewRoster::new(&body, &dup).unwrap_err(),
        ViewError::DuplicateAssignment
    );
    let mut unknown = all.clone();
    unknown.push(ViewAssignment {
        case_id: id("case-unknown"),
        view: PopulationView::DiagnosticBalanced,
    });
    assert_eq!(
        ViewRoster::new(&body, &unknown).unwrap_err(),
        ViewError::UnknownCase
    );
    assert_eq!(
        PopulationView::DiagnosticBalanced.as_str(),
        "diagnostic-balanced"
    );
    assert_eq!(
        PopulationView::BenignHeavyStress.as_str(),
        "benign-heavy-stress"
    );
}

// ---------------------------------------------------------------------------
// Determinism: input order, worker completion order, batching, repetition, seeds
// ---------------------------------------------------------------------------

/// `n` copies of one case per method with distinct ids, plus one refused case per copy.
fn corpus(n: usize) -> Vec<AuthoredCase> {
    let mut cases = Vec::new();
    for i in 0..n {
        for c in one_of_each() {
            let name = format!("{}-{i}", c.case_id.as_str());
            cases.push(with(c, |c| c.case_id = id(&name)));
        }
        cases.push(with(schema_case(&format!("case-bad-{i}")), |c| {
            c.candidate = ByteRange { start: 5, end: 5 }
        }));
    }
    cases
}

fn digest_of(out: &GenerationOutput, rule: &str) -> String {
    let body = assemble_body(population(), rules(rule), out.generated.clone()).unwrap();
    let mut doc = CorpusSnapshot::unsealed(body);
    seal(&mut doc).unwrap();
    doc.semantic_digest.as_str().to_owned()
}

#[test]
fn input_order_does_not_change_results_or_the_snapshot_digest() {
    let cases = corpus(6);
    assert_eq!(cases.len(), 48);
    let canonical = generate_all(&cases, SEED_RULE_V1);
    assert_eq!(canonical.report.cases_in, 48);
    assert_eq!(canonical.report.cases_refused(), 6);
    assert_eq!(
        canonical.report.refused.get(&RefusalReason::RangeInvalid),
        Some(&6)
    );
    assert!(canonical.report.is_conserved());
    let digest = digest_of(&canonical, SEED_RULE_V1);
    for seed in 0..40 {
        let mut shuffled = cases.clone();
        Rng(seed).shuffle(&mut shuffled);
        let out = generate_all(&shuffled, SEED_RULE_V1);
        assert_eq!(out, canonical, "seed {seed}");
        assert_eq!(digest_of(&out, SEED_RULE_V1), digest, "seed {seed}");
    }
}

#[test]
fn repeated_runs_are_identical() {
    let cases = corpus(3);
    let first = generate_all(&cases, SEED_RULE_V1);
    for _ in 0..5 {
        assert_eq!(generate_all(&cases, SEED_RULE_V1), first);
    }
}

#[test]
fn worker_completion_order_does_not_change_the_assembled_cases() {
    let cases = corpus(4);
    let canonical = generate_all(&cases, SEED_RULE_V1);
    let reg = ValidatorRegistry::builtin();
    let g = Generator::new(&rules(SEED_RULE_V1), &reg, GenerationLimits::DEFAULT).unwrap();
    let expected = assemble_cases(canonical.generated.clone()).unwrap();
    for seed in 0..30 {
        // Workers finish in any order: generate each case independently, then assemble.
        let mut order: Vec<usize> = (0..cases.len()).collect();
        Rng(seed).shuffle(&mut order);
        let finished: Vec<_> = order
            .iter()
            .filter_map(|&i| g.generate_case(&cases[i]).ok())
            .collect();
        assert_eq!(assemble_cases(finished).unwrap(), expected, "seed {seed}");
    }
}

#[test]
fn batch_size_does_not_change_the_results() {
    // 12 x (9 variants + 1 refusal) = 120 units: more than one batch of 64.
    let cases = corpus(12);
    let canonical = generate_all(&cases, SEED_RULE_V1);
    let reg = ValidatorRegistry::builtin();
    for size in [64usize, 65, 130, 1024] {
        let limits = GenerationLimits {
            batch_variants: size,
            ..GenerationLimits::DEFAULT
        };
        let g = Generator::new(&rules(SEED_RULE_V1), &reg, limits).unwrap();
        let mut generated = Vec::new();
        let mut refused = Vec::new();
        let mut batches = 0;
        let mut run = g.run(&cases).batches();
        for batch in run.by_ref() {
            let batch = batch.unwrap();
            // Bounded: at most `size` variants plus refusals per batch.
            assert!(
                batch.variant_count() as usize + batch.refused.len() <= size,
                "size {size}"
            );
            batches += 1;
            generated.extend(batch.generated);
            refused.extend(batch.refused);
        }
        assert!(batches >= 1);
        if size == 64 {
            assert!(batches > 1, "a small batch must split this corpus");
        }
        assert_eq!(run.report(), &canonical.report, "size {size}");
        generated.sort_by(|a, b| a.case.case_id.cmp(&b.case.case_id));
        refused.sort_by(|a, b| a.case_id.cmp(&b.case_id));
        assert_eq!(generated, canonical.generated, "size {size}");
        assert_eq!(refused, canonical.refused, "size {size}");
    }
}

#[test]
fn generation_is_lazy_and_does_not_materialize_the_corpus() {
    let cases: Vec<AuthoredCase> = (0..1000)
        .map(|i| schema_case(&format!("case-schema-{i}")))
        .collect();
    let pulled = Rc::new(Cell::new(0usize));
    let counter = Rc::clone(&pulled);
    let counted = cases
        .iter()
        .inspect(move |_| counter.set(counter.get() + 1));
    let reg = ValidatorRegistry::builtin();
    let limits = GenerationLimits {
        batch_variants: 64,
        ..GenerationLimits::DEFAULT
    };
    let g = Generator::new(&rules(SEED_RULE_V1), &reg, limits).unwrap();
    let mut batches = g.run(counted).batches();
    let first = batches.next().unwrap().unwrap();
    assert_eq!(first.variant_count(), 64);
    // At most one case of lookahead beyond the batch.
    assert!(pulled.get() <= 65, "pulled {}", pulled.get());
    assert!(pulled.get() < 1000);
}

#[test]
fn changing_seeds_changes_only_recorded_seeds_never_ids_text_or_accounting() {
    let base = corpus(2);
    let reseeded: Vec<AuthoredCase> = base
        .iter()
        .cloned()
        .map(|c| {
            let seed = pii_eval_contracts::Seed::new(format!("other-{}", c.case_id)).unwrap();
            with(c, |c| c.seed = seed)
        })
        .collect();
    let a = generate_all(&base, SEED_RULE_V1);
    let b = generate_all(&reseeded, SEED_RULE_V1);
    assert_ne!(a, b);
    let strip = |mut out: GenerationOutput| {
        let mut derived = 0;
        for g in &mut out.generated {
            for v in &mut g.case.variants {
                if v.derivation.seed.take().is_some() {
                    derived += 1;
                }
            }
            for p in &mut g.provenance {
                p.seed = None;
            }
        }
        (out, derived)
    };
    let (sa, derived_a) = strip(a.clone());
    let (sb, derived_b) = strip(b.clone());
    // Ids, text, expectations and provenance are identical once the seeds are removed.
    assert_eq!(sa, sb);
    assert_eq!(derived_a, derived_b);
    assert!(derived_a > 0);
    // The seed-dependent part is exactly the derived variants' seeds.
    for (ga, gb) in a.generated.iter().zip(&b.generated) {
        for (va, vb) in ga.case.variants.iter().zip(&gb.case.variants) {
            assert_eq!(
                va.derivation.seed == vb.derivation.seed,
                va.derivation.seed.is_none()
            );
        }
    }
    // Accounting on a seed-changed corpus is identical.
    let acc_a = account_rows(
        &body_of(a.clone(), SEED_RULE_V1),
        &perfect_rows(&a, true),
        ScannerStatus::Complete,
    );
    let acc_b = account_rows(
        &body_of(b.clone(), SEED_RULE_V1),
        &perfect_rows(&b, true),
        ScannerStatus::Complete,
    );
    assert_eq!(acc_a, acc_b);
}

#[test]
fn the_seed_rule_changes_seeds_only() {
    let cases = corpus(1);
    let v1 = generate_all(&cases, SEED_RULE_V1);
    let legacy = generate_all(&cases, SEED_RULE_LEGACY);
    for (a, b) in v1.generated.iter().zip(&legacy.generated) {
        let ids = |g: &pii_eval_kernel::methods::GeneratedCase| {
            g.case
                .variants
                .iter()
                .map(|v| (v.variant_id.clone(), v.text.clone(), v.expectations.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(a), ids(b));
    }
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

fn run_with(
    limits: GenerationLimits,
    cases: &[AuthoredCase],
) -> Result<GenerationOutput, GenerateError> {
    let reg = ValidatorRegistry::builtin();
    let g = Generator::new(&rules(SEED_RULE_V1), &reg, limits).unwrap();
    g.generate_all(cases)
}

#[test]
fn run_level_limits_end_the_run_instead_of_truncating() {
    let schema: Vec<AuthoredCase> = (0..4)
        .map(|i| schema_case(&format!("case-s-{i}")))
        .collect();
    // Four schema-only variants against a per-method limit of three.
    let per_method = GenerationLimits {
        max_variants_per_method: 3,
        max_total_variants: 3,
        ..GenerationLimits::DEFAULT
    };
    assert_eq!(
        run_with(per_method, &schema).unwrap_err(),
        GenerateError::LimitExceeded {
            limit: GenerationLimit::VariantsPerMethod,
            max: 3
        }
    );
    // Three schema-only and two type-validation variants against a total of four,
    // with no method over its own limit.
    let mixed: Vec<AuthoredCase> = (0..3)
        .map(|i| schema_case(&format!("case-s-{i}")))
        .chain((0..2).map(|i| {
            mod10_case(
                &format!("case-t-{i}"),
                "SYNTHETIC-1236",
                ExpectedType::Valid,
            )
        }))
        .collect();
    let total = GenerationLimits {
        max_variants_per_method: 4,
        max_total_variants: 4,
        ..GenerationLimits::DEFAULT
    };
    assert_eq!(
        run_with(total, &mixed).unwrap_err(),
        GenerateError::LimitExceeded {
            limit: GenerationLimit::TotalVariants,
            max: 4
        }
    );
    // Cases.
    let cases = GenerationLimits {
        max_cases: 3,
        ..GenerationLimits::DEFAULT
    };
    assert_eq!(
        run_with(cases, &schema).unwrap_err(),
        GenerateError::LimitExceeded {
            limit: GenerationLimit::Cases,
            max: 3
        }
    );
    // Exactly at the limit is fine, and the failing predicate does not depend on order.
    let exact = GenerationLimits {
        max_variants_per_method: 4,
        max_total_variants: 4,
        max_cases: 4,
        ..GenerationLimits::DEFAULT
    };
    assert!(run_with(exact, &schema).is_ok());
    for seed in 0..10 {
        let mut shuffled = mixed.clone();
        Rng(seed).shuffle(&mut shuffled);
        assert!(run_with(total, &shuffled).is_err(), "seed {seed}");
    }
}

#[test]
fn a_run_stops_after_an_error() {
    let cases: Vec<AuthoredCase> = (0..5)
        .map(|i| schema_case(&format!("case-s-{i}")))
        .collect();
    let reg = ValidatorRegistry::builtin();
    let limits = GenerationLimits {
        max_variants_per_method: 2,
        max_total_variants: 2,
        ..GenerationLimits::DEFAULT
    };
    let g = Generator::new(&rules(SEED_RULE_V1), &reg, limits).unwrap();
    let results: Vec<_> = g.run(&cases).collect();
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok() && results[1].is_ok() && results[2].is_err());
}

#[test]
fn a_duplicate_case_id_is_an_error() {
    let cases = [schema_case("case-same"), schema_case("case-same")];
    assert_eq!(
        run_with(GenerationLimits::DEFAULT, &cases).unwrap_err(),
        GenerateError::DuplicateCase
    );
}

#[test]
fn an_empty_run_reports_zero_and_is_conserved() {
    let out = run_with(GenerationLimits::DEFAULT, &[]).unwrap();
    assert!(out.generated.is_empty() && out.refused.is_empty());
    assert_eq!(out.report.cases_in, 0);
    assert!(out.report.is_conserved());
}
