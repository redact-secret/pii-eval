//! Accounting conformance with a hand-calculated fixture.
//!
//! The fixture below has twelve authored cases (21 variants) chosen so that
//! every metric sees every bucket: numerator, other, unresolved, not-measured
//! and not-applicable. Every expected count in this file was derived by hand
//! from the metric definitions in `schemas/registry/pii-v1.registry.json` and
//! the pinned oracle's `metricBuckets` (see ADR 0005), case by case, before the
//! implementation was run. The point and bound values come from the
//! independent decimal reference (`tests/vectors/wilson_reference.py`).

mod acct_common;

use acct_common::*;
use pii_eval_contracts::{
    ContextClass::{Neutral, NonSensitive as CtxNonSensitive, Sensitive as CtxSensitive},
    CorpusSnapshotBody, ExpectedType, Mechanics,
    MethodId::*,
    MetricCounts, MetricId, MetricStatus, MetricValue,
    RangeState::*,
    ScaledDecimal, ScannerId, ScannerStatus, SensitivityExpectation as Sx, SensitivityState as Ss,
    TypeState as Ts, WithheldReason,
};
use pii_eval_kernel::{
    AccountError, Accounting, AuthoredIndex, OutcomeRef, ScannerInput, UnmeasuredCause, account,
    account_outcomes,
};

const V: ExpectedType = ExpectedType::Valid;
const I: ExpectedType = ExpectedType::Invalid;

/// Twelve cases. Languages: `ko` for the US cases c02, c07 and c08, else `en`.
fn fixture() -> (CorpusSnapshotBody, Vec<RowSpec>) {
    let o = |ty, sens| vec![occ("o1", ty, sens)];
    let body = snapshot_body(vec![
        case(
            "c01",
            TypeValidation,
            "en",
            None,
            vec![
                var("c01-a", Neutral, o(V, Sx::Sensitive)),
                var("c01-b", Neutral, o(I, Sx::Sensitive)),
            ],
        ),
        case(
            "c02",
            TypeValidation,
            "ko",
            Some("US"),
            vec![var("c02-a", Neutral, o(V, Sx::Sensitive))],
        ),
        case(
            "c03",
            TypeValidation,
            "en",
            None,
            vec![var("c03-a", Neutral, o(V, Sx::NonSensitive))],
        ),
        case(
            "c04",
            PiiBenign,
            "en",
            None,
            vec![var("c04-a", Neutral, o(I, Sx::NonSensitive))],
        ),
        case(
            "c05",
            PiiBenign,
            "en",
            None,
            vec![var("c05-a", Neutral, o(I, Sx::NonSensitive))],
        ),
        case(
            "c06",
            PiiBenign,
            "en",
            None,
            vec![var("c06-a", Neutral, o(I, Sx::NonSensitive))],
        ),
        case(
            "c07",
            JurisdictionCollision,
            "ko",
            Some("US"),
            vec![var("c07-a", Neutral, o(V, Sx::Sensitive))],
        ),
        case(
            "c08",
            JurisdictionCollision,
            "ko",
            Some("US"),
            vec![var("c08-a", Neutral, o(V, Sx::Sensitive))],
        ),
        trio("c09", Sx::Sensitive, Sx::NotEstablished),
        trio("c10", Sx::Sensitive, Sx::NotEstablished),
        trio("c11", Sx::Sensitive, Sx::NotEstablished),
        // c12: the sensitive-class frame itself is not established.
        trio("c12", Sx::NotEstablished, Sx::NotEstablished),
    ]);
    let rows: Vec<RowSpec> = vec![
        ("c01", "c01-a", "o1", Ts::Correct, Ss::Correct, Exact),
        ("c01", "c01-b", "o1", Ts::InvalidCorrect, Ss::Correct, Miss),
        ("c02", "c02-a", "o1", Ts::Miss, Ss::Miss, Miss),
        (
            "c03",
            "c03-a",
            "o1",
            Ts::WrongFamily,
            Ss::FalsePositive,
            Partial,
        ),
        ("c04", "c04-a", "o1", Ts::InvalidCorrect, Ss::Correct, Miss),
        (
            "c05",
            "c05-a",
            "o1",
            Ts::InvalidAccepted,
            Ss::FalsePositive,
            Exact,
        ),
        (
            "c06",
            "c06-a",
            "o1",
            Ts::NotMeasured,
            Ss::NotMeasured,
            NotApplicable,
        ),
        ("c07", "c07-a", "o1", Ts::Correct, Ss::Correct, Exact),
        (
            "c08",
            "c08-a",
            "o1",
            Ts::WrongJurisdiction,
            Ss::Correct,
            Exact,
        ),
        ("c09", "c09-s", "o1", Ts::Correct, Ss::Correct, Exact),
        ("c09", "c09-n", "o1", Ts::Correct, Ss::Unresolved, Exact),
        ("c09", "c09-ns", "o1", Ts::Correct, Ss::Correct, Exact),
        ("c10", "c10-s", "o1", Ts::Correct, Ss::Miss, Exact),
        ("c10", "c10-n", "o1", Ts::Correct, Ss::Unresolved, Exact),
        ("c10", "c10-ns", "o1", Ts::Correct, Ss::Correct, Exact),
        (
            "c11",
            "c11-s",
            "o1",
            Ts::NotMeasured,
            Ss::NotMeasured,
            NotApplicable,
        ),
        (
            "c11",
            "c11-n",
            "o1",
            Ts::NotMeasured,
            Ss::NotMeasured,
            NotApplicable,
        ),
        ("c11", "c11-ns", "o1", Ts::Correct, Ss::Correct, Exact),
        ("c12", "c12-s", "o1", Ts::Correct, Ss::Unresolved, Exact),
        ("c12", "c12-n", "o1", Ts::Correct, Ss::Unresolved, Exact),
        ("c12", "c12-ns", "o1", Ts::Correct, Ss::Correct, Exact),
    ];
    (body, rows)
}

fn trio(id: &str, sensitive: Sx, neutral: Sx) -> CaseSpec {
    case(
        id,
        ContextDiscrimination,
        "en",
        None,
        vec![
            var(
                &format!("{id}-s"),
                CtxSensitive,
                vec![occ("o1", V, sensitive)],
            ),
            var(&format!("{id}-n"), Neutral, vec![occ("o1", V, neutral)]),
            var(
                &format!("{id}-ns"),
                CtxNonSensitive,
                vec![occ("o1", V, Sx::NonSensitive)],
            ),
        ],
    )
}

fn scanner_id() -> ScannerId {
    sid("scan-one")
}

fn run(body: &CorpusSnapshotBody, rows: &[RowSpec], status: ScannerStatus) -> Accounting {
    let index = AuthoredIndex::new(body).unwrap();
    let id = scanner_id();
    let outcomes = outcomes_of("scan-one", body, rows);
    account_outcomes(
        &index,
        &[ScannerInput { id: &id, status }],
        &outcomes,
        &Mechanics::PII_V1,
    )
    .unwrap()
}

fn counts(e: u64, m: u64, n: u64, u: u64, nm: u64, na: u64, t: u64) -> MetricCounts {
    MetricCounts {
        eligible: e,
        measured: m,
        numerator: n,
        unresolved: u,
        not_measured: nm,
        not_applicable: na,
        total: t,
    }
}

fn dec(mantissa: u64, scale: u8) -> ScaledDecimal {
    ScaledDecimal::new(mantissa, scale).unwrap()
}

fn measured(point: u64, bound: u64) -> MetricValue {
    MetricValue::Measured {
        point: dec(point, 6),
        bound: dec(bound, 6),
    }
}

fn insufficient() -> MetricValue {
    MetricValue::Withheld {
        reason: WithheldReason::InsufficientEvidence,
    }
}

/// (metric, counts, effective N, status, value), derived by hand.
#[allow(clippy::type_complexity)]
fn expected() -> Vec<(MetricId, MetricCounts, u64, MetricStatus, MetricValue)> {
    use MetricStatus::*;
    vec![
        // valid-type occurrences: c01 other, c02 miss, c03 wrong-family, c07, c08 other,
        // c09 c10 c12 other, c11 not-measured; c04 c05 c06 have no valid occurrence.
        (
            MetricId::TypeMissRate,
            counts(9, 8, 1, 0, 1, 3, 12),
            8,
            Partial,
            measured(125_000, 470_895),
        ),
        (
            MetricId::WrongFamilyRate,
            counts(9, 8, 1, 0, 1, 3, 12),
            8,
            Partial,
            measured(125_000, 470_895),
        ),
        // jurisdictional cases c02 (miss: other), c07 (other), c08 (wrong-jurisdiction).
        (
            MetricId::WrongJurisdictionRate,
            counts(3, 3, 1, 0, 0, 9, 12),
            3,
            Measured,
            insufficient(),
        ),
        (
            MetricId::SensitiveMissRate,
            counts(7, 6, 2, 0, 1, 5, 12),
            6,
            Partial,
            measured(333_333, 700_012),
        ),
        (
            MetricId::NonSensitiveFlagRate,
            counts(8, 7, 2, 0, 1, 4, 12),
            7,
            Partial,
            measured(285_714, 641_071),
        ),
        // trios c09 numerator, c10 other, c11 not-measured, c12 unresolved.
        (
            MetricId::ContextDiscriminationRate,
            counts(4, 2, 1, 1, 1, 0, 4),
            2,
            Partial,
            insufficient(),
        ),
        (
            MetricId::BenignSuppressionRate,
            counts(3, 2, 1, 0, 1, 9, 12),
            2,
            Partial,
            insufficient(),
        ),
        (
            MetricId::JurisdictionCollisionRate,
            counts(2, 2, 1, 0, 0, 10, 12),
            2,
            Measured,
            insufficient(),
        ),
        // c02's only valid range is a miss (not applicable); c11's range is not-applicable.
        (
            MetricId::RangeCollateralRate,
            counts(8, 7, 1, 0, 1, 4, 12),
            7,
            Partial,
            measured(142_857, 513_135),
        ),
        // 12 cases x 2 axes: effective N is the eligible count, not the measured count.
        (
            MetricId::MeasurableShare,
            counts(24, 17, 17, 4, 3, 0, 24),
            24,
            Partial,
            measured(708_333, 508_319),
        ),
    ]
}

#[test]
fn authored_counts_are_separate_from_effective_n() {
    let (body, rows) = fixture();
    let acc = run(&body, &rows, ScannerStatus::Complete);
    assert_eq!(acc.authored.authored_cases, 12);
    assert_eq!(acc.authored.variants, 21);
    assert_eq!(acc.authored.occurrences, 21);
    // No metric's effective N is the variant or occurrence count.
    for m in &acc.scanners[0].overall.metrics {
        assert_ne!(m.effective_n, 21, "{:?}", m.metric);
    }
}

#[test]
fn every_metric_matches_the_hand_calculation() {
    let (body, rows) = fixture();
    let acc = run(&body, &rows, ScannerStatus::Complete);
    let overall = &acc.scanners[0].overall;
    assert_eq!(overall.metrics.len(), 10);
    for (metric, c, n, status, value) in expected() {
        let got = overall.metric(metric).expect("metric present");
        assert_eq!(got.counts, c, "{metric:?} counts");
        assert_eq!(got.effective_n, n, "{metric:?} effective N");
        assert_eq!(got.status, status, "{metric:?} status");
        assert_eq!(got.value, value, "{metric:?} value");
    }
}

#[test]
fn metrics_come_out_in_artifact_order() {
    let (body, rows) = fixture();
    let acc = run(&body, &rows, ScannerStatus::Complete);
    let ids: Vec<&str> = acc.scanners[0]
        .overall
        .metrics
        .iter()
        .map(|m| m.metric.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
}

#[test]
fn sample_basis_keeps_cases_variants_and_occurrences_apart() {
    let (body, rows) = fixture();
    let acc = run(&body, &rows, ScannerStatus::Complete);
    let overall = &acc.scanners[0].overall;
    // Valid-type cases: c01 (2 variants), c02, c03, c07, c08, c09-c12 (3 variants each).
    let b = overall.metric(MetricId::TypeMissRate).unwrap().basis;
    assert_eq!(
        (
            b.eligible_cases,
            b.eligible_variants,
            b.eligible_occurrences
        ),
        (9, 18, 18)
    );
    assert!(b.correlated_variants && !b.shared_case_axes);
    // Jurisdictional cases are single-variant: no correlated variants.
    let b = overall
        .metric(MetricId::WrongJurisdictionRate)
        .unwrap()
        .basis;
    assert_eq!(
        (
            b.eligible_cases,
            b.eligible_variants,
            b.eligible_occurrences
        ),
        (3, 3, 3)
    );
    assert!(!b.correlated_variants);
    // Two axis assertions per authored case share that case.
    let b = overall.metric(MetricId::MeasurableShare).unwrap().basis;
    assert_eq!(
        (
            b.eligible_cases,
            b.eligible_variants,
            b.eligible_occurrences
        ),
        (12, 21, 21)
    );
    assert!(b.shared_case_axes && b.correlated_variants);
    assert!(b.interpretation().contains("not real-world confidence"));
}

#[test]
fn strata_are_separate_and_hand_checkable() {
    let (body, rows) = fixture();
    let acc = run(&body, &rows, ScannerStatus::Complete);
    let s = &acc.scanners[0];
    let languages: Vec<&str> = s.by_language.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(languages, ["en", "ko"]);
    let ko = &s.by_language[1].1;
    assert_eq!(ko.authored.authored_cases, 3);
    // ko = c02 (miss), c07, c08.
    assert_eq!(
        ko.metric(MetricId::TypeMissRate).unwrap().counts,
        counts(3, 3, 1, 0, 0, 0, 3)
    );
    assert_eq!(
        ko.metric(MetricId::JurisdictionCollisionRate)
            .unwrap()
            .counts,
        counts(2, 2, 1, 0, 0, 1, 3)
    );
    // Jurisdictions: global first, then US; the US stratum is the same three cases.
    assert_eq!(s.by_jurisdiction.len(), 2);
    assert!(s.by_jurisdiction[0].0.is_none());
    assert_eq!(s.by_jurisdiction[1].0.as_ref().unwrap().as_str(), "US");
    assert_eq!(
        s.by_jurisdiction[1].1.metrics, ko.metrics,
        "same case set, same accounting"
    );
    let methods: Vec<&str> = s.by_method.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(
        methods,
        [
            "context-discrimination",
            "jurisdiction-collision",
            "pii-benign",
            "type-validation"
        ]
    );
    // The context metric exists only in the context-discrimination stratum.
    assert_eq!(
        s.by_method[0]
            .1
            .metric(MetricId::ContextDiscriminationRate)
            .unwrap()
            .counts,
        counts(4, 2, 1, 1, 1, 0, 4)
    );
    assert_eq!(
        s.by_method[3]
            .1
            .metric(MetricId::ContextDiscriminationRate)
            .unwrap()
            .counts,
        counts(0, 0, 0, 0, 0, 0, 0)
    );
}

#[test]
fn counts_conserve_across_strata() {
    let (body, rows) = fixture();
    assert_conserved(&run(&body, &rows, ScannerStatus::Complete));
}

#[test]
fn measurable_share_total_is_two_axes_per_case_and_others_total_the_cases() {
    let (body, rows) = fixture();
    let acc = run(&body, &rows, ScannerStatus::Complete);
    for m in &acc.scanners[0].overall.metrics {
        let expected_total = match m.metric {
            MetricId::MeasurableShare => 24,
            MetricId::ContextDiscriminationRate => 4,
            _ => 12,
        };
        assert_eq!(m.counts.total, expected_total, "{:?}", m.metric);
    }
}

#[test]
fn a_scanner_that_did_not_complete_is_not_measured_with_a_distinct_cause() {
    let (body, rows) = fixture();
    // Every row of a non-complete scanner is unmeasured, whatever the status.
    let unmeasured: Vec<RowSpec> = rows
        .iter()
        .map(|r| {
            (
                r.0,
                r.1,
                r.2,
                Ts::NotMeasured,
                Ss::NotMeasured,
                NotApplicable,
            )
        })
        .collect();
    let cases = [
        (
            ScannerStatus::Unsupported,
            UnmeasuredCause::ScannerUnsupported,
        ),
        (
            ScannerStatus::Unavailable,
            UnmeasuredCause::ScannerUnavailable,
        ),
        (ScannerStatus::Unstable, UnmeasuredCause::ScannerUnstable),
        (ScannerStatus::Error, UnmeasuredCause::ExecutionFailure),
    ];
    for (status, cause) in cases {
        let acc = run(&body, &unmeasured, status);
        let s = &acc.scanners[0];
        assert_eq!(s.status, status);
        for m in &s.overall.metrics {
            match m.metric {
                // Not-applicable for the metric's own reasons stays not-applicable.
                MetricId::WrongJurisdictionRate => {
                    // Jurisdictional valid cases exist and are eligible but not measured.
                    assert_eq!(m.status, MetricStatus::NotMeasured, "{:?}", m.metric);
                }
                // Unresolved axes stay unresolved: not-established is authored, not scanner-caused.
                MetricId::MeasurableShare | MetricId::ContextDiscriminationRate => assert!(
                    matches!(
                        m.status,
                        MetricStatus::Unresolved | MetricStatus::NotMeasured
                    ),
                    "{:?} {:?}",
                    m.metric,
                    m.status
                ),
                _ => assert!(
                    matches!(
                        m.status,
                        MetricStatus::NotMeasured | MetricStatus::NotApplicable
                    ),
                    "{:?} {:?}",
                    m.metric,
                    m.status
                ),
            }
            if m.counts.not_measured > 0 {
                assert_eq!(m.not_measured_cause, Some(cause), "{:?}", m.metric);
            } else {
                assert_eq!(m.not_measured_cause, None);
            }
            // Nothing measured is never a published success: no numerator.
            assert_eq!(m.counts.measured, 0, "{:?}", m.metric);
            assert_eq!(m.counts.numerator, 0);
        }
        // measurable-share still publishes a share of 0 over all eligible axes,
        // unresolved and not-measured counted in the denominator.
        let share = s.overall.metric(MetricId::MeasurableShare).unwrap();
        assert_eq!(share.effective_n, 24);
        assert_eq!(share.counts.numerator, 0);
        assert_eq!(share.counts.unresolved, 4);
        assert_eq!(share.counts.not_measured, 20);
        // measured == 0 with unresolved axes present is `unresolved`.
        assert_eq!(share.status, MetricStatus::Unresolved);
    }
}

#[test]
fn unresolved_not_measured_and_not_applicable_are_distinct_statuses() {
    // One case per status: all rows of a group are judged together.
    let body = snapshot_body(vec![
        case(
            "a1",
            PiiBenign,
            "en",
            None,
            vec![var("a1-v", Neutral, vec![occ("o1", I, Sx::NotEstablished)])],
        ),
        case(
            "a2",
            PiiBenign,
            "en",
            None,
            vec![var("a2-v", Neutral, vec![occ("o1", I, Sx::NonSensitive)])],
        ),
    ]);
    let id = scanner_id();
    let index = AuthoredIndex::new(&body).unwrap();
    let go = |rows: &[RowSpec]| {
        let outcomes = outcomes_of("scan-one", &body, rows);
        account_outcomes(
            &index,
            &[ScannerInput {
                id: &id,
                status: ScannerStatus::Complete,
            }],
            &outcomes,
            &Mechanics::PII_V1,
        )
        .unwrap()
    };
    let unresolved_only = go(&[
        ("a1", "a1-v", "o1", Ts::InvalidCorrect, Ss::Unresolved, Miss),
        (
            "a2",
            "a2-v",
            "o1",
            Ts::NotMeasured,
            Ss::NotMeasured,
            NotApplicable,
        ),
    ]);
    let benign = unresolved_only.scanners[0]
        .overall
        .metric(MetricId::BenignSuppressionRate)
        .unwrap();
    // a1 unresolved + a2 not-measured: nothing measured, one unresolved => unresolved.
    assert_eq!(benign.counts, counts(2, 0, 0, 1, 1, 0, 2));
    assert_eq!(benign.status, MetricStatus::Unresolved);
    assert_eq!(
        benign.value,
        MetricValue::Withheld {
            reason: WithheldReason::ZeroDenominator
        }
    );
    // No eligible group at all: not-applicable.
    let none = scanner_without_benign();
    assert_eq!(none.0, MetricStatus::NotApplicable);
    assert_eq!(none.1, 0);
}

fn scanner_without_benign() -> (MetricStatus, u64) {
    let body = snapshot_body(vec![case(
        "t1",
        TypeValidation,
        "en",
        None,
        vec![var("t1-v", Neutral, vec![occ("o1", V, Sx::Sensitive)])],
    )]);
    let acc = run(
        &body,
        &[("t1", "t1-v", "o1", Ts::Correct, Ss::Correct, Exact)],
        ScannerStatus::Complete,
    );
    let m = acc.scanners[0]
        .overall
        .metric(MetricId::BenignSuppressionRate)
        .unwrap();
    (m.status, m.effective_n)
}

#[test]
fn derived_variants_never_add_samples() {
    // One authored case with 1 and with 64 variants is one sample either way.
    let build = |variants: usize| {
        let vs = (0..variants)
            .map(|i| {
                var(
                    &format!("v{i:03}"),
                    Neutral,
                    vec![occ("o1", V, Sx::Sensitive)],
                )
            })
            .collect();
        let body = snapshot_body(vec![case("only", TypeValidation, "en", None, vs)]);
        let rows: Vec<(
            String,
            String,
            String,
            Ts,
            Ss,
            pii_eval_contracts::RangeState,
        )> = (0..variants)
            .map(|i| {
                (
                    "only".to_owned(),
                    format!("v{i:03}"),
                    "o1".to_owned(),
                    Ts::Miss,
                    Ss::Miss,
                    Miss,
                )
            })
            .collect();
        let outcomes: Vec<_> = rows.iter().map(|r| outcome("scan-one", &body, r)).collect();
        let index = AuthoredIndex::new(&body).unwrap();
        let id = scanner_id();
        let acc = account_outcomes(
            &index,
            &[ScannerInput {
                id: &id,
                status: ScannerStatus::Complete,
            }],
            &outcomes,
            &Mechanics::PII_V1,
        )
        .unwrap();
        let m = acc.scanners[0]
            .overall
            .metric(MetricId::TypeMissRate)
            .unwrap()
            .clone();
        (acc.authored.variants, m)
    };
    let (v1, one) = build(1);
    let (v64, many) = build(64);
    assert_eq!((v1, v64), (1, 64));
    assert_eq!(one.counts, many.counts);
    assert_eq!(one.effective_n, 1);
    assert_eq!(many.effective_n, 1);
    assert_eq!(many.basis.eligible_variants, 64);
    assert!(many.basis.correlated_variants && !one.basis.correlated_variants);
}

#[test]
fn replays_are_not_rows_a_repeated_row_is_refused() {
    // A replay would appear as a second row for the same occurrence. That is
    // a DuplicateRow error, so replays cannot raise N.
    let (body, rows) = fixture();
    let index = AuthoredIndex::new(&body).unwrap();
    let id = scanner_id();
    let mut outcomes = outcomes_of("scan-one", &body, &rows);
    outcomes.push(outcomes[0].clone());
    let err = account_outcomes(
        &index,
        &[ScannerInput {
            id: &id,
            status: ScannerStatus::Complete,
        }],
        &outcomes,
        &Mechanics::PII_V1,
    )
    .unwrap_err();
    // The extra row is beyond the complete matrix: bounded before it is read.
    assert!(matches!(
        err,
        AccountError::TooMany { .. } | AccountError::DuplicateRow(_)
    ));
    // Replacing one row by a repeat of another is a DuplicateRow at that row.
    let mut outcomes = outcomes_of("scan-one", &body, &rows);
    outcomes[5] = outcomes[4].clone();
    let err = account_outcomes(
        &index,
        &[ScannerInput {
            id: &id,
            status: ScannerStatus::Complete,
        }],
        &outcomes,
        &Mechanics::PII_V1,
    )
    .unwrap_err();
    assert_eq!(err, AccountError::DuplicateRow(5));
}

#[test]
fn rows_are_checked_never_trusted() {
    let (body, rows) = fixture();
    let index = AuthoredIndex::new(&body).unwrap();
    let id = scanner_id();
    let inputs = [ScannerInput {
        id: &id,
        status: ScannerStatus::Complete,
    }];
    let m = Mechanics::PII_V1;
    let good = outcomes_of("scan-one", &body, &rows);
    let acct = |o: &[pii_eval_contracts::CaseOutcome]| account_outcomes(&index, &inputs, o, &m);

    // Missing row.
    let missing = &good[..good.len() - 1];
    assert_eq!(
        acct(missing).unwrap_err(),
        AccountError::MissingRows {
            scanner: 0,
            expected: 21,
            found: 20
        }
    );
    // Unknown scanner.
    let mut bad = good.clone();
    bad[3].scanner_id = sid("other-scan");
    assert_eq!(acct(&bad).unwrap_err(), AccountError::UnknownScanner(3));
    // Unknown variant and unknown occurrence.
    let mut bad = good.clone();
    bad[4].variant_id = id_("no-such-variant");
    assert_eq!(acct(&bad).unwrap_err(), AccountError::UnknownOccurrence(4));
    let mut bad = good.clone();
    bad[4].occurrence_id = id_("o2");
    assert_eq!(acct(&bad).unwrap_err(), AccountError::UnknownOccurrence(4));
    // Case and method must match the authored case.
    let mut bad = good.clone();
    bad[2].case_id = id_("c03");
    assert_eq!(acct(&bad).unwrap_err(), AccountError::CaseMismatch(2));
    let mut bad = good.clone();
    bad[2].method = PiiBenign;
    assert_eq!(acct(&bad).unwrap_err(), AccountError::CaseMismatch(2));
    // A state unreachable under the authored expectation: `miss` for an invalid occurrence.
    let mut bad = good.clone();
    bad[1].type_identity = Ts::Miss;
    assert_eq!(
        acct(&bad).unwrap_err(),
        AccountError::OutcomeContradiction(1)
    );
    // `unresolved` for a sensitive occurrence.
    let mut bad = good.clone();
    bad[0].sensitivity_context = Ss::Unresolved;
    assert_eq!(
        acct(&bad).unwrap_err(),
        AccountError::OutcomeContradiction(0)
    );
    // A scanner that did not complete cannot report a measured axis.
    let failed = [ScannerInput {
        id: &id,
        status: ScannerStatus::Error,
    }];
    assert_eq!(
        account_outcomes(&index, &failed, &good, &m).unwrap_err(),
        AccountError::OutcomeContradiction(0)
    );
    // Duplicate scanner ids and invalid mechanics.
    let twice = [inputs[0], inputs[0]];
    assert_eq!(
        account_outcomes(&index, &twice, &good, &m).unwrap_err(),
        AccountError::DuplicateScanner
    );
    let zero_floor = Mechanics {
        min_denominator: 0,
        ..m
    };
    assert_eq!(
        account_outcomes(&index, &inputs, &good, &zero_floor).unwrap_err(),
        AccountError::InvalidMechanics
    );
}

fn id_(s: &str) -> pii_eval_contracts::Id {
    id(s)
}

#[test]
fn explicit_limits_are_enforced() {
    let (body, rows) = fixture();
    let index = AuthoredIndex::new(&body).unwrap();
    let ids: Vec<ScannerId> = (0..33).map(|i| sid(&format!("scan-{i:02}"))).collect();
    let many: Vec<ScannerInput<'_>> = ids
        .iter()
        .map(|id| ScannerInput {
            id,
            status: ScannerStatus::Complete,
        })
        .collect();
    let outcomes = outcomes_of("scan-00", &body, &rows);
    let err = account(
        &index,
        &many,
        outcomes.iter().map(OutcomeRef::from),
        &Mechanics::PII_V1,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        AccountError::TooMany {
            limit: pii_eval_kernel::Limit::Scanners,
            max: 32,
            actual: 33
        }
    ));
}

#[test]
fn snapshot_defects_are_refused_not_scored() {
    use pii_eval_kernel::SnapshotDefect as D;
    // Incomplete trio: only two frames.
    let mut body = snapshot_body(vec![trio("c09", Sx::Sensitive, Sx::NotEstablished)]);
    body.cases[0].variants.pop();
    assert_eq!(
        AuthoredIndex::new(&body).unwrap_err(),
        AccountError::InvalidSnapshot(D::IncompleteContextTrio)
    );
    // Duplicate variant ids across cases.
    let mut body = snapshot_body(vec![
        case(
            "ca1",
            TypeValidation,
            "en",
            None,
            vec![var("var-a", Neutral, vec![occ("o1", V, Sx::Sensitive)])],
        ),
        case(
            "cb1",
            TypeValidation,
            "en",
            None,
            vec![var("var-b", Neutral, vec![occ("o1", V, Sx::Sensitive)])],
        ),
    ]);
    body.cases[1].variants[0].variant_id = id("var-a");
    assert_eq!(
        AuthoredIndex::new(&body).unwrap_err(),
        AccountError::InvalidSnapshot(D::DuplicateVariant)
    );
    // Cases out of order and empty groups.
    let mut body = snapshot_body(vec![
        case(
            "ca1",
            TypeValidation,
            "en",
            None,
            vec![var("var-a", Neutral, vec![occ("o1", V, Sx::Sensitive)])],
        ),
        case(
            "cb1",
            TypeValidation,
            "en",
            None,
            vec![var("var-b", Neutral, vec![occ("o1", V, Sx::Sensitive)])],
        ),
    ]);
    body.cases.reverse();
    assert_eq!(
        AuthoredIndex::new(&body).unwrap_err(),
        AccountError::InvalidSnapshot(D::CaseOrder)
    );
    let mut body = snapshot_body(vec![case(
        "ca1",
        TypeValidation,
        "en",
        None,
        vec![var("var-a", Neutral, vec![occ("o1", V, Sx::Sensitive)])],
    )]);
    body.cases[0].variants[0].expectations.clear();
    assert_eq!(
        AuthoredIndex::new(&body).unwrap_err(),
        AccountError::InvalidSnapshot(D::EmptyGroup)
    );
    body.cases[0].variants.clear();
    assert_eq!(
        AuthoredIndex::new(&body).unwrap_err(),
        AccountError::InvalidSnapshot(D::EmptyGroup)
    );
}

#[test]
fn a_complete_context_trio_is_scored_as_one_sample_not_per_frame() {
    // c09 alone: three frames, one sample.
    let body = snapshot_body(vec![trio("c09", Sx::Sensitive, Sx::NotEstablished)]);
    let rows: Vec<RowSpec> = vec![
        ("c09", "c09-s", "o1", Ts::Correct, Ss::Correct, Exact),
        ("c09", "c09-n", "o1", Ts::Correct, Ss::Unresolved, Exact),
        ("c09", "c09-ns", "o1", Ts::Correct, Ss::Correct, Exact),
    ];
    let acc = run(&body, &rows, ScannerStatus::Complete);
    let m = acc.scanners[0]
        .overall
        .metric(MetricId::ContextDiscriminationRate)
        .unwrap();
    assert_eq!(m.counts, counts(1, 1, 1, 0, 0, 0, 1));
    assert_eq!(m.effective_n, 1);
    assert_eq!(
        m.basis.sample_unit,
        pii_eval_contracts::SampleUnit::ContextTrio
    );
    assert_eq!(m.basis.eligible_variants, 3);
}

#[test]
fn identical_input_gives_identical_accounting_on_repeat() {
    let (body, rows) = fixture();
    let first = run(&body, &rows, ScannerStatus::Complete);
    for _ in 0..3 {
        assert_eq!(run(&body, &rows, ScannerStatus::Complete), first);
    }
}
