//! Authored `not-established` type identity (schema 1.3, ADR 0017), with
//! hand-calculated controls. The authored uncertainty is preserved: it is never
//! read as valid or invalid, never dropped, and never changes a denominator the
//! type metrics already had. Its sensitivity and range axes stay independent.

mod acct_common;

use acct_common::*;
use pii_eval_contracts::{
    ContextClass::Neutral, CorpusSnapshotBody, ExpectedType, Mechanics, MethodId::*, MetricCounts,
    MetricId, MetricStatus, RangeState::*, ScannerId, ScannerStatus, SensitivityExpectation as Sx,
    SensitivityState as Ss, TypeState as Ts,
};
use pii_eval_kernel::{Accounting, AuthoredIndex, ScannerInput, account_outcomes};

const V: ExpectedType = ExpectedType::Valid;
const N: ExpectedType = ExpectedType::NotEstablished;

fn body(with_uncertain: bool) -> CorpusSnapshotBody {
    let o = |ty| vec![occ("o1", ty, Sx::Sensitive)];
    let mut cases = vec![
        case(
            "v1",
            TypeValidation,
            "en",
            None,
            vec![var("v1-a", Neutral, o(V))],
        ),
        case(
            "v2",
            TypeValidation,
            "en",
            None,
            vec![var("v2-a", Neutral, o(V))],
        ),
    ];
    if with_uncertain {
        cases.push(case(
            "n1",
            TypeValidation,
            "en",
            None,
            vec![var("n1-a", Neutral, o(N))],
        ));
        cases.push(case(
            "n2",
            TypeValidation,
            "en",
            None,
            vec![var("n2-a", Neutral, o(N))],
        ));
    }
    snapshot_body(cases)
}

fn rows(with_uncertain: bool) -> Vec<RowSpec> {
    let mut rows: Vec<RowSpec> = vec![
        ("v1", "v1-a", "o1", Ts::Correct, Ss::Correct, Exact),
        ("v2", "v2-a", "o1", Ts::Miss, Ss::Miss, Miss),
    ];
    if with_uncertain {
        // The scanner found n1 and missed n2. The type axis is unresolved for
        // both: a finding is not evidence of the authored identity.
        rows.push(("n1", "n1-a", "o1", Ts::Unresolved, Ss::Correct, Exact));
        rows.push(("n2", "n2-a", "o1", Ts::Unresolved, Ss::Miss, Miss));
    }
    rows
}

fn run(with_uncertain: bool) -> Accounting {
    let body = body(with_uncertain);
    let index = AuthoredIndex::new(&body).unwrap();
    let id: ScannerId = sid("scan-one");
    let outcomes = outcomes_of("scan-one", &body, &rows(with_uncertain));
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
}

fn counts(acc: &Accounting, m: MetricId) -> MetricCounts {
    acc.scanners[0].overall.metric(m).unwrap().counts
}

fn c(e: u64, m: u64, n: u64, u: u64, nm: u64, na: u64, t: u64) -> MetricCounts {
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

#[test]
fn uncertain_identity_changes_no_type_metric_numerator_or_denominator() {
    let (without, with) = (run(false), run(true));
    for m in [
        MetricId::TypeMissRate,
        MetricId::WrongFamilyRate,
        MetricId::WrongJurisdictionRate,
        MetricId::RangeCollateralRate,
    ] {
        let (a, b) = (counts(&without, m), counts(&with, m));
        assert_eq!(
            (
                a.eligible,
                a.measured,
                a.numerator,
                a.unresolved,
                a.not_measured
            ),
            (
                b.eligible,
                b.measured,
                b.numerator,
                b.unresolved,
                b.not_measured
            ),
            "{m:?}: the uncertain cases are outside the population"
        );
    }
    // Hand calculation: v1 correct, v2 missed => 1 of 2; n1 and n2 are not judged.
    assert_eq!(
        counts(&with, MetricId::TypeMissRate),
        c(2, 2, 1, 0, 0, 2, 4)
    );
    assert_eq!(
        counts(&without, MetricId::TypeMissRate),
        c(2, 2, 1, 0, 0, 0, 2)
    );
    let status = with.scanners[0]
        .overall
        .metric(MetricId::TypeMissRate)
        .unwrap()
        .status;
    assert_eq!(status, MetricStatus::Measured);
}

#[test]
fn uncertain_identity_keeps_its_independent_sensitivity_axis() {
    // Sensitivity is authored sensitive for all four: v1 ok, v2 miss, n1 ok, n2 miss.
    let with = run(true);
    assert_eq!(
        counts(&with, MetricId::SensitiveMissRate),
        c(4, 4, 2, 0, 0, 0, 4)
    );
}

#[test]
fn measurable_share_reports_the_uncertain_identity_as_unresolved_not_measured() {
    // Two axes per case. Type axis: v1, v2 resolved; n1, n2 unresolved.
    // Sensitivity axis: all four resolved. 8 samples, 6 measured, 2 unresolved.
    let with = run(true);
    assert_eq!(
        counts(&with, MetricId::MeasurableShare),
        c(8, 6, 6, 2, 0, 0, 8)
    );
    assert_conserved(&with);
}

#[test]
fn accounting_is_identical_on_repeat() {
    assert_eq!(run(true), run(true));
}
