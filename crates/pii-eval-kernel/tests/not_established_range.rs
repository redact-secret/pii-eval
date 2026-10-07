//! Authored `not-established` range (schema 1.4, ADR 0018), with hand-calculated
//! controls. An occurrence the corpus authors located nowhere has no expected
//! range: its range axis is `unresolved`, its identity and sensitivity stay
//! `unresolved` (both are authored `not-established` too), nothing is read from
//! the scanner's findings, and no numerator, denominator or interval the located
//! occurrences already had changes.

mod acct_common;
mod common;

use acct_common::*;
use pii_eval_contracts::axes::{AuthoredAxes, OutcomeRow, validate_outcome_lattice};
use pii_eval_contracts::{
    ActionOutcome, CapabilityState, ContextClass::Neutral, CorpusSnapshotBody, ExpectedType,
    FamilyId, Mechanics, MethodId::*, MetricCounts, MetricId, RangeState, ScannerId, ScannerStatus,
    SensitivityExpectation as Sx, SensitivityState as Ss, TypeState as Ts,
};
use pii_eval_kernel::{Accounting, AuthoredIndex, ScannerInput, account_outcomes};

const V: ExpectedType = ExpectedType::Valid;
const N: ExpectedType = ExpectedType::NotEstablished;

/// v1 and v2 (valid, sensitive, located) and, when `with_rangeless`, n1 and n2:
/// not-established identity and sensitivity, and no range.
fn body(with_rangeless: bool) -> CorpusSnapshotBody {
    let located = |id: &str| {
        case(
            id,
            SchemaOnly,
            "en",
            None,
            vec![var(
                &format!("{id}-a"),
                Neutral,
                vec![occ("o1", V, Sx::Sensitive)],
            )],
        )
    };
    let mut cases = vec![located("v1"), located("v2")];
    if with_rangeless {
        for id in ["n1", "n2"] {
            cases.push(case(
                id,
                SchemaOnly,
                "en",
                None,
                vec![var(
                    &format!("{id}-a"),
                    Neutral,
                    vec![occ("o1", N, Sx::NotEstablished)],
                )],
            ));
        }
    }
    let mut body = snapshot_body(cases);
    for case in &mut body.cases {
        if case.case_id.as_str().starts_with('n') {
            case.variants[0].expectations[0].range = None;
        }
    }
    body
}

fn rows(with_rangeless: bool) -> Vec<RowSpec> {
    let mut rows: Vec<RowSpec> = vec![
        (
            "v1",
            "v1-a",
            "o1",
            Ts::Correct,
            Ss::Correct,
            RangeState::Exact,
        ),
        ("v2", "v2-a", "o1", Ts::Miss, Ss::Miss, RangeState::Miss),
    ];
    if with_rangeless {
        // Whatever the scanner reported inside n1 and n2, the observation is the
        // same: there is no authored range to compare a finding with.
        for id in [("n1", "n1-a"), ("n2", "n2-a")] {
            rows.push((
                id.0,
                id.1,
                "o1",
                Ts::Unresolved,
                Ss::Unresolved,
                RangeState::Unresolved,
            ));
        }
    }
    rows
}

fn run(with_rangeless: bool) -> Accounting {
    let body = body(with_rangeless);
    let index = AuthoredIndex::new(&body).unwrap();
    let id: ScannerId = sid("scan-one");
    let outcomes = outcomes_of("scan-one", &body, &rows(with_rangeless));
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
fn a_rangeless_occurrence_changes_no_metric_of_the_located_ones() {
    let (without, with) = (run(false), run(true));
    // Hand calculation: v1 correct, v2 missed => type-miss 1 of 2. n1 and n2 are
    // outside the valid-type population, as an invalid or uncertain identity is.
    assert_eq!(
        counts(&without, MetricId::TypeMissRate),
        c(2, 2, 1, 0, 0, 0, 2)
    );
    assert_eq!(
        counts(&with, MetricId::TypeMissRate),
        c(2, 2, 1, 0, 0, 2, 4)
    );
    for m in [
        MetricId::WrongFamilyRate,
        MetricId::WrongJurisdictionRate,
        MetricId::RangeCollateralRate,
        MetricId::SensitiveMissRate,
        MetricId::NonSensitiveFlagRate,
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
            "{m:?}"
        );
    }
    // Sensitivity: only v1 and v2 are authored sensitive: 1 miss of 2.
    let sens = counts(&with, MetricId::SensitiveMissRate);
    assert_eq!((sens.eligible, sens.numerator), (2, 1));
}

#[test]
fn measurable_share_reports_the_rangeless_cases_as_unresolved_never_measured() {
    // Two axes per case. v1, v2: both resolved (4 samples measured). n1, n2: type
    // and sensitivity axes both unresolved (4 samples). 8 samples, 4 measured,
    // 4 unresolved.
    let with = run(true);
    assert_eq!(
        counts(&with, MetricId::MeasurableShare),
        c(8, 4, 4, 4, 0, 0, 8)
    );
    assert_conserved(&with);
}

#[test]
fn accounting_is_identical_on_repeat() {
    assert_eq!(run(true), run(true));
}

fn row(range: RangeState) -> OutcomeRow {
    OutcomeRow {
        type_identity: Ts::Unresolved,
        sensitivity_context: Ss::Unresolved,
        range,
        action: ActionOutcome::NotMeasured,
    }
}

#[test]
fn the_lattice_makes_unresolved_the_only_measured_range_of_a_rangeless_occurrence() {
    let family = FamilyId::new("pii:global:email").unwrap();
    let caps = common::supported();
    let ok = |range_established, range| {
        validate_outcome_lattice(
            &AuthoredAxes {
                expected_type: N,
                sensitivity: Sx::NotEstablished,
                range_established,
                family: &family,
                jurisdiction: None,
            },
            ScannerStatus::Complete,
            &caps,
            &row(range),
        )
    };
    assert!(ok(false, RangeState::Unresolved).is_ok());
    for state in [
        RangeState::Exact,
        RangeState::Overbroad,
        RangeState::Partial,
        RangeState::Miss,
    ] {
        assert!(ok(false, state).is_err(), "{state:?}");
    }
    // A located occurrence can never be unresolved on the range axis.
    assert!(ok(true, RangeState::Unresolved).is_err());
}

fn rangeless(family: &str) -> pii_eval_contracts::Expectation {
    let mut e = common::exp("occ-a", 0, 1, family, N, Sx::NotEstablished);
    e.range = None;
    e
}

#[test]
fn matching_ignores_every_finding_for_a_rangeless_occurrence() {
    use common::*;
    let text = "contact: 4111 1111 1111 1111 here";
    let e = rangeless("pii:global:payment-card");
    let caps = supported();
    let none = assess(text, None, std::slice::from_ref(&e), &[], &caps);
    let wide = assess(
        text,
        None,
        &[e],
        &[
            found(9, 28, "pii:global:payment-card"),
            found(0, 33, "pii:global:email"),
        ],
        &caps,
    );
    for a in [&none, &wide] {
        let row = a.occurrences[0].row;
        assert_eq!(
            (
                row.type_identity,
                row.sensitivity_context,
                row.range,
                row.action
            ),
            (
                Ts::Unresolved,
                Ss::Unresolved,
                RangeState::Unresolved,
                ActionOutcome::NotMeasured
            )
        );
        assert_eq!(a.occurrences[0].primary, None);
        assert_eq!(a.occurrences[0].observed.finding_count, 0);
    }
    // The findings are still accounted for, as findings that match no occurrence.
    assert_eq!(wide.reported.len(), 2);
    assert!(wide.reported.iter().all(|r| r.matched.is_none()));
    assert_eq!(none.reported.len(), 0);
}

#[test]
fn a_missing_capability_leaves_identity_and_sensitivity_unmeasured() {
    use common::*;
    let mut caps = supported();
    caps.sensitivity_classification = CapabilityState::Unsupported;
    caps.family_classification = CapabilityState::Unsupported;
    let a = assess(
        "contact: someone",
        None,
        &[rangeless("pii:global:email")],
        &[],
        &caps,
    );
    let row = a.occurrences[0].row;
    assert_eq!(row.type_identity, Ts::NotMeasured);
    assert_eq!(row.sensitivity_context, Ss::NotMeasured);
    // The range axis does not depend on the scanner: still not established.
    assert_eq!(row.range, RangeState::Unresolved);
}

#[test]
fn a_scanner_that_cannot_report_ranges_leaves_the_row_unmeasured() {
    use common::*;
    let caps = caps(CapabilityState::Unsupported);
    let a = assess(
        "contact: someone",
        None,
        &[rangeless("pii:global:email")],
        &[],
        &caps,
    );
    assert!(a.occurrences[0].row.is_unmeasured());
}
