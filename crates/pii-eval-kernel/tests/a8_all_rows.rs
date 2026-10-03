//! A8 (ADR 0005 section 11, resolved by ADR 0008): the benign-suppression and
//! jurisdiction-collision buckets count a case only when ALL of its rows pass.
//! The oracle counted a case when ANY row passed (`group.some`).
//!
//! Hand-calculated vector. Four benign cases and four collision cases, one
//! occurrence per variant. A row "passes" when its axis is correct and "fails"
//! when the scanner flags the benign text (sensitivity `false-positive`) or
//! reports the wrong jurisdiction (type `wrong-jurisdiction`).
//!
//! | case | variants (pass/fail) | any (oracle) | all (canonical) |
//! | ---- | -------------------- | ------------ | --------------- |
//! | 1    | pass, pass           | suppressed   | suppressed      |
//! | 2    | pass, fail           | suppressed   | not suppressed  |
//! | 3    | fail, fail           | not          | not             |
//! | 4    | pass, pass, pass     | suppressed   | suppressed      |
//!
//! Oracle: 3 of 4; canonical: 2 of 4. Both metrics have direction `lower`, so
//! the published bound is the Wilson lower endpoint at z = 1.96, six places.
//! The values were computed independently with Python `decimal` at 60 digits
//! (the textbook formula, not the kernel's integer algorithm):
//!
//! * 2 of 4: point 0.5, lower 0.150036;
//! * 3 of 4: point 0.75, lower 0.300636.

mod acct_common;

use acct_common::*;
use pii_eval_contracts::{
    BoundDirection, ContextClass::Neutral, ExpectedType, Mechanics, MethodId::*, MetricCounts,
    MetricId, MetricValue, RangeState::*, ScaledDecimal, ScannerStatus,
    SensitivityExpectation as Sx, SensitivityState as Ss, TypeState as Ts,
};
use pii_eval_kernel::{AuthoredIndex, ScannerInput, account_outcomes, published_value};

fn value(point: (u64, u8), bound: (u64, u8)) -> MetricValue {
    MetricValue::Measured {
        point: ScaledDecimal::new(point.0, point.1).unwrap(),
        bound: ScaledDecimal::new(bound.0, bound.1).unwrap(),
    }
}

/// `(variant suffixes, passes)` per case: 1 pass,pass; 2 pass,fail; 3 fail,fail; 4 pass x3.
const SHAPES: [(&str, &[bool]); 4] = [
    ("1", &[true, true]),
    ("2", &[true, false]),
    ("3", &[false, false]),
    ("4", &[true, true, true]),
];

fn snapshot_and_rows() -> (pii_eval_contracts::CorpusSnapshotBody, Vec<RowSpec>) {
    let mut cases = Vec::new();
    for (n, passes) in SHAPES {
        let variants = |prefix: &str, ty, sens| {
            passes
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    var(
                        &format!("{prefix}{n}-v{i}"),
                        Neutral,
                        vec![occ("o1", ty, sens)],
                    )
                })
                .collect::<Vec<_>>()
        };
        cases.push(case(
            &format!("benign{n}"),
            PiiBenign,
            "en",
            None,
            variants("benign", ExpectedType::Invalid, Sx::NonSensitive),
        ));
        cases.push(case(
            &format!("collide{n}"),
            JurisdictionCollision,
            "en",
            Some("US"),
            variants("collide", ExpectedType::Valid, Sx::Sensitive),
        ));
    }
    let body = snapshot_body(cases);
    // Test-only: row specs borrow `'static` names, so the few names are leaked.
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    let mut rows: Vec<RowSpec> = Vec::new();
    for (n, passes) in SHAPES {
        for (i, pass) in passes.iter().enumerate() {
            rows.push((
                leak(format!("benign{n}")),
                leak(format!("benign{n}-v{i}")),
                "o1",
                Ts::InvalidCorrect,
                if *pass {
                    Ss::Correct
                } else {
                    Ss::FalsePositive
                },
                Miss,
            ));
            rows.push((
                leak(format!("collide{n}")),
                leak(format!("collide{n}-v{i}")),
                "o1",
                if *pass {
                    Ts::Correct
                } else {
                    Ts::WrongJurisdiction
                },
                Ss::Correct,
                Exact,
            ));
        }
    }
    (body, rows)
}

#[test]
fn a_case_counts_only_when_every_row_passes() {
    let (body, rows) = snapshot_and_rows();
    let index = AuthoredIndex::new(&body).unwrap();
    let id = sid("scan-one");
    let acc = account_outcomes(
        &index,
        &[ScannerInput {
            id: &id,
            status: ScannerStatus::Complete,
        }],
        &outcomes_of("scan-one", &body, &rows),
        &Mechanics::PII_V1,
    )
    .unwrap();
    let overall = &acc.scanners[0].overall;
    for metric in [
        MetricId::BenignSuppressionRate,
        MetricId::JurisdictionCollisionRate,
    ] {
        let m = overall.metric(metric).unwrap();
        // Four eligible cases of the method; the other method's four cases are
        // not applicable. Canonical numerator 2 (cases 1 and 4); the oracle's
        // would be 3 (cases 1, 2 and 4).
        assert_eq!(
            m.counts,
            MetricCounts {
                eligible: 4,
                measured: 4,
                numerator: 2,
                unresolved: 0,
                not_measured: 0,
                not_applicable: 4,
                total: 8,
            },
            "{metric:?}"
        );
        assert_eq!(m.effective_n, 4);
        assert_eq!(m.value, value((5, 1), (150_036, 6)), "{metric:?}");
    }
    // The classified difference in numbers: the oracle's 3 of 4 would publish
    // 0.75 with lower bound 0.300636.
    let direction = MetricId::BenignSuppressionRate.definition().direction;
    assert_eq!(direction, BoundDirection::Lower);
    assert_eq!(
        published_value(3, 4, direction, &Mechanics::PII_V1).unwrap(),
        value((75, 2), (300_636, 6))
    );
    // Variants never add samples (A3) and the authored counts stay separate.
    assert_eq!(acc.authored.authored_cases, 8);
    assert_eq!(acc.authored.variants, 2 * (2 + 2 + 2 + 3));
}

#[test]
fn review_required_and_not_measured_still_win_over_the_all_rule() {
    // One benign case: variant a passes, variant b is not measured: the case is
    // not-measured, not suppressed and not "other".
    let body = snapshot_body(vec![case(
        "benign9",
        PiiBenign,
        "en",
        None,
        vec![
            var(
                "benign9-a",
                Neutral,
                vec![occ("o1", ExpectedType::Invalid, Sx::NonSensitive)],
            ),
            var(
                "benign9-b",
                Neutral,
                vec![occ("o1", ExpectedType::Invalid, Sx::NonSensitive)],
            ),
        ],
    )]);
    let rows: Vec<RowSpec> = vec![
        (
            "benign9",
            "benign9-a",
            "o1",
            Ts::InvalidCorrect,
            Ss::Correct,
            Miss,
        ),
        (
            "benign9",
            "benign9-b",
            "o1",
            Ts::NotMeasured,
            Ss::NotMeasured,
            NotApplicable,
        ),
    ];
    let index = AuthoredIndex::new(&body).unwrap();
    let id = sid("scan-one");
    let acc = account_outcomes(
        &index,
        &[ScannerInput {
            id: &id,
            status: ScannerStatus::Complete,
        }],
        &outcomes_of("scan-one", &body, &rows),
        &Mechanics::PII_V1,
    )
    .unwrap();
    let m = acc.scanners[0]
        .overall
        .metric(MetricId::BenignSuppressionRate)
        .unwrap();
    assert_eq!(
        m.counts,
        MetricCounts {
            eligible: 1,
            measured: 0,
            numerator: 0,
            unresolved: 0,
            not_measured: 1,
            not_applicable: 0,
            total: 1,
        }
    );
}
