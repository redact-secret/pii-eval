//! Compatibility of the canonical accounting with the pinned oracle's PII
//! accounting (`benchmarks/evaluation/domains/pii/accounting.ts` and
//! `benchmarks/accounting/shared/primitives.ts` at oracle commit
//! `4b846967346505baca11e0b98cab1475fbce6773`).
//!
//! Provenance of the expected values:
//!
//! * Bucket counts and denominators for the hand-built fixtures were derived by
//!   hand from `accounting.ts` (`buildAccounting`, `metricBuckets`,
//!   `groupBucket`, lines 217-296 at the pin), case by case; the derivation is
//!   in the comments next to each fixture.
//! * The numeric rate values (`point`, `bound`) were obtained by running the
//!   oracle's own `proportion()` from `primitives.ts` under Node 22 type
//!   stripping on the same counts. They are literals here; nothing is computed
//!   by the Rust code under test.
//!
//! Where the canonical rule intentionally differs, both values are asserted
//! and the difference carries an id and a class (ADR 0005, "Compatibility").
//!
//! * S1 rounding: the oracle rounds a binary64 value with `toFixed`; the
//!   canonical rule rounds the exact rational half up. They differ only when a
//!   value is an exact tie that binary64 stores on the other side.
//! * A2 mixed-type groups: the oracle decides eligibility for the valid-type
//!   metrics from the first variant after a locale-dependent `localeCompare`
//!   sort of variant ids and judges all variants; the canonical rule judges the
//!   valid-type occurrences.
//! * A3 multi-variant benign cases: the oracle throws; the canonical rule
//!   counts one sample.

#[path = "../../pii-eval-kernel/tests/acct_common/mod.rs"]
mod acct_common;

use acct_common::*;
use pii_eval_contracts::{
    ContextClass::Neutral, CorpusSnapshotBody, ExpectedType, Mechanics, MethodId::*, MetricCounts,
    MetricId, MetricStatus, MetricValue, RangeState::*, ScaledDecimal, ScannerStatus,
    SensitivityExpectation as Sx, SensitivityState as Ss, TypeState as Ts, WithheldReason,
};
use pii_eval_kernel::{AuthoredIndex, ScannerInput, account_outcomes, published_value};

const V: ExpectedType = ExpectedType::Valid;
const I: ExpectedType = ExpectedType::Invalid;

fn run(body: &CorpusSnapshotBody, rows: &[RowSpec]) -> pii_eval_kernel::Accounting {
    let index = AuthoredIndex::new(body).unwrap();
    let id = sid("scan-one");
    account_outcomes(
        &index,
        &[ScannerInput {
            id: &id,
            status: ScannerStatus::Complete,
        }],
        &outcomes_of("scan-one", body, rows),
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

fn dec6(mantissa: u64) -> ScaledDecimal {
    ScaledDecimal::new(mantissa, 6).unwrap()
}

/// The oracle's `rate` rendered in contract terms: `null` is a zero
/// denominator, the string `insufficient-evidence` is itself.
enum OracleRate {
    Null,
    Insufficient,
    Value { point: u64, bound: u64 },
}

fn assert_rate(got: &MetricValue, oracle: OracleRate, what: &str) {
    let expected = match oracle {
        OracleRate::Null => MetricValue::Withheld {
            reason: WithheldReason::ZeroDenominator,
        },
        OracleRate::Insufficient => MetricValue::Withheld {
            reason: WithheldReason::InsufficientEvidence,
        },
        OracleRate::Value { point, bound } => MetricValue::Measured {
            point: dec6(point),
            bound: dec6(bound),
        },
    };
    assert_eq!(*got, expected, "{what}");
}

#[test]
fn uniform_groups_give_the_oracles_counts_denominators_and_rates() {
    // Six authored cases, one variant each, one scanner, all global:
    //   t1 valid sensitive:     type miss,          sensitivity miss,           range miss
    //   t2 valid sensitive:     type correct,       sensitivity correct,        range exact
    //   t3 valid sensitive:     type wrong-family,  sensitivity correct,        range partial
    //   t4 valid non-sensitive: type correct,       sensitivity false-positive, range overbroad
    //   b1 benign (invalid, non-sensitive): invalid-correct, correct,           range miss
    //   b2 benign (invalid, non-sensitive): invalid-accepted, false-positive,   range exact
    let o = |ty, sens| vec![occ("o1", ty, sens)];
    let body = snapshot_body(vec![
        case(
            "t1",
            TypeValidation,
            "en",
            None,
            vec![var("t1-v", Neutral, o(V, Sx::Sensitive))],
        ),
        case(
            "t2",
            TypeValidation,
            "en",
            None,
            vec![var("t2-v", Neutral, o(V, Sx::Sensitive))],
        ),
        case(
            "t3",
            TypeValidation,
            "en",
            None,
            vec![var("t3-v", Neutral, o(V, Sx::Sensitive))],
        ),
        case(
            "t4",
            TypeValidation,
            "en",
            None,
            vec![var("t4-v", Neutral, o(V, Sx::NonSensitive))],
        ),
        case(
            "b1",
            PiiBenign,
            "en",
            None,
            vec![var("b1-v", Neutral, o(I, Sx::NonSensitive))],
        ),
        case(
            "b2",
            PiiBenign,
            "en",
            None,
            vec![var("b2-v", Neutral, o(I, Sx::NonSensitive))],
        ),
    ]);
    let rows: Vec<RowSpec> = vec![
        ("t1", "t1-v", "o1", Ts::Miss, Ss::Miss, Miss),
        ("t2", "t2-v", "o1", Ts::Correct, Ss::Correct, Exact),
        ("t3", "t3-v", "o1", Ts::WrongFamily, Ss::Correct, Partial),
        (
            "t4",
            "t4-v",
            "o1",
            Ts::Correct,
            Ss::FalsePositive,
            Overbroad,
        ),
        ("b1", "b1-v", "o1", Ts::InvalidCorrect, Ss::Correct, Miss),
        (
            "b2",
            "b2-v",
            "o1",
            Ts::InvalidAccepted,
            Ss::FalsePositive,
            Exact,
        ),
    ];
    let acc = run(&body, &rows);
    let overall = &acc.scanners[0].overall;

    // (metric, oracle counts, oracle effectiveN, oracle status, oracle rate).
    // Oracle `proportion(numerator, effectiveN, direction, {minDenominator 4, z 1.96, precision 6})`.
    let oracle: Vec<(MetricId, MetricCounts, u64, MetricStatus, OracleRate)> = vec![
        // 4 valid groups: t1 miss -> numerator, t2 t3 t4 other. b1 b2: first row invalid -> notApplicable.
        (
            MetricId::TypeMissRate,
            counts(4, 4, 1, 0, 0, 2, 6),
            4,
            MetricStatus::Measured,
            OracleRate::Value {
                point: 250_000,
                bound: 699_364,
            },
        ),
        // t3 wrong-family -> numerator, others other.
        (
            MetricId::WrongFamilyRate,
            counts(4, 4, 1, 0, 0, 2, 6),
            4,
            MetricStatus::Measured,
            OracleRate::Value {
                point: 250_000,
                bound: 699_364,
            },
        ),
        // scope is global for every case: all notApplicable, denominator 0 -> rate null.
        (
            MetricId::WrongJurisdictionRate,
            counts(0, 0, 0, 0, 0, 6, 6),
            0,
            MetricStatus::NotApplicable,
            OracleRate::Null,
        ),
        // sensitive rows: t1 miss -> numerator, t2 t3 other; t4 b1 b2 have none -> notApplicable.
        // effectiveN 3 < minDenominator 4 -> 'insufficient-evidence'.
        (
            MetricId::SensitiveMissRate,
            counts(3, 3, 1, 0, 0, 3, 6),
            3,
            MetricStatus::Measured,
            OracleRate::Insufficient,
        ),
        // non-sensitive rows: t4 false-positive -> numerator, b1 other, b2 false-positive -> numerator.
        (
            MetricId::NonSensitiveFlagRate,
            counts(3, 3, 2, 0, 0, 3, 6),
            3,
            MetricStatus::Measured,
            OracleRate::Insufficient,
        ),
        // no context-discrimination rows: contexts = [] -> metricBuckets([]) -> total 0, not-applicable.
        (
            MetricId::ContextDiscriminationRate,
            counts(0, 0, 0, 0, 0, 0, 0),
            0,
            MetricStatus::NotApplicable,
            OracleRate::Null,
        ),
        // b1 sensitivity pass -> numerator, b2 fail -> other; the four type cases notApplicable.
        (
            MetricId::BenignSuppressionRate,
            counts(2, 2, 1, 0, 0, 4, 6),
            2,
            MetricStatus::Measured,
            OracleRate::Insufficient,
        ),
        // no jurisdiction-collision case.
        (
            MetricId::JurisdictionCollisionRate,
            counts(0, 0, 0, 0, 0, 6, 6),
            0,
            MetricStatus::NotApplicable,
            OracleRate::Null,
        ),
        // t1: every range 'miss' -> notApplicable; t2 exact -> other; t3 partial, t4 overbroad -> numerator;
        // b1 b2: first row invalid -> notApplicable. effectiveN 3.
        (
            MetricId::RangeCollateralRate,
            counts(3, 3, 2, 0, 0, 3, 6),
            3,
            MetricStatus::Measured,
            OracleRate::Insufficient,
        ),
        // 6 groups x 2 axes, nothing unresolved or not measured: 12 resolved. rate = proportion(12, 12, 'lower').
        (
            MetricId::MeasurableShare,
            counts(12, 12, 12, 0, 0, 0, 12),
            12,
            MetricStatus::Measured,
            OracleRate::Value {
                point: 1_000_000,
                bound: 757_499,
            },
        ),
    ];
    for (metric, c, n, status, rate) in oracle {
        let got = overall.metric(metric).unwrap();
        assert_eq!(got.counts, c, "{metric:?} counts");
        assert_eq!(got.effective_n, n, "{metric:?} effectiveN");
        assert_eq!(got.status, status, "{metric:?} status");
        assert_rate(&got.value, rate, &format!("{metric:?} rate"));
    }
}

#[test]
fn s1_rounding_differs_from_binary64_only_at_exact_ties() {
    // Oracle `proportion(k, n, dir, {minDenominator 1, z 1.96, precision 1})`
    // (primitives.ts `round = Number(v.toFixed(precision))`):
    //   3/20: point 0.15 is stored as 0.1499999999999999944...; toFixed(1) -> "0.1".
    //   7/20: point 0.35 is stored as 0.34999999999999997...;   toFixed(1) -> "0.3".
    // The canonical rule rounds the exact rational half up: 0.15 -> 0.2, 0.35 -> 0.4.
    // The Wilson endpoints are irrational, so they cannot tie and agree (0.4 and 0.2).
    let m = Mechanics {
        min_denominator: 1,
        interval_precision: 1,
        ..Mechanics::PII_V1
    };
    let up = pii_eval_contracts::BoundDirection::Upper;
    let lo = pii_eval_contracts::BoundDirection::Lower;
    let d1 = |n| ScaledDecimal::new(n, 1).unwrap();
    assert_eq!(
        published_value(3, 20, up, &m),
        Ok(MetricValue::Measured {
            point: d1(2), // oracle: 0.1
            bound: d1(4), // oracle: 0.4 (agrees)
        })
    );
    assert_eq!(
        published_value(7, 20, lo, &m),
        Ok(MetricValue::Measured {
            point: d1(4), // oracle: 0.3
            bound: d1(2), // oracle: 0.2 (agrees)
        })
    );
    // Exact dyadic ties agree: 1/8 at two places is 0.13 in both (toFixed breaks a
    // tie that binary64 stores exactly toward the larger value).
    let m2 = Mechanics {
        min_denominator: 1,
        interval_precision: 2,
        ..Mechanics::PII_V1
    };
    assert_eq!(
        published_value(1, 8, up, &m2),
        Ok(MetricValue::Measured {
            point: ScaledDecimal::new(13, 2).unwrap(), // oracle 0.13
            bound: ScaledDecimal::new(47, 2).unwrap(), // oracle 0.47
        })
    );
}

#[test]
fn oracle_primitive_values_agree_at_default_precision() {
    // Values produced by the oracle's `proportion` (precision 6, z 1.96):
    // identical mantissas, point and bound, for these inputs.
    let m = Mechanics::PII_V1;
    let up = pii_eval_contracts::BoundDirection::Upper;
    let lo = pii_eval_contracts::BoundDirection::Lower;
    // (k, n, direction, oracle point, oracle bound)
    let vectors = [
        (1u64, 4u64, up, 250_000u64, 699_364u64),
        (1, 8, up, 125_000, 470_895),
        (2, 8, up, 250_000, 590_730),
        (12, 12, lo, 1_000_000, 757_499),
    ];
    for (k, n, dir, point, bound) in vectors {
        assert_eq!(
            published_value(k, n, dir, &m),
            Ok(MetricValue::Measured {
                point: dec6(point),
                bound: dec6(bound),
            }),
            "k={k} n={n}"
        );
    }
    // null and 'insufficient-evidence'.
    assert_eq!(
        published_value(0, 0, up, &m),
        Ok(MetricValue::Withheld {
            reason: WithheldReason::ZeroDenominator
        })
    );
    assert_eq!(
        published_value(1, 3, up, &m),
        Ok(MetricValue::Withheld {
            reason: WithheldReason::InsufficientEvidence
        })
    );
}

#[test]
fn a2_mixed_type_groups_oracle_versus_canonical() {
    // Two type-validation cases, each with a valid and an invalid variant.
    //   m2: variants m2-a (invalid, row invalid-correct) and m2-b (valid, row miss, range miss)
    //   m3: variants m3-a (valid, correct, exact) and m3-b (invalid, row not-measured, range not-applicable)
    // Oracle: rows sorted by `scanner/case/method/variant`.localeCompare, so group[0] is
    // m2-a (invalid) and m3-a (valid). type-miss-rate:
    //   m2: group[0].type is invalid -> notApplicable (its valid-type miss is not counted)
    //   m3: group[0] valid; groupBucket over BOTH rows: m3-b is not-measured -> notMeasured
    //   => eligible 1, measured 0, notMeasured 1, notApplicable 1, total 2, status not-measured
    // Canonical: valid-type occurrences only: m2 -> miss (numerator), m3 -> correct (other).
    let o = |ty| vec![occ("o1", ty, Sx::Sensitive)];
    let body = snapshot_body(vec![
        case(
            "m2",
            TypeValidation,
            "en",
            None,
            vec![var("m2-a", Neutral, o(I)), var("m2-b", Neutral, o(V))],
        ),
        case(
            "m3",
            TypeValidation,
            "en",
            None,
            vec![var("m3-a", Neutral, o(V)), var("m3-b", Neutral, o(I))],
        ),
    ]);
    let rows: Vec<RowSpec> = vec![
        ("m2", "m2-a", "o1", Ts::InvalidCorrect, Ss::Correct, Miss),
        ("m2", "m2-b", "o1", Ts::Miss, Ss::Miss, Miss),
        ("m3", "m3-a", "o1", Ts::Correct, Ss::Correct, Exact),
        (
            "m3",
            "m3-b",
            "o1",
            Ts::NotMeasured,
            Ss::NotMeasured,
            NotApplicable,
        ),
    ];
    let acc = run(&body, &rows);
    let overall = &acc.scanners[0].overall;
    let oracle_type_miss = counts(1, 0, 0, 0, 1, 1, 2);
    let canonical_type_miss = counts(2, 2, 1, 0, 0, 0, 2);
    assert_ne!(
        oracle_type_miss, canonical_type_miss,
        "the difference is real"
    );
    assert_eq!(
        overall.metric(MetricId::TypeMissRate).unwrap().counts,
        canonical_type_miss
    );
    // range-collateral-rate. Oracle: m2: group[0] invalid -> notApplicable; m3: group[0] valid, not
    // every range miss, a row is not-applicable -> notMeasured: counts (1, 0, 0, 0, 1, 1, 2).
    // Canonical: m2: the only valid row is a miss -> notApplicable; m3: the valid row is exact -> other:
    // eligible 1, measured 1, numerator 0, notApplicable 1.
    assert_eq!(
        overall
            .metric(MetricId::RangeCollateralRate)
            .unwrap()
            .counts,
        counts(1, 1, 0, 0, 0, 1, 2)
    );
    // Where the oracle's first row is valid and no invalid row is unmeasured the two agree:
    // sensitive-miss-rate: oracle groupBucket over the sensitive rows of the group.
    //   m2: rows m2-a (correct), m2-b (miss) -> numerator; m3: rows correct, not-measured -> notMeasured.
    // The canonical rule judges sensitivity over the same rows, so it agrees (U-equal).
    assert_eq!(
        overall.metric(MetricId::SensitiveMissRate).unwrap().counts,
        counts(2, 1, 1, 0, 1, 0, 2)
    );
}

#[test]
fn a3_a_benign_case_with_several_variants_is_one_sample() {
    // The oracle throws 'PII benign controls must be distinct authored cases'
    // (accounting.ts:315) when a benign case has more than one variant. The
    // canonical rule keeps the case as the sample: one case, two variants, one
    // sample (variants are never independent samples).
    let o = || vec![occ("o1", I, Sx::NonSensitive)];
    let body = snapshot_body(vec![case(
        "b1",
        PiiBenign,
        "en",
        None,
        vec![var("b1-a", Neutral, o()), var("b1-b", Neutral, o())],
    )]);
    let rows: Vec<RowSpec> = vec![
        ("b1", "b1-a", "o1", Ts::InvalidCorrect, Ss::Correct, Miss),
        (
            "b1",
            "b1-b",
            "o1",
            Ts::InvalidCorrect,
            Ss::FalsePositive,
            Miss,
        ),
    ];
    let acc = run(&body, &rows);
    let m = acc.scanners[0]
        .overall
        .metric(MetricId::BenignSuppressionRate)
        .unwrap();
    // One group, one sample. Oracle: any pass row -> numerator (`group.some(event)`),
    // so counts (1, 1, 1, ...). Canonical (A8, ADR 0008): variant b1-b is a false
    // positive, so the case is NOT suppressed: numerator 0.
    assert_eq!(m.counts, counts(1, 1, 0, 0, 0, 0, 1));
    assert_eq!(acc.authored.variants, 2);
}

#[test]
fn a8_all_rows_must_pass_for_benign_and_collision_unlike_the_oracle() {
    // Oracle accounting.ts:281-286: `groupBucket(group, axis, row => status === 'pass')`,
    // and groupBucket's event is `group.some(event)`. Hand evaluation, ORACLE:
    //   benign d1: variants pass + false-positive -> no review, no not-measured, some pass -> numerator
    //   collision k1: variants pass + wrong-jurisdiction -> some pass -> numerator
    // CANONICAL (A8, ADR 0008): the context metric already requires all endpoints to pass
    // (accounting.ts:272); benign and collision now do too, so each case has a failing
    // row and lands in `other`, not in the numerator.
    let body = snapshot_body(vec![
        case(
            "d1",
            PiiBenign,
            "en",
            None,
            vec![
                var("d1-a", Neutral, vec![occ("o1", I, Sx::NonSensitive)]),
                var("d1-b", Neutral, vec![occ("o1", I, Sx::NonSensitive)]),
            ],
        ),
        case(
            "k1",
            JurisdictionCollision,
            "en",
            Some("US"),
            vec![
                var("k1-a", Neutral, vec![occ("o1", V, Sx::Sensitive)]),
                var("k1-b", Neutral, vec![occ("o1", V, Sx::Sensitive)]),
            ],
        ),
    ]);
    let rows: Vec<RowSpec> = vec![
        ("d1", "d1-a", "o1", Ts::InvalidCorrect, Ss::Correct, Miss),
        (
            "d1",
            "d1-b",
            "o1",
            Ts::InvalidCorrect,
            Ss::FalsePositive,
            Miss,
        ),
        ("k1", "k1-a", "o1", Ts::Correct, Ss::Correct, Exact),
        (
            "k1",
            "k1-b",
            "o1",
            Ts::WrongJurisdiction,
            Ss::Correct,
            Exact,
        ),
    ];
    let acc = run(&body, &rows);
    let o = &acc.scanners[0].overall;
    // Oracle: (1, 1, 1, 0, 0, 1, 2) for both. Canonical: numerator 0.
    assert_eq!(
        o.metric(MetricId::BenignSuppressionRate).unwrap().counts,
        counts(1, 1, 0, 0, 0, 1, 2)
    );
    assert_eq!(
        o.metric(MetricId::JurisdictionCollisionRate)
            .unwrap()
            .counts,
        counts(1, 1, 0, 0, 0, 1, 2)
    );
}

#[test]
fn wrong_jurisdiction_population_equals_the_oracles_scope_test() {
    // Oracle accounting.ts:276 gates on `scope.startsWith('jurisdiction:')`, and validateRow
    // (lines 190-193) ties scope to the family scope (global <-> `pii:global:*`, jurisdiction XX
    // <-> `pii:xx:*`). The contracts tie `case.jurisdiction` to the family scope the same way
    // (`family-scope-mismatch`), so `case.jurisdiction.is_some()` is the same predicate.
    //   j1 (US, valid, wrong-jurisdiction) -> eligible, numerator
    //   g1 (global, valid, correct)        -> not-applicable
    let body = snapshot_body(vec![
        case(
            "g1",
            TypeValidation,
            "en",
            None,
            vec![var("g1-v", Neutral, vec![occ("o1", V, Sx::Sensitive)])],
        ),
        case(
            "j1",
            TypeValidation,
            "en",
            Some("US"),
            vec![var("j1-v", Neutral, vec![occ("o1", V, Sx::Sensitive)])],
        ),
    ]);
    let rows: Vec<RowSpec> = vec![
        ("g1", "g1-v", "o1", Ts::Correct, Ss::Correct, Exact),
        (
            "j1",
            "j1-v",
            "o1",
            Ts::WrongJurisdiction,
            Ss::Correct,
            Exact,
        ),
    ];
    let acc = run(&body, &rows);
    assert_eq!(
        acc.scanners[0]
            .overall
            .metric(MetricId::WrongJurisdictionRate)
            .unwrap()
            .counts,
        counts(1, 1, 1, 0, 0, 1, 2)
    );
}
