//! `legacy-accounting`: the oracle's metric accounting, reproduced as a named
//! compatibility mode with switchable quirks.
//!
//! Source: `buildAccounting`, `metricBuckets` and `groupBucket` in
//! `benchmarks/evaluation/domains/pii/accounting.ts` and `proportion` / `wilson`
//! in `benchmarks/accounting/shared/primitives.ts` at oracle commit
//! `4b846967346505baca11e0b98cab1475fbce6773`. It is a port, quirks included, and
//! is checked against the oracle's own output by the parity suite
//! (`crates/pii-eval-cli/tests/oracle_parity.rs`), not by hand alone.
//!
//! Unlike the canonical accounting, this mode uses binary64 arithmetic: the
//! oracle computes in IEEE-754 doubles and rounds with `Number.prototype.toFixed`,
//! which is reproduced exactly by [`to_fixed_mantissa`]. Floating point is
//! confined to this removable crate; the contracts and the kernel have none.
//!
//! The oracle behaviors that the canonical accounting changed are three
//! switches, so that a difference between the two can be attributed by flipping
//! one switch at a time ([`Quirks`]):
//!
//! * `a2_first_row`: eligibility for the valid-type metrics comes from the first
//!   row of a case group (variants ordered by id) and all rows are judged
//!   (ADR 0005 A2); the canonical rule judges the valid-type rows.
//! * `a3_benign_distinct`: a benign case with several variants is an error
//!   (ADR 0005 A3); the canonical rule counts one sample.
//! * `a8_any_row`: benign and collision cases count when ANY row passes
//!   (ADR 0005 A8, revised by ADR 0008 R3); the canonical rule requires ALL.
//!
//! Variant ids and case ids are compared byte-wise. The oracle sorts with
//! `localeCompare`; for identifiers over `[a-z0-9-]` (the only ones the parity
//! input uses) ICU orders hyphen, digits and lowercase letters in byte order.

use std::collections::BTreeMap;

use pii_eval_contracts::{
    AxisStatus, BoundDirection, ContextClass, ExpectedType, METRICS, MethodId, MetricCounts,
    MetricId, MetricStatus, RangeState, SensitivityExpectation, SensitivityState, TypeState,
};

/// Identifier of this compatibility mode.
pub const LEGACY_ACCOUNTING_RULE_ID: &str = "legacy-accounting";

/// The oracle behaviors the canonical accounting changed. `true` is the oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quirks {
    /// A2: eligibility from the first row of the group; all rows judged.
    pub a2_first_row: bool,
    /// A3: a benign case with several variants is an error.
    pub a3_benign_distinct: bool,
    /// A8: benign and collision cases count when any row passes.
    pub a8_any_row: bool,
}

impl Quirks {
    /// Exactly the oracle.
    pub const ORACLE: Quirks = Quirks {
        a2_first_row: true,
        a3_benign_distinct: true,
        a8_any_row: true,
    };

    /// The oracle with the given quirks switched to the canonical behavior.
    pub const fn with_canonical(self, a2: bool, a3: bool, a8: bool) -> Quirks {
        Quirks {
            a2_first_row: self.a2_first_row && !a2,
            a3_benign_distinct: self.a3_benign_distinct && !a3,
            a8_any_row: self.a8_any_row && !a8,
        }
    }
}

/// One outcome row as the oracle's accounting reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyRow {
    /// Authored case id.
    pub case_id: String,
    /// The case's method.
    pub method: MethodId,
    /// Variant id (slot).
    pub variant: String,
    /// The case is jurisdictional (the oracle's `scope` starts with `jurisdiction:`).
    pub jurisdictional: bool,
    /// Authored type expectation.
    pub expected_type: ExpectedType,
    /// Authored sensitivity expectation.
    pub sensitivity: SensitivityExpectation,
    /// Authored context class of the variant.
    pub context_class: ContextClass,
    /// Observed type state.
    pub type_state: TypeState,
    /// Observed sensitivity state.
    pub sensitivity_state: SensitivityState,
    /// Observed range state.
    pub range: RangeState,
}

/// The oracle's `MechanicalAccountingConfig` (without `replays`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LegacyMechanics {
    /// Smallest effective N for which a value is published.
    pub min_denominator: u64,
    /// Wilson z value (a binary64 number, as in the oracle).
    pub interval_z: f64,
    /// Decimal places of published values.
    pub interval_precision: u32,
}

impl LegacyMechanics {
    /// `qualification/pii-v1.json`: 4, 1.96, 6.
    pub const PII_V1: LegacyMechanics = LegacyMechanics {
        min_denominator: 4,
        interval_z: 1.96,
        interval_precision: 6,
    };
}

/// The oracle's `MechanicalPublished`, with decimals as integer mantissas at
/// `precision` places (the oracle's `Number(value.toFixed(precision))`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyRate {
    /// `null`: zero denominator.
    Null,
    /// `'insufficient-evidence'`.
    InsufficientEvidence,
    /// A published value.
    Value {
        /// Point estimate mantissa.
        point: u64,
        /// Wilson endpoint mantissa.
        bound: u64,
        /// Decimal places of both mantissas.
        precision: u32,
        /// The oracle's `n`.
        n: u64,
        /// The reported side.
        direction: BoundDirection,
    },
}

/// One metric as the oracle reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyMetric {
    /// Bucket counts.
    pub counts: MetricCounts,
    /// Status derived from the counts.
    pub status: MetricStatus,
    /// Effective N.
    pub effective_n: u64,
    /// The published rate.
    pub rate: LegacyRate,
}

/// Why the oracle's accounting refuses its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyAccountError {
    /// `PII benign controls must be distinct authored cases`.
    BenignControlsNotDistinct,
}

/// The oracle's `Number.prototype.toFixed(places)` of a value in `[0, 1]`, as the
/// integer `n` with `n / 10^places` closest to the exact value of the binary64
/// number; an exact tie takes the larger `n` (ECMA-262 Number::toFixed).
pub fn to_fixed_mantissa(x: f64, places: u32) -> u64 {
    assert!(x.is_finite() && (0.0..=1.0).contains(&x) && places <= 12);
    if x == 0.0 {
        return 0;
    }
    let bits = x.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);
    let (mantissa, e) = if exponent == 0 {
        (fraction, -1074)
    } else {
        (fraction | (1u64 << 52), exponent - 1075)
    };
    // x = mantissa * 2^e with e <= -52 because x <= 1.
    let scaled = u128::from(mantissa) * 10u128.pow(places);
    let shift = (-e) as u32;
    if shift >= 127 {
        return 0;
    }
    let half = 1u128 << (shift - 1);
    ((scaled + half) >> shift) as u64
}

/// The oracle's `wilson` (pessimistic side), in the same operation order.
fn wilson(p: f64, n: f64, direction: BoundDirection, mechanics: &LegacyMechanics) -> u64 {
    let z = mechanics.interval_z;
    let scale = 1.0 + (z * z) / n;
    let centre = (p + (z * z) / (2.0 * n)) / scale;
    let spread = (z / scale) * ((p * (1.0 - p)) / n + (z * z) / (4.0 * n * n)).sqrt();
    let value = match direction {
        BoundDirection::Upper => centre + spread,
        BoundDirection::Lower => centre - spread,
    };
    // `Math.min(1, Math.max(0, value))`.
    to_fixed_mantissa(value.clamp(0.0, 1.0), mechanics.interval_precision)
}

/// The oracle's `proportion(numerator, denominator, direction, config)`.
pub fn proportion(
    numerator: u64,
    denominator: u64,
    direction: BoundDirection,
    mechanics: &LegacyMechanics,
) -> LegacyRate {
    if denominator == 0 {
        return LegacyRate::Null;
    }
    if denominator < mechanics.min_denominator {
        return LegacyRate::InsufficientEvidence;
    }
    let point = numerator as f64 / denominator as f64;
    LegacyRate::Value {
        point: to_fixed_mantissa(point, mechanics.interval_precision),
        bound: wilson(point, denominator as f64, direction, mechanics),
        precision: mechanics.interval_precision,
        n: denominator,
        direction,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Numerator,
    Other,
    Unresolved,
    NotMeasured,
    NotApplicable,
}

#[derive(Clone, Copy)]
enum Axis {
    Type,
    Sensitivity,
}

fn status(row: &LegacyRow, axis: Axis) -> AxisStatus {
    match axis {
        Axis::Type => row.type_state.status(),
        Axis::Sensitivity => row.sensitivity_state.status(),
    }
}

/// The oracle's `groupBucket`. `any_row` selects `group.some(event)` (the oracle)
/// or `group.every(event)` for the numerator decision.
fn group_bucket(
    rows: &[&LegacyRow],
    axis: Axis,
    any_row: bool,
    event: impl Fn(&LegacyRow) -> bool,
) -> Bucket {
    if rows
        .iter()
        .any(|r| status(r, axis) == AxisStatus::ReviewRequired)
    {
        Bucket::Unresolved
    } else if rows
        .iter()
        .any(|r| status(r, axis) == AxisStatus::NotMeasured)
    {
        Bucket::NotMeasured
    } else if if any_row {
        rows.iter().any(|r| event(r))
    } else {
        rows.iter().all(|r| event(r))
    } {
        Bucket::Numerator
    } else {
        Bucket::Other
    }
}

fn counts_of(buckets: &[Bucket]) -> MetricCounts {
    let n = |b: Bucket| buckets.iter().filter(|x| **x == b).count() as u64;
    MetricCounts {
        eligible: buckets.len() as u64 - n(Bucket::NotApplicable),
        measured: n(Bucket::Numerator) + n(Bucket::Other),
        numerator: n(Bucket::Numerator),
        unresolved: n(Bucket::Unresolved),
        not_measured: n(Bucket::NotMeasured),
        not_applicable: n(Bucket::NotApplicable),
        total: buckets.len() as u64,
    }
}

fn metric_of(
    buckets: &[Bucket],
    direction: BoundDirection,
    eligible_basis: bool,
    mechanics: &LegacyMechanics,
) -> LegacyMetric {
    let counts = counts_of(buckets);
    let status = if counts.eligible == 0 {
        MetricStatus::NotApplicable
    } else if counts.measured == 0 {
        if counts.unresolved > 0 {
            MetricStatus::Unresolved
        } else {
            MetricStatus::NotMeasured
        }
    } else if counts.unresolved > 0 || counts.not_measured > 0 {
        MetricStatus::Partial
    } else {
        MetricStatus::Measured
    };
    let effective_n = if eligible_basis {
        counts.eligible
    } else {
        counts.measured
    };
    LegacyMetric {
        counts,
        status,
        effective_n,
        rate: proportion(counts.numerator, effective_n, direction, mechanics),
    }
}

/// The ten metrics of one scanner's rows, in the registry order, as the oracle
/// computes them (`buildAccounting`), with the given quirks.
pub fn account_rows(
    rows: &[LegacyRow],
    mechanics: &LegacyMechanics,
    quirks: Quirks,
) -> Result<Vec<(MetricId, LegacyMetric)>, LegacyAccountError> {
    let mut sorted: Vec<&LegacyRow> = rows.iter().collect();
    sorted.sort_by(|a, b| {
        (a.case_id.as_str(), a.method.as_str(), a.variant.as_str()).cmp(&(
            b.case_id.as_str(),
            b.method.as_str(),
            b.variant.as_str(),
        ))
    });
    if quirks.a3_benign_distinct {
        let benign: Vec<&&LegacyRow> = sorted
            .iter()
            .filter(|r| r.method == MethodId::PiiBenign)
            .collect();
        let mut cases: Vec<&str> = benign.iter().map(|r| r.case_id.as_str()).collect();
        cases.dedup();
        if cases.len() != benign.len() {
            return Err(LegacyAccountError::BenignControlsNotDistinct);
        }
    }
    let mut groups: BTreeMap<(&str, &str), Vec<&LegacyRow>> = BTreeMap::new();
    for row in &sorted {
        groups
            .entry((row.case_id.as_str(), row.method.as_str()))
            .or_default()
            .push(row);
    }
    let groups: Vec<&Vec<&LegacyRow>> = groups.values().collect();

    // Rows a valid-type metric judges, and whether the group belongs to it.
    fn view<'a>(g: &[&'a LegacyRow], first_row: bool) -> Option<Vec<&'a LegacyRow>> {
        if first_row {
            (g[0].expected_type == ExpectedType::Valid).then(|| g.to_vec())
        } else {
            let valid: Vec<&LegacyRow> = g
                .iter()
                .copied()
                .filter(|r| r.expected_type == ExpectedType::Valid)
                .collect();
            (!valid.is_empty()).then_some(valid)
        }
    }
    let first_row = quirks.a2_first_row;
    let type_metric = |event: fn(&LegacyRow) -> bool, juris: bool| -> Vec<Bucket> {
        groups
            .iter()
            .map(|g| match view(g, first_row) {
                Some(view) if !juris || g[0].jurisdictional => {
                    group_bucket(&view, Axis::Type, true, event)
                }
                _ => Bucket::NotApplicable,
            })
            .collect()
    };
    let sensitivity_metric = |expected: SensitivityExpectation, event: fn(&LegacyRow) -> bool| {
        groups
            .iter()
            .map(|g| {
                let eligible: Vec<&LegacyRow> = g
                    .iter()
                    .copied()
                    .filter(|r| r.sensitivity == expected)
                    .collect();
                if eligible.is_empty() {
                    Bucket::NotApplicable
                } else {
                    group_bucket(&eligible, Axis::Sensitivity, true, event)
                }
            })
            .collect::<Vec<_>>()
    };
    let context: Vec<Bucket> = groups
        .iter()
        .filter(|g| g[0].method == MethodId::ContextDiscrimination)
        .map(|g| {
            let endpoints: Vec<&&LegacyRow> = g
                .iter()
                .filter(|r| r.context_class != ContextClass::Neutral)
                .collect();
            if endpoints
                .iter()
                .any(|r| r.sensitivity_state.status() == AxisStatus::ReviewRequired)
            {
                Bucket::Unresolved
            } else if endpoints
                .iter()
                .any(|r| r.sensitivity_state.status() == AxisStatus::NotMeasured)
            {
                Bucket::NotMeasured
            } else if endpoints
                .iter()
                .all(|r| r.sensitivity_state.status() == AxisStatus::Pass)
            {
                Bucket::Numerator
            } else {
                Bucket::Other
            }
        })
        .collect();
    let benign: Vec<Bucket> = groups
        .iter()
        .map(|g| {
            if g[0].method != MethodId::PiiBenign {
                Bucket::NotApplicable
            } else {
                group_bucket(g, Axis::Sensitivity, quirks.a8_any_row, |r| {
                    r.sensitivity_state.status() == AxisStatus::Pass
                })
            }
        })
        .collect();
    let collision: Vec<Bucket> = groups
        .iter()
        .map(|g| {
            if g[0].method != MethodId::JurisdictionCollision {
                Bucket::NotApplicable
            } else {
                group_bucket(g, Axis::Type, quirks.a8_any_row, |r| {
                    r.type_state.status() == AxisStatus::Pass
                })
            }
        })
        .collect();
    let range: Vec<Bucket> = groups
        .iter()
        .map(|g| match view(g, first_row) {
            Some(view) if !view.iter().all(|r| r.range == RangeState::Miss) => {
                if view.iter().any(|r| r.range == RangeState::NotApplicable) {
                    Bucket::NotMeasured
                } else if view
                    .iter()
                    .any(|r| matches!(r.range, RangeState::Overbroad | RangeState::Partial))
                {
                    Bucket::Numerator
                } else {
                    Bucket::Other
                }
            }
            _ => Bucket::NotApplicable,
        })
        .collect();
    let share: Vec<Bucket> = groups
        .iter()
        .flat_map(|g| {
            let type_axis = group_bucket(g, Axis::Type, true, |_| true);
            let sensitivity_axis = if g
                .iter()
                .any(|r| r.sensitivity == SensitivityExpectation::NotEstablished)
            {
                Bucket::Unresolved
            } else {
                group_bucket(g, Axis::Sensitivity, true, |_| true)
            };
            [type_axis, sensitivity_axis]
        })
        .collect();

    let mut out = Vec::with_capacity(METRICS.len());
    for definition in &METRICS {
        let (buckets, eligible_basis) = match definition.id {
            MetricId::TypeMissRate => (
                type_metric(|r| r.type_state == TypeState::Miss, false),
                false,
            ),
            MetricId::WrongFamilyRate => (
                type_metric(|r| r.type_state == TypeState::WrongFamily, false),
                false,
            ),
            MetricId::WrongJurisdictionRate => (
                type_metric(|r| r.type_state == TypeState::WrongJurisdiction, true),
                false,
            ),
            MetricId::SensitiveMissRate => (
                sensitivity_metric(SensitivityExpectation::Sensitive, |r| {
                    r.sensitivity_state == SensitivityState::Miss
                }),
                false,
            ),
            MetricId::NonSensitiveFlagRate => (
                sensitivity_metric(SensitivityExpectation::NonSensitive, |r| {
                    r.sensitivity_state == SensitivityState::FalsePositive
                }),
                false,
            ),
            MetricId::ContextDiscriminationRate => (context.clone(), false),
            MetricId::BenignSuppressionRate => (benign.clone(), false),
            MetricId::JurisdictionCollisionRate => (collision.clone(), false),
            MetricId::RangeCollateralRate => (range.clone(), false),
            MetricId::MeasurableShare => (share.clone(), true),
        };
        out.push((
            definition.id,
            metric_of(&buckets, definition.direction, eligible_basis, mechanics),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_fixed_reproduces_javascript_on_ties_and_binary64_representation() {
        // (0.0078125).toFixed(6) === '0.007813': an exact tie takes the larger n.
        assert_eq!(to_fixed_mantissa(1.0 / 128.0, 6), 7_813);
        // (0.15).toFixed(1) === '0.1' and (0.35).toFixed(1) === '0.3': the binary64
        // value is just below the decimal tie (ADR 0005, S1).
        assert_eq!(to_fixed_mantissa(0.15, 1), 1);
        assert_eq!(to_fixed_mantissa(0.35, 1), 3);
        assert_eq!(to_fixed_mantissa(0.0, 6), 0);
        assert_eq!(to_fixed_mantissa(1.0, 6), 1_000_000);
        assert_eq!(to_fixed_mantissa(0.5, 6), 500_000);
        assert_eq!(to_fixed_mantissa(1.0 / 3.0, 6), 333_333);
        assert_eq!(to_fixed_mantissa(2.0 / 3.0, 6), 666_667);
        assert_eq!(to_fixed_mantissa(f64::MIN_POSITIVE, 12), 0);
        assert_eq!(to_fixed_mantissa(5e-324, 12), 0);
    }

    #[test]
    fn proportion_has_the_oracles_three_states() {
        let m = LegacyMechanics::PII_V1;
        assert_eq!(
            proportion(0, 0, BoundDirection::Upper, &m),
            LegacyRate::Null
        );
        assert_eq!(
            proportion(1, 3, BoundDirection::Upper, &m),
            LegacyRate::InsufficientEvidence
        );
        // 1 of 4, upper: the P4 oracle vector (point 0.25, bound 0.699364).
        assert_eq!(
            proportion(1, 4, BoundDirection::Upper, &m),
            LegacyRate::Value {
                point: 250_000,
                bound: 699_364,
                precision: 6,
                n: 4,
                direction: BoundDirection::Upper
            }
        );
    }

    fn row(case: &str, method: MethodId, variant: &str, expected: ExpectedType) -> LegacyRow {
        LegacyRow {
            case_id: case.to_owned(),
            method,
            variant: variant.to_owned(),
            jurisdictional: false,
            expected_type: expected,
            sensitivity: SensitivityExpectation::Sensitive,
            context_class: ContextClass::Neutral,
            type_state: TypeState::Correct,
            sensitivity_state: SensitivityState::Correct,
            range: RangeState::Exact,
        }
    }

    #[test]
    fn a3_benign_with_two_variants_is_an_error_only_under_the_oracle_quirk() {
        let rows = vec![
            row("b1", MethodId::PiiBenign, "v1", ExpectedType::Invalid),
            row("b1", MethodId::PiiBenign, "v2", ExpectedType::Invalid),
        ];
        let m = LegacyMechanics::PII_V1;
        assert_eq!(
            account_rows(&rows, &m, Quirks::ORACLE),
            Err(LegacyAccountError::BenignControlsNotDistinct)
        );
        assert!(account_rows(&rows, &m, Quirks::ORACLE.with_canonical(false, true, false)).is_ok());
    }

    #[test]
    fn a8_switch_changes_only_the_pass_metrics() {
        let mut r1 = row(
            "c1",
            MethodId::JurisdictionCollision,
            "v1",
            ExpectedType::Valid,
        );
        let mut r2 = r1.clone();
        r2.variant = "v2".to_owned();
        r2.type_state = TypeState::WrongJurisdiction;
        r1.jurisdictional = true;
        r2.jurisdictional = true;
        let rows = vec![r1, r2];
        let m = LegacyMechanics::PII_V1;
        let oracle = account_rows(&rows, &m, Quirks::ORACLE).unwrap();
        let canonical =
            account_rows(&rows, &m, Quirks::ORACLE.with_canonical(false, false, true)).unwrap();
        let get = |v: &[(MetricId, LegacyMetric)], id| v.iter().find(|(i, _)| *i == id).unwrap().1;
        assert_eq!(
            get(&oracle, MetricId::JurisdictionCollisionRate)
                .counts
                .numerator,
            1
        );
        assert_eq!(
            get(&canonical, MetricId::JurisdictionCollisionRate)
                .counts
                .numerator,
            0
        );
        assert_eq!(
            get(&oracle, MetricId::TypeMissRate),
            get(&canonical, MetricId::TypeMissRate)
        );
    }
}
