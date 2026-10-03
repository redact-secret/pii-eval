//! Versioned PII metric statistics: point estimate, Wilson interval endpoint,
//! decimal rounding, zero-denominator and minimum-denominator behavior.
//!
//! Identity: [`STATS_RULE_ID`] `pii-v1-wilson-exact`, [`STATS_REVISION`] 1.
//! Specified in `docs/adr/0005-indexed-accounting-and-metric-statistics.md`.
//!
//! # Deterministic computation
//!
//! Contracts carry no floating-point numbers, so published values are
//! [`ScaledDecimal`]s (integer mantissa and scale). This module does not use
//! `f64` at all. Both the point estimate and the Wilson endpoint are computed
//! with exact integer arithmetic and rounded **once**, half up, to
//! `interval_precision` decimal places:
//!
//! * point: `round_half_up(k / n)`, an exact rational;
//! * endpoint: with `p = k / n` and `z = zm / 10^zs`,
//!   `(2k + z^2 +- z * sqrt(z^2 + 4k(n - k) / n)) / (2 (n + z^2))`, evaluated
//!   as an exact rational plus one irrational term and rounded by integer
//!   square root. The result is the correctly rounded (half up) decimal of the
//!   mathematical value for every input, on every host. The only inexactness
//!   is the one rounding step; nothing is accumulated or re-rounded.
//!
//! Counts, `z` and precision stay available unrounded in the accounting
//! output, so a consumer can recompute or re-round under another declared
//! precision.
//!
//! The legacy oracle computes the same formulas in IEEE-754 binary64 and then
//! rounds with `Number(value.toFixed(precision))`. The two agree except where a
//! binary64 value falls on the other side of a rounding boundary than the exact
//! value (for example the exact tie `3/20` at one decimal place). See ADR 0005
//! (compatibility, difference S1) and `crates/pii-eval-compat/tests/accounting_oracle.rs`.
//!
//! # Domain
//!
//! Any numerator and effective N up to the contract limit (2^53 - 1), z up to a
//! 2^53 - 1 mantissa at scale 12 and precision 1 to 12 fit in 512 bits (the
//! largest intermediate is below 10^129 against a capacity of about 10^154). Each
//! step is nevertheless checked and an overflow is reported as
//! [`StatsError::Overflow`].

use pii_eval_contracts::{
    BoundDirection, Mechanics, MetricValue, ScaledDecimal, WithheldReason,
    decimal::MAX_DECIMAL_SCALE,
};

use crate::bigint::U512;

/// Identifier of the statistics rule (point, Wilson endpoint, rounding).
pub const STATS_RULE_ID: &str = "pii-v1-wilson-exact";

/// Revision of the statistics rule. Part of protocol revision 2
/// (ADR 0005, bound by ADR 0008); the legacy oracle's binary64 variant is revision 1 semantics.
pub const STATS_REVISION: u32 = 1;

/// Why a statistic could not be computed. Numeric payloads only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsError {
    /// The numerator exceeds the denominator, or the denominator is zero where
    /// one is required.
    InvalidCounts {
        /// Numerator.
        numerator: u64,
        /// Denominator.
        denominator: u64,
    },
    /// Precision outside 1 to 12, or z not a positive normalized decimal.
    InvalidMechanics,
    /// A checked intermediate overflowed 512 bits (unreachable for in-contract inputs).
    Overflow,
}

fn check_precision(precision: u8) -> Result<(), StatsError> {
    if (1..=12).contains(&precision) {
        Ok(())
    } else {
        Err(StatsError::InvalidMechanics)
    }
}

/// `round_half_up(numerator / denominator * 10^precision)` as an integer.
pub fn round_ratio(numerator: u64, denominator: u64, precision: u8) -> Result<u64, StatsError> {
    check_precision(precision)?;
    if denominator == 0 || numerator > denominator {
        return Err(StatsError::InvalidCounts {
            numerator,
            denominator,
        });
    }
    let scale = 10u128.pow(u32::from(precision));
    // numerator * 10^12 < 2^53 * 10^12 < 2^113: fits u128.
    let top = u128::from(numerator) * scale * 2 + u128::from(denominator);
    let m = top / (u128::from(denominator) * 2);
    u64::try_from(m).map_err(|_| StatsError::Overflow)
}

/// The Wilson interval endpoint, rounded half up to `precision` decimal places,
/// as an integer mantissa (value `mantissa / 10^precision`, in `[0, 10^precision]`).
///
/// `Upper` returns the upper endpoint and `Lower` the lower one.
pub fn wilson_mantissa(
    numerator: u64,
    n: u64,
    direction: BoundDirection,
    z: ScaledDecimal,
    precision: u8,
) -> Result<u64, StatsError> {
    check_precision(precision)?;
    if n == 0 || numerator > n {
        return Err(StatsError::InvalidCounts {
            numerator,
            denominator: n,
        });
    }
    if z.mantissa == 0 || z.scale > MAX_DECIMAL_SCALE {
        return Err(StatsError::InvalidMechanics);
    }
    let k = numerator;
    let ovf = StatsError::Overflow;

    // Scale everything by Z^2 (Z = 10^zs) so that only integers remain:
    //   A = 2 k Z^2 + zm^2            numerator rational part
    //   D = 2 (n Z^2 + zm^2)          denominator
    //   Q = zm^2 (zm^2 n + 4k(n-k) Z^2)   so that z-term * Z^2 = sqrt(Q / n)
    //   bound = (A n +- sqrt(Q n)) / (D n)
    let big_z = U512::pow10(u32::from(z.scale)).ok_or(ovf)?;
    let z2 = big_z.checked_mul(&big_z).ok_or(ovf)?;
    let zm2 = U512::from_u64(z.mantissa)
        .checked_mul(&U512::from_u64(z.mantissa))
        .ok_or(ovf)?;
    let n_big = U512::from_u64(n);
    let a = U512::from_u64(k)
        .mul_u64(2)
        .and_then(|v| v.checked_mul(&z2))
        .and_then(|v| v.checked_add(&zm2))
        .ok_or(ovf)?;
    let d = n_big
        .checked_mul(&z2)
        .and_then(|v| v.checked_add(&zm2))
        .and_then(|v| v.mul_u64(2))
        .ok_or(ovf)?;
    // 4 k (n - k) < 2^108: fits u128.
    let q4 = 4 * u128::from(k) * u128::from(n - k);
    let r = zm2
        .checked_mul(&n_big)
        .and_then(|v| v.checked_add(&U512::from_u128(q4).checked_mul(&z2)?))
        .ok_or(ovf)?;
    let q = zm2.checked_mul(&r).ok_or(ovf)?;
    let w = q.checked_mul(&n_big).ok_or(ovf)?;
    let e = a.checked_mul(&n_big).ok_or(ovf)?;

    // X = floor(10^p * bound + 1/2) = floor((t E + D n +- t s) / L)
    // with t = 2 * 10^p, s = sqrt(W), L = 2 D n.
    let t = U512::pow10(u32::from(precision))
        .and_then(|v| v.mul_u64(2))
        .ok_or(ovf)?;
    let t2w = t
        .checked_mul(&t)
        .and_then(|v| v.checked_mul(&w))
        .ok_or(ovf)?;
    let root = t2w.isqrt();
    let exact = root.checked_mul(&root) == Some(t2w);
    let dn = d.checked_mul(&n_big).ok_or(ovf)?;
    let m = t
        .checked_mul(&e)
        .and_then(|v| v.checked_add(&dn))
        .ok_or(ovf)?;
    let l = dn.mul_u64(2).ok_or(ovf)?;
    let top = match direction {
        BoundDirection::Upper => m.checked_add(&root).ok_or(ovf)?,
        BoundDirection::Lower => {
            // floor((M - t s) / L) = floor((M - ceil(t s)) / L); t s >= 0 and
            // M - t s >= D n > 0 mathematically, so this cannot underflow.
            let ceil = if exact {
                root
            } else {
                root.checked_add(&U512::from_u64(1)).ok_or(ovf)?
            };
            m.checked_sub(&ceil).unwrap_or(U512::ZERO)
        }
    };
    let (quotient, _) = top.div_rem(&l).ok_or(ovf)?;
    let mantissa = quotient.to_u64().ok_or(ovf)?;
    // The interval is inside [0, 1] mathematically; clamp as the legacy rule does.
    let one = 10u64.pow(u32::from(precision));
    Ok(mantissa.min(one))
}

/// A decimal with `precision` places, normalized for the contracts.
fn decimal(mantissa: u64, precision: u8) -> Result<ScaledDecimal, StatsError> {
    ScaledDecimal::new(mantissa, precision).ok_or(StatsError::Overflow)
}

/// The published value of a metric from its unrounded counts.
///
/// * `effective_n == 0`: withheld, `zero-denominator`;
/// * `effective_n < min_denominator`: withheld, `insufficient-evidence`;
/// * otherwise the point `numerator / effective_n` and the Wilson endpoint on
///   the side `direction` names, each rounded once to `interval_precision`.
///
/// `numerator > effective_n` is an error, not a clamp.
pub fn published_value(
    numerator: u64,
    effective_n: u64,
    direction: BoundDirection,
    mechanics: &Mechanics,
) -> Result<MetricValue, StatsError> {
    if numerator > effective_n {
        return Err(StatsError::InvalidCounts {
            numerator,
            denominator: effective_n,
        });
    }
    if effective_n == 0 {
        return Ok(MetricValue::Withheld {
            reason: WithheldReason::ZeroDenominator,
        });
    }
    if effective_n < u64::from(mechanics.min_denominator) {
        return Ok(MetricValue::Withheld {
            reason: WithheldReason::InsufficientEvidence,
        });
    }
    let precision = mechanics.interval_precision;
    let point = round_ratio(numerator, effective_n, precision)?;
    let bound = wilson_mantissa(
        numerator,
        effective_n,
        direction,
        mechanics.interval_z,
        precision,
    )?;
    Ok(MetricValue::Measured {
        point: decimal(point, precision)?,
        bound: decimal(bound, precision)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const Z196: ScaledDecimal = ScaledDecimal {
        mantissa: 196,
        scale: 2,
    };

    #[test]
    fn rounding_is_half_up_on_the_exact_rational() {
        // 1/8 = 0.125 exactly: half up gives 0.13.
        assert_eq!(round_ratio(1, 8, 2), Ok(13));
        // 3/20 = 0.15 exactly: half up gives 0.2 at one place.
        assert_eq!(round_ratio(3, 20, 1), Ok(2));
        assert_eq!(round_ratio(1, 3, 6), Ok(333_333));
        assert_eq!(round_ratio(2, 3, 6), Ok(666_667));
        assert_eq!(round_ratio(0, 5, 6), Ok(0));
        assert_eq!(round_ratio(5, 5, 6), Ok(1_000_000));
        assert!(matches!(
            round_ratio(6, 5, 6),
            Err(StatsError::InvalidCounts { .. })
        ));
        assert!(matches!(
            round_ratio(0, 0, 6),
            Err(StatsError::InvalidCounts { .. })
        ));
        assert_eq!(round_ratio(1, 2, 0), Err(StatsError::InvalidMechanics));
        assert_eq!(round_ratio(1, 2, 13), Err(StatsError::InvalidMechanics));
    }

    #[test]
    fn wilson_exact_edge_cases_have_closed_forms() {
        // k = 0: lower endpoint is exactly 0 (z^2 - z*sqrt(z^2) = 0).
        assert_eq!(wilson_mantissa(0, 4, BoundDirection::Lower, Z196, 6), Ok(0));
        // k = n: upper endpoint is exactly 1.
        assert_eq!(
            wilson_mantissa(4, 4, BoundDirection::Upper, Z196, 6),
            Ok(1_000_000)
        );
    }

    #[test]
    fn wilson_matches_a_hand_computed_value() {
        // k=1, n=4, z=1.96: the textbook 95% Wilson interval of 1/4 is about
        // (0.0456, 0.6994). The six-place values below come from the independent
        // decimal reference (tests/vectors/wilson_reference.py), not from this code.
        let upper = wilson_mantissa(1, 4, BoundDirection::Upper, Z196, 6).unwrap();
        assert_eq!(upper, 699_364);
        let lower = wilson_mantissa(1, 4, BoundDirection::Lower, Z196, 6).unwrap();
        assert_eq!(lower, 45_586);
    }

    #[test]
    fn extreme_in_contract_inputs_do_not_overflow() {
        let max = (1u64 << 53) - 1;
        let big_z = ScaledDecimal {
            mantissa: max,
            scale: 12,
        };
        for k in [0, 1, max / 2, max - 1, max] {
            for dir in [BoundDirection::Upper, BoundDirection::Lower] {
                let v = wilson_mantissa(k, max, dir, big_z, 12).unwrap();
                assert!(v <= 1_000_000_000_000);
                let v = wilson_mantissa(k, max, dir, Z196, 12).unwrap();
                assert!(v <= 1_000_000_000_000);
            }
        }
    }

    #[test]
    fn invalid_mechanics_and_counts_are_errors_not_panics() {
        let zero = ScaledDecimal::ZERO;
        assert_eq!(
            wilson_mantissa(1, 4, BoundDirection::Upper, zero, 6),
            Err(StatsError::InvalidMechanics)
        );
        assert!(matches!(
            wilson_mantissa(5, 4, BoundDirection::Upper, Z196, 6),
            Err(StatsError::InvalidCounts { .. })
        ));
        assert!(matches!(
            wilson_mantissa(0, 0, BoundDirection::Upper, Z196, 6),
            Err(StatsError::InvalidCounts { .. })
        ));
    }

    #[test]
    fn published_value_states() {
        let m = Mechanics::PII_V1;
        assert_eq!(
            published_value(0, 0, BoundDirection::Upper, &m),
            Ok(MetricValue::Withheld {
                reason: WithheldReason::ZeroDenominator
            })
        );
        assert_eq!(
            published_value(1, 3, BoundDirection::Upper, &m),
            Ok(MetricValue::Withheld {
                reason: WithheldReason::InsufficientEvidence
            })
        );
        assert!(matches!(
            published_value(1, 4, BoundDirection::Upper, &m),
            Ok(MetricValue::Measured { .. })
        ));
        assert!(matches!(
            published_value(5, 4, BoundDirection::Upper, &m),
            Err(StatsError::InvalidCounts { .. })
        ));
    }
}
