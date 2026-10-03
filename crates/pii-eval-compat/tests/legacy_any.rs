//! A8 made executable: the oracle's "any row passes" rule applied to the
//! hand-derived vector of `pii-eval-kernel/tests/a8_all_rows.rs` gives 3 of 4
//! (point 0.75, lower bound 0.300636), where the canonical "all rows pass"
//! rule gives 2 of 4 (0.5, 0.150036).

use pii_eval_compat::legacy::legacy_any_row_passes;
use pii_eval_contracts::{BoundDirection, Mechanics, MetricValue, ScaledDecimal};
use pii_eval_kernel::published_value;

const CASES: [&[bool]; 4] = [
    &[true, true],
    &[true, false],
    &[false, false],
    &[true, true, true],
];

#[test]
fn the_oracle_counts_three_of_four_where_the_canonical_rule_counts_two() {
    let any = CASES.iter().filter(|c| legacy_any_row_passes(c)).count() as u64;
    let all = CASES.iter().filter(|c| c.iter().all(|p| *p)).count() as u64;
    assert_eq!((any, all), (3, 2));
    let value = |n: u64, bound: u64| MetricValue::Measured {
        point: ScaledDecimal::new(if n == 3 { 75 } else { 5 }, if n == 3 { 2 } else { 1 }).unwrap(),
        bound: ScaledDecimal::new(bound, 6).unwrap(),
    };
    let dir = BoundDirection::Lower;
    assert_eq!(
        published_value(any, 4, dir, &Mechanics::PII_V1).unwrap(),
        value(3, 300_636)
    );
    assert_eq!(
        published_value(all, 4, dir, &Mechanics::PII_V1).unwrap(),
        value(2, 150_036)
    );
}
