//! Complexity and memory growth of accounting, measured as deterministic work
//! and element-count state, not as time.
//!
//! Method: build synthetic populations of 1000, 2000 and 4000 authored cases
//! (three variants of one occurrence each) for one and for three scanners,
//! account them, and read the pass's own counters (`ResourceUse`):
//! `rows_visited` (each outcome row read), `group_visits` ((scanner, case)
//! groups classified) and `state_bytes` (the per-run state the pass allocates:
//! group flag words, the duplicate bitset, found counters and the tallies, as
//! element counts times element sizes; the input and the output are excluded).
//! Doubling the population must double the work and must grow the state by the
//! group and row terms only, because the tally term depends on the number of
//! strata, not on the number of cases. This is an element-count model, not an
//! RSS measurement; no wall-clock or speed claim is made or asserted. The
//! limits that bound the worst case are asserted at the end.

mod acct_common;

use acct_common::*;
use pii_eval_contracts::limits::{MAX_OUTCOMES, MAX_SCANNERS};
use pii_eval_contracts::{
    ContextClass, CorpusSnapshotBody, ExpectedType, Mechanics, MethodId, RangeState, ScannerStatus,
    SensitivityExpectation, SensitivityState, TypeState,
};
use pii_eval_kernel::{AuthoredIndex, OutcomeRef, ResourceUse, ScannerInput, account};

fn population(cases: usize) -> CorpusSnapshotBody {
    snapshot_body(
        (0..cases)
            .map(|c| {
                case(
                    &format!("case-{c:05}"),
                    MethodId::TypeValidation,
                    ["en", "ko"][c % 2],
                    None,
                    (0..3)
                        .map(|v| {
                            var(
                                &format!("case-{c:05}-v{v}"),
                                ContextClass::Neutral,
                                vec![occ(
                                    "o1",
                                    ExpectedType::Valid,
                                    SensitivityExpectation::Sensitive,
                                )],
                            )
                        })
                        .collect(),
                )
            })
            .collect(),
    )
}

fn measure(cases: usize, scanners: usize) -> (ResourceUse, u64) {
    let body = population(cases);
    let index = AuthoredIndex::new(&body).unwrap();
    let ids: Vec<_> = (0..scanners).map(|s| sid(&format!("scan-{s}"))).collect();
    let mut rows = Vec::new();
    for id in &ids {
        for c in &body.cases {
            for v in &c.variants {
                rows.push(outcome(
                    id.as_str(),
                    &body,
                    &(
                        c.case_id.as_str().to_owned(),
                        v.variant_id.as_str().to_owned(),
                        "o1".to_owned(),
                        TypeState::Correct,
                        SensitivityState::Correct,
                        RangeState::Exact,
                    ),
                ));
            }
        }
    }
    let inputs: Vec<_> = ids
        .iter()
        .map(|id| ScannerInput {
            id,
            status: ScannerStatus::Complete,
        })
        .collect();
    let acc = account(
        &index,
        &inputs,
        rows.iter().map(OutcomeRef::from),
        &Mechanics::PII_V1,
    )
    .unwrap();
    (acc.resources, acc.authored.occurrences)
}

#[test]
fn work_is_linear_in_rows_and_groups_and_state_grows_by_group_and_row_terms_only() {
    for scanners in [1usize, 3] {
        let results: Vec<_> = [1000usize, 2000, 4000]
            .iter()
            .map(|&c| (c, measure(c, scanners)))
            .collect();
        for (c, (r, occurrences)) in &results {
            let s = scanners as u64;
            // Each row is read exactly once and each group classified exactly once.
            assert_eq!(r.rows_visited, s * occurrences, "cases={c}");
            assert_eq!(r.group_visits, s * *c as u64, "cases={c}");
            // The state model: flag words + duplicate bitset + counters + tallies.
            let strata = 1 + 2 + 1 + 7; // overall, 2 languages, global, 7 methods
            let model =
                4 * s * *c as u64 + 8 * (s * occurrences).div_ceil(64) + 8 * s + s * strata * 640;
            assert_eq!(r.state_bytes, model, "cases={c} scanners={s}");
        }
        // Doubling the population doubles the work exactly.
        let tallies = scanners as u64 * 11 * 640;
        for pair in results.windows(2) {
            let (a, b) = (&pair[0].1.0, &pair[1].1.0);
            assert_eq!(b.rows_visited, 2 * a.rows_visited);
            assert_eq!(b.group_visits, 2 * a.group_visits);
            // The state minus the constant tally term doubles, up to the
            // per-scanner found counter (8 bytes, constant) and the rounding
            // of the bitset to whole 64-bit words (at most 8 bytes).
            let (va, vb) = (a.state_bytes - tallies, b.state_bytes - tallies);
            let slack = 8 * scanners as u64 + 8;
            assert!(vb <= 2 * va && 2 * va <= vb + slack, "{va} -> {vb}");
            assert!(b.state_bytes < 2 * a.state_bytes);
        }
    }
}

#[test]
fn the_documented_worst_case_state_is_bounded() {
    // Worst case within the explicit limits (ADR 0005): rows are bounded by
    // MAX_OUTCOMES, scanners by MAX_SCANNERS, each dimension by 1024 values.
    let rows = MAX_OUTCOMES as u64;
    let flags = 4 * rows; // at most one group per row
    let bitset = rows.div_ceil(64) * 8;
    let strata = 1 + 1024 + 1024 + 7;
    let tallies = MAX_SCANNERS as u64 * strata * 640;
    let total = flags + bitset + tallies;
    assert!(total < 128 * 1024 * 1024, "{total}");
}
