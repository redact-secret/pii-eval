//! Pins `legacy-first-overlap` exactly, quirks included.
//!
//! Expected values are hand-calculated from the oracle's `interpretPiiOutcome`
//! / `rangeOutcome` / `overlaps` (`a.start < b.end && b.start < a.end`) and the
//! layout of `A` = `"연락처: kim@example.test 입니다"` (37 bytes; the email is
//! bytes 11..27, ':' 9..10, ' ' 10..11, ' ' 27..28, the last three syllables
//! 28..37). Nothing here is a statement that the legacy behavior is right.

mod common;

use common::*;
use pii_eval_compat::legacy::{
    LEGACY_PROTOCOL_REVISION, LEGACY_RULE_ID, LegacyExpectation, LegacyScanner, interpret,
};
use pii_eval_contracts::{
    ExpectedType, FamilyId, Finding, JurisdictionCode, RangeState, ScannerStatus,
    SensitivityExpectation, SensitivityState, TypeState,
};

use SensitivityExpectation::{NonSensitive, NotEstablished, Sensitive};

#[test]
fn the_mode_is_named() {
    assert_eq!(LEGACY_RULE_ID, "legacy-first-overlap");
    assert_eq!(LEGACY_PROTOCOL_REVISION, 1);
    assert_eq!(A.len(), 37);
}

#[test]
fn the_first_overlapping_finding_decides_so_order_matters() {
    let case = Case::email(Sensitive);
    // partial wrong-family finding [11,14) first, exact right-family finding second.
    let partial_phone = found(11, 14, PHONE);
    let exact_email = found(11, 27, EMAIL);

    let a = legacy(&case, &[partial_phone.clone(), exact_email.clone()]);
    assert_eq!(a.type_identity, TypeState::WrongFamily);
    assert_eq!(a.range, RangeState::Partial);
    assert_eq!(a.observed.finding_count, 2);

    let b = legacy(&case, &[exact_email, partial_phone]);
    assert_eq!(b.type_identity, TypeState::Correct);
    assert_eq!(b.range, RangeState::Exact);
    assert_eq!(b.observed.finding_count, 2);
    // The summary covers every overlapping finding, in either order.
    assert_eq!(a.observed, b.observed);
    let names: Vec<_> = a.observed.families.iter().map(|f| f.as_str()).collect();
    assert_eq!(names, [EMAIL, PHONE]);
}

#[test]
fn non_overlapping_findings_are_skipped_before_selection() {
    let case = Case::email(Sensitive);
    // [28,37) is disjoint; [0,11) and [27,28) are adjacent. Only [9,28) overlaps.
    let findings = [
        found(28, 37, PHONE),
        found(0, 11, PHONE),
        found(27, 28, PHONE),
        found(9, 28, EMAIL),
    ];
    let out = legacy(&case, &findings);
    assert_eq!(out.observed.finding_count, 1);
    assert_eq!(out.range, RangeState::Overbroad);
    assert_eq!(out.type_identity, TypeState::Correct);
}

#[test]
fn range_states_follow_the_oracle() {
    let case = Case::email(Sensitive);
    let vectors = [
        ((11, 27), RangeState::Exact),
        ((9, 28), RangeState::Overbroad),
        ((11, 28), RangeState::Overbroad),
        ((10, 27), RangeState::Overbroad),
        ((11, 20), RangeState::Partial),
        ((20, 31), RangeState::Partial),
        ((0, 12), RangeState::Partial),
        ((26, 27), RangeState::Partial),
        ((0, 11), RangeState::Miss),
        ((27, 37), RangeState::Miss),
    ];
    for ((s, e), state) in vectors {
        assert_eq!(
            legacy(&case, &[found(s, e, EMAIL)]).range,
            state,
            "[{s},{e})"
        );
    }
    assert_eq!(legacy(&case, &[]).range, RangeState::Miss);
    assert_eq!(legacy(&case, &[]).type_identity, TypeState::Miss);
}

#[test]
fn duplicates_count_and_do_not_merge() {
    let case = Case::email(Sensitive);
    let f = found(11, 27, EMAIL);
    let one = legacy(&case, std::slice::from_ref(&f));
    let two = legacy(&case, &[f.clone(), f]);
    assert_eq!(one.observed.finding_count, 1);
    assert_eq!(two.observed.finding_count, 2);
    assert_eq!(
        (one.type_identity, one.range),
        (two.type_identity, two.range)
    );
    assert_eq!(two.observed.families.len(), 1);
}

#[test]
fn degenerate_ranges_are_not_rejected_by_the_legacy_rule() {
    // The oracle never validated ranges. With candidate [11,27):
    //   [20,20): 11 < 20 && 20 < 27           -> overlaps, and partial
    //   [11,11): 11 < 11 is false              -> no overlap
    //   [27,27): 11 < 27 && 27 < 27 is false   -> no overlap
    //   [25,13) (inverted): 11 < 13 && 25 < 27 -> overlaps; not exact, not
    //            overbroad (25 <= 11 is false), so partial
    let case = Case::email(Sensitive);
    let inside_empty = legacy(&case, &[found(20, 20, EMAIL)]);
    assert_eq!(inside_empty.observed.finding_count, 1);
    assert_eq!(inside_empty.range, RangeState::Partial);
    assert_eq!(
        legacy(&case, &[found(11, 11, EMAIL)])
            .observed
            .finding_count,
        0
    );
    assert_eq!(
        legacy(&case, &[found(27, 27, EMAIL)])
            .observed
            .finding_count,
        0
    );
    let inverted = legacy(&case, &[found(25, 13, EMAIL)]);
    assert_eq!(inverted.observed.finding_count, 1);
    assert_eq!(inverted.range, RangeState::Partial);
    // Beyond the text and mid-character offsets are accepted too.
    assert_eq!(
        legacy(&case, &[found(0, 9_999, EMAIL)]).range,
        RangeState::Overbroad
    );
    assert_eq!(
        legacy(&case, &[found(2, 12, EMAIL)]).range,
        RangeState::Partial
    );
}

#[test]
fn sensitivity_reads_only_the_first_finding_and_absence_means_not_flagged() {
    let flagged = found(11, 27, EMAIL);
    let unflagged = Finding {
        sensitive: Some(false),
        ..found(11, 27, EMAIL)
    };
    let silent = Finding {
        sensitive: None,
        ..found(11, 27, EMAIL)
    };

    let s = Case::email(Sensitive);
    assert_eq!(
        legacy(&s, std::slice::from_ref(&flagged)).sensitivity_context,
        SensitivityState::Correct
    );
    assert_eq!(
        legacy(&s, std::slice::from_ref(&unflagged)).sensitivity_context,
        SensitivityState::Miss
    );
    assert_eq!(
        legacy(&s, std::slice::from_ref(&silent)).sensitivity_context,
        SensitivityState::Miss
    );
    assert_eq!(legacy(&s, &[]).sensitivity_context, SensitivityState::Miss);
    // Order matters: first unflagged, second flagged vs the reverse.
    let order1 = [
        unflagged.clone(),
        Finding {
            range: range(11, 28),
            ..flagged.clone()
        },
    ];
    let order2 = [
        Finding {
            range: range(11, 28),
            ..flagged.clone()
        },
        unflagged.clone(),
    ];
    assert_eq!(
        legacy(&s, &order1).sensitivity_context,
        SensitivityState::Miss
    );
    assert_eq!(
        legacy(&s, &order2).sensitivity_context,
        SensitivityState::Correct
    );

    let n = Case::email(NonSensitive);
    assert_eq!(
        legacy(&n, &[flagged]).sensitivity_context,
        SensitivityState::FalsePositive
    );
    assert_eq!(
        legacy(&n, &[silent]).sensitivity_context,
        SensitivityState::Correct
    );
    assert_eq!(
        legacy(&n, &[unflagged]).sensitivity_context,
        SensitivityState::Correct
    );
    assert_eq!(
        legacy(&n, &[]).sensitivity_context,
        SensitivityState::Correct
    );

    let u = Case::email(NotEstablished);
    assert_eq!(
        legacy(&u, &[]).sensitivity_context,
        SensitivityState::Unresolved
    );
    assert_eq!(
        legacy(&u, &[found(11, 27, EMAIL)]).sensitivity_context,
        SensitivityState::Unresolved
    );
}

#[test]
fn invalid_expectations_accept_on_any_overlap() {
    let case = Case {
        expected_type: ExpectedType::Invalid,
        ..Case::email(NonSensitive)
    };
    assert_eq!(legacy(&case, &[]).type_identity, TypeState::InvalidCorrect);
    // Adjacent: no overlap.
    assert_eq!(
        legacy(&case, &[found(27, 37, EMAIL)]).type_identity,
        TypeState::InvalidCorrect
    );
    // One byte of overlap, wrong family: still accepted.
    assert_eq!(
        legacy(&case, &[found(26, 37, PHONE)]).type_identity,
        TypeState::InvalidAccepted
    );
}

#[test]
fn family_and_jurisdiction_precedence_follows_the_oracle() {
    let kr = JurisdictionCode::new("KR").unwrap();
    let case = Case {
        candidate: range(7, 20),
        expected_type: ExpectedType::Valid,
        family: FamilyId::new("pii:kr:phone").unwrap(),
        jurisdiction: Some(kr),
        sensitivity: Sensitive,
    };
    let with = |family: &str, jur: Option<&str>| {
        let mut f = found(7, 20, family);
        f.jurisdiction = jur.map(|j| JurisdictionCode::new(j).unwrap());
        legacy(&case, &[f]).type_identity
    };
    assert_eq!(with("pii:kr:phone", Some("KR")), TypeState::Correct);
    assert_eq!(
        with("pii:kr:phone", Some("US")),
        TypeState::WrongJurisdiction
    );
    assert_eq!(with("pii:kr:phone", None), TypeState::NotMeasured);
    assert_eq!(
        with("pii:us:phone", Some("US")),
        TypeState::WrongJurisdiction
    );
    assert_eq!(with("pii:us:phone", None), TypeState::WrongFamily);
    assert_eq!(with(PHONE, Some("KR")), TypeState::WrongFamily);
    // A finding with no family at all: not measured.
    let mut f = found(7, 20, PHONE);
    f.family = None;
    assert_eq!(legacy(&case, &[f]).type_identity, TypeState::NotMeasured);
}

#[test]
fn a_scanner_that_did_not_complete_measures_nothing() {
    let case = Case::email(Sensitive);
    let bogus = [found(11, 27, EMAIL)];
    for status in [
        ScannerStatus::Unsupported,
        ScannerStatus::Unavailable,
        ScannerStatus::Error,
        ScannerStatus::Unstable,
    ] {
        let out = interpret(
            &LegacyExpectation {
                candidate: case.candidate,
                expected_type: case.expected_type,
                family: &case.family,
                jurisdiction: None,
                sensitivity: case.sensitivity,
            },
            &LegacyScanner {
                status,
                findings: &bogus,
            },
        );
        assert_eq!(out.type_identity, TypeState::NotMeasured);
        assert_eq!(out.sensitivity_context, SensitivityState::NotMeasured);
        assert_eq!(out.range, RangeState::NotApplicable);
        assert_eq!(out.observed.finding_count, 0);
    }
}

fn random_findings(rng: &mut Rng) -> Vec<Finding> {
    // Valid, non-empty ranges at the boundaries of A that matter.
    let points = [0u64, 9, 10, 11, 14, 15, 22, 27, 28, 31, 37];
    (0..rng.below(7))
        .map(|_| {
            let i = rng.below(points.len() - 1);
            let j = i + 1 + rng.below(points.len() - i - 1);
            let mut f = found(points[i], points[j], [EMAIL, PHONE][rng.below(2)]);
            f.sensitive = [Some(true), Some(false), None][rng.below(3)];
            f
        })
        .collect()
}

fn decisive(
    o: &pii_eval_compat::legacy::LegacyOutcome,
) -> (TypeState, SensitivityState, RangeState) {
    (o.type_identity, o.sensitivity_context, o.range)
}

#[test]
fn property_the_first_overlapping_finding_alone_decides() {
    let mut rng = Rng(11);
    let mut order_dependent = 0;
    for iteration in 0..3000 {
        let case = Case::email([Sensitive, NonSensitive, NotEstablished][rng.below(3)]);
        let findings = random_findings(&mut rng);
        let out = legacy(&case, &findings);
        match findings
            .iter()
            .find(|f| f.range.start < 27 && 11 < f.range.end)
        {
            Some(first) => {
                // The result equals the result for that finding alone...
                assert_eq!(
                    decisive(&out),
                    decisive(&legacy(&case, std::slice::from_ref(first))),
                    "iteration {iteration}"
                );
                // ...and survives dropping every non-overlapping finding.
                let overlapping: Vec<_> = findings
                    .iter()
                    .filter(|f| f.range.start < 27 && 11 < f.range.end)
                    .cloned()
                    .collect();
                assert_eq!(out, legacy(&case, &overlapping), "iteration {iteration}");
                // Appending findings after it never changes the deciding finding.
                let mut appended = findings.clone();
                appended.extend(random_findings(&mut rng).into_iter().map(|mut f| {
                    f.range = range(11, 27);
                    f
                }));
                assert_eq!(
                    decisive(&legacy(&case, &appended)),
                    decisive(&out),
                    "iteration {iteration}"
                );
            }
            None => {
                assert_eq!(out.observed.finding_count, 0);
                assert_eq!(out.range, RangeState::Miss);
            }
        }
        // Count how often a permutation changes the outcome: the characterization
        // that justifies the canonical rule.
        let mut shuffled = findings.clone();
        rng.shuffle(&mut shuffled);
        if decisive(&legacy(&case, &shuffled)) != decisive(&out) {
            order_dependent += 1;
        }
    }
    assert!(
        order_dependent > 50,
        "legacy order dependence not exercised: {order_dependent}"
    );
}
