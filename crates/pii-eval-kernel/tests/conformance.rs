//! Hand-calculated conformance vectors for the canonical rule (`pii-v1-canonical`).
//!
//! Every expected value below was derived by hand from the byte layouts in the
//! comments, not by running the code under test.
//!
//! Layout A: `"연락처: kim@example.test 입니다"`
//!
//! ```text
//! 연락처  = 3 syllables x 3 bytes      bytes  0..9
//! ':'                                  bytes  9..10
//! ' '                                  bytes 10..11
//! "kim"                                bytes 11..14
//! '@'                                  bytes 14..15
//! "example"                            bytes 15..22
//! ".test"                              bytes 22..27
//! ' '                                  bytes 27..28
//! 입니다  = 3 syllables x 3 bytes      bytes 28..37
//! ```
//!
//! Total 37 bytes. Valid boundaries include 0, 3, 6, 9, 10, 11, 14, 15, 22,
//! 27, 28, 31, 34, 37. The email occurrence is `[11, 27)` (length 16).
//!
//! Layout B: `"전화 010-0000-0000"`: 전화 is bytes 0..6, ' ' is 6..7, the
//! 13-byte number is 7..20; total 20 bytes.

mod common;

use common::*;
use pii_eval_contracts::axes::AuthoredAxes;
use pii_eval_contracts::{
    ActionCapability, ActionKind, ActionOutcome, CapabilityState, ExpectedType, FamilyId, Finding,
    JurisdictionCode, RangeState, ScannerStatus, SensitivityExpectation, SensitivityState,
    TypeState, validate_outcome_lattice,
};
use pii_eval_kernel::{
    AssessError, RangeError, ScannerView, Subject, VariantInput, assess_variant, closeness,
    relation,
};

const A: &str = "연락처: kim@example.test 입니다";
const B: &str = "전화 010-0000-0000";
const EMAIL: &str = "pii:global:email";
const PHONE: &str = "pii:global:phone";
const KR_PHONE: &str = "pii:kr:phone";

#[test]
fn layouts_match_the_hand_tables() {
    assert_eq!(A.len(), 37);
    assert_eq!(&A[11..27], "kim@example.test");
    assert_eq!(&A[11..14], "kim");
    assert_eq!(&A[15..22], "example");
    assert_eq!(&A[28..37], "입니다");
    assert_eq!(B.len(), 20);
    assert_eq!(&B[7..20], "010-0000-0000");
}

#[test]
fn range_state_vectors_for_the_email_occurrence() {
    // (finding range, expected state, note)
    let vectors: [((u64, u64), RangeState); 12] = [
        ((11, 27), RangeState::Exact),
        ((9, 28), RangeState::Overbroad),  // contains [11,27)
        ((0, 37), RangeState::Overbroad),  // whole input
        ((11, 28), RangeState::Overbroad), // same start, longer
        ((10, 27), RangeState::Overbroad), // same end, longer
        ((11, 20), RangeState::Partial),   // strictly inside
        ((20, 31), RangeState::Partial),   // straddles the end
        ((0, 12), RangeState::Partial),    // straddles the start by one byte
        ((26, 27), RangeState::Partial),   // last byte only
        ((0, 11), RangeState::Miss),       // adjacent before: [0,11) and [11,27)
        ((27, 37), RangeState::Miss),      // adjacent after: [11,27) and [27,37)
        ((28, 37), RangeState::Miss),      // disjoint
    ];
    let e = [valid("occ-a", 11, 27, EMAIL)];
    for ((s, f), state) in vectors {
        let a = assess(A, None, &e, &[found(s, f, EMAIL)], &supported());
        assert_eq!(a.occurrences[0].row.range, state, "[{s},{f})");
        let expected_candidates = u64::from(state != RangeState::Miss);
        assert_eq!(a.occurrences[0].observed.finding_count, expected_candidates);
    }
    // No finding at all is also a miss, and a type miss.
    let a = assess(A, None, &e, &[], &supported());
    assert_eq!(a.occurrences[0].row.range, RangeState::Miss);
    assert_eq!(a.occurrences[0].row.type_identity, TypeState::Miss);
    assert_eq!(a.occurrences[0].primary, None);
}

#[test]
fn closeness_keys_are_hand_checked() {
    let e = range(11, 27);
    // exact
    assert_eq!(closeness(&e, &range(11, 27)), Some((0, 0)));
    // overbroad: extra bytes = reported length - 16
    assert_eq!(closeness(&e, &range(9, 28)), Some((1, 3))); // 19 - 16
    assert_eq!(closeness(&e, &range(0, 37)), Some((1, 21))); // 37 - 16
    // partial: uncovered expected bytes = 16 - overlap
    assert_eq!(closeness(&e, &range(11, 20)), Some((2, 7))); // overlap 9
    assert_eq!(closeness(&e, &range(20, 31)), Some((2, 9))); // overlap 27-20 = 7
    assert_eq!(closeness(&e, &range(0, 12)), Some((2, 15))); // overlap 1
    // no overlap
    assert_eq!(closeness(&e, &range(0, 11)), None);
    assert_eq!(closeness(&e, &range(27, 37)), None);
    assert_eq!(relation(&e, &range(27, 37)), None);
}

#[test]
fn primary_is_the_closest_candidate_whatever_the_order() {
    let e = [valid("occ-a", 11, 27, EMAIL)];
    let partial = found(11, 14, PHONE); // (2, 13)
    let wide = found(0, 37, PHONE); // (1, 21)
    let near = found(9, 28, PHONE); // (1, 3)
    let exact = found(11, 27, EMAIL); // (0, 0)

    // exact beats everything.
    let all = [partial.clone(), wide.clone(), near.clone(), exact.clone()];
    // without exact: near (extra 3) beats wide (extra 21) beats partial.
    let no_exact = [partial.clone(), wide.clone(), near.clone()];
    let no_near = [partial.clone(), wide.clone()];
    for (set, primary_range) in [
        (&all[..], range(11, 27)),
        (&no_exact[..], range(9, 28)),
        (&no_near[..], range(0, 37)),
        (&all[3..], range(11, 27)),
    ] {
        for rotation in 0..set.len() {
            let mut rotated = set.to_vec();
            rotated.rotate_left(rotation);
            let a = assess(A, None, &e, &rotated, &supported());
            let primary = a.occurrences[0].primary.expect("a candidate exists");
            assert_eq!(a.findings[primary].range, primary_range);
        }
    }
    let only_partial = assess(A, None, &e, &[partial], &supported());
    assert_eq!(only_partial.occurrences[0].row.range, RangeState::Partial);
}

#[test]
fn equal_closeness_ties_are_broken_by_identity_then_by_value() {
    let e = [valid("occ-a", 11, 27, EMAIL)];
    // Partials [11,20) (overlap 9) and [18,27) (overlap 9) are both (2, 7).
    // Same family evidence: the lower canonical finding, [11,20), wins.
    let low = found(11, 20, EMAIL);
    let high = found(18, 27, EMAIL);
    for order in [[low.clone(), high.clone()], [high.clone(), low.clone()]] {
        let a = assess(A, None, &e, &order, &supported());
        assert_eq!(
            a.findings[a.occurrences[0].primary.unwrap()].range,
            range(11, 20)
        );
    }
    // Overbroad [10,28) and [9,27) are both (1, 2); [9,27) sorts first.
    for order in [
        [found(10, 28, EMAIL), found(9, 27, EMAIL)],
        [found(9, 27, EMAIL), found(10, 28, EMAIL)],
    ] {
        let a = assess(A, None, &e, &order, &supported());
        assert_eq!(
            a.findings[a.occurrences[0].primary.unwrap()].range,
            range(9, 27)
        );
    }
    // Two exact findings on the same range: the one reporting the expected
    // family is primary even though "phone" sorts after "email"... and also
    // when the order of the names is reversed (expected family phone).
    let email = found(11, 27, EMAIL);
    let phone = found(11, 27, PHONE);
    for expected_family in [EMAIL, PHONE] {
        let e = [valid("occ-a", 11, 27, expected_family)];
        for order in [
            [email.clone(), phone.clone()],
            [phone.clone(), email.clone()],
        ] {
            let a = assess(A, None, &e, &order, &supported());
            assert_eq!(a.occurrences[0].row.type_identity, TypeState::Correct);
            assert_eq!(a.occurrences[0].observed.finding_count, 2);
            assert_eq!(a.occurrences[0].observed.families.len(), 2);
        }
    }
    // A finding without a family is weaker evidence than one with another family.
    let e = [valid("occ-a", 11, 27, EMAIL)];
    for order in [
        [without_family(found(11, 27, EMAIL)), found(11, 27, PHONE)],
        [found(11, 27, PHONE), without_family(found(11, 27, EMAIL))],
    ] {
        let a = assess(A, None, &e, &order, &supported());
        assert_eq!(a.occurrences[0].row.type_identity, TypeState::WrongFamily);
    }
    // All best candidates lacking a family: not measured.
    let a = assess(
        A,
        None,
        &e,
        &[without_family(found(11, 27, EMAIL))],
        &supported(),
    );
    assert_eq!(a.occurrences[0].row.type_identity, TypeState::NotMeasured);
}

#[test]
fn a_closer_wrong_finding_still_beats_a_looser_right_one() {
    // Geometry decides first: identity only breaks ties.
    let e = [valid("occ-a", 11, 27, EMAIL)];
    let a = assess(
        A,
        None,
        &e,
        &[found(11, 27, PHONE), found(0, 37, EMAIL)],
        &supported(),
    );
    assert_eq!(a.occurrences[0].row.type_identity, TypeState::WrongFamily);
    assert_eq!(a.occurrences[0].row.range, RangeState::Exact);
}

#[test]
fn duplicates_are_kept_counted_and_do_not_change_the_outcome() {
    let e = [valid("occ-a", 11, 27, EMAIL)];
    let f = found(11, 27, EMAIL);
    let once = assess(A, None, &e, std::slice::from_ref(&f), &supported());
    let twice = assess(A, None, &e, &[f.clone(), f.clone()], &supported());
    assert_eq!(once.occurrences[0].row, twice.occurrences[0].row);
    assert_eq!(once.occurrences[0].observed.finding_count, 1);
    assert_eq!(twice.occurrences[0].observed.finding_count, 2);
    assert_eq!(twice.occurrences[0].observed.families.len(), 1);
    // Both duplicates are reported spans: nothing is merged or hidden.
    assert_eq!(once.reported.len(), 1);
    assert_eq!(twice.reported.len(), 2);
    assert!(
        twice
            .reported
            .iter()
            .all(|r| r.matched.unwrap().state == RangeState::Exact)
    );
}

#[test]
fn multiple_findings_are_all_accounted_for() {
    // One exact, one overbroad, one disjoint finding over one occurrence.
    let e = [valid("occ-a", 11, 27, EMAIL)];
    let findings = [
        found(28, 37, PHONE),
        found(9, 28, PHONE),
        found(11, 27, EMAIL),
    ];
    let a = assess(A, None, &e, &findings, &supported());
    let occ = &a.occurrences[0];
    assert_eq!(occ.row.range, RangeState::Exact);
    assert_eq!(occ.observed.finding_count, 2); // the disjoint one is not a candidate
    // Canonical order: [9,28) < [11,27) < [28,37).
    let ranges: Vec<_> = a.reported.iter().map(|r| r.range).collect();
    assert_eq!(ranges, [range(9, 28), range(11, 27), range(28, 37)]);
    let states: Vec<_> = a
        .reported
        .iter()
        .map(|r| r.matched.map(|m| m.state))
        .collect();
    assert_eq!(
        states,
        [Some(RangeState::Overbroad), Some(RangeState::Exact), None]
    );
}

#[test]
fn nested_occurrences_are_assessed_independently() {
    // occ-a is the whole email [11,27); occ-b is "example" [15,22), nested in it.
    let e = [valid("occ-b", 15, 22, PHONE), valid("occ-a", 11, 27, EMAIL)];
    // One finding spanning the email: exact for occ-a, overbroad for occ-b.
    let a = assess(A, None, &e, &[found(11, 27, EMAIL)], &supported());
    assert_eq!(a.occurrences[0].occurrence_id.as_str(), "occ-a");
    assert_eq!(a.occurrences[0].row.range, RangeState::Exact);
    assert_eq!(a.occurrences[0].row.type_identity, TypeState::Correct);
    assert_eq!(a.occurrences[1].row.range, RangeState::Overbroad);
    assert_eq!(a.occurrences[1].row.type_identity, TypeState::WrongFamily);
    // The same finding is one reported span, closest to occ-a, overlapping both.
    let m = a.reported[0].matched.unwrap();
    assert_eq!(
        (m.occurrence, m.state, m.overlapping_occurrences),
        (0, RangeState::Exact, 2)
    );
    // A finding on the inner range: exact for occ-b, partial for occ-a.
    let a = assess(A, None, &e, &[found(15, 22, PHONE)], &supported());
    assert_eq!(a.occurrences[0].row.range, RangeState::Partial);
    assert_eq!(a.occurrences[1].row.range, RangeState::Exact);
    assert_eq!(a.occurrences[1].row.type_identity, TypeState::Correct);
}

#[test]
fn adjacent_occurrences_do_not_share_findings() {
    // "kim" [11,14) and "@" [14,15) are adjacent; so are [14,15) and "example" [15,22).
    let e = [valid("occ-a", 11, 14, EMAIL), valid("occ-b", 14, 15, EMAIL)];
    let a = assess(A, None, &e, &[found(11, 14, EMAIL)], &supported());
    assert_eq!(a.occurrences[0].row.range, RangeState::Exact);
    assert_eq!(a.occurrences[1].row.range, RangeState::Miss);
    assert_eq!(a.occurrences[1].row.type_identity, TypeState::Miss);
    assert_eq!(a.reported[0].matched.unwrap().overlapping_occurrences, 1);
}

#[test]
fn a_span_covering_two_occurrences_matches_the_tighter_one() {
    // local "kim" [11,14) len 3 and domain "example.test" [15,27) len 12; the
    // finding [11,27) has length 16: extras 13 and 4, so the domain is closer.
    let e = [valid("occ-a", 11, 14, EMAIL), valid("occ-b", 15, 27, EMAIL)];
    let a = assess(A, None, &e, &[found(11, 27, EMAIL)], &supported());
    let m = a.reported[0].matched.unwrap();
    assert_eq!(
        (m.occurrence, m.state, m.overlapping_occurrences),
        (1, RangeState::Overbroad, 2)
    );
    assert_eq!(a.occurrences[0].row.range, RangeState::Overbroad);
    assert_eq!(a.occurrences[1].row.range, RangeState::Overbroad);
}

#[test]
fn korean_and_english_boundaries() {
    let e = [valid("occ-a", 11, 27, EMAIL)];
    // [27,31) is " " plus the first Korean syllable: valid, adjacent to the occurrence.
    let a = assess(A, None, &e, &[found(27, 31, EMAIL)], &supported());
    assert_eq!(a.occurrences[0].row.range, RangeState::Miss);
    // [9,12) is ":" " " "k": overlaps the first byte of the occurrence only.
    let a = assess(A, None, &e, &[found(9, 12, EMAIL)], &supported());
    assert_eq!(a.occurrences[0].row.range, RangeState::Partial);
    // Byte 2 is inside the first Korean syllable, byte 29 inside the last block.
    for (s, f, bad) in [(0, 2, 2u64), (29, 37, 29)] {
        let err = assess_variant(
            &VariantInput {
                text: A,
                case_jurisdiction: None,
                expectations: &e,
            },
            &ScannerView {
                status: ScannerStatus::Complete,
                capabilities: &supported(),
                findings: &[found(s, f, EMAIL)],
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            AssessError::Range {
                subject: Subject::Finding(range(s, f)),
                error: RangeError::NotOnCharBoundary
            },
            "byte {bad}"
        );
    }
}

fn expect_error(
    findings: &[Finding],
    expectations: &[pii_eval_contracts::Expectation],
) -> AssessError {
    assess_variant(
        &VariantInput {
            text: A,
            case_jurisdiction: None,
            expectations,
        },
        &ScannerView {
            status: ScannerStatus::Complete,
            capabilities: &supported(),
            findings,
        },
    )
    .unwrap_err()
}

#[test]
fn invalid_ranges_are_rejected_not_repaired() {
    let e = [valid("occ-a", 11, 27, EMAIL)];
    let cases = [
        (range(0, 38), RangeError::OutOfBounds), // length is 37
        (range(11, 11), RangeError::Empty),
        (range(12, 11), RangeError::Inverted),
        (range(0, 2), RangeError::NotOnCharBoundary),
        (range(0, u64::MAX), RangeError::OffsetTooLarge),
    ];
    for (r, error) in cases {
        let f = Finding {
            range: r,
            ..found(0, 1, EMAIL)
        };
        assert_eq!(
            expect_error(&[f], &e),
            AssessError::Range {
                subject: Subject::Finding(r),
                error
            },
            "{r:?}"
        );
    }
    // An invalid authored range is also rejected, and reported as an expectation.
    let bad = [valid("occ-a", 0, 38, EMAIL)];
    assert_eq!(
        expect_error(&[], &bad),
        AssessError::Range {
            subject: Subject::Expectation(range(0, 38)),
            error: RangeError::OutOfBounds
        }
    );
    // The first failure in canonical order is reported, whatever the input order.
    let f1 = found(0, 2, EMAIL); // [0,2): not on a boundary
    let f2 = Finding {
        range: range(0, 38),
        ..found(0, 1, EMAIL)
    };
    for order in [[f1.clone(), f2.clone()], [f2.clone(), f1.clone()]] {
        assert_eq!(
            expect_error(&order, &e),
            AssessError::Range {
                subject: Subject::Finding(range(0, 2)),
                error: RangeError::NotOnCharBoundary
            }
        );
    }
    // Duplicate occurrence ids and oversize inputs.
    let dup = [valid("occ-a", 11, 27, EMAIL), valid("occ-a", 11, 14, EMAIL)];
    assert_eq!(expect_error(&[], &dup), AssessError::DuplicateOccurrence);
    let many: Vec<_> = (0..17)
        .map(|i| valid(&format!("occ-{i:02}"), 11, 14, EMAIL))
        .collect();
    assert_eq!(expect_error(&[], &many), AssessError::TooManyExpectations);
    let flood = vec![found(11, 14, EMAIL); 10_001];
    assert_eq!(expect_error(&flood, &e), AssessError::TooManyFindings);
    let at_limit = vec![found(11, 14, EMAIL); 10_000];
    assert!(
        assess_variant(
            &VariantInput {
                text: A,
                case_jurisdiction: None,
                expectations: &e
            },
            &ScannerView {
                status: ScannerStatus::Complete,
                capabilities: &supported(),
                findings: &at_limit
            },
        )
        .is_ok()
    );
}

fn kr_row(findings: &[Finding]) -> TypeState {
    let e = [valid("occ-a", 7, 20, KR_PHONE)];
    assess(B, Some("KR"), &e, findings, &supported()).occurrences[0]
        .row
        .type_identity
}

#[test]
fn family_and_jurisdiction_precedence() {
    let kr = |f: Finding| with_jurisdiction(f, "KR");
    let us = |f: Finding| with_jurisdiction(f, "US");
    // Right family and jurisdiction.
    assert_eq!(kr_row(&[kr(found(7, 20, KR_PHONE))]), TypeState::Correct);
    // Right family, reported jurisdiction differs.
    assert_eq!(
        kr_row(&[us(found(7, 20, KR_PHONE))]),
        TypeState::WrongJurisdiction
    );
    // Right family, no jurisdiction reported: cannot tell.
    assert_eq!(kr_row(&[found(7, 20, KR_PHONE)]), TypeState::NotMeasured);
    // Other family and other jurisdiction: wrong-jurisdiction takes precedence.
    assert_eq!(
        kr_row(&[us(found(7, 20, "pii:us:phone"))]),
        TypeState::WrongJurisdiction
    );
    // Other family, no jurisdiction reported: wrong-family.
    assert_eq!(
        kr_row(&[found(7, 20, "pii:us:phone")]),
        TypeState::WrongFamily
    );
    // Other family but the expected jurisdiction: wrong-family.
    assert_eq!(kr_row(&[kr(found(7, 20, PHONE))]), TypeState::WrongFamily);
    // No finding.
    assert_eq!(kr_row(&[]), TypeState::Miss);
    // Global case: a reported jurisdiction does not matter for a family mismatch.
    let e = [valid("occ-a", 7, 20, PHONE)];
    let a = assess(
        B,
        None,
        &e,
        &[us(found(7, 20, "pii:us:phone"))],
        &supported(),
    );
    assert_eq!(a.occurrences[0].row.type_identity, TypeState::WrongFamily);
}

#[test]
fn invalid_expectations_accept_or_reject_by_overlap() {
    let e = [exp(
        "occ-a",
        11,
        27,
        EMAIL,
        ExpectedType::Invalid,
        SensitivityExpectation::NonSensitive,
    )];
    let a = assess(A, None, &e, &[], &supported());
    assert_eq!(
        a.occurrences[0].row.type_identity,
        TypeState::InvalidCorrect
    );
    // Adjacent finding: no overlap, still rejected.
    let a = assess(A, None, &e, &[found(27, 37, EMAIL)], &supported());
    assert_eq!(
        a.occurrences[0].row.type_identity,
        TypeState::InvalidCorrect
    );
    let a = assess(A, None, &e, &[found(26, 37, PHONE)], &supported());
    assert_eq!(
        a.occurrences[0].row.type_identity,
        TypeState::InvalidAccepted
    );
}

fn sens_row(
    expectation: SensitivityExpectation,
    findings: &[Finding],
    capabilities: &pii_eval_contracts::ScannerCapabilities,
) -> SensitivityState {
    let e = [exp(
        "occ-a",
        11,
        27,
        EMAIL,
        ExpectedType::Valid,
        expectation,
    )];
    assess(A, None, &e, findings, capabilities).occurrences[0]
        .row
        .sensitivity_context
}

#[test]
fn sensitivity_axis_is_independent_of_type_and_capability_aware() {
    use SensitivityExpectation::{NonSensitive, NotEstablished, Sensitive};
    let flagged = found(11, 27, EMAIL);
    let unflagged = with_sensitive(found(11, 27, EMAIL), Some(false));
    let silent = with_sensitive(found(11, 27, EMAIL), None);
    let wrong_family_flagged = found(11, 27, PHONE);
    let s = supported();
    assert_eq!(
        sens_row(Sensitive, std::slice::from_ref(&flagged), &s),
        SensitivityState::Correct
    );
    assert_eq!(
        sens_row(Sensitive, std::slice::from_ref(&unflagged), &s),
        SensitivityState::Miss
    );
    assert_eq!(sens_row(Sensitive, &[], &s), SensitivityState::Miss);
    assert_eq!(
        sens_row(NonSensitive, std::slice::from_ref(&flagged), &s),
        SensitivityState::FalsePositive
    );
    assert_eq!(
        sens_row(NonSensitive, &[unflagged], &s),
        SensitivityState::Correct
    );
    assert_eq!(sens_row(NonSensitive, &[], &s), SensitivityState::Correct);
    // The sensitivity of a wrong-family finding is still judged: separate axes.
    assert_eq!(
        sens_row(Sensitive, &[wrong_family_flagged], &s),
        SensitivityState::Correct
    );
    // A finding that does not answer is not a negative answer.
    assert_eq!(
        sens_row(Sensitive, std::slice::from_ref(&silent), &s),
        SensitivityState::NotMeasured
    );
    assert_eq!(
        sens_row(NonSensitive, &[silent], &s),
        SensitivityState::NotMeasured
    );
    // Not established stays unresolved (review-required), never pass or fail.
    assert_eq!(
        sens_row(NotEstablished, std::slice::from_ref(&flagged), &s),
        SensitivityState::Unresolved
    );
    // Undeclared capability: only an explicit report counts.
    let undeclared = caps(CapabilityState::Undeclared);
    assert_eq!(
        sens_row(Sensitive, std::slice::from_ref(&flagged), &undeclared),
        SensitivityState::Correct
    );
    assert_eq!(
        sens_row(Sensitive, &[], &undeclared),
        SensitivityState::NotMeasured
    );
    assert_eq!(
        sens_row(NonSensitive, &[], &undeclared),
        SensitivityState::NotMeasured
    );
    // Unsupported capability: never measured, whatever the finding says.
    let unsupported = pii_eval_contracts::ScannerCapabilities {
        sensitivity_classification: CapabilityState::Unsupported,
        ..supported()
    };
    for exp_s in [Sensitive, NonSensitive, NotEstablished] {
        assert_eq!(
            sens_row(exp_s, &[], &unsupported),
            SensitivityState::NotMeasured
        );
    }
}

#[test]
fn action_is_observed_separately_and_never_inferred() {
    let e = [valid("occ-a", 11, 27, EMAIL)];
    let redact = with_action(found(11, 27, EMAIL), ActionKind::Redact);
    let preserve = with_action(found(11, 27, EMAIL), ActionKind::Preserve);
    let action = |findings: &[Finding], c: &pii_eval_contracts::ScannerCapabilities| {
        assess(A, None, &e, findings, c).occurrences[0].row.action
    };
    let s = supported();
    assert_eq!(
        action(std::slice::from_ref(&redact), &s),
        ActionOutcome::Reported {
            action: ActionKind::Redact
        }
    );
    assert_eq!(
        action(&[preserve], &s),
        ActionOutcome::Reported {
            action: ActionKind::Preserve
        }
    );
    // A sensitive flag does not imply an action.
    assert_eq!(
        action(&[found(11, 27, EMAIL)], &s),
        ActionOutcome::NoActionReported
    );
    assert_eq!(action(&[], &s), ActionOutcome::NoActionReported);
    // Unavailable: not measured, even with a finding that carries an action.
    let unavailable = pii_eval_contracts::ScannerCapabilities {
        action: ActionCapability::Unavailable,
        ..supported()
    };
    assert_eq!(
        action(std::slice::from_ref(&redact), &unavailable),
        ActionOutcome::NotMeasured
    );
    // Sanitized-output capability alone does not produce `output-verified`.
    let output = pii_eval_contracts::ScannerCapabilities {
        action: ActionCapability::SanitizedOutput,
        ..supported()
    };
    assert_eq!(
        action(&[redact], &output),
        ActionOutcome::Reported {
            action: ActionKind::Redact
        }
    );
    // Action does not move type or range.
    let a = assess(A, None, &e, &[found(11, 27, EMAIL)], &unavailable);
    assert_eq!(a.occurrences[0].row.type_identity, TypeState::Correct);
    assert_eq!(a.occurrences[0].row.range, RangeState::Exact);
}

#[test]
fn missing_capability_is_not_measured_never_success() {
    let e = [valid("occ-a", 11, 27, EMAIL)];
    let f = [found(11, 27, EMAIL)];
    // Family classification unsupported: the type axis is not measured; the
    // range and sensitivity axes still are.
    let no_family = pii_eval_contracts::ScannerCapabilities {
        family_classification: CapabilityState::Unsupported,
        ..supported()
    };
    let row = assess(A, None, &e, &f, &no_family).occurrences[0].row;
    assert_eq!(row.type_identity, TypeState::NotMeasured);
    assert_eq!(row.range, RangeState::Exact);
    assert_eq!(row.sensitivity_context, SensitivityState::Correct);
    // The expected family itself unsupported (explicit entry).
    let one_family_gone = pii_eval_contracts::ScannerCapabilities {
        families: vec![pii_eval_contracts::FamilyCapability {
            family: FamilyId::new(EMAIL).unwrap(),
            state: CapabilityState::Unsupported,
        }],
        ..supported()
    };
    assert_eq!(
        assess(A, None, &e, &f, &one_family_gone).occurrences[0]
            .row
            .type_identity,
        TypeState::NotMeasured
    );
    // The case jurisdiction unsupported.
    let kr_gone = pii_eval_contracts::ScannerCapabilities {
        jurisdictions: vec![pii_eval_contracts::JurisdictionCapability {
            jurisdiction: JurisdictionCode::new("KR").unwrap(),
            state: CapabilityState::Unsupported,
        }],
        ..supported()
    };
    let kr = [valid("occ-a", 7, 20, KR_PHONE)];
    assert_eq!(
        assess(B, Some("KR"), &kr, &[found(7, 20, KR_PHONE)], &kr_gone).occurrences[0]
            .row
            .type_identity,
        TypeState::NotMeasured
    );
    // An invalid-type expectation is also unmeasured without family capability.
    let invalid = [exp(
        "occ-a",
        11,
        27,
        EMAIL,
        ExpectedType::Invalid,
        SensitivityExpectation::NonSensitive,
    )];
    assert_eq!(
        assess(A, None, &invalid, &[], &no_family).occurrences[0]
            .row
            .type_identity,
        TypeState::NotMeasured
    );
    // Ranges unsupported: nothing can be matched, every axis is unmeasured.
    let no_ranges = pii_eval_contracts::ScannerCapabilities {
        ranges: CapabilityState::Unsupported,
        ..supported()
    };
    let a = assess(A, None, &e, &f, &no_ranges);
    assert!(a.findings.is_empty() && a.reported.is_empty());
    assert_eq!(a.occurrences[0].row.range, RangeState::NotApplicable);
    assert_eq!(a.occurrences[0].row.type_identity, TypeState::NotMeasured);
}

#[test]
fn a_scanner_that_did_not_complete_measured_nothing() {
    let e = [valid("occ-a", 11, 27, EMAIL), valid("occ-b", 15, 22, EMAIL)];
    for status in [
        ScannerStatus::Unsupported,
        ScannerStatus::Unavailable,
        ScannerStatus::Error,
        ScannerStatus::Unstable,
    ] {
        // Even bogus findings are not read.
        let bogus = [found(0, 999, EMAIL)];
        let a = assess_variant(
            &VariantInput {
                text: A,
                case_jurisdiction: None,
                expectations: &e,
            },
            &ScannerView {
                status,
                capabilities: &supported(),
                findings: &bogus,
            },
        )
        .unwrap();
        assert_eq!(a.occurrences.len(), 2);
        for o in &a.occurrences {
            assert_eq!(o.row.type_identity, TypeState::NotMeasured);
            assert_eq!(o.row.sensitivity_context, SensitivityState::NotMeasured);
            assert_eq!(o.row.range, RangeState::NotApplicable);
            assert_eq!(o.row.action, ActionOutcome::NotMeasured);
            assert_eq!(o.observed.finding_count, 0);
        }
    }
}

#[test]
fn rows_always_satisfy_the_contract_lattice() {
    let family = FamilyId::new(EMAIL).unwrap();
    let kr = JurisdictionCode::new("KR").unwrap();
    let variants: [(
        Option<&JurisdictionCode>,
        ExpectedType,
        SensitivityExpectation,
    ); 4] = [
        (None, ExpectedType::Valid, SensitivityExpectation::Sensitive),
        (
            None,
            ExpectedType::Invalid,
            SensitivityExpectation::NonSensitive,
        ),
        (
            Some(&kr),
            ExpectedType::Valid,
            SensitivityExpectation::NotEstablished,
        ),
        (
            None,
            ExpectedType::Valid,
            SensitivityExpectation::NonSensitive,
        ),
    ];
    let states = [
        CapabilityState::Supported,
        CapabilityState::Unsupported,
        CapabilityState::Undeclared,
    ];
    let actions = [
        ActionCapability::Unavailable,
        ActionCapability::ReportedAction,
        ActionCapability::SanitizedOutput,
    ];
    let findings = [
        vec![],
        vec![found(11, 27, EMAIL)],
        vec![with_sensitive(without_family(found(9, 28, EMAIL)), None)],
        vec![with_jurisdiction(found(11, 20, "pii:us:email"), "US")],
    ];
    for (jur, ty, sens) in variants {
        for fam in states {
            for sensitivity in states {
                for jurisdiction in states {
                    for action in actions {
                        let c = pii_eval_contracts::ScannerCapabilities {
                            ranges: CapabilityState::Supported,
                            family_classification: fam,
                            sensitivity_classification: sensitivity,
                            jurisdiction_reporting: jurisdiction,
                            action,
                            families: vec![],
                            jurisdictions: vec![],
                        };
                        for fs in &findings {
                            // Observation validation forbids reporting an
                            // unsupported field; keep only legal findings.
                            let legal: Vec<Finding> = fs
                                .iter()
                                .map(|f| {
                                    let mut f = f.clone();
                                    if fam == CapabilityState::Unsupported {
                                        f.family = None;
                                    }
                                    if jurisdiction == CapabilityState::Unsupported {
                                        f.jurisdiction = None;
                                    }
                                    if sensitivity == CapabilityState::Unsupported {
                                        f.sensitive = None;
                                    }
                                    if action == ActionCapability::Unavailable {
                                        f.action = None;
                                    }
                                    f
                                })
                                .collect();
                            let e = [exp("occ-a", 11, 27, EMAIL, ty, sens)];
                            let a = assess(A, jur.map(JurisdictionCode::as_str), &e, &legal, &c);
                            let authored = AuthoredAxes {
                                expected_type: ty,
                                sensitivity: sens,
                                range_established: true,
                                family: &family,
                                jurisdiction: jur,
                            };
                            assert_eq!(
                                validate_outcome_lattice(
                                    &authored,
                                    ScannerStatus::Complete,
                                    &c,
                                    &a.occurrences[0].row
                                ),
                                Ok(()),
                                "{:?}",
                                a.occurrences[0].row
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn geometry_helpers_are_total_on_unvalidated_ranges() {
    // Empty and inverted ranges must not panic (no overflow in debug or release).
    let shapes = [
        range(5, 3),
        range(0, 0),
        range(3, 3),
        range(0, u64::MAX),
        range(u64::MAX, 0),
        range(u64::MAX, u64::MAX),
        range(0, 10),
    ];
    for a in &shapes {
        for b in &shapes {
            let _ = relation(a, b);
            let _ = pii_eval_kernel::overlaps(a, b);
            let _ = closeness(a, b);
            let _ = pii_eval_kernel::range_state(a, Some(b));
        }
    }
    // Hand check: expected [5,3) (length saturates to 0) against [0,10):
    // overlap test 5 < 10 && 0 < 3 holds; reported contains expected (0 <= 5,
    // 10 >= 3), not equal: overbroad with extra 10 - 0 = 10.
    assert_eq!(closeness(&range(5, 3), &range(0, 10)), Some((1, 10)));
}

#[test]
fn a_finding_reporting_more_fields_is_not_shadowed_by_an_equal_one_reporting_less() {
    // Two exact findings on [11,27), same family. F1 reports no sensitivity and
    // no action; F2 reports sensitive=true and action=redact. F1 sorts first
    // (absent before present), but completeness (3 - 0 = 3 vs 3 - 2 = 1) makes
    // F2 primary in either input order.
    let e = [valid("occ-a", 11, 27, EMAIL)];
    let f1 = with_sensitive(found(11, 27, EMAIL), None);
    let f2 = with_action(found(11, 27, EMAIL), ActionKind::Redact);
    for order in [[f1.clone(), f2.clone()], [f2.clone(), f1.clone()]] {
        let a = assess(A, None, &e, &order, &supported());
        let row = a.occurrences[0].row;
        assert_eq!(row.sensitivity_context, SensitivityState::Correct);
        assert_eq!(
            row.action,
            ActionOutcome::Reported {
                action: ActionKind::Redact
            }
        );
        assert_eq!(a.occurrences[0].observed.finding_count, 2);
    }
}

#[test]
fn unsupported_ranges_leave_every_axis_unmeasured_without_reading_findings() {
    let e = [valid("occ-a", 11, 27, EMAIL)];
    let caps = pii_eval_contracts::ScannerCapabilities {
        ranges: CapabilityState::Unsupported,
        ..supported()
    };
    // Even an invalid finding range is not read.
    let a = assess(A, None, &e, &[found(0, 9_999, EMAIL)], &caps);
    let row = a.occurrences[0].row;
    assert_eq!(row.type_identity, TypeState::NotMeasured);
    assert_eq!(row.sensitivity_context, SensitivityState::NotMeasured);
    assert_eq!(row.range, RangeState::NotApplicable);
    assert_eq!(row.action, ActionOutcome::NotMeasured);
}
