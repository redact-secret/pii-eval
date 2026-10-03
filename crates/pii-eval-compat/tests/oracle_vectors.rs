//! Frozen vectors derived by hand from the oracle source
//! (`contract-model.ts`, `rangeOutcome` / `interpretPiiOutcome` /
//! `overlaps`, oracle commit 4b846967346505baca11e0b98cab1475fbce6773), NOT
//! from `legacy.rs` output. Each comment shows the oracle evaluation.
//!
//! Candidate is [10, 20).

mod common;

use common::*;
use pii_eval_contracts::{
    ExpectedType, FamilyId, Finding, JurisdictionCode, RangeState, SensitivityExpectation,
    SensitivityState, TypeState,
};

fn case(ty: ExpectedType, sens: SensitivityExpectation, family: &str, jur: Option<&str>) -> Case {
    Case {
        candidate: range(10, 20),
        expected_type: ty,
        family: FamilyId::new(family).unwrap(),
        jurisdiction: jur.map(|j| JurisdictionCode::new(j).unwrap()),
        sensitivity: sens,
    }
}

fn f(start: u64, end: u64, family: Option<&str>, jur: Option<&str>, sens: Option<bool>) -> Finding {
    Finding {
        range: range(start, end),
        family: family.map(|x| FamilyId::new(x).unwrap()),
        jurisdiction: jur.map(|j| JurisdictionCode::new(j).unwrap()),
        sensitive: sens,
        action: None,
    }
}

#[test]
fn range_outcome_vectors() {
    let c = case(
        ExpectedType::Valid,
        SensitivityExpectation::Sensitive,
        EMAIL,
        None,
    );
    // (10,20): start==start && end==end -> exact
    // (5,25): 5<=10 && 25>=20 -> overbroad
    // (10,25): 10<=10 && 25>=20 -> overbroad
    // (12,18): not exact, not containing; overlaps 10<18 && 12<20 -> partial
    // (15,30): 15<=10 false; overlaps 10<30 && 15<20 -> partial
    // (20,30): overlaps needs 20<20, false -> filtered out -> miss
    // (0,10): overlaps needs 10<10, false -> miss
    for ((s, e), want) in [
        ((10, 20), RangeState::Exact),
        ((5, 25), RangeState::Overbroad),
        ((10, 25), RangeState::Overbroad),
        ((12, 18), RangeState::Partial),
        ((15, 30), RangeState::Partial),
        ((20, 30), RangeState::Miss),
        ((0, 10), RangeState::Miss),
    ] {
        assert_eq!(
            legacy(&c, &[f(s, e, Some(EMAIL), None, Some(true))]).range,
            want,
            "[{s},{e})"
        );
    }
}

#[test]
fn first_overlap_and_axis_vectors() {
    use ExpectedType::{Invalid, Valid};
    use SensitivityExpectation::{NonSensitive, NotEstablished, Sensitive};
    // findings = [(0,5) phone, (12,14) phone, (10,20) email]: the filter drops
    // (0,5) (10<5 false); first kept = (12,14) phone -> family != expected and
    // the scope is global, so wrong-family; range partial; sensitive===true so
    // the sensitive expectation is correct; two overlapping findings.
    let c = case(Valid, Sensitive, EMAIL, None);
    let out = legacy(
        &c,
        &[
            f(0, 5, Some(PHONE), None, Some(true)),
            f(12, 14, Some(PHONE), None, Some(true)),
            f(10, 20, Some(EMAIL), None, Some(true)),
        ],
    );
    assert_eq!(out.type_identity, TypeState::WrongFamily);
    assert_eq!(out.range, RangeState::Partial);
    assert_eq!(out.sensitivity_context, SensitivityState::Correct);
    assert_eq!(out.observed.finding_count, 2);

    // invalid + overlap (15,16) -> invalid-accepted; non-sensitive with
    // sensitive !== true -> correct.
    let c = case(Invalid, NonSensitive, EMAIL, None);
    let out = legacy(&c, &[f(15, 16, Some(PHONE), None, None)]);
    assert_eq!(out.type_identity, TypeState::InvalidAccepted);
    assert_eq!(out.sensitivity_context, SensitivityState::Correct);

    // valid, first overlapping finding has no family -> not-measured, even
    // though a later finding is right.
    let c = case(Valid, Sensitive, EMAIL, None);
    let out = legacy(
        &c,
        &[
            f(10, 20, None, None, Some(true)),
            f(10, 20, Some(EMAIL), None, Some(true)),
        ],
    );
    assert_eq!(out.type_identity, TypeState::NotMeasured);

    // not-established -> unresolved whatever is found.
    let c = case(Valid, NotEstablished, EMAIL, None);
    assert_eq!(
        legacy(&c, &[]).sensitivity_context,
        SensitivityState::Unresolved
    );

    // jurisdiction KR, family pii:kr:phone:
    //  family equal, jurisdiction absent -> not-measured
    //  family equal, jurisdiction US -> wrong-jurisdiction
    //  family differs, jurisdiction US != KR -> wrong-jurisdiction
    //  family differs, jurisdiction absent -> wrong-family
    let c = case(Valid, Sensitive, "pii:kr:phone", Some("KR"));
    let t = |fam, jur| legacy(&c, &[f(10, 20, Some(fam), jur, Some(true))]).type_identity;
    assert_eq!(t("pii:kr:phone", None), TypeState::NotMeasured);
    assert_eq!(t("pii:kr:phone", Some("US")), TypeState::WrongJurisdiction);
    assert_eq!(t("pii:us:phone", Some("US")), TypeState::WrongJurisdiction);
    assert_eq!(t("pii:us:phone", None), TypeState::WrongFamily);
    assert_eq!(t("pii:kr:phone", Some("KR")), TypeState::Correct);
}
