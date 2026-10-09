//! The classified difference list between `legacy-first-overlap` (protocol
//! revision 1) and `pii-v1-canonical` (proposed revision 2), as executable
//! evidence. Each test names the difference id used in
//! `docs/adr/0004-order-invariant-pii-matching.md`; the ADR and this file must
//! change together.
//!
//! Vectors use the layout `A` documented in `legacy_first_overlap.rs`: the
//! email occurrence is bytes 11..27.

mod common;

use SensitivityExpectation::{NonSensitive, Sensitive};
use common::*;
use pii_eval_contracts::{
    ActionCapability, CapabilityState, ExpectedType, Finding, RangeState, ScannerCapabilities,
    SensitivityExpectation, SensitivityState, TypeState,
};
use pii_eval_kernel::AssessError;

fn rows(o: &pii_eval_kernel::OccurrenceAssessment) -> (TypeState, SensitivityState, RangeState) {
    (o.row.type_identity, o.row.sensitivity_context, o.row.range)
}

#[test]
fn d1_selection_no_longer_depends_on_order() {
    let case = Case::email(Sensitive);
    // Partial wrong-family first / exact right-family second, and a wide
    // finding before an exact one.
    let pairs = [
        (found(11, 14, PHONE), found(11, 27, EMAIL)),
        (found(0, 37, EMAIL), found(11, 27, EMAIL)),
    ];
    for (loose, tight) in pairs {
        let forward = [loose.clone(), tight.clone()];
        let backward = [tight.clone(), loose.clone()];
        // Legacy: the first finding wins, so the two orders disagree.
        let (lf, lb) = (legacy(&case, &forward), legacy(&case, &backward));
        assert_eq!(lf.range, range_of(&loose));
        assert_eq!(lb.range, RangeState::Exact);
        assert_ne!(lf.range, lb.range);
        // Canonical: the closest candidate wins in both orders.
        let (cf, cb) = (canonical(&case, &forward), canonical(&case, &backward));
        assert_eq!(cf, cb);
        assert_eq!(cf.row.range, RangeState::Exact);
        assert_eq!(cf.row.type_identity, TypeState::Correct);
    }
}

fn range_of(f: &Finding) -> RangeState {
    // Hand-checked: [11,14) is partial, [0,37) is overbroad, over [11,27).
    match (f.range.start, f.range.end) {
        (11, 14) => RangeState::Partial,
        (0, 37) => RangeState::Overbroad,
        other => panic!("unexpected vector {other:?}"),
    }
}

#[test]
fn d2_stored_findings_are_in_canonical_order_not_emission_order() {
    // The oracle saw scanner emission order. A contract document stores the
    // canonical order (ascending range), which can move a different finding
    // first. Emission order: exact email, then overbroad phone [9,28).
    let case = Case::email(Sensitive);
    let emission = [found(11, 27, EMAIL), found(9, 28, PHONE)];
    let mut stored = emission.clone();
    stored.sort();
    assert_eq!(stored[0].range, range(9, 28));
    let on_emission = legacy(&case, &emission);
    let on_stored = legacy(&case, &stored);
    assert_eq!(
        (on_emission.type_identity, on_emission.range),
        (TypeState::Correct, RangeState::Exact)
    );
    assert_eq!(
        (on_stored.type_identity, on_stored.range),
        (TypeState::WrongFamily, RangeState::Overbroad)
    );
    // The canonical rule gives one answer for both.
    assert_eq!(canonical(&case, &emission), canonical(&case, &stored));
}

#[test]
fn d3_a_finding_that_does_not_answer_sensitivity_is_not_a_negative_answer() {
    let silent = Finding {
        sensitive: None,
        ..found(11, 27, EMAIL)
    };
    let s = Case::email(Sensitive);
    assert_eq!(
        legacy(&s, std::slice::from_ref(&silent)).sensitivity_context,
        SensitivityState::Miss
    );
    assert_eq!(
        canonical(&s, std::slice::from_ref(&silent))
            .row
            .sensitivity_context,
        SensitivityState::NotMeasured
    );
    let n = Case::email(NonSensitive);
    assert_eq!(
        legacy(&n, std::slice::from_ref(&silent)).sensitivity_context,
        SensitivityState::Correct
    );
    assert_eq!(
        canonical(&n, &[silent]).row.sensitivity_context,
        SensitivityState::NotMeasured
    );
}

#[test]
fn d4_no_finding_is_negative_sensitivity_evidence_only_with_declared_support() {
    let undeclared = ScannerCapabilities {
        sensitivity_classification: CapabilityState::Undeclared,
        ..supported()
    };
    for (expectation, legacy_state) in [
        (Sensitive, SensitivityState::Miss),
        (NonSensitive, SensitivityState::Correct),
    ] {
        let case = Case::email(expectation);
        assert_eq!(legacy(&case, &[]).sensitivity_context, legacy_state);
        // Supported: unchanged.
        assert_eq!(canonical(&case, &[]).row.sensitivity_context, legacy_state);
        // Undeclared: legacy cannot tell the difference, canonical can.
        assert_eq!(
            canonical_with(A, &case, &[], &undeclared)
                .row
                .sensitivity_context,
            SensitivityState::NotMeasured
        );
    }
}

#[test]
fn d5_legacy_ignores_declared_capability() {
    let no_family = ScannerCapabilities {
        family_classification: CapabilityState::Unsupported,
        ..supported()
    };
    // An invalid-type expectation: legacy classifies from overlap alone.
    let invalid = Case {
        expected_type: ExpectedType::Invalid,
        ..Case::email(NonSensitive)
    };
    let overlap = [Finding {
        family: None,
        ..found(11, 27, EMAIL)
    }];
    assert_eq!(
        legacy(&invalid, &overlap).type_identity,
        TypeState::InvalidAccepted
    );
    assert_eq!(
        canonical_with(A, &invalid, &overlap, &no_family)
            .row
            .type_identity,
        TypeState::NotMeasured
    );
    assert_eq!(
        legacy(&invalid, &[]).type_identity,
        TypeState::InvalidCorrect
    );
    assert_eq!(
        canonical_with(A, &invalid, &[], &no_family)
            .row
            .type_identity,
        TypeState::NotMeasured
    );
    // Action capability unavailable: legacy has no action axis at all.
    let no_action = ScannerCapabilities {
        action: ActionCapability::Unavailable,
        ..supported()
    };
    let valid = Case::email(Sensitive);
    assert_eq!(
        canonical_with(A, &valid, &[found(11, 27, EMAIL)], &no_action)
            .row
            .action,
        pii_eval_contracts::ActionOutcome::NotMeasured
    );
}

#[test]
fn d6_degenerate_and_invalid_ranges_are_rejected_not_matched() {
    let case = Case::email(Sensitive);
    // Legacy matches an empty finding strictly inside the candidate and an
    // inverted one (see legacy_first_overlap.rs); canonical refuses them.
    for degenerate in [
        found(20, 20, EMAIL),
        found(25, 13, EMAIL),
        found(0, 9_999, EMAIL),
        found(2, 12, EMAIL),
    ] {
        assert_eq!(
            legacy(&case, std::slice::from_ref(&degenerate))
                .observed
                .finding_count,
            1
        );
        let e = [pii_eval_contracts::Expectation {
            evidence: None,
            occurrence_id: pii_eval_contracts::Id::new("occ-a").unwrap(),
            range: Some(case.candidate),
            family: case.family.clone(),
            type_expectation: ExpectedType::Valid,
            validator: None,
            sensitivity: Sensitive,
            context_class: pii_eval_contracts::ContextClass::Neutral,
            context_obligation: pii_eval_contracts::ContextObligation::None,
            action: pii_eval_contracts::ActionExpectation::NotSpecified,
        }];
        let err = pii_eval_kernel::assess_variant(
            &pii_eval_kernel::VariantInput {
                text: A,
                case_jurisdiction: None,
                expectations: &e,
            },
            &pii_eval_kernel::ScannerView {
                status: pii_eval_contracts::ScannerStatus::Complete,
                capabilities: &supported(),
                findings: std::slice::from_ref(&degenerate),
            },
        )
        .unwrap_err();
        assert!(matches!(err, AssessError::Range { .. }), "{err:?}");
    }
}

#[test]
fn d9_legacy_has_one_candidate_per_variant() {
    // Legacy: one candidate per variant, so one outcome. Canonical: one per
    // occurrence, selected independently. Kernel-side behavior is covered by
    // the kernel's conformance tests; this pins the legacy side of the
    // difference: the legacy interpreter has no way to express two occurrences.
    let case = Case::email(Sensitive);
    let out = legacy(&case, &[found(11, 27, EMAIL)]);
    assert_eq!(out.observed.finding_count, 1);
}

#[test]
fn unchanged_the_observed_summary_counts_every_overlapping_finding() {
    // Same definition on both sides: all overlapping findings, duplicates
    // included, families ascending and unique.
    let case = Case::email(Sensitive);
    let findings = [
        found(11, 27, EMAIL),
        found(11, 27, EMAIL),
        found(9, 28, PHONE),
        found(28, 37, PHONE),
    ];
    let l = legacy(&case, &findings);
    let c = canonical(&case, &findings);
    assert_eq!(l.observed, c.observed);
    assert_eq!(c.observed.finding_count, 3);
}

fn single_candidate_findings(rng: &mut Rng) -> Vec<Finding> {
    let points = [0u64, 9, 10, 11, 14, 15, 22, 27, 28, 31, 37];
    let mut findings: Vec<Finding> = Vec::new();
    let mut have_candidate = false;
    for _ in 0..rng.below(6) {
        let i = rng.below(points.len() - 1);
        let j = i + 1 + rng.below(points.len() - i - 1);
        let mut f = found(points[i], points[j], [EMAIL, PHONE][rng.below(2)]);
        f.sensitive = Some(rng.below(2) == 0);
        let overlapping = f.range.start < 27 && 11 < f.range.end;
        if overlapping {
            if have_candidate {
                continue;
            }
            have_candidate = true;
        }
        findings.push(f);
    }
    findings
}

#[test]
fn legacy_and_canonical_agree_when_there_is_at_most_one_candidate() {
    // Where the revisions are allowed to differ is the list above; with at most
    // one overlapping finding, every field reported and full capabilities,
    // they must agree on every axis the legacy model has.
    let mut rng = Rng(21);
    let mut with_candidate = 0;
    for iteration in 0..3000 {
        let case = Case::email(
            [
                Sensitive,
                NonSensitive,
                SensitivityExpectation::NotEstablished,
            ][rng.below(3)],
        );
        let findings = single_candidate_findings(&mut rng);
        let l = legacy(&case, &findings);
        let c = canonical(&case, &findings);
        assert_eq!(
            l.type_identity, c.row.type_identity,
            "iteration {iteration}"
        );
        assert_eq!(
            l.sensitivity_context, c.row.sensitivity_context,
            "iteration {iteration}"
        );
        assert_eq!(l.range, c.row.range, "iteration {iteration}");
        assert_eq!(l.observed, c.observed, "iteration {iteration}");
        with_candidate += usize::from(l.observed.finding_count == 1);
    }
    assert!(with_candidate > 500, "{with_candidate}");
}

#[test]
fn canonical_never_depends_on_order_where_legacy_does() {
    let mut rng = Rng(31);
    let mut legacy_changed = 0;
    for _ in 0..2000 {
        let case = Case::email(Sensitive);
        let mut findings: Vec<Finding> = (0..2 + rng.below(4))
            .map(|_| {
                let points = [0u64, 9, 11, 14, 22, 27, 28, 37];
                let i = rng.below(points.len() - 1);
                let j = i + 1 + rng.below(points.len() - i - 1);
                found(points[i], points[j], [EMAIL, PHONE][rng.below(2)])
            })
            .collect();
        let (l0, c0) = (legacy(&case, &findings), canonical(&case, &findings));
        rng.shuffle(&mut findings);
        let (l1, c1) = (legacy(&case, &findings), canonical(&case, &findings));
        assert_eq!(rows(&c0), rows(&c1));
        assert_eq!(c0, c1);
        legacy_changed += usize::from((l0.type_identity, l0.range) != (l1.type_identity, l1.range));
    }
    assert!(legacy_changed > 100, "{legacy_changed}");
}

#[test]
fn d11_unsupported_ranges_leave_every_axis_unmeasured() {
    // Legacy has no capability input and measures from the findings it is
    // given; canonical treats a scanner that cannot report ranges as having
    // measured nothing (the contracts' lattice).
    let case = Case::email(Sensitive);
    let findings = [found(11, 27, EMAIL)];
    let l = legacy(&case, &findings);
    assert_eq!(l.range, RangeState::Exact);
    let caps = ScannerCapabilities {
        ranges: CapabilityState::Unsupported,
        ..supported()
    };
    let c = canonical_with(A, &case, &findings, &caps);
    assert_eq!(c.row.range, RangeState::NotApplicable);
    assert_eq!(c.row.type_identity, TypeState::NotMeasured);
    assert_eq!(c.row.sensitivity_context, SensitivityState::NotMeasured);
    assert_eq!(c.row.action, pii_eval_contracts::ActionOutcome::NotMeasured);
}
