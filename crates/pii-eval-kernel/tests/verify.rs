//! The metric verifier (the P2 item deferred to P4): published values against
//! counts, and counts against the outcome rows.
//!
//! The artifact is the committed contract fixture reduced to its complete
//! scanner (`alpha-scan`); its metrics are replaced by the accounting of its own
//! rows. Expected counts and values were derived by hand from the fixture's rows
//! (three authored cases: a US collision case, a Korean context trio and a
//! two-variant type-validation case) and the independent decimal reference.

use std::path::Path;

use pii_eval_contracts::{
    CorpusSnapshot, MetricId, MetricResult, MetricValue, ReasonCode, RunArtifact, ScaledDecimal,
    WithheldReason, parse_default, seal, validate,
};
use pii_eval_kernel::{
    AccountError, AuthoredIndex, ScannerInput, VerifyFailure, account_outcomes,
    verify_metric_result, verify_public_artifact_accounting, verify_run_artifact_accounting,
};

fn read(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/contracts/v1")
        .join(name);
    std::fs::read(path).expect("fixture exists")
}

fn fixtures() -> (CorpusSnapshot, RunArtifact) {
    (
        parse_default(&read("snapshot.json")).expect("snapshot"),
        parse_default(&read("run-artifact.json")).expect("artifact"),
    )
}

/// The complete scanner only, with a minimum denominator of 1 so every metric
/// that has a sample publishes a value, and metrics recomputed from the rows.
fn single_scanner(snapshot: &CorpusSnapshot, mut artifact: RunArtifact) -> RunArtifact {
    let body = &mut artifact.semantic;
    body.scanners
        .retain(|s| s.identity.scanner_id.as_str() == "alpha-scan");
    body.outcomes
        .retain(|o| o.scanner_id.as_str() == "alpha-scan");
    body.failures.clear();
    body.mechanics.min_denominator = 1;
    let index = AuthoredIndex::new(&snapshot.semantic).unwrap();
    let id = body.scanners[0].identity.scanner_id.clone();
    let accounting = account_outcomes(
        &index,
        &[ScannerInput {
            id: &id,
            status: body.scanners[0].status,
        }],
        &body.outcomes,
        &body.mechanics,
    )
    .unwrap();
    body.metrics = accounting.scanners[0].overall.results();
    seal(&mut artifact).unwrap();
    artifact
}

fn resealed(mut artifact: RunArtifact, edit: impl FnOnce(&mut RunArtifact)) -> RunArtifact {
    edit(&mut artifact);
    seal(&mut artifact).unwrap();
    artifact
}

fn metric_mut(a: &mut RunArtifact, id: MetricId) -> &mut MetricResult {
    a.semantic
        .metrics
        .iter_mut()
        .find(|m| m.metric.id == id)
        .unwrap()
}

fn dec(mantissa: u64) -> ScaledDecimal {
    ScaledDecimal::new(mantissa, 6).unwrap()
}

fn mismatch_codes(err: VerifyFailure) -> Vec<ReasonCode> {
    match err {
        VerifyFailure::Mismatch(v) => v.errors.iter().map(|e| e.code).collect(),
        other => panic!("expected a mismatch, got {other:?}"),
    }
}

#[test]
fn the_reduced_fixture_verifies_and_matches_the_hand_derived_values() {
    let (snapshot, artifact) = fixtures();
    let artifact = single_scanner(&snapshot, artifact);
    // The contracts accept it, and so does the verifier.
    validate(&artifact).expect("contract-valid");
    verify_run_artifact_accounting(&artifact, &snapshot).expect("verifies");
    // (metric, numerator, effective N, point, bound); wrong-jurisdiction has the
    // one jurisdictional case (the US collision case).
    let hand: [(MetricId, u64, u64, u64, u64); 8] = [
        (MetricId::TypeMissRate, 0, 3, 0, 561_506),
        (MetricId::WrongJurisdictionRate, 0, 1, 0, 793_457),
        (MetricId::SensitiveMissRate, 0, 3, 0, 561_506),
        (MetricId::NonSensitiveFlagRate, 0, 2, 0, 657_628),
        (
            MetricId::ContextDiscriminationRate,
            1,
            1,
            1_000_000,
            206_543,
        ),
        (
            MetricId::JurisdictionCollisionRate,
            1,
            1,
            1_000_000,
            206_543,
        ),
        (MetricId::RangeCollateralRate, 1, 3, 333_333, 792_345),
        (MetricId::MeasurableShare, 5, 6, 833_333, 436_491),
    ];
    for (id, numerator, n, point, bound) in hand {
        let m = artifact
            .semantic
            .metrics
            .iter()
            .find(|m| m.metric.id == id)
            .unwrap();
        assert_eq!(m.counts.numerator, numerator, "{id:?}");
        assert_eq!(m.effective_n, n, "{id:?}");
        let expected = MetricValue::Measured {
            point: ScaledDecimal::new(point, 6).unwrap(),
            bound: ScaledDecimal::new(bound, 6).unwrap(),
        };
        assert_eq!(m.value, expected, "{id:?}");
    }
    // No benign case exists: not applicable, zero denominator.
    let benign = artifact
        .semantic
        .metrics
        .iter()
        .find(|m| m.metric.id == MetricId::BenignSuppressionRate)
        .unwrap();
    assert_eq!(benign.counts.eligible, 0);
    assert_eq!(
        benign.value,
        MetricValue::Withheld {
            reason: WithheldReason::ZeroDenominator
        }
    );
    // The public projection verifies the same way.
    let public = artifact.to_public_synthetic().expect("public synthetic");
    verify_public_artifact_accounting(&public, &snapshot).expect("public verifies");
}

#[test]
fn a_point_or_bound_off_by_one_digit_is_caught_though_contracts_accept_it() {
    let (snapshot, artifact) = fixtures();
    let base = single_scanner(&snapshot, artifact);
    for (field_point, delta) in [(true, 1i64), (false, 1), (true, -1), (false, -1)] {
        let tampered = resealed(base.clone(), |a| {
            let m = metric_mut(a, MetricId::MeasurableShare);
            if let MetricValue::Measured { point, bound } = &mut m.value {
                let d = if field_point { point } else { bound };
                *d = dec((d.mantissa as i64 + delta) as u64);
            }
        });
        // Structural validation (the contracts) cannot see it...
        validate(&tampered).expect("contract validation does not recompute values");
        // ...the kernel verifier does.
        assert_eq!(
            mismatch_codes(verify_run_artifact_accounting(&tampered, &snapshot).unwrap_err()),
            [ReasonCode::MetricValueInconsistent]
        );
    }
    // A published value where the count says withheld, and vice versa.
    let tampered = resealed(base.clone(), |a| {
        metric_mut(a, MetricId::BenignSuppressionRate).value = MetricValue::Measured {
            point: dec(0),
            bound: dec(0),
        };
    });
    assert!(
        !mismatch_codes(verify_run_artifact_accounting(&tampered, &snapshot).unwrap_err())
            .is_empty()
    );
    let tampered = resealed(base, |a| {
        metric_mut(a, MetricId::TypeMissRate).value = MetricValue::Withheld {
            reason: WithheldReason::InsufficientEvidence,
        };
    });
    assert_eq!(
        mismatch_codes(verify_run_artifact_accounting(&tampered, &snapshot).unwrap_err()),
        [ReasonCode::MetricValueInconsistent]
    );
}

#[test]
fn counts_that_do_not_conserve_against_the_rows_are_caught() {
    let (snapshot, artifact) = fixtures();
    let base = single_scanner(&snapshot, artifact);
    // Move one sample from `other` to the numerator: every identity still holds,
    // and the value is recomputed to match, so only the rows can expose it.
    let tampered = resealed(base.clone(), |a| {
        let mechanics = a.semantic.mechanics;
        let m = metric_mut(a, MetricId::TypeMissRate);
        m.counts.numerator += 1;
        m.value = pii_eval_kernel::published_value(
            m.counts.numerator,
            m.effective_n,
            MetricId::TypeMissRate.definition().direction,
            &mechanics,
        )
        .unwrap();
    });
    validate(&tampered).expect("contract-valid: identities hold");
    assert_eq!(
        mismatch_codes(verify_run_artifact_accounting(&tampered, &snapshot).unwrap_err()),
        [ReasonCode::CountMismatch]
    );
    // Shift one eligible sample to not-applicable (identities still hold).
    let tampered = resealed(base, |a| {
        let m = metric_mut(a, MetricId::SensitiveMissRate);
        m.counts.eligible -= 1;
        m.counts.measured -= 1;
        m.counts.not_applicable += 1;
        m.effective_n -= 1;
        m.value = MetricValue::Withheld {
            reason: WithheldReason::InsufficientEvidence,
        };
    });
    // contracts might accept the identities; the verifier must not accept the rows.
    assert!(verify_run_artifact_accounting(&tampered, &snapshot).is_err());
}

#[test]
fn metric_results_are_checked_on_their_own_too() {
    let (snapshot, artifact) = fixtures();
    let base = single_scanner(&snapshot, artifact);
    let mechanics = base.semantic.mechanics;
    for m in &base.semantic.metrics {
        verify_metric_result(m, &mechanics).expect("consistent");
    }
    let mut m = *base
        .semantic
        .metrics
        .iter()
        .find(|m| m.metric.id == MetricId::MeasurableShare)
        .unwrap();
    // Value contradicts counts.
    if let MetricValue::Measured { bound, .. } = &mut m.value {
        *bound = dec(bound.mantissa + 1);
    }
    assert!(
        verify_metric_result(&m, &mechanics)
            .unwrap_err()
            .contains(ReasonCode::MetricValueInconsistent)
    );
    // The same result under another precision is a different value.
    let finer = pii_eval_contracts::Mechanics {
        interval_precision: 4,
        ..mechanics
    };
    let original = base
        .semantic
        .metrics
        .iter()
        .find(|m| m.metric.id == MetricId::MeasurableShare)
        .unwrap();
    assert!(
        verify_metric_result(original, &finer)
            .unwrap_err()
            .contains(ReasonCode::MetricValueInconsistent)
    );
    // Numerator above the effective N is a counts error, never clamped.
    let mut m = *original;
    m.counts.numerator = m.counts.measured + 1;
    assert!(
        verify_metric_result(&m, &mechanics)
            .unwrap_err()
            .contains(ReasonCode::MetricCountsInconsistent)
    );
    // Wrong definition version.
    let mut m = *original;
    m.metric.version = 2;
    assert!(
        verify_metric_result(&m, &mechanics)
            .unwrap_err()
            .contains(ReasonCode::MetricDefinitionMismatch)
    );
}

#[test]
fn the_stock_two_scanner_fixture_cannot_attribute_its_single_metric_list() {
    // Schema 1.0 has one metric list per artifact, so with two scanners the
    // metrics belong to no scanner: not verifiable (ADR 0005, R2 requirements).
    let (snapshot, artifact) = fixtures();
    assert_eq!(
        verify_run_artifact_accounting(&artifact, &snapshot).unwrap_err(),
        VerifyFailure::MetricScopeAmbiguous { scanners: 2 }
    );
}

#[test]
fn the_stock_fixtures_hand_written_metrics_do_not_match_its_rows() {
    // The P2 fixture's metrics are structural placeholders. Reduced to one
    // scanner but keeping them, the verifier shows they are not the accounting
    // of the rows.
    let (snapshot, mut artifact) = fixtures();
    let body = &mut artifact.semantic;
    body.scanners
        .retain(|s| s.identity.scanner_id.as_str() == "alpha-scan");
    body.outcomes
        .retain(|o| o.scanner_id.as_str() == "alpha-scan");
    body.failures.clear();
    seal(&mut artifact).unwrap();
    validate(&artifact).expect("contract-valid");
    let codes = mismatch_codes(verify_run_artifact_accounting(&artifact, &snapshot).unwrap_err());
    assert!(codes.contains(&ReasonCode::CountMismatch));
}

#[test]
fn missing_and_duplicate_rows_are_typed_errors() {
    let (snapshot, artifact) = fixtures();
    let base = single_scanner(&snapshot, artifact);
    let missing = resealed(base.clone(), |a| {
        a.semantic.outcomes.pop();
        a.semantic.completeness = pii_eval_contracts::Completeness::Partial;
    });
    assert!(matches!(
        verify_run_artifact_accounting(&missing, &snapshot).unwrap_err(),
        VerifyFailure::Accounting(AccountError::MissingRows { .. }) | VerifyFailure::Mismatch(_)
    ));
    let duplicate = resealed(base, |a| {
        let first = a.semantic.outcomes[0].clone();
        a.semantic.outcomes[1] = first;
    });
    assert!(matches!(
        verify_run_artifact_accounting(&duplicate, &snapshot).unwrap_err(),
        VerifyFailure::Accounting(AccountError::DuplicateRow(_)) | VerifyFailure::Mismatch(_)
    ));
}

#[test]
fn verification_is_deterministic_and_order_independent() {
    let (snapshot, artifact) = fixtures();
    let base = single_scanner(&snapshot, artifact);
    for _ in 0..3 {
        verify_run_artifact_accounting(&base, &snapshot).unwrap();
    }
    // The accounting does not read row order: a reversed (non-canonical) row
    // list gives the same metrics, so only the contracts' canonical-order rule
    // rejects it, never a different count.
    let mut reversed = base.clone();
    reversed.semantic.outcomes.reverse();
    let index = AuthoredIndex::new(&snapshot.semantic).unwrap();
    let id = reversed.semantic.scanners[0].identity.scanner_id.clone();
    let reversed_accounting = account_outcomes(
        &index,
        &[ScannerInput {
            id: &id,
            status: reversed.semantic.scanners[0].status,
        }],
        &reversed.semantic.outcomes,
        &reversed.semantic.mechanics,
    )
    .unwrap();
    assert_eq!(
        reversed_accounting.scanners[0].overall.results(),
        base.semantic.metrics
    );
}

#[test]
fn the_public_projection_is_verified_and_tampering_is_caught() {
    let (snapshot, artifact) = fixtures();
    let internal = single_scanner(&snapshot, artifact);
    let public = internal.to_public_synthetic().expect("public synthetic");
    verify_public_artifact_accounting(&public, &snapshot).expect("verifies");
    // A published bound off by one digit, resealed so the digest still matches.
    let mut tampered = public.clone();
    let m = tampered
        .semantic
        .metrics
        .iter_mut()
        .find(|m| m.metric.id == MetricId::TypeMissRate)
        .unwrap();
    if let MetricValue::Measured { bound, .. } = &mut m.value {
        *bound = dec(bound.mantissa + 1);
    }
    seal(&mut tampered).unwrap();
    pii_eval_contracts::validate(&tampered).expect("contract validation does not recompute values");
    assert_eq!(
        mismatch_codes(verify_public_artifact_accounting(&tampered, &snapshot).unwrap_err()),
        [ReasonCode::MetricValueInconsistent]
    );
    // Verified against another population's snapshot.
    let mut other = snapshot.clone();
    other.semantic_digest = pii_eval_contracts::Sha256Digest::of_bytes(b"another population");
    assert_eq!(
        mismatch_codes(verify_public_artifact_accounting(&public, &other).unwrap_err()),
        [ReasonCode::PopulationBindingMismatch]
    );
}
