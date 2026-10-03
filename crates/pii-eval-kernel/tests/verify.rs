//! The metric verifier (the P2 item deferred to P4), for protocol revision 2:
//! published values against counts, counts against the outcome rows, one
//! scanner at a time.
//!
//! The artifacts are the committed legacy contract fixture (protocol revision
//! 1, schema 1.0) converted to revision 2: protocol identity and schema version
//! changed, and its metrics replaced by the accounting of its own rows, keyed by
//! scanner. Expected counts and values were derived by hand from the fixture's
//! rows (three authored cases: a US collision case, a Korean context trio and a
//! two-variant type-validation case) and the independent decimal reference.

use std::path::Path;

use pii_eval_contracts::{
    CorpusSnapshot, MetricId, MetricResult, MetricValue, ProtocolIdentity, ReasonCode, RunArtifact,
    ScaledDecimal, ScannerId, ScannerMetrics, ScannerStatus, SchemaVersion, WithheldReason,
    parse_default, seal, validate,
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

/// Convert the legacy fixture to revision 2 with a minimum denominator of 1 (so
/// every metric that has a sample publishes a value) and per-scanner metrics
/// recomputed from the rows. `only` keeps one scanner.
fn canonical(
    snapshot: &CorpusSnapshot,
    mut artifact: RunArtifact,
    only: Option<&str>,
) -> RunArtifact {
    {
        let body = &mut artifact.semantic;
        if let Some(name) = only {
            body.scanners
                .retain(|s| s.identity.scanner_id.as_str() == name);
            body.outcomes.retain(|o| o.scanner_id.as_str() == name);
            body.failures.retain(|f| f.scanner_id.as_str() == name);
        }
        body.protocol = ProtocolIdentity::CANONICAL_V2;
        body.mechanics.min_denominator = 1;
        body.metrics.clear();
        let index = AuthoredIndex::new(&snapshot.semantic).unwrap();
        let inputs: Vec<ScannerInput<'_>> = body
            .scanners
            .iter()
            .map(|s| ScannerInput {
                id: &s.identity.scanner_id,
                status: s.status,
            })
            .collect();
        let accounting =
            account_outcomes(&index, &inputs, &body.outcomes, &body.mechanics).unwrap();
        body.scanner_metrics = accounting
            .scanners
            .iter()
            .map(|s| ScannerMetrics {
                scanner_id: s.scanner_id.clone(),
                metrics: s.overall.results(),
            })
            .collect();
    }
    artifact.schema_version = SchemaVersion::V1_1;
    seal(&mut artifact).unwrap();
    artifact
}

fn single_scanner(snapshot: &CorpusSnapshot, artifact: RunArtifact) -> RunArtifact {
    canonical(snapshot, artifact, Some("alpha-scan"))
}

fn resealed(mut artifact: RunArtifact, edit: impl FnOnce(&mut RunArtifact)) -> RunArtifact {
    edit(&mut artifact);
    seal(&mut artifact).unwrap();
    artifact
}

/// The metric `id` of the scanner at `scanner` in the list.
fn metric_mut(a: &mut RunArtifact, scanner: usize, id: MetricId) -> &mut MetricResult {
    a.semantic.scanner_metrics[scanner]
        .metrics
        .iter_mut()
        .find(|m| m.metric.id == id)
        .unwrap()
}

fn metrics_of(a: &RunArtifact, scanner: usize) -> &[MetricResult] {
    &a.semantic.scanner_metrics[scanner].metrics
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
        let m = metrics_of(&artifact, 0)
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
    let benign = metrics_of(&artifact, 0)
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
            let m = metric_mut(a, 0, MetricId::MeasurableShare);
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
        metric_mut(a, 0, MetricId::BenignSuppressionRate).value = MetricValue::Measured {
            point: dec(0),
            bound: dec(0),
        };
    });
    assert!(
        !mismatch_codes(verify_run_artifact_accounting(&tampered, &snapshot).unwrap_err())
            .is_empty()
    );
    let tampered = resealed(base, |a| {
        metric_mut(a, 0, MetricId::TypeMissRate).value = MetricValue::Withheld {
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
        let m = metric_mut(a, 0, MetricId::TypeMissRate);
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
        let m = metric_mut(a, 0, MetricId::SensitiveMissRate);
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
    for m in metrics_of(&base, 0) {
        verify_metric_result(m, &mechanics).expect("consistent");
    }
    let original = *metrics_of(&base, 0)
        .iter()
        .find(|m| m.metric.id == MetricId::MeasurableShare)
        .unwrap();
    let mut m = original;
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
    assert!(
        verify_metric_result(&original, &finer)
            .unwrap_err()
            .contains(ReasonCode::MetricValueInconsistent)
    );
    // Numerator above the effective N is a counts error, never clamped.
    let mut m = original;
    m.counts.numerator = m.counts.measured + 1;
    assert!(
        verify_metric_result(&m, &mechanics)
            .unwrap_err()
            .contains(ReasonCode::MetricCountsInconsistent)
    );
    // Wrong definition version.
    let mut m = original;
    m.metric.version = 2;
    assert!(
        verify_metric_result(&m, &mechanics)
            .unwrap_err()
            .contains(ReasonCode::MetricDefinitionMismatch)
    );
}

#[test]
fn a_two_scanner_artifact_is_verified_scanner_by_scanner() {
    // Schema 1.0 had one unkeyed list, so a multi-scanner artifact could not be
    // verified (ADR 0005 section 8). Revision 2 keys the metrics by scanner.
    let (snapshot, artifact) = fixtures();
    let base = canonical(&snapshot, artifact, None);
    let ids: Vec<&str> = base
        .semantic
        .scanner_metrics
        .iter()
        .map(|m| m.scanner_id.as_str())
        .collect();
    assert_eq!(ids, ["alpha-scan", "beta-scan"]);
    validate(&base).expect("contract-valid");
    verify_run_artifact_accounting(&base, &snapshot).expect("both scanners verify");
    // The unsupported scanner measured nothing: every metric is eligible and
    // not-measured or not-applicable, never a success.
    for m in metrics_of(&base, 1) {
        assert_eq!(m.counts.measured, 0, "{:?}", m.metric.id);
        assert_eq!(m.counts.numerator, 0, "{:?}", m.metric.id);
    }
    // The other scanner's numbers are not pooled into it.
    assert!(metrics_of(&base, 0).iter().any(|m| m.counts.measured > 0));

    // Tampering with one scanner's metric is reported against that scanner.
    let tampered = resealed(base.clone(), |a| {
        metric_mut(a, 1, MetricId::TypeMissRate).counts.numerator = 1;
    });
    assert!(verify_run_artifact_accounting(&tampered, &snapshot).is_err());

    // Swapping the two scanners' lists is caught: each is verified against its own rows.
    let swapped = resealed(base.clone(), |a| {
        let (left, right) = a.semantic.scanner_metrics.split_at_mut(1);
        std::mem::swap(&mut left[0].metrics, &mut right[0].metrics);
    });
    assert!(
        mismatch_codes(verify_run_artifact_accounting(&swapped, &snapshot).unwrap_err())
            .contains(&ReasonCode::CountMismatch)
    );

    // An omitted scanner cannot hide its metrics, and an unknown scanner is refused.
    let omitted = resealed(base.clone(), |a| {
        a.semantic.scanner_metrics.pop();
    });
    assert!(
        mismatch_codes(verify_run_artifact_accounting(&omitted, &snapshot).unwrap_err())
            .contains(&ReasonCode::MetricDefinitionMismatch)
    );
    let unknown = resealed(base.clone(), |a| {
        a.semantic.scanner_metrics[1].scanner_id = ScannerId::new("zeta-scan").unwrap();
    });
    assert!(
        mismatch_codes(verify_run_artifact_accounting(&unknown, &snapshot).unwrap_err())
            .contains(&ReasonCode::UnknownScanner)
    );
    // The unkeyed legacy list is not allowed next to the keyed one.
    let both = resealed(base, |a| {
        a.semantic.metrics = a.semantic.scanner_metrics[0].metrics.clone();
    });
    assert!(
        mismatch_codes(verify_run_artifact_accounting(&both, &snapshot).unwrap_err())
            .contains(&ReasonCode::ProtocolBindingMismatch)
    );
}

#[test]
fn a_legacy_revision_artifact_is_readable_but_not_verifiable() {
    // The committed P2 fixture is protocol revision 1: its accounting was the
    // legacy one (any-row buckets, one unkeyed list), which the verifier does
    // not implement (ADR 0008 section 1).
    let (snapshot, artifact) = fixtures();
    assert!(artifact.semantic.protocol.is_legacy());
    assert_eq!(
        verify_run_artifact_accounting(&artifact, &snapshot).unwrap_err(),
        VerifyFailure::UnsupportedRevision { version: 1 }
    );
    let public = artifact.to_public_synthetic().expect("public synthetic");
    assert_eq!(
        verify_public_artifact_accounting(&public, &snapshot).unwrap_err(),
        VerifyFailure::UnsupportedRevision { version: 1 }
    );
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
        metrics_of(&base, 0)
    );
    assert_eq!(base.semantic.scanners[0].status, ScannerStatus::Complete);
}

#[test]
fn the_public_projection_is_verified_and_tampering_is_caught() {
    let (snapshot, artifact) = fixtures();
    let internal = single_scanner(&snapshot, artifact);
    let public = internal.to_public_synthetic().expect("public synthetic");
    verify_public_artifact_accounting(&public, &snapshot).expect("verifies");
    // A published bound off by one digit, resealed so the digest still matches.
    let mut tampered = public.clone();
    let m = tampered.semantic.scanner_metrics[0]
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

#[test]
fn the_artifact_must_list_exactly_the_ten_metrics_per_scanner() {
    let (snapshot, artifact) = fixtures();
    let base = single_scanner(&snapshot, artifact);
    assert_eq!(metrics_of(&base, 0).len(), 10);
    // Omitting a metric (even a correct one) is refused, so a bad metric cannot be dropped.
    let omitted = resealed(base.clone(), |a| {
        a.semantic.scanner_metrics[0]
            .metrics
            .retain(|m| m.metric.id != MetricId::TypeMissRate);
    });
    validate(&omitted).expect("contracts accept a shorter list");
    assert!(
        mismatch_codes(verify_run_artifact_accounting(&omitted, &snapshot).unwrap_err())
            .contains(&ReasonCode::MetricDefinitionMismatch)
    );
    // A repeated metric in place of another is refused too.
    let mut doubled = base.clone();
    doubled.semantic.scanner_metrics[0].metrics[1] = doubled.semantic.scanner_metrics[0].metrics[0];
    assert!(
        mismatch_codes(verify_run_artifact_accounting(&doubled, &snapshot).unwrap_err())
            .contains(&ReasonCode::MetricDefinitionMismatch)
    );
    // The public projection is held to the same rule.
    let mut public = base.to_public_synthetic().unwrap();
    public.semantic.scanner_metrics[0].metrics.pop();
    seal(&mut public).unwrap();
    assert!(
        mismatch_codes(verify_public_artifact_accounting(&public, &snapshot).unwrap_err())
            .contains(&ReasonCode::MetricDefinitionMismatch)
    );
}

#[test]
fn the_public_projection_is_bound_to_the_snapshot_as_strongly_as_the_internal_artifact() {
    let (snapshot, artifact) = fixtures();
    let internal = canonical(&snapshot, artifact, None);
    let public = internal.to_public_synthetic().expect("public synthetic");
    verify_public_artifact_accounting(&public, &snapshot).expect("verifies");
    let reseal =
        |mut p: pii_eval_contracts::PublicSyntheticArtifact,
         edit: &dyn Fn(&mut pii_eval_contracts::PublicSyntheticArtifactBody)| {
            edit(&mut p.semantic);
            seal(&mut p).unwrap();
            p
        };
    // The reviewer's probe: swap the case and variant counts of two methods.
    let swapped = reseal(public.clone(), &|b| {
        let (x, y) = (b.method_coverage[0], b.method_coverage[1]);
        b.method_coverage[0].cases = y.cases;
        b.method_coverage[0].variants = y.variants;
        b.method_coverage[1].cases = x.cases;
        b.method_coverage[1].variants = x.variants;
    });
    validate(&swapped).expect("contract-valid: the sums still match");
    assert!(
        mismatch_codes(verify_public_artifact_accounting(&swapped, &snapshot).unwrap_err())
            .contains(&ReasonCode::CountMismatch)
    );
    // Authored counts.
    let counts = reseal(public.clone(), &|b| b.population_counts.occurrences += 1);
    assert!(verify_public_artifact_accounting(&counts, &snapshot).is_err());
    // A row whose state is unreachable for its authored expectation.
    let lattice = reseal(public.clone(), &|b| {
        let row = b
            .outcomes
            .iter_mut()
            .find(|o| o.scanner_id.as_str() == "alpha-scan")
            .unwrap();
        row.type_identity = pii_eval_contracts::TypeState::InvalidAccepted;
    });
    assert!(
        mismatch_codes(verify_public_artifact_accounting(&lattice, &snapshot).unwrap_err())
            .contains(&ReasonCode::OutcomeContradiction)
    );
    // An action that contradicts the scanner's capability.
    let action = reseal(public, &|b| {
        let row = b
            .outcomes
            .iter_mut()
            .find(|o| o.scanner_id.as_str() == "beta-scan")
            .unwrap();
        row.action = pii_eval_contracts::ActionOutcome::Reported {
            action: pii_eval_contracts::ActionKind::Redact,
        };
    });
    assert!(verify_public_artifact_accounting(&action, &snapshot).is_err());
}
