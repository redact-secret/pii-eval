//! The product-projection block of schema 1.2 (ADR 0016), structure level: the
//! rejections the benchmarks request names, each with its stable reason code,
//! additivity (a document without the block is byte-identical to 1.1), and the
//! block's inclusion in the semantic digest. Metric values are recomputed by
//! the kernel's tests, not here.

mod common;

use common::*;
use pii_eval_contracts::*;

fn canonical() -> Fixtures {
    Fixtures::default_canonical()
}

fn codes(doc: &PublicSyntheticArtifact) -> Vec<ReasonCode> {
    match validate(doc) {
        Ok(()) => vec![],
        Err(v) => v.errors.iter().map(|e| e.code).collect(),
    }
}

fn valid(f: &Fixtures) -> PublicSyntheticArtifact {
    let base = f.artifact.to_public_synthetic().unwrap();
    public_with_projection(f, projection_block(&base, ProjectionMode::Official))
}

#[test]
fn a_valid_block_validates_round_trips_and_is_sealed_under_1_2() {
    let f = canonical();
    let doc = valid(&f);
    assert_eq!(doc.schema_version, SchemaVersion::V1_2);
    validate(&doc).unwrap();
    let text = serialize_public_synthetic(&doc).unwrap();
    let back: PublicSyntheticArtifact = parse_default(text.as_bytes()).unwrap();
    assert_eq!(back, doc);
    assert!(text.contains("\"productProjection\""));
}

#[test]
fn without_a_block_the_projection_is_the_1_1_document_unchanged() {
    let f = canonical();
    let plain = f.artifact.to_public_synthetic().unwrap();
    assert_eq!(plain.schema_version, SchemaVersion::V1_1);
    assert!(plain.semantic.product_projection.is_none());
    let text = serialize_public_synthetic(&plain).unwrap();
    assert!(!text.contains("productProjection"));
    let again = f
        .artifact
        .to_public_synthetic_with_projection(None)
        .unwrap();
    assert_eq!(again, plain);
}

#[test]
fn the_block_is_part_of_the_semantic_digest() {
    let f = canonical();
    let with = valid(&f);
    let without = f.artifact.to_public_synthetic().unwrap();
    assert_ne!(with.semantic_digest, without.semantic_digest);
    // Any change inside the block changes the digest.
    let mut other = with.clone();
    other
        .semantic
        .product_projection
        .as_mut()
        .unwrap()
        .roster_digest = digest_of("another-roster");
    assert_eq!(compute_digest(&with).unwrap(), with.semantic_digest);
    assert_ne!(compute_digest(&other).unwrap(), with.semantic_digest);
    // Mode is covered too: an exploratory row is a different artifact.
    let mut mode = with.clone();
    for r in &mut mode.semantic.product_projection.as_mut().unwrap().rows {
        r.mode = ProjectionMode::Exploratory;
    }
    assert_ne!(compute_digest(&mode).unwrap(), with.semantic_digest);
}

#[test]
fn a_block_under_schema_1_1_is_refused() {
    let f = canonical();
    let mut doc = valid(&f);
    doc.schema_version = SchemaVersion::V1_1;
    seal(&mut doc).unwrap();
    assert!(codes(&doc).contains(&ReasonCode::ProjectionInvalid));
}

#[test]
fn duplicate_family_view_rows_are_rejected() {
    let f = canonical();
    let doc = edited_projection(&f, |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        let again = block.rows[0].clone();
        block.rows.insert(1, again);
    });
    assert!(codes(&doc).contains(&ReasonCode::DuplicateIdentity));
}

#[test]
fn an_absent_required_view_is_rejected() {
    let f = canonical();
    let doc = edited_projection(&f, |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        block
            .rows
            .retain(|r| r.view != ProjectionView::QualificationPlan);
    });
    assert!(codes(&doc).contains(&ReasonCode::ProjectionViewMissing));
    // A required view absent for one scanner only is rejected too.
    let one = edited_projection(&f, |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        block.rows.retain(|r| {
            !(r.binding.scanner_id.as_str() == "beta-scan" && r.view == ProjectionView::OraclePlan)
        });
    });
    assert!(codes(&one).contains(&ReasonCode::ProjectionViewMissing));
}

#[test]
fn a_row_for_a_view_the_roster_did_not_require_is_rejected() {
    let f = canonical();
    let doc = edited_projection(&f, |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        block.required_views = vec![ProjectionView::OraclePlan];
    });
    assert!(codes(&doc).contains(&ReasonCode::ProjectionInvalid));
}

#[test]
fn pooled_denominators_are_rejected() {
    let f = canonical();
    // An extra "everything" row on top of the cells counts every case twice.
    let doc = edited_projection(&f, |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        let mut pooled = block.rows[1].clone();
        pooled.view = ProjectionView::DiagnosticBalanced;
        pooled.family = fam("pii:global:phone");
        pooled.counts = PopulationCounts {
            authored_cases: 3,
            variants: 6,
            occurrences: 6,
        };
        pooled.method_coverage = d.semantic.method_coverage.clone();
        block
            .required_views
            .push(ProjectionView::DiagnosticBalanced);
        block.required_views.sort_by_key(|v| v.as_str());
        block.rows.push(pooled);
        block.rows.sort_by_key(|r| {
            (
                r.binding.scanner_id.as_str().to_owned(),
                r.view.as_str(),
                r.family.as_str().to_owned(),
            )
        });
    });
    assert!(codes(&doc).contains(&ReasonCode::ProjectionPooledDenominator));
    // A metric whose denominator exceeds the row's own cases.
    let metric = edited_projection(&f, |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        let m = &mut block.rows[0].metrics[0];
        m.counts.eligible = 5;
        m.counts.measured = 5;
        m.counts.total = 5;
        m.effective_n = 5;
        m.status = MetricStatus::Measured;
        m.value = MetricValue::Measured {
            point: ScaledDecimal {
                mantissa: 0,
                scale: 0,
            },
            bound: ScaledDecimal {
                mantissa: 1,
                scale: 0,
            },
        };
    });
    assert!(codes(&metric).contains(&ReasonCode::ProjectionPooledDenominator));
    // A row that claims more cases than the population holds.
    let big = edited_projection(&f, |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        block.rows[0].counts.authored_cases = 99;
    });
    assert!(!codes(&big).is_empty());
}

#[test]
fn an_unknown_mode_or_view_is_rejected_by_the_closed_vocabulary() {
    let f = canonical();
    let text = serialize_public_synthetic(&valid(&f)).unwrap();
    for (from, to) in [
        ("\"mode\": \"official\"", "\"mode\": \"pilot\""),
        ("\"view\": \"oracle-plan\"", "\"view\": \"merged-plan\""),
    ] {
        assert!(text.contains(from));
        let bad = text.replacen(from, to, 1);
        let err = parse_default::<PublicSyntheticArtifact>(bad.as_bytes()).unwrap_err();
        assert_eq!(err.first_code(), Some(ReasonCode::SchemaViolation), "{to}");
    }
    // A field outside the block's closed shape.
    let bad = text.replacen(
        "\"rosterDigest\"",
        "\"extra\": 1,\n      \"rosterDigest\"",
        1,
    );
    let err = parse_default::<PublicSyntheticArtifact>(bad.as_bytes()).unwrap_err();
    assert_eq!(err.first_code(), Some(ReasonCode::SchemaViolation));
}

#[test]
fn mixed_modes_in_one_artifact_are_rejected() {
    let f = canonical();
    let doc = edited_projection(&f, |d| {
        let block = d.semantic.product_projection.as_mut().unwrap();
        block.rows[0].mode = ProjectionMode::Official;
    });
    assert!(codes(&doc).contains(&ReasonCode::ProjectionInvalid));
}

#[test]
fn a_row_bound_to_another_scanner_configuration_activation_candidate_or_population_is_rejected() {
    let f = canonical();
    type Edit = Box<dyn Fn(&mut ProjectionRow)>;
    let edits: Vec<(&str, Edit)> = vec![
        (
            "configuration",
            Box::new(|r| r.binding.configuration_digest = digest_of("another-configuration")),
        ),
        (
            "activation",
            Box::new(|r| r.binding.activation_digest = digest_of("another-activation")),
        ),
        (
            "candidate",
            Box::new(|r| {
                r.binding.product = ProductIdentity::Candidate {
                    candidate_digest: digest_of("another-candidate"),
                }
            }),
        ),
        (
            "population-digest",
            Box::new(|r| r.binding.population.population_digest = digest_of("another-population")),
        ),
        (
            "population-version",
            Box::new(|r| r.binding.population.population_version += 1),
        ),
        (
            "unknown-scanner",
            Box::new(|r| r.binding.scanner_id = sid("gamma-scan")),
        ),
    ];
    for (name, edit) in edits {
        let doc = edited_projection(&f, |d| {
            edit(&mut d.semantic.product_projection.as_mut().unwrap().rows[0]);
        });
        assert!(
            codes(&doc).contains(&ReasonCode::ProjectionBindingMismatch),
            "{name}"
        );
    }
}

#[test]
fn a_revision_1_artifact_cannot_carry_a_block() {
    let f = Fixtures::default_public();
    let base = f.artifact.to_public_synthetic().unwrap();
    let canonical_base = canonical().artifact.to_public_synthetic().unwrap();
    let block = projection_block(&canonical_base, ProjectionMode::Official);
    let mut doc = base;
    doc.schema_version = SchemaVersion::V1_2;
    doc.semantic.product_projection = Some(block);
    seal(&mut doc).unwrap();
    assert!(codes(&doc).contains(&ReasonCode::ProjectionInvalid));
}

#[test]
fn schema_1_2_is_still_readable_and_1_5_is_not() {
    // The block is the 1.2 addition (1.3 is ADR 0017, 1.4 is ADR 0018); the next
    // minor is not readable yet.
    assert_eq!(
        SchemaVersion { major: 1, minor: 5 }.readable(),
        Err(ReasonCode::SchemaMinorTooNew)
    );
    assert_eq!(SchemaVersion::V1_2.readable(), Ok(()));
}
