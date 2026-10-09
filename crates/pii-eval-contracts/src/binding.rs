//! Cross-document binding checks.
//!
//! Each document validates on its own (structure and digest). These functions
//! check that documents which claim to belong together actually do: the same
//! population, the same plan, the same scanner configuration, the same input
//! bytes. They take documents that already passed [`crate::validate`] and trust
//! their declared digests; call [`crate::parse`] or [`crate::validate`] first.
//!
//! A population is consumed separately and identified, never merged: a plan
//! binds exactly one population digest, and nothing here composes populations.

use std::collections::{BTreeMap, BTreeSet};

use crate::artifact::{PublicSyntheticArtifact, RunArtifact};
use crate::axes::{AuthoredAxes, OutcomeRow, validate_outcome_lattice};
use crate::corpus::{Case, CorpusSnapshot, Variant};
use crate::ident::Id;
use crate::manifest::RunManifest;
use crate::observation::ObservationSet;
use crate::reason::{Collector, Meta, Path, ReasonCode, Violations};
use crate::scanner::ScannerStatus;

fn index_variants(snapshot: &CorpusSnapshot) -> BTreeMap<&Id, (&Case, &Variant)> {
    snapshot
        .semantic
        .cases
        .iter()
        .flat_map(|case| {
            case.variants
                .iter()
                .map(move |v| (&v.variant_id, (case, v)))
        })
        .collect()
}

/// A manifest must bind the snapshot it plans to measure: population identity,
/// run class equal to visibility, and every case within the declared scope and
/// methods.
pub fn validate_manifest_against_snapshot(
    manifest: &RunManifest,
    snapshot: &CorpusSnapshot,
) -> Result<(), Violations> {
    let mut c = Collector::new();
    let body = Path::ROOT.field("semantic");
    let m = &manifest.semantic;
    let s = &snapshot.semantic;
    if s.authors_evidence_semantics() && m.protocol != crate::ProtocolIdentity::CANONICAL_V3 {
        c.push(ReasonCode::ProtocolBindingMismatch, &body.field("protocol"));
    }
    if !m.run_class.matches(s.population.visibility) {
        c.push(ReasonCode::RunClassMismatch, &body.field("runClass"));
    }
    if m.generation != s.generation {
        c.push(
            ReasonCode::GenerationBindingMismatch,
            &body.field("generation"),
        );
    }
    let binding = &m.population;
    if binding.population_id != s.population.population_id
        || binding.visibility != s.population.visibility
        || binding.population_version != s.population.population_version
        || binding.population_digest != snapshot.semantic_digest
    {
        c.push(
            ReasonCode::PopulationBindingMismatch,
            &body.field("population"),
        );
    }
    let scope = body.field("scope");
    let (mut bad_language, mut bad_jurisdiction, mut bad_method) = (false, false, false);
    for case in &s.cases {
        bad_language |= !m.scope.languages.contains(&case.language);
        bad_jurisdiction |= case
            .jurisdiction
            .as_ref()
            .is_some_and(|j| !m.scope.jurisdictions.contains(j));
        bad_method |= !m.methods.iter().any(|r| r.id == case.method);
    }
    if bad_language {
        c.push(ReasonCode::ScopeViolation, &scope.field("languages"));
    }
    if bad_jurisdiction {
        c.push(ReasonCode::ScopeViolation, &scope.field("jurisdictions"));
    }
    if bad_method {
        c.push(ReasonCode::ProtocolBindingMismatch, &body.field("methods"));
    }
    c.finish()
}

/// An observation set must belong to the plan: same engine and protocol, same
/// population digest, and a scanner whose full identity (scanner, adapter,
/// product, configuration, activation) matches the plan entry.
pub fn validate_observation_against_manifest(
    observation: &ObservationSet,
    manifest: &RunManifest,
) -> Result<(), Violations> {
    let mut c = Collector::new();
    let body = Path::ROOT.field("semantic");
    let o = &observation.semantic;
    let m = &manifest.semantic;
    if o.engine != m.engine {
        c.push(ReasonCode::EngineBindingMismatch, &body.field("engine"));
    }
    if o.protocol != m.protocol {
        c.push(ReasonCode::ProtocolBindingMismatch, &body.field("protocol"));
    }
    if o.population_digest != m.population.population_digest {
        c.push(
            ReasonCode::PopulationBindingMismatch,
            &body.field("populationDigest"),
        );
    }
    match m
        .scanners
        .iter()
        .find(|s| s.identity.scanner_id == o.scanner.scanner_id)
    {
        None => c.push(ReasonCode::UnknownScanner, &body.field("scanner")),
        Some(plan) if plan.identity != o.scanner => {
            c.push(
                ReasonCode::ConfigurationBindingMismatch,
                &body.field("scanner"),
            );
        }
        Some(_) => {}
    }
    if observation.semantic.replays.count != m.mechanics.replays {
        c.push(
            ReasonCode::ConfigurationBindingMismatch,
            &body.field("replays"),
        );
    }
    c.finish()
}

/// An observation set must observe the snapshot's exact bytes: the population
/// digest, every variant id, every input digest, and every finding range
/// against the variant text (bounds and UTF-8 character boundaries).
pub fn validate_observation_against_snapshot(
    observation: &ObservationSet,
    snapshot: &CorpusSnapshot,
) -> Result<(), Violations> {
    let mut c = Collector::new();
    let body = Path::ROOT.field("semantic");
    let o = &observation.semantic;
    if o.population_digest != snapshot.semantic_digest {
        c.push(
            ReasonCode::PopulationBindingMismatch,
            &body.field("populationDigest"),
        );
    }
    let variants = index_variants(snapshot);
    let inputs = body.field("inputs");
    let mut seen: BTreeSet<&Id> = BTreeSet::new();
    for (i, input) in o.inputs.iter().enumerate() {
        let p = inputs.index(i);
        let Some((_, variant)) = variants.get(&input.variant_id) else {
            c.push(ReasonCode::UnknownVariant, &p.field("variantId"));
            continue;
        };
        seen.insert(&input.variant_id);
        if input.input_digest != variant.text_digest {
            c.push(ReasonCode::InputDigestMismatch, &p.field("inputDigest"));
        }
        let findings = p.field("findings");
        for (j, f) in input.findings.iter().enumerate() {
            f.range
                .check(&variant.text, &findings.index(j).field("range"), &mut c);
        }
        if c.is_full() {
            break;
        }
    }
    if o.status == ScannerStatus::Complete && seen.len() != variants.len() {
        c.push_with(
            ReasonCode::ObservationIncomplete,
            &inputs,
            Meta::limit(variants.len() as u64, seen.len() as u64),
        );
    }
    c.finish()
}

/// An artifact must realize the manifest: identical engine, protocol, run
/// class, population, mechanics, manifest digest and scanner identities, and
/// exactly the planned metrics.
pub fn validate_artifact_against_manifest(
    artifact: &RunArtifact,
    manifest: &RunManifest,
) -> Result<(), Violations> {
    let mut c = Collector::new();
    let body = Path::ROOT.field("semantic");
    let a = &artifact.semantic;
    let m = &manifest.semantic;
    if a.engine != m.engine {
        c.push(ReasonCode::EngineBindingMismatch, &body.field("engine"));
    }
    if a.protocol != m.protocol || a.mechanics != m.mechanics {
        c.push(ReasonCode::ProtocolBindingMismatch, &body.field("protocol"));
    }
    if a.run_class != m.run_class {
        c.push(ReasonCode::RunClassMismatch, &body.field("runClass"));
    }
    if a.manifest_digest != manifest.semantic_digest {
        c.push(
            ReasonCode::ConfigurationBindingMismatch,
            &body.field("manifestDigest"),
        );
    }
    if a.population != m.population {
        c.push(
            ReasonCode::PopulationBindingMismatch,
            &body.field("population"),
        );
    }
    let scanners = body.field("scanners");
    if a.scanners.len() != m.scanners.len() {
        c.push(ReasonCode::ConfigurationBindingMismatch, &scanners);
    }
    for (i, s) in a.scanners.iter().enumerate() {
        match m
            .scanners
            .iter()
            .find(|p| p.identity.scanner_id == s.identity.scanner_id)
        {
            None => c.push(ReasonCode::UnknownScanner, &scanners.index(i)),
            Some(plan) if plan.identity != s.identity => {
                c.push(ReasonCode::ConfigurationBindingMismatch, &scanners.index(i));
            }
            Some(_) => {}
        }
    }
    let planned: Vec<_> = m.metrics.iter().map(|r| r.id).collect();
    if a.protocol.is_canonical() {
        // Revision 2: every scanner carries exactly the planned metrics.
        let each_planned = a.scanner_metrics.iter().all(|s| {
            s.metrics
                .iter()
                .map(|r| r.metric.id)
                .eq(planned.iter().copied())
        });
        if !each_planned {
            c.push(
                ReasonCode::ProtocolBindingMismatch,
                &body.field("scannerMetrics"),
            );
        }
    } else {
        let produced: Vec<_> = a.metrics.iter().map(|r| r.metric.id).collect();
        if planned != produced {
            c.push(ReasonCode::ProtocolBindingMismatch, &body.field("metrics"));
        }
    }
    if a.method_coverage
        .iter()
        .any(|cov| !m.methods.iter().any(|r| r.id == cov.method.id))
    {
        c.push(
            ReasonCode::ProtocolBindingMismatch,
            &body.field("methodCoverage"),
        );
    }
    c.finish()
}

struct RowView<'a> {
    evidence: Option<&'a crate::corpus::EvidenceSemantics>,
    scanner_id: &'a crate::ident::ScannerId,
    case_id: &'a Id,
    variant_id: &'a Id,
    occurrence_id: &'a Id,
    method: crate::protocol::MethodId,
    row: OutcomeRow,
}

type ScannerParts<'a> = (
    &'a crate::ident::ScannerId,
    ScannerStatus,
    &'a crate::scanner::ScannerCapabilities,
);

struct SnapshotParts<'a> {
    population: (
        &'a Id,
        crate::corpus::Visibility,
        u32,
        &'a crate::ident::Sha256Digest,
    ),
    counts: &'a crate::artifact::PopulationCounts,
    coverage: &'a [crate::artifact::MethodCoverage],
    scanners: Vec<ScannerParts<'a>>,
    rows: Vec<RowView<'a>>,
}

/// The checks shared by the internal and the public artifact shape.
fn check_snapshot_parts(parts: &SnapshotParts<'_>, snapshot: &CorpusSnapshot) -> Collector {
    let mut c = Collector::new();
    let body = Path::ROOT.field("semantic");
    let s = &snapshot.semantic;
    let (id, visibility, version, digest) = parts.population;
    if *digest != snapshot.semantic_digest
        || *id != s.population.population_id
        || visibility != s.population.visibility
        || version != s.population.population_version
    {
        c.push(
            ReasonCode::PopulationBindingMismatch,
            &body.field("population"),
        );
    }
    let counts = parts.counts;
    if counts.authored_cases != s.case_count()
        || counts.variants != s.variant_count()
        || counts.occurrences != s.occurrence_count()
    {
        c.push(ReasonCode::CountMismatch, &body.field("populationCounts"));
    }
    for cov in parts.coverage {
        let (cases, variants) = s
            .cases
            .iter()
            .filter(|case| case.method == cov.method.id)
            .fold((0u64, 0u64), |(n, v), case| {
                (n + 1, v + case.variants.len() as u64)
            });
        if cov.cases != cases || cov.variants != variants {
            c.push(ReasonCode::CountMismatch, &body.field("methodCoverage"));
        }
    }
    // Every method with cases is covered, so an omitted entry cannot hide a count.
    if s.cases.iter().any(|case| {
        !parts
            .coverage
            .iter()
            .any(|cov| cov.method.id == case.method)
    }) {
        c.push(ReasonCode::CountMismatch, &body.field("methodCoverage"));
    }
    let variants = index_variants(snapshot);
    let outcomes = body.field("outcomes");
    for (i, o) in parts.rows.iter().enumerate() {
        let p = outcomes.index(i);
        let Some((case, variant)) = variants.get(o.variant_id) else {
            c.push(ReasonCode::UnknownVariant, &p.field("variantId"));
            continue;
        };
        if case.case_id != *o.case_id || case.method != o.method {
            c.push(ReasonCode::OutcomeContradiction, &p.field("caseId"));
            continue;
        }
        let Ok(k) = variant
            .expectations
            .binary_search_by(|e| e.occurrence_id.cmp(o.occurrence_id))
        else {
            c.push(ReasonCode::UnknownVariant, &p.field("occurrenceId"));
            continue;
        };
        let expectation = &variant.expectations[k];
        if expectation.is_text_negative()
            && (o.row.range != crate::RangeState::NotApplicable
                || o.row.action != crate::ActionOutcome::NotMeasured)
        {
            c.push(ReasonCode::OutcomeContradiction, &p);
        }
        if o.evidence != expectation.evidence.as_ref() {
            c.push(ReasonCode::OutcomeContradiction, &p.field("evidence"));
        }
        let Some((_, status, capabilities)) =
            parts.scanners.iter().find(|(id, _, _)| *id == o.scanner_id)
        else {
            c.push(ReasonCode::UnknownScanner, &p.field("scannerId"));
            continue;
        };
        let authored = AuthoredAxes {
            expected_type: expectation.type_expectation,
            sensitivity: expectation.sensitivity,
            range_established: expectation.range.is_some(),
            family: &expectation.family,
            jurisdiction: case.jurisdiction.as_ref(),
        };
        if validate_outcome_lattice(&authored, *status, capabilities, &o.row).is_err() {
            c.push(ReasonCode::OutcomeContradiction, &p);
        }
        if c.is_full() {
            break;
        }
    }
    c
}

macro_rules! row_views {
    ($outcomes:expr) => {
        $outcomes
            .iter()
            .map(|o| RowView {
                evidence: o.evidence.as_ref(),
                scanner_id: &o.scanner_id,
                case_id: &o.case_id,
                variant_id: &o.variant_id,
                occurrence_id: &o.occurrence_id,
                method: o.method,
                row: OutcomeRow {
                    type_identity: o.type_identity,
                    sensitivity_context: o.sensitivity_context,
                    range: o.range,
                    action: o.action,
                },
            })
            .collect()
    };
}

/// An artifact must be consistent with the snapshot it measured: population
/// digest, authored counts, per-method coverage, and every outcome row against
/// its authored expectation (the outcome lattice).
pub fn validate_artifact_against_snapshot(
    artifact: &RunArtifact,
    snapshot: &CorpusSnapshot,
) -> Result<(), Violations> {
    let a = &artifact.semantic;
    let parts = SnapshotParts {
        population: (
            &a.population.population_id,
            a.population.visibility,
            a.population.population_version,
            &a.population.population_digest,
        ),
        counts: &a.population_counts,
        coverage: &a.method_coverage,
        scanners: a
            .scanners
            .iter()
            .map(|s| (&s.identity.scanner_id, s.status, &s.capabilities))
            .collect(),
        rows: row_views!(a.outcomes),
    };
    let mut c = check_snapshot_parts(&parts, snapshot);
    if !a.run_class.matches(snapshot.semantic.population.visibility) {
        c.push(
            ReasonCode::RunClassMismatch,
            &Path::ROOT.field("semantic").field("runClass"),
        );
    }
    c.finish()
}

/// The public-synthetic projection must be consistent with the snapshot as far
/// as it carries data: population identity, authored counts, per-method
/// coverage and every outcome row against its authored expectation. (The type
/// admits only `public-synthetic`, so the snapshot must be public-synthetic
/// too.)
pub fn validate_public_artifact_against_snapshot(
    artifact: &PublicSyntheticArtifact,
    snapshot: &CorpusSnapshot,
) -> Result<(), Violations> {
    let a = &artifact.semantic;
    let parts = SnapshotParts {
        population: (
            &a.population.population_id,
            crate::corpus::Visibility::PublicSynthetic,
            a.population.population_version,
            &a.population.population_digest,
        ),
        counts: &a.population_counts,
        coverage: &a.method_coverage,
        scanners: a
            .scanners
            .iter()
            .map(|s| (&s.identity.scanner_id, s.status, &s.capabilities))
            .collect(),
        rows: row_views!(a.outcomes),
    };
    check_snapshot_parts(&parts, snapshot).finish()
}
