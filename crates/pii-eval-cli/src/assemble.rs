//! Assembly of the revision-2 documents from executor output: observation sets,
//! the internal run artifact and the public-synthetic projection.
//!
//! Scoring is the kernel's: every row comes from `assess_variant` (matching
//! rule `pii-v1-canonical`) and every metric from `account_outcomes`
//! (`pii-v1-canonical-accounting`, `pii-v1-wilson-exact`). This module only
//! arranges rows in canonical order, replaces the action axis by the verified
//! sanitized-output verdict where the scanner returned output, and records
//! failures, so nothing a worker did can reorder the semantic result.
//!
//! Non-semantic timing goes to `diagnostics` only. Nothing here reads a
//! finding's value, and no raw scanner output is copied into any document.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use pii_eval_contracts::ENGINE_VERSION;
use pii_eval_contracts::{
    ActionCapability, ActionOutcome, ArtifactScanner, CaseOutcome, Completeness, ContractError,
    CorpusSnapshot, EngineIdentity, EngineName, InputObservation, MeasurementFailure,
    MethodCoverage, MethodId, MethodRef, ObservationDiagnostics, ObservationSet,
    ObservationSetBody, Phase, PhaseTiming, ProjectionMode, ProtocolIdentity,
    PublicSyntheticArtifact, RunArtifact, RunArtifactBody, RunClass, RunDiagnostics, RunManifest,
    ScannerIdentity, ScannerMetrics, ScannerStatus, TimestampUtc, VersionString, seal,
};
use pii_eval_kernel::methods::ReviewGate;
use pii_eval_kernel::{
    AccountError, AssessError, AuthoredIndex, OutcomeRef, ProjectionError, ProjectionInput,
    ProjectionRoster, ScannerInput, ScannerView, VariantInput, account_outcomes, assess_variant,
    build_projection,
};

use crate::exec::{ObservedInput, ScannerRun, VariantTask};

/// Why assembly failed. These are defects of the inputs or of this engine, never
/// scanner failures (those are recorded in the documents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    /// The snapshot is not accountable.
    Account(AccountError),
    /// A variant could not be assessed (invalid authored or reported range).
    Assess(AssessError),
    /// A document could not be built or sealed.
    Contract(ContractError),
    /// The product projection could not be built from the roster.
    Projection(ProjectionError),
    /// The runs do not correspond to the manifest's scanners.
    ScannerMismatch,
    /// The observations of a complete scanner do not cover every variant once.
    IncompleteObservations,
}

impl std::fmt::Display for AssembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssembleError::Account(e) => write!(f, "accounting: {e}"),
            AssembleError::Assess(_) => f.write_str("a variant could not be assessed"),
            AssembleError::Contract(e) => write!(f, "{e}"),
            AssembleError::Projection(e) => write!(f, "projection: {e}"),
            AssembleError::ScannerMismatch => f.write_str("runs do not match the manifest"),
            AssembleError::IncompleteObservations => {
                f.write_str("a complete scanner did not observe every variant")
            }
        }
    }
}

impl std::error::Error for AssembleError {}

/// The assembled, sealed documents.
#[derive(Debug, Clone)]
pub struct Assembled {
    /// One observation set per scanner, in manifest order.
    pub observations: Vec<ObservationSet>,
    /// The internal run artifact.
    pub artifact: RunArtifact,
    /// The public-synthetic projection, for public-synthetic runs only.
    pub public: Option<PublicSyntheticArtifact>,
    /// Time spent in matching and accounting (the kernel).
    pub kernel_time: Duration,
}

/// Variants in canonical order (cases, then variants within a case) with their
/// authored occurrence ranges. The index of a task is its identity during a run.
pub fn variant_tasks(snapshot: &CorpusSnapshot) -> Vec<VariantTask<'_>> {
    snapshot
        .semantic
        .cases
        .iter()
        .flat_map(|case| &case.variants)
        .map(|variant| VariantTask {
            variant_id: &variant.variant_id,
            text: &variant.text,
            ranges: variant
                .expectations
                .iter()
                .filter_map(|e| e.range)
                .collect(),
        })
        .collect()
}

/// A civil timestamp with millisecond precision, from the system clock.
pub fn timestamp(time: SystemTime) -> TimestampUtc {
    let millis = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let (secs, ms) = (millis / 1000, millis % 1000);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil-from-days (Howard Hinnant's algorithm), valid for the whole range.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let text = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    TimestampUtc::new(text).unwrap_or_else(|_| {
        TimestampUtc::new("1970-01-01T00:00:00.000Z").expect("constant timestamp is valid")
    })
}

/// Options for [`assemble`].
#[derive(Debug, Clone, Copy)]
pub struct AssembleOptions {
    /// Attach non-semantic diagnostics (timestamps, durations, runtime
    /// provenance). Golden fixtures turn this off so they are byte-stable.
    pub diagnostics: bool,
    /// When the whole run started.
    pub run_started_at: SystemTime,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The optional product projection of a run (schema 1.2, ADR 0016): the
/// caller's roster and the run's mode. With none, the public artifact is the
/// 1.1 document, byte for byte.
#[derive(Debug, Clone)]
pub struct ProjectionRequest {
    /// The caller's roster, already checked against the snapshot.
    pub roster: ProjectionRoster,
    /// The run's mode, copied into every row.
    pub mode: ProjectionMode,
}

/// Assemble the documents for `runs` (one per manifest scanner, in manifest order).
pub fn assemble(
    snapshot: &CorpusSnapshot,
    manifest: &RunManifest,
    tasks: &[VariantTask<'_>],
    runs: &[ScannerRun],
    options: AssembleOptions,
) -> Result<Assembled, AssembleError> {
    assemble_with_projection(snapshot, manifest, tasks, runs, options, None)
}

/// [`assemble`], with the optional product projection attached to the public
/// artifact (public-synthetic runs only; the internal artifact is unchanged).
pub fn assemble_with_projection(
    snapshot: &CorpusSnapshot,
    manifest: &RunManifest,
    tasks: &[VariantTask<'_>],
    runs: &[ScannerRun],
    options: AssembleOptions,
    projection: Option<&ProjectionRequest>,
) -> Result<Assembled, AssembleError> {
    let m = &manifest.semantic;
    if runs.len() != m.scanners.len()
        || runs
            .iter()
            .zip(&m.scanners)
            .any(|(r, p)| r.plan.identity != p.identity)
    {
        return Err(AssembleError::ScannerMismatch);
    }
    let kernel_start = std::time::Instant::now();
    let engine = EngineIdentity {
        name: EngineName::PiiEval,
        version: VersionString::new(ENGINE_VERSION).map_err(|_| {
            AssembleError::Contract(ContractError::root(
                pii_eval_contracts::ReasonCode::InvalidIdentifier,
            ))
        })?,
    };
    let protocol = ProtocolIdentity::CANONICAL_V2;
    let body = &snapshot.semantic;

    // Rows, scanner by scanner, in canonical order. Every row passes the review
    // gate of the sealed snapshot (a `review-required` variant has an unmeasured
    // type axis, ADR 0007), so a replay of a stored snapshot scores exactly what
    // the run did and a held variant can never read as a clean pass.
    let gate = ReviewGate::from_body(body);
    let mut rows: Vec<CaseOutcome> = Vec::new();
    for run in runs {
        let by_index = observations_by_index(run, tasks.len())?;
        let mut index = 0usize;
        for case in &body.cases {
            for variant in &case.variants {
                let observed = by_index[index];
                let findings = observed.map_or(&[][..], |o| o.findings.as_slice());
                let assessment = assess_variant(
                    &VariantInput {
                        text: &variant.text,
                        case_jurisdiction: case.jurisdiction.as_ref(),
                        expectations: &variant.expectations,
                    },
                    &ScannerView {
                        status: run.status,
                        capabilities: &run.capabilities,
                        findings,
                    },
                )
                .map_err(AssembleError::Assess)?;
                let verified = observed.and_then(|o| o.verification.as_ref()).filter(|_| {
                    run.status == ScannerStatus::Complete
                        && run.capabilities.action == ActionCapability::SanitizedOutput
                });
                for (i, occ) in assessment.occurrences.iter().enumerate() {
                    let gated = gate.apply(variant.variant_id.as_str(), occ.row);
                    let action = match verified.and_then(|v| v.get(i)) {
                        Some(&verification) => ActionOutcome::OutputVerified { verification },
                        None => gated.action,
                    };
                    rows.push(CaseOutcome {
                        scanner_id: run.plan.identity.scanner_id.clone(),
                        case_id: case.case_id.clone(),
                        variant_id: variant.variant_id.clone(),
                        occurrence_id: occ.occurrence_id.clone(),
                        method: case.method,
                        type_identity: gated.type_identity,
                        sensitivity_context: gated.sensitivity_context,
                        range: gated.range,
                        action,
                        observed: occ.observed.clone(),
                    });
                }
                index += 1;
            }
        }
    }

    // Metrics per scanner from that scanner's own rows.
    let index = AuthoredIndex::new(body).map_err(AssembleError::Account)?;
    let inputs: Vec<ScannerInput<'_>> = runs
        .iter()
        .map(|r| ScannerInput {
            id: &r.plan.identity.scanner_id,
            status: r.status,
        })
        .collect();
    let accounting =
        account_outcomes(&index, &inputs, &rows, &m.mechanics).map_err(AssembleError::Account)?;
    let scanner_metrics: Vec<ScannerMetrics> = accounting
        .scanners
        .iter()
        .map(|s| ScannerMetrics {
            scanner_id: s.scanner_id.clone(),
            metrics: s.overall.results(),
        })
        .collect();
    let kernel_time = kernel_start.elapsed();
    let materialize_start = std::time::Instant::now();

    // Observation sets.
    let mut observations = Vec::with_capacity(runs.len());
    for run in runs {
        let mut inputs: Vec<InputObservation> = run
            .inputs
            .iter()
            .map(|o| InputObservation {
                variant_id: tasks[o.index].variant_id.clone(),
                input_digest: o.input_digest.clone(),
                sanitized_output_digest: o.sanitized_output_digest.clone(),
                findings: o.findings.clone(),
            })
            .collect();
        inputs.sort_by(|a, b| a.variant_id.cmp(&b.variant_id));
        let mut set = ObservationSet::unsealed(ObservationSetBody {
            engine: engine.clone(),
            protocol,
            population_digest: snapshot.semantic_digest.clone(),
            scanner: run.plan.identity.clone(),
            status: run.status,
            capabilities: run.capabilities.clone(),
            replays: run.replays,
            inputs,
        });
        if options.diagnostics {
            set.diagnostics = Some(ObservationDiagnostics {
                started_at: timestamp(run.timing.started_at),
                finished_at: timestamp(run.timing.finished_at.max(run.timing.started_at)),
                duration_ms: millis(run.timing.wall),
                runtime: run.runtime.clone(),
            });
        }
        seal(&mut set).map_err(AssembleError::Contract)?;
        observations.push(set);
    }

    // The artifact.
    let mut coverage: BTreeMap<&'static str, (MethodId, u64, u64)> = BTreeMap::new();
    for case in &body.cases {
        let e = coverage
            .entry(case.method.as_str())
            .or_insert((case.method, 0, 0));
        e.1 += 1;
        e.2 += case.variants.len() as u64;
    }
    let method_coverage: Vec<MethodCoverage> = coverage
        .into_values()
        .map(|(id, cases, variants)| MethodCoverage {
            method: MethodRef::frozen(id),
            cases,
            variants,
        })
        .collect();
    let failures: Vec<MeasurementFailure> = runs
        .iter()
        .filter_map(|r| {
            r.failure.map(|f| MeasurementFailure {
                scanner_id: r.plan.identity.scanner_id.clone(),
                code: f.code,
                affected_inputs: f.affected_inputs,
            })
        })
        .collect();
    let scanners: Vec<ArtifactScanner> = runs
        .iter()
        .zip(&observations)
        .map(|(r, o)| ArtifactScanner {
            identity: r.plan.identity.clone(),
            status: r.status,
            capabilities: r.capabilities.clone(),
            replays: r.replays,
            observation_digest: o.semantic_digest.clone(),
        })
        .collect();
    let mut artifact = RunArtifact::unsealed(RunArtifactBody {
        engine,
        protocol,
        run_class: m.run_class,
        manifest_digest: manifest.semantic_digest.clone(),
        population: m.population.clone(),
        mechanics: m.mechanics,
        population_counts: index.counts(),
        scanners,
        method_coverage,
        outcomes: rows,
        metrics: Vec::new(),
        scanner_metrics,
        failures,
        completeness: Completeness::Complete,
    });
    if options.diagnostics {
        let startup: Duration = runs.iter().map(|r| r.timing.startup).sum();
        let scan: Duration = runs.iter().map(|r| r.timing.scan).sum();
        let finished = runs
            .iter()
            .map(|r| r.timing.finished_at)
            .max()
            .unwrap_or(options.run_started_at)
            .max(options.run_started_at);
        let wall = finished
            .duration_since(options.run_started_at)
            .unwrap_or_default();
        // Sorted by wire string, as the contract requires. `serialization` is
        // filled in by the writer, which is the only one that knows it.
        let mut phases = vec![
            PhaseTiming {
                phase: Phase::KernelReplay,
                duration_ms: millis(kernel_time),
            },
            PhaseTiming {
                phase: Phase::Materialization,
                duration_ms: millis(materialize_start.elapsed()),
            },
            PhaseTiming {
                phase: Phase::Scan,
                duration_ms: millis(scan),
            },
            PhaseTiming {
                phase: Phase::ScannerStartup,
                duration_ms: millis(startup),
            },
            PhaseTiming {
                phase: Phase::Serialization,
                duration_ms: 0,
            },
            PhaseTiming {
                phase: Phase::Total,
                duration_ms: millis(wall),
            },
        ];
        phases.sort_by_key(|p| p.phase.as_str());
        artifact.diagnostics = Some(RunDiagnostics {
            started_at: timestamp(options.run_started_at),
            finished_at: timestamp(finished),
            duration_ms: millis(wall),
            phases,
        });
    }
    seal(&mut artifact).map_err(AssembleError::Contract)?;
    let public = if m.run_class == RunClass::PublicSynthetic {
        let block = match projection {
            None => None,
            Some(request) => {
                let a = &artifact.semantic;
                let scanners: Vec<(&ScannerIdentity, ScannerStatus)> =
                    a.scanners.iter().map(|s| (&s.identity, s.status)).collect();
                let outcome_rows: Vec<OutcomeRef<'_>> =
                    a.outcomes.iter().map(OutcomeRef::from).collect();
                let population = pii_eval_contracts::PublicPopulationBinding {
                    population_id: a.population.population_id.clone(),
                    visibility: pii_eval_contracts::PublicSyntheticClass::Only,
                    population_version: a.population.population_version,
                    population_digest: a.population.population_digest.clone(),
                };
                Some(
                    build_projection(
                        &ProjectionInput {
                            snapshot: body,
                            population: &population,
                            scanners: &scanners,
                            rows: &outcome_rows,
                            mechanics: &a.mechanics,
                            mode: request.mode,
                        },
                        &request.roster,
                    )
                    .map_err(AssembleError::Projection)?,
                )
            }
        };
        Some(
            artifact
                .to_public_synthetic_with_projection(block)
                .map_err(|_| {
                    AssembleError::Contract(ContractError::root(
                        pii_eval_contracts::ReasonCode::PublicProjectionForbidden,
                    ))
                })?,
        )
    } else {
        None
    };
    Ok(Assembled {
        observations,
        artifact,
        public,
        kernel_time,
    })
}

/// The observation of each variant by task index, or `None` where the scanner
/// measured nothing. A complete scanner must cover every variant exactly once.
fn observations_by_index(
    run: &ScannerRun,
    variants: usize,
) -> Result<Vec<Option<&ObservedInput>>, AssembleError> {
    let mut by_index: Vec<Option<&ObservedInput>> = vec![None; variants];
    for o in &run.inputs {
        let slot = by_index
            .get_mut(o.index)
            .ok_or(AssembleError::IncompleteObservations)?;
        if slot.replace(o).is_some() {
            return Err(AssembleError::IncompleteObservations);
        }
    }
    if run.status == ScannerStatus::Complete && by_index.iter().any(Option::is_none) {
        return Err(AssembleError::IncompleteObservations);
    }
    if run.status != ScannerStatus::Complete && !run.inputs.is_empty() {
        return Err(AssembleError::IncompleteObservations);
    }
    Ok(by_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64, ms: u32) -> TimestampUtc {
        timestamp(SystemTime::UNIX_EPOCH + Duration::new(secs, ms * 1_000_000))
    }

    #[test]
    fn timestamps_are_civil_utc_with_milliseconds() {
        assert_eq!(at(0, 0).as_str(), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(86_400 + 1, 5).as_str(), "1970-01-02T00:00:01.005Z");
        // 2000-03-01T00:00:00Z, the day after a leap day.
        assert_eq!(at(951_868_800, 0).as_str(), "2000-03-01T00:00:00.000Z");
        // 2026-10-02T09:00:01.250Z
        assert_eq!(at(1_790_931_601, 250).as_str(), "2026-10-02T09:00:01.250Z");
        // 2100-03-01 (2100 is not a leap year).
        assert_eq!(at(4_107_542_400, 0).as_str(), "2100-03-01T00:00:00.000Z");
    }
}
