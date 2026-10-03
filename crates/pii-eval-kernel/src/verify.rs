//! Verification of metric results: published values against counts, and
//! counts against the outcome rows they summarize.
//!
//! This is the P2 item that ADR 0002 deferred ("point and bound against
//! counts, and metric counts against outcome rows"). It lives in the kernel,
//! not in the contracts crate: it needs the statistics and the accounting
//! rule, which are protocol semantics that the contracts deliberately do not
//! carry (ADR 0002, "Consequences"), and putting them there would have forced
//! a schema, fixture and digest change. The price is that
//! `pii_eval_contracts::validate` alone does not prove metric values; any
//! consumer that accepts an artifact must also call
//! [`verify_run_artifact_accounting`] (or the public variant). ADR 0005
//! records this and assigns the call sites (P8 `validate` and `replay`, P7
//! after writing: the artifact writer calls it on every artifact it produces).
//!
//! Since protocol revision 2 (ADR 0008) metrics are keyed by scanner, so an
//! artifact with several scanners is verified scanner by scanner. A revision-1
//! artifact is not verifiable here ([`VerifyFailure::UnsupportedRevision`]): its
//! accounting was the legacy one.
//!
//! Failures reuse the contracts' stable reason codes
//! (`metric-counts-inconsistent`, `metric-value-inconsistent`,
//! `metric-definition-mismatch`, `count-mismatch`); no reason code is added.

use std::fmt;

use pii_eval_contracts::{
    Collector, ContractError, CorpusSnapshot, EffectiveNBasis, Mechanics, Meta, MetricResult, Path,
    ProtocolIdentity, PublicSyntheticArtifact, ReasonCode, RunArtifact, ScannerMetrics, Violations,
    validate_artifact_against_snapshot,
};

use crate::accounting::{
    AccountError, AuthoredIndex, OutcomeRef, ScannerInput, StratumAccounting, account,
};
use crate::stats::{StatsError, published_value};

/// Why verification could not conclude `Ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyFailure {
    /// The outcome rows or snapshot are not accountable (missing, duplicate or
    /// unknown rows, limits, ...).
    Accounting(AccountError),
    /// The artifact is not protocol revision 2. Revision 1 uses the legacy
    /// accounting (any-row benign and collision buckets, one unkeyed metric
    /// list), which this verifier does not implement: such an artifact is
    /// readable and structurally valid, but its metrics are not recomputed
    /// (ADR 0008, section 1).
    UnsupportedRevision {
        /// The revision the artifact declares.
        version: u32,
    },
    /// The artifact disagrees with the snapshot or with its own rows.
    Mismatch(Violations),
}

impl fmt::Display for VerifyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyFailure::Accounting(e) => write!(f, "accounting: {e}"),
            VerifyFailure::UnsupportedRevision { version } => {
                write!(f, "protocol revision {version} is not verifiable")
            }
            VerifyFailure::Mismatch(v) => write!(f, "{v}"),
        }
    }
}

impl std::error::Error for VerifyFailure {}

impl From<AccountError> for VerifyFailure {
    fn from(e: AccountError) -> Self {
        VerifyFailure::Accounting(e)
    }
}

/// Check one metric result against its own counts and the mechanics, with no
/// rows: frozen definition, count identities, derived status, effective-N
/// basis, and the published point and bound recomputed from `numerator` and
/// `effective_n` (equality of integer mantissa and scale).
pub fn verify_metric_result(
    result: &MetricResult,
    mechanics: &Mechanics,
) -> Result<(), Violations> {
    let mut c = Collector::new();
    check_metric_result(result, mechanics, &Path::ROOT, true, &mut c);
    c.finish()
}

/// Definition, identities and effective-N basis; the published value too when
/// `check_value` (callers that compare against the accounting of the rows
/// compare the value there instead, so it is not reported twice).
fn check_metric_result(
    result: &MetricResult,
    mechanics: &Mechanics,
    path: &Path<'_>,
    check_value: bool,
    c: &mut Collector,
) {
    let definition = result.metric.id.definition();
    if result.metric.version != definition.version {
        c.push(ReasonCode::MetricDefinitionMismatch, &path.field("metric"));
    }
    if !result.counts.is_consistent() || result.status != result.counts.derived_status() {
        c.push(ReasonCode::MetricCountsInconsistent, &path.field("counts"));
        return;
    }
    let expected_n = match definition.effective_n {
        EffectiveNBasis::Measured => result.counts.measured,
        EffectiveNBasis::Eligible => result.counts.eligible,
    };
    if result.effective_n != expected_n {
        c.push(
            ReasonCode::MetricCountsInconsistent,
            &path.field("effectiveN"),
        );
        return;
    }
    if !check_value {
        return;
    }
    match published_value(
        result.counts.numerator,
        result.effective_n,
        definition.direction,
        mechanics,
    ) {
        Ok(expected) => {
            if expected != result.value {
                c.push(ReasonCode::MetricValueInconsistent, &path.field("value"));
            }
        }
        Err(StatsError::InvalidCounts { .. }) => {
            c.push(ReasonCode::MetricCountsInconsistent, &path.field("counts"));
        }
        Err(StatsError::InvalidMechanics | StatsError::Overflow) => {
            c.push(ReasonCode::MechanicsInvalid, &path.field("value"));
        }
    }
}

struct Parts<'a> {
    protocol: &'a ProtocolIdentity,
    scanners: Vec<ScannerInput<'a>>,
    rows: Vec<OutcomeRef<'a>>,
    metrics: &'a [MetricResult],
    scanner_metrics: &'a [ScannerMetrics],
    mechanics: &'a Mechanics,
}

fn verify_parts(parts: Parts<'_>, snapshot: &CorpusSnapshot) -> Result<(), VerifyFailure> {
    if !parts.protocol.is_canonical() {
        return Err(VerifyFailure::UnsupportedRevision {
            version: parts.protocol.version,
        });
    }
    let index = AuthoredIndex::new(&snapshot.semantic)?;
    let accounting = account(
        &index,
        &parts.scanners,
        parts.rows.iter().copied(),
        parts.mechanics,
    )?;
    let mut c = Collector::new();
    let root = Path::ROOT.field("semantic");
    // Revision 2 has no unkeyed list.
    if !parts.metrics.is_empty() {
        c.push(ReasonCode::ProtocolBindingMismatch, &root.field("metrics"));
    }
    let list = root.field("scannerMetrics");
    // No entry for an unknown scanner, and exactly one entry per scanner: an
    // omitted scanner cannot hide a bad metric.
    for (i, entry) in parts.scanner_metrics.iter().enumerate() {
        if !accounting
            .scanners
            .iter()
            .any(|s| s.scanner_id == entry.scanner_id)
        {
            c.push(
                ReasonCode::UnknownScanner,
                &list.index(i).field("scannerId"),
            );
        }
    }
    for scanner in &accounting.scanners {
        let entries: Vec<(usize, &ScannerMetrics)> = parts
            .scanner_metrics
            .iter()
            .enumerate()
            .filter(|(_, e)| e.scanner_id == scanner.scanner_id)
            .collect();
        match entries.as_slice() {
            [(i, entry)] => compare(
                &scanner.overall,
                &entry.metrics,
                parts.mechanics,
                &list.index(*i).field("metrics"),
                &mut c,
            ),
            _ => c.push(ReasonCode::MetricDefinitionMismatch, &list),
        }
    }
    c.finish().map_err(VerifyFailure::Mismatch)
}

fn compare(
    stratum: &StratumAccounting,
    metrics: &[MetricResult],
    mechanics: &Mechanics,
    list: &Path<'_>,
    c: &mut Collector,
) {
    // Exactly the registry's ten metrics, each once: an artifact that omits
    // (or repeats) a metric cannot hide a bad one.
    let complete = pii_eval_contracts::METRICS
        .iter()
        .all(|d| metrics.iter().filter(|m| m.metric.id == d.id).count() == 1)
        && metrics.len() == pii_eval_contracts::METRICS.len();
    if !complete {
        c.push(ReasonCode::MetricDefinitionMismatch, list);
    }
    for (i, result) in metrics.iter().enumerate() {
        let path = list.index(i);
        // Own consistency first (definition and identities); the value is
        // compared with the accounting of the rows below.
        check_metric_result(result, mechanics, &path, false, c);
        let Some(account) = stratum.metric(result.metric.id) else {
            c.push(ReasonCode::MetricDefinitionMismatch, &path.field("metric"));
            continue;
        };
        if result.counts != account.counts {
            c.push(ReasonCode::CountMismatch, &path.field("counts"));
        } else if result.effective_n != account.effective_n || result.status != account.status {
            c.push(
                ReasonCode::MetricCountsInconsistent,
                &path.field("effectiveN"),
            );
        } else if result.value != account.value {
            c.push(ReasonCode::MetricValueInconsistent, &path.field("value"));
        }
    }
}

/// Verify an internal artifact against the snapshot it measured: the
/// contracts' snapshot binding (population, authored counts, method coverage,
/// outcome lattice), then every scanner's metrics against that scanner's rows.
///
/// Requires protocol revision 2 ([`VerifyFailure::UnsupportedRevision`]
/// otherwise) and a complete outcome matrix (a missing row is
/// `Accounting(MissingRows)`). Scanners are never pooled.
pub fn verify_run_artifact_accounting(
    artifact: &RunArtifact,
    snapshot: &CorpusSnapshot,
) -> Result<(), VerifyFailure> {
    validate_artifact_against_snapshot(artifact, snapshot).map_err(VerifyFailure::Mismatch)?;
    let body = &artifact.semantic;
    verify_parts(
        Parts {
            protocol: &body.protocol,
            scanners: body
                .scanners
                .iter()
                .map(|s| ScannerInput {
                    id: &s.identity.scanner_id,
                    status: s.status,
                })
                .collect(),
            rows: body.outcomes.iter().map(OutcomeRef::from).collect(),
            metrics: &body.metrics,
            scanner_metrics: &body.scanner_metrics,
            mechanics: &body.mechanics,
        },
        snapshot,
    )
}

/// Verify a public-synthetic artifact the same way. The public shape has no
/// snapshot-binding function in the contracts, so the population digest is
/// compared here.
pub fn verify_public_artifact_accounting(
    artifact: &PublicSyntheticArtifact,
    snapshot: &CorpusSnapshot,
) -> Result<(), VerifyFailure> {
    let body = &artifact.semantic;
    if body.population.population_digest != snapshot.semantic_digest {
        return Err(VerifyFailure::Mismatch(Violations::single(ContractError {
            code: ReasonCode::PopulationBindingMismatch,
            path: Path::ROOT.field("semantic").field("population").render(),
            meta: Meta::NONE,
        })));
    }
    verify_parts(
        Parts {
            protocol: &body.protocol,
            scanners: body
                .scanners
                .iter()
                .map(|s| ScannerInput {
                    id: &s.identity.scanner_id,
                    status: s.status,
                })
                .collect(),
            rows: body.outcomes.iter().map(OutcomeRef::from).collect(),
            metrics: &body.metrics,
            scanner_metrics: &body.scanner_metrics,
            mechanics: &body.mechanics,
        },
        snapshot,
    )
}
