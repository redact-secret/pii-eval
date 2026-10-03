//! Replay: rebuild the executor's per-scanner results from fixed
//! [`ObservationSet`]s, so the kernel can re-derive the artifact **without
//! launching any scanner** (ADR 0010).
//!
//! Observation sets hold digests and findings only; two facts the artifact
//! needs are not in them:
//!
//! * the sanitized-output verdicts (`output-verified` rows), which need the
//!   sanitized text that observation sets deliberately never keep;
//! * the failure code and affected-input count of a scanner that did not
//!   complete.
//!
//! Both are taken from the **original run artifact** when one is supplied: the
//! artifact must itself pass the accounting verifier and must bind to exactly
//! these observation sets by digest. Without an original, replay works only
//! when no scanner needs either fact ([`needs_original`]).

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use pii_eval_contracts::{
    ActionCapability, ActionOutcome, CorpusSnapshot, Id, ObservationSet, OutputVerification,
    RunArtifact, RunManifest, ScannerId, ScannerPlan, ScannerStatus,
};

use crate::assemble::variant_tasks;
use crate::exec::{ObservedInput, ScannerFailure, ScannerRun, ScannerTiming};
use crate::status::{Exit, Failure, reason};

/// Whether replay cannot proceed without the original artifact: some scanner
/// did not complete (its failure code is only in the artifact) or returned
/// sanitized output (its verdicts are only in the artifact).
pub fn needs_original(sets: &[ObservationSet]) -> bool {
    sets.iter().any(|s| {
        let o = &s.semantic;
        o.status != ScannerStatus::Complete
            || (o.capabilities.action == ActionCapability::SanitizedOutput
                && o.inputs.iter().any(|i| i.sanitized_output_digest.is_some()))
    })
}

fn zero_timing() -> ScannerTiming {
    ScannerTiming {
        startup: Duration::ZERO,
        scan: Duration::ZERO,
        wall: Duration::ZERO,
        started_at: SystemTime::UNIX_EPOCH,
        finished_at: SystemTime::UNIX_EPOCH,
        peak_rss_bytes: 0,
    }
}

/// One [`ScannerRun`] per manifest scanner, in manifest order, from `sets` (any
/// order, validated against the manifest and snapshot by the caller).
pub fn runs_from_observations(
    snapshot: &CorpusSnapshot,
    manifest: &RunManifest,
    sets: &[ObservationSet],
    original: Option<&RunArtifact>,
) -> Result<Vec<ScannerRun>, Failure> {
    let tasks = variant_tasks(snapshot);
    let index_of: BTreeMap<&Id, usize> = tasks
        .iter()
        .enumerate()
        .map(|(i, t)| (t.variant_id, i))
        .collect();
    let by_scanner: BTreeMap<&ScannerId, &ObservationSet> = sets
        .iter()
        .map(|s| (&s.semantic.scanner.scanner_id, s))
        .collect();
    // Verdicts of the original artifact, by (scanner, variant, occurrence).
    let mut verdicts: BTreeMap<(&ScannerId, &Id, &Id), OutputVerification> = BTreeMap::new();
    if let Some(a) = original {
        for row in &a.semantic.outcomes {
            if let ActionOutcome::OutputVerified { verification } = row.action {
                verdicts.insert(
                    (&row.scanner_id, &row.variant_id, &row.occurrence_id),
                    verification,
                );
            }
        }
    }
    let incomplete = || Failure::new(Exit::Invalid, reason::REPLAY_INCOMPLETE);
    let mut runs = Vec::new();
    for plan in &manifest.semantic.scanners {
        let id = &plan.identity.scanner_id;
        let set = by_scanner
            .get(id)
            .ok_or_else(|| Failure::provenance("scanner-set"))?;
        let o = &set.semantic;
        let failure = if o.status == ScannerStatus::Complete {
            None
        } else {
            let f = original
                .and_then(|a| a.semantic.failures.iter().find(|f| f.scanner_id == *id))
                .ok_or_else(|| Failure::new(Exit::Invalid, reason::REPLAY_ORIGINAL_REQUIRED))?;
            Some(ScannerFailure {
                code: f.code,
                affected_inputs: f.affected_inputs,
            })
        };
        let with_verdicts = o.status == ScannerStatus::Complete
            && o.capabilities.action == ActionCapability::SanitizedOutput;
        let mut inputs = Vec::with_capacity(o.inputs.len());
        for input in &o.inputs {
            let index = *index_of.get(&input.variant_id).ok_or_else(incomplete)?;
            let verification = if with_verdicts && input.sanitized_output_digest.is_some() {
                let variant = snapshot
                    .semantic
                    .cases
                    .iter()
                    .flat_map(|c| &c.variants)
                    .nth(index)
                    .ok_or_else(incomplete)?;
                variant
                    .expectations
                    .iter()
                    .map(|e| {
                        verdicts
                            .get(&(id, &variant.variant_id, &e.occurrence_id))
                            .copied()
                    })
                    .collect::<Option<Vec<_>>>()
            } else {
                None
            };
            inputs.push(ObservedInput {
                index,
                input_digest: input.input_digest.clone(),
                sanitized_output_digest: input.sanitized_output_digest.clone(),
                findings: input.findings.clone(),
                verification,
            });
        }
        inputs.sort_by_key(|i| i.index);
        runs.push(ScannerRun {
            plan: ScannerPlan {
                identity: plan.identity.clone(),
                configuration: plan.configuration.clone(),
            },
            status: o.status,
            capabilities: o.capabilities.clone(),
            replays: o.replays,
            inputs,
            failure,
            runtime: None,
            timing: zero_timing(),
        });
    }
    Ok(runs)
}
