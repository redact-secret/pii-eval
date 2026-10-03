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
    RunArtifact, RunManifest, ScannerId, ScannerPlan, ScannerStatus, Variant,
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

/// The snapshot's variants in the canonical order of [`variant_tasks`] (cases, then
/// the variants of each case): one pass, so a lookup by task index is O(1).
fn variants_in_task_order(snapshot: &CorpusSnapshot) -> Vec<&Variant> {
    snapshot
        .semantic
        .cases
        .iter()
        .flat_map(|c| &c.variants)
        .collect()
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
    // The variant at each task index, built once: `variant_tasks` and this list walk the
    // snapshot in the same canonical order, so `variants[index]` is the variant of task
    // `index`. (Looking it up with an iterator `nth` per observed input made a replay of a
    // sanitized-output scanner quadratic in the number of cases: ADR 0013.)
    let variants = variants_in_task_order(snapshot);
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
                let variant = *variants.get(index).ok_or_else(incomplete)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use pii_eval_contracts::parse_default;

    /// `variants[index]` must be the variant of task `index`: replay indexes this list with
    /// the executor's task indices (ADR 0013 replaced a per-input `nth` walk with it).
    #[test]
    fn the_variant_list_is_aligned_with_the_task_indices() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for name in [
            "fixtures/contracts/v1/snapshot.json",
            "examples/quickstart/snapshot.json",
        ] {
            let bytes = std::fs::read(root.join(name)).expect("committed snapshot");
            let snapshot: CorpusSnapshot = parse_default(&bytes).expect("snapshot parses");
            let tasks = variant_tasks(&snapshot);
            let variants = variants_in_task_order(&snapshot);
            assert_eq!(tasks.len(), variants.len());
            assert!(!tasks.is_empty());
            for (task, variant) in tasks.iter().zip(&variants) {
                assert_eq!(task.variant_id, &variant.variant_id);
                assert_eq!(task.text, variant.text);
            }
        }
    }
}
