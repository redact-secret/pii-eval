//! `pii-eval replay`: re-derive the artifact from fixed observation sets with
//! no scanner launched (ADR 0010). The same observations, snapshot and manifest
//! give the same semantic digests as the original run; any changed input,
//! setting or identity is rejected before anything is written.

use std::path::Path;
use std::time::Instant;

use pii_eval_contracts::{
    CorpusSnapshot, ObservationSet, ParseLimits, RunArtifact, RunClass, RunManifest, Sha256Digest,
    parse, validate_artifact_against_manifest, validate_artifact_against_snapshot,
    validate_manifest_against_snapshot, validate_observation_against_manifest,
    validate_observation_against_snapshot,
};
use pii_eval_kernel::{VerifyFailure, verify_run_artifact_accounting};
use serde_json::json;

use crate::args::ReplayArgs;
use crate::assemble::{
    AssembleOptions, ProjectionRequest, assemble_with_projection, variant_tasks,
};
use crate::cmd_run::{read_document, wire, write_failure};
use crate::files::{confine, prepare_output, read_input};
use crate::replay::{needs_original, runs_from_observations};
use crate::status::{Exit, Failure, from_binding, from_violations, reason};
use crate::summary::{Report, files_value};
use crate::write::{
    ArtifactWriter, MANIFEST_FILE, OverwritePolicy, PUBLIC_ARTIFACT_FILE, RUN_ARTIFACT_FILE,
    WriteError, observation_file_name,
};

fn digest_option(value: &Option<String>, option: &str) -> Result<Option<Sha256Digest>, Failure> {
    match value {
        None => Ok(None),
        Some(v) => Sha256Digest::new(v)
            .map(Some)
            .map_err(|_| Failure::usage(reason::INVALID_OPTION_VALUE, option)),
    }
}

/// Execute `pii-eval replay`. No scanner is launched: this function reaches no
/// adapter and no process API (a test spawns nothing and asserts it).
pub fn replay(args: &ReplayArgs) -> Result<Report, Failure> {
    let started = Instant::now();
    let overwrite = match args.overwrite.as_deref() {
        None | Some("refuse") => OverwritePolicy::Refuse,
        Some("replace") => OverwritePolicy::Replace,
        Some(_) => return Err(Failure::usage(reason::INVALID_OPTION_VALUE, "overwrite")),
    };
    let expect_snapshot = digest_option(&args.expect_snapshot_digest, "expect-snapshot-digest")?;
    let expect_manifest = digest_option(&args.expect_manifest_digest, "expect-manifest-digest")?;
    // A replay has no run configuration, so the projection's mode is stated on
    // the command line: both options or neither.
    let projection_mode = match (&args.projection_roster, &args.projection_mode) {
        (None, None) => None,
        (Some(_), Some(mode)) => Some(match mode.as_str() {
            "official" => pii_eval_contracts::ProjectionMode::Official,
            "exploratory" => pii_eval_contracts::ProjectionMode::Exploratory,
            _ => {
                return Err(Failure::usage(
                    reason::INVALID_OPTION_VALUE,
                    "projection-mode",
                ));
            }
        }),
        (Some(_), None) => {
            return Err(Failure::usage(
                reason::MISSING_REQUIRED_OPTION,
                "projection-mode",
            ));
        }
        (None, Some(_)) => {
            return Err(Failure::usage(
                reason::MISSING_REQUIRED_OPTION,
                "projection-roster",
            ));
        }
    };
    if args.observations.len() > pii_eval_contracts::limits::MAX_SCANNERS {
        return Err(Failure::usage(reason::INVALID_OPTION_VALUE, "observation"));
    }

    let (snapshot, _) = read_document::<CorpusSnapshot>(Path::new(&args.snapshot), "snapshot")?;
    let (manifest, _) = read_document::<RunManifest>(Path::new(&args.manifest), "manifest")?;
    if expect_snapshot.is_some_and(|d| d != snapshot.semantic_digest) {
        return Err(Failure::provenance("snapshot-digest"));
    }
    if expect_manifest.is_some_and(|d| d != manifest.semantic_digest) {
        return Err(Failure::provenance("manifest-digest"));
    }
    let m = &manifest.semantic;
    // Protected inputs are handled only inside a custodian job context.
    let protected = snapshot.semantic.population.visibility
        == pii_eval_contracts::Visibility::Protected
        || m.run_class == RunClass::Protected;
    let mut inputs: Vec<&Path> = vec![Path::new(&args.snapshot), Path::new(&args.manifest)];
    inputs.extend(args.observations.iter().map(|o| Path::new(o.as_str())));
    inputs.extend(args.original.as_deref().map(Path::new));
    confine(
        protected,
        args.job_context.as_deref(),
        &inputs,
        Some(Path::new(&args.out)),
    )?;
    if !m.protocol.is_canonical() {
        return Err(
            Failure::new(Exit::Invalid, reason::PROTOCOL_UNSUPPORTED).with_detail("manifest")
        );
    }
    validate_manifest_against_snapshot(&manifest, &snapshot)
        .map_err(|v| from_binding("manifest", &v))?;

    let mut sets: Vec<ObservationSet> = Vec::new();
    for path in &args.observations {
        let (set, _) = read_document::<ObservationSet>(Path::new(path), "observation-set")?;
        validate_observation_against_manifest(&set, &manifest)
            .map_err(|v| from_binding("observation-set", &v))?;
        validate_observation_against_snapshot(&set, &snapshot)
            .map_err(|v| from_binding("observation-set", &v))?;
        if sets
            .iter()
            .any(|s| s.semantic.scanner.scanner_id == set.semantic.scanner.scanner_id)
        {
            return Err(Failure::new(Exit::Invalid, reason::DOCUMENT_INVALID)
                .with_detail("observation-set (scanner repeated)"));
        }
        sets.push(set);
    }
    if sets.len() != m.scanners.len() {
        return Err(Failure::provenance("scanner-set"));
    }

    let original: Option<RunArtifact> = match &args.original {
        None => None,
        Some(path) => {
            let bytes = read_input(
                Path::new(path),
                ParseLimits::default().max_bytes,
                "original",
            )?;
            let artifact = parse::<RunArtifact>(&bytes, &ParseLimits::default())
                .map_err(|v| from_violations("original", &v))?;
            validate_artifact_against_manifest(&artifact, &manifest)
                .map_err(|v| from_binding("original", &v))?;
            validate_artifact_against_snapshot(&artifact, &snapshot)
                .map_err(|v| from_binding("original", &v))?;
            verify_run_artifact_accounting(&artifact, &snapshot).map_err(|e| match e {
                VerifyFailure::UnsupportedRevision { .. } => {
                    Failure::new(Exit::Invalid, reason::PROTOCOL_UNSUPPORTED)
                        .with_detail("original")
                }
                VerifyFailure::Mismatch(v) => {
                    Failure::new(Exit::Invalid, reason::VERIFICATION_FAILED)
                        .with_detail("original")
                        .with_codes(v.errors.iter().map(|e| e.code))
                }
                VerifyFailure::Accounting(_) => {
                    Failure::new(Exit::Invalid, reason::VERIFICATION_FAILED).with_detail("original")
                }
            })?;
            // The original must be the run these very observations came from.
            for scanner in &artifact.semantic.scanners {
                let same = sets.iter().any(|s| {
                    s.semantic.scanner == scanner.identity
                        && s.semantic_digest == scanner.observation_digest
                });
                if !same {
                    return Err(Failure::provenance("observation-digest"));
                }
            }
            if artifact.semantic.scanners.len() != sets.len() {
                return Err(Failure::provenance("scanner-set"));
            }
            Some(artifact)
        }
    };
    if original.is_none() && needs_original(&sets) {
        return Err(Failure::new(
            Exit::Invalid,
            reason::REPLAY_ORIGINAL_REQUIRED,
        ));
    }

    // The optional product projection (schema 1.2): the roster is read now that
    // the snapshot is; its mode was checked with the other options.
    let projection: Option<ProjectionRequest> = match (&args.projection_roster, projection_mode) {
        (Some(path), Some(mode)) => {
            if protected {
                return Err(Failure::usage(
                    reason::INVALID_OPTION_VALUE,
                    "projection-roster (public-synthetic runs only)",
                ));
            }
            Some(ProjectionRequest {
                roster: crate::projection::load_roster(Path::new(path), &snapshot, None)?,
                mode,
            })
        }
        _ => None,
    };

    let runs = runs_from_observations(&snapshot, &manifest, &sets, original.as_ref())?;
    let tasks = variant_tasks(&snapshot);
    let mut assembled = assemble_with_projection(
        &snapshot,
        &manifest,
        &tasks,
        &runs,
        AssembleOptions {
            diagnostics: false,
            run_started_at: std::time::SystemTime::UNIX_EPOCH,
        },
        projection.as_ref(),
    )
    .map_err(|_| Failure::new(Exit::Invalid, reason::ASSEMBLY_FAILED))?;

    // Parity with the original, before anything is written.
    let parity = match &original {
        None => "not-checked",
        Some(o) => {
            if o.semantic_digest != assembled.artifact.semantic_digest
                || o.semantic != assembled.artifact.semantic
            {
                return Err(Failure::new(Exit::Provenance, reason::REPLAY_DIVERGED)
                    .with_detail("run-artifact"));
            }
            "identical"
        }
    };

    let mut names = vec![MANIFEST_FILE.to_owned()];
    names.extend(
        m.scanners
            .iter()
            .map(|s| observation_file_name(s.identity.scanner_id.as_str())),
    );
    if m.run_class == RunClass::PublicSynthetic {
        names.push(PUBLIC_ARTIFACT_FILE.to_owned());
    }
    names.push(RUN_ARTIFACT_FILE.to_owned());
    let output = prepare_output(Path::new(&args.out), &names, overwrite)?;
    // The directory is the CLI's own: temporaries a crashed earlier run left in
    // it are removed (never while another writer uses the directory).
    let _ = crate::write::cleanup_stale_temps(output.path());
    let writer = crate::files::with_test_faults(
        ArtifactWriter::new(output.path(), overwrite).with_manifest(),
        output.path(),
    );
    let written = match writer.write_run(&snapshot, &manifest, &mut assembled, started) {
        Ok(w) => w,
        Err(WriteError::CommitNotDurable { files }) => {
            output.commit();
            return Err(write_failure(&WriteError::CommitNotDurable { files }));
        }
        Err(e) => return Err(write_failure(&e)),
    };
    output.commit();

    let artifact = &assembled.artifact;
    let mut carried: Vec<&str> = Vec::new();
    if original.is_some() {
        if sets.iter().any(|s| {
            s.semantic.status == pii_eval_contracts::ScannerStatus::Complete
                && s.semantic.capabilities.action
                    == pii_eval_contracts::ActionCapability::SanitizedOutput
                && s.semantic
                    .inputs
                    .iter()
                    .any(|i| i.sanitized_output_digest.is_some())
        }) {
            carried.push("output-verdicts");
        }
        if sets
            .iter()
            .any(|s| s.semantic.status != pii_eval_contracts::ScannerStatus::Complete)
        {
            carried.push("failure-codes");
        }
    }
    let semantic = json!({
        "parity": parity,
        "verification": {
            // Re-derived from the observation sets by the kernel on this run.
            "recomputed": ["accounting", "artifact-digest", "matching", "metrics", "review-gate"],
            // Taken from the original run artifact (which passed the accounting
            // verifier): not re-derived, so `parity` is not an independent check
            // of these parts.
            "carriedFromOriginal": carried,
        },
        "scannersLaunched": 0,
        "runClass": wire(&m.run_class),
        "populationDigest": snapshot.semantic_digest.as_str(),
        "manifestDigest": manifest.semantic_digest.as_str(),
        "runArtifactDigest": artifact.semantic_digest.as_str(),
        "publicArtifactDigest": assembled.public.as_ref().map(|p| p.semantic_digest.as_str()),
        "scanners": artifact.semantic.scanners.iter().map(|s| json!({
            "scannerId": s.identity.scanner_id.as_str(),
            "status": wire(&s.status),
            "observationDigest": s.observation_digest.as_str(),
        })).collect::<Vec<_>>(),
    });
    let mut semantic = semantic;
    if let Some(block) = assembled
        .public
        .as_ref()
        .and_then(|p| p.semantic.product_projection.as_ref())
    {
        semantic["productProjection"] = json!({
            "rosterDigest": block.roster_digest.as_str(),
            "mode": block.rows.first().map(|r| r.mode.as_str()),
            "requiredViews": block.required_views.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            "rows": block.rows.len(),
        });
    }
    if assembled.public.is_none() {
        if let Some(o) = semantic.as_object_mut() {
            o.remove("publicArtifactDigest");
        }
    }
    let incomplete = artifact
        .semantic
        .scanners
        .iter()
        .any(|s| s.status != pii_eval_contracts::ScannerStatus::Complete);
    Ok(Report {
        exit: if incomplete {
            Exit::ScannerFailure
        } else {
            Exit::Success
        },
        state: if incomplete { "incomplete" } else { "replayed" },
        reason: incomplete.then_some(reason::SCANNER_FAILURE),
        semantic,
        outputs: Some(files_value(&written.files)),
    })
}
