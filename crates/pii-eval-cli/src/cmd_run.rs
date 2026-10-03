//! `pii-eval run`: strict provenance validation, then the bounded executor,
//! then the validated atomic writer (ADR 0010).
//!
//! Order of work (each step before the next, nothing launched before step 9):
//!
//! 1. parse the configuration;
//! 2. for a protected run, require and validate the custodian job context
//!    **before any input path is touched**;
//! 3. read the snapshot and the manifest (a protected run only from inside the
//!    context's input root);
//! 4. check every identity pin and binding;
//! 5. build the pinned adapters and derive each scanner plan, which must equal
//!    the manifest's;
//! 6. hash every pinned artifact;
//! 7. prepare the output directory;
//! 8. check the execution limits;
//! 9. run, assemble, verify and write.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pii_eval_adapters::ScannerAdapter;
use pii_eval_contracts::{
    CorpusSnapshot, ENGINE_NAME, ENGINE_VERSION, PROTOCOL_ID, ParseLimits, ProductIdentity,
    RunClass, RunManifest, ScannerStatus, Visibility, parse, validate_manifest_against_snapshot,
};
use serde_json::{Value, json};

use crate::args::RunArgs;
use crate::config::{JobContext, ProductKind, RunConfig};
use crate::exec::{CancelToken, ExecError, ExecutorConfig};
use crate::files::{OutputDir, canonical_or_parent, is_inside, prepare_output, read_input};
use crate::run::{RunConfig as PipelineConfig, RunError, RunRequest, run_and_write};
use crate::scanners::{build_adapter, preflight_pins};
use crate::status::{Exit, Failure, from_binding, from_violations, reason};
use crate::summary::{Report, files_value};
use crate::write::{
    ArtifactWriter, MANIFEST_FILE, PUBLIC_ARTIFACT_FILE, RUN_ARTIFACT_FILE, WriteError,
    observation_file_name,
};

/// Environment variable that names the job-context file (the option wins).
pub const JOB_CONTEXT_ENV: &str = "PII_EVAL_JOB_CONTEXT";

/// A wire name of a serializable enum.
pub fn wire<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub(crate) fn exec_failure(e: &ExecError) -> Failure {
    let detail = match e {
        ExecError::InvalidLimits => "invalid-limits",
        ExecError::AdapterExceedsManifestBounds { .. } => "adapter-exceeds-manifest-bounds",
        ExecError::BudgetTooSmall => "budget-too-small",
        ExecError::ResourceMonitor(_) => "resource-monitor",
        ExecError::TreeCleanupUnsupported => "tree-cleanup-unsupported",
        ExecError::Scratch => "scratch",
        ExecError::AdapterCountMismatch => "adapter-count",
        ExecError::ThreadSpawn => "thread-spawn",
    };
    let reason = if matches!(e, ExecError::TreeCleanupUnsupported) {
        reason::PLATFORM_UNSUPPORTED
    } else {
        reason::EXECUTION_REFUSED
    };
    Failure::new(Exit::Execution, reason).with_detail(detail)
}

/// A write failure as a command failure.
pub(crate) fn write_failure(e: &WriteError) -> Failure {
    match e {
        WriteError::Exists => Failure::new(Exit::Output, reason::OUTPUT_EXISTS),
        WriteError::Destination => {
            Failure::new(Exit::Output, reason::OUTPUT_UNUSABLE).with_detail("destination")
        }
        WriteError::Io(_) => Failure::new(Exit::Output, reason::OUTPUT_WRITE_FAILED),
        WriteError::PartiallyCommitted { .. } => Failure::new(Exit::Output, reason::OUTPUT_PARTIAL),
        WriteError::CommitNotDurable { .. } => {
            Failure::new(Exit::Output, reason::OUTPUT_NOT_DURABLE)
        }
        // A document this engine built failed its own validation, round trip or
        // accounting verification: a defect here, never a scanner's.
        WriteError::Invalid | WriteError::RoundTrip | WriteError::Verification(_) => {
            Failure::new(Exit::Internal, reason::ARTIFACT_VERIFICATION_FAILED)
        }
    }
}

pub(crate) fn read_document<D: pii_eval_contracts::Document>(
    path: &Path,
    kind: &'static str,
) -> Result<(D, Vec<u8>), Failure> {
    let bytes = read_input(path, ParseLimits::default().max_bytes, kind)?;
    let doc = parse::<D>(&bytes, &ParseLimits::default()).map_err(|v| from_violations(kind, &v))?;
    Ok((doc, bytes))
}

fn require_job_context(args: &RunArgs) -> Result<JobContext, Failure> {
    let path = args
        .job_context
        .clone()
        .or_else(|| {
            std::env::var(JOB_CONTEXT_ENV)
                .ok()
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| Failure::new(Exit::ProtectedContext, reason::PROTECTED_CONTEXT_REQUIRED))?;
    JobContext::load(Path::new(&path))
}

fn product_of(identity: &ProductIdentity) -> ProductKind {
    match identity {
        ProductIdentity::Released => ProductKind::Released,
        ProductIdentity::Candidate { .. } => ProductKind::Candidate,
    }
}

/// Execute `pii-eval run`.
pub fn run(args: &RunArgs, cancel: &CancelToken) -> Result<Report, Failure> {
    // 1. Configuration.
    let config_path = PathBuf::from(&args.config);
    let bytes = read_input(&config_path, crate::config::MAX_CONFIG_BYTES, "run-config")?;
    let base = std::fs::canonicalize(&config_path)
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .ok_or_else(|| Failure::new(Exit::Invalid, reason::INPUT_UNREADABLE))?;
    let config = RunConfig::parse(&bytes, &base)?;
    if !cfg!(unix) {
        return Err(Failure::new(Exit::Execution, reason::PLATFORM_UNSUPPORTED)
            .with_detail("scanner execution needs Linux or macOS"));
    }

    // 2. A protected run needs a valid custodian context before any input is read.
    let protected = config.run_class == RunClass::Protected;
    let job = if protected {
        Some(require_job_context(args)?)
    } else {
        None
    };

    // 3. Inputs. A protected run reads protected inputs only inside the context.
    if let Some(job) = &job {
        for path in [&config.snapshot.path, &config.manifest.path] {
            if !is_inside(&job.input_root, path) {
                return Err(
                    Failure::new(Exit::ProtectedContext, reason::PROTECTED_PATH_OUTSIDE)
                        .with_detail("input"),
                );
            }
        }
    }
    let (snapshot, _) = read_document::<CorpusSnapshot>(&config.snapshot.path, "snapshot")?;
    let (manifest, _) = read_document::<RunManifest>(&config.manifest.path, "manifest")?;

    // 4. Identity pins and bindings.
    if let Some(expected) = &config.snapshot.digest {
        if *expected != snapshot.semantic_digest {
            return Err(Failure::provenance("snapshot-digest"));
        }
    }
    if let Some(expected) = &config.manifest.digest {
        if *expected != manifest.semantic_digest {
            return Err(Failure::provenance("manifest-digest"));
        }
    }
    let m = &manifest.semantic;
    if m.engine.version.as_str() != ENGINE_VERSION
        || config
            .engine_version
            .as_deref()
            .is_some_and(|v| v != ENGINE_VERSION)
    {
        return Err(Failure::provenance("engine"));
    }
    if !m.protocol.is_canonical() {
        return Err(
            Failure::new(Exit::Invalid, reason::PROTOCOL_UNSUPPORTED).with_detail("manifest")
        );
    }
    if let Some((id, revision)) = &config.protocol {
        if id != PROTOCOL_ID || *revision != m.protocol.version {
            return Err(Failure::provenance("protocol"));
        }
    }
    if config.run_class != m.run_class {
        return Err(Failure::provenance("run-class"));
    }
    if !m.run_class.matches(snapshot.semantic.population.visibility) {
        return Err(Failure::provenance("population-visibility"));
    }
    validate_manifest_against_snapshot(&manifest, &snapshot)
        .map_err(|v| from_binding("manifest", &v))?;
    if m.scanners
        .iter()
        .any(|s| product_of(&s.identity.product) != config.product)
    {
        return Err(Failure::provenance("product"));
    }
    if let Some(job) = &job {
        let mismatch = job.population_digest != snapshot.semantic_digest
            || job.manifest_digest != manifest.semantic_digest
            || snapshot.semantic.population.visibility != Visibility::Protected;
        let candidate_mismatch = m.scanners.iter().any(|s| match &s.identity.product {
            ProductIdentity::Candidate { candidate_digest } => {
                job.candidate_digest.as_ref() != Some(candidate_digest)
            }
            ProductIdentity::Released => false,
        });
        if mismatch || candidate_mismatch {
            return Err(Failure::new(
                Exit::ProtectedContext,
                reason::PROTECTED_CONTEXT_MISMATCH,
            ));
        }
    }

    // 5. Adapters; each derived plan must equal the manifest's.
    let node_of = |cfg: &crate::config::ScannerConfig| -> Result<PathBuf, Failure> {
        let node = args
            .node
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| cfg.node.clone())
            .ok_or_else(|| Failure::config("node (give --node or scanners[].node)"))?;
        if !node.is_absolute() {
            return Err(Failure::config("node (must be an absolute path)"));
        }
        // The shim is JavaScript: another interpreter (a shell, say) would
        // execute its lines as commands. The configuration names an executable,
        // so treat it like a command line (docs/cli.md); this only stops the
        // obvious mistake of naming something that is not Node.
        if node.file_name().and_then(|n| n.to_str()) != Some("node") {
            return Err(Failure::config("node (the file must be named node)"));
        }
        Ok(node)
    };
    let mut adapters: Vec<Arc<dyn ScannerAdapter>> = Vec::new();
    let mut matched: Vec<Option<Arc<dyn ScannerAdapter>>> = vec![None; m.scanners.len()];
    for cfg in &config.scanners {
        let adapter = build_adapter(cfg, config.product, &node_of(cfg)?)?;
        let slot = m.scanners.iter().position(|plan| {
            adapter
                .plan(plan.configuration.clone())
                .is_ok_and(|derived| derived.identity == plan.identity)
        });
        match slot {
            Some(i) if matched[i].is_none() => matched[i] = Some(adapter),
            _ => return Err(Failure::provenance("scanner-plan")),
        }
    }
    for slot in matched {
        adapters.push(slot.ok_or_else(|| Failure::provenance("scanner-set"))?);
    }

    // 6. Hash every pinned artifact before anything starts.
    for cfg in &config.scanners {
        preflight_pins(cfg, config.product)?;
    }

    // 7. Output directory.
    let out_dir = args
        .out
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| config.output.dir.clone())
        .ok_or_else(|| Failure::config("output.dir (give --out or output.dir)"))?;
    if let Some(job) = &job {
        let inside = canonical_or_parent(&out_dir).is_some_and(|p| p.starts_with(&job.output_root));
        if !inside {
            return Err(
                Failure::new(Exit::ProtectedContext, reason::PROTECTED_PATH_OUTSIDE)
                    .with_detail("output"),
            );
        }
    }
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
    let output: OutputDir = prepare_output(&out_dir, &names, config.output.overwrite)?;

    // 8. Execution limits, refused before any scanner starts.
    let mut executor = ExecutorConfig {
        max_workers: config.host.max_workers,
        resources: config.host.resources,
        scratch_root: config.host.scratch_dir.clone(),
        ..ExecutorConfig::default()
    };
    if let Some(min) = config.host.min_session_memory_bytes {
        executor.min_session_memory_bytes = min;
    }
    crate::exec::effective_limits(&m.limits, &executor).map_err(|e| exec_failure(&e))?;

    // 9. Run, assemble, verify, write.
    let writer = ArtifactWriter::new(output.path(), config.output.overwrite).with_manifest();
    let result = run_and_write(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters,
        },
        &PipelineConfig {
            executor,
            diagnostics: config.host.diagnostics,
            commit_cancelled: false,
        },
        cancel,
        &writer,
    );
    let (out, written) = match result {
        Ok(ok) => ok,
        Err(RunError::Cancelled) => {
            return Err(Failure::new(Exit::Cancelled, reason::CANCELLED));
        }
        Err(RunError::Write(WriteError::CommitNotDurable { files })) => {
            output.commit();
            return Err(write_failure(&WriteError::CommitNotDurable { files }));
        }
        Err(RunError::Write(e)) => return Err(write_failure(&e)),
        Err(RunError::InvalidPlan) => {
            return Err(Failure::new(Exit::Invalid, reason::DOCUMENT_INVALID).with_detail("plan"));
        }
        Err(RunError::UnsupportedProtocol) => {
            return Err(Failure::new(Exit::Invalid, reason::PROTOCOL_UNSUPPORTED));
        }
        Err(RunError::AdapterMismatch) => return Err(Failure::provenance("scanner-set")),
        Err(RunError::Exec(e)) => return Err(exec_failure(&e)),
        Err(RunError::Assemble(_)) => {
            return Err(Failure::new(Exit::Invalid, reason::ASSEMBLY_FAILED));
        }
    };
    output.commit();

    // Report. A scanner that did not complete is never reported as success.
    let artifact = &out.assembled.artifact;
    let scanners: Vec<Value> = artifact
        .semantic
        .scanners
        .iter()
        .map(|s| {
            let failure = artifact
                .semantic
                .failures
                .iter()
                .find(|f| f.scanner_id == s.identity.scanner_id);
            let mut v = json!({
                "scannerId": s.identity.scanner_id.as_str(),
                "status": wire(&s.status),
                "observationDigest": s.observation_digest.as_str(),
                "replays": {"count": s.replays.count, "agreed": s.replays.agreed},
            });
            if let Some(f) = failure {
                v["failure"] = json!({"code": wire(&f.code), "affectedInputs": f.affected_inputs});
            }
            v
        })
        .collect();
    let incomplete = artifact
        .semantic
        .scanners
        .iter()
        .any(|s| s.status != ScannerStatus::Complete);
    let semantic = json!({
        "mode": config.mode.as_str(),
        "product": config.product.as_str(),
        "runClass": wire(&m.run_class),
        "protocol": {"id": PROTOCOL_ID, "revision": m.protocol.version},
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        "populationDigest": snapshot.semantic_digest.as_str(),
        "manifestDigest": manifest.semantic_digest.as_str(),
        "runArtifactDigest": artifact.semantic_digest.as_str(),
        "publicArtifactDigest": out.assembled.public.as_ref().map(|p| p.semantic_digest.as_str()),
        "populationCounts": serde_json::to_value(artifact.semantic.population_counts)
            .unwrap_or(Value::Null),
        "scanners": scanners,
        "completeness": wire(&artifact.semantic.completeness),
        "failureCodes": artifact.semantic.failures.iter().map(|f| wire(&f.code)).collect::<Vec<_>>(),
    });
    let mut semantic = semantic;
    if let Some(o) = semantic.as_object_mut() {
        if protected {
            // A protected run reports identities and statuses, not the
            // population's size or shape: that is the custodian's to disclose.
            o.remove("populationCounts");
        }
        if o.get("publicArtifactDigest").is_some_and(Value::is_null) {
            o.remove("publicArtifactDigest");
        }
    }
    Ok(Report {
        exit: if incomplete {
            Exit::ScannerFailure
        } else {
            Exit::Success
        },
        state: if incomplete { "incomplete" } else { "complete" },
        reason: incomplete.then_some(reason::SCANNER_FAILURE),
        semantic,
        outputs: Some(files_value(&written.files)),
    })
}
