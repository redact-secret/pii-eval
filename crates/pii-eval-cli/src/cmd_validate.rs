//! `pii-eval validate`: strict contract validation of one document, optional
//! binding checks against a snapshot and manifest, and the accounting verifier
//! for revision-2 artifacts (ADR 0010).
//!
//! Legacy (protocol revision 1) documents are **readable**: they validate
//! structurally and keep their digests. A legacy *artifact* is not
//! **verifiable** (its metrics came from the legacy accounting, ADR 0008), so
//! the command reports `valid-legacy-not-verifiable` with exit 11 instead of a
//! verified success. Reasons are stable codes; no input text is echoed.

use std::path::Path;

use pii_eval_contracts::{
    CorpusSnapshot, Document, DocumentKind, ObservationSet, ParseLimits, PublicSyntheticArtifact,
    ReasonCode, RunArtifact, RunClass, RunManifest, Visibility, parse, parse_strict,
    validate_artifact_against_manifest, validate_artifact_against_snapshot,
    validate_manifest_against_snapshot, validate_observation_against_manifest,
    validate_observation_against_snapshot, validate_public_artifact_against_snapshot,
};
use pii_eval_kernel::{
    VerifyFailure, verify_public_artifact_accounting, verify_public_projection,
    verify_run_artifact_accounting,
};
use serde_json::{Value, json};

use crate::args::ValidateArgs;
use crate::cmd_run::{read_document, wire};
use crate::files::{confine, read_input};
use crate::status::{Exit, Failure, from_binding, from_contract_error, from_violations, reason};
use crate::summary::Report;

fn kind_from_option(text: &str) -> Result<DocumentKind, Failure> {
    DocumentKind::ALL
        .into_iter()
        .find(|k| k.schema_file_stem() == text)
        .ok_or_else(|| Failure::usage(reason::INVALID_OPTION_VALUE, "kind"))
}

pub(crate) fn verify_failure(e: VerifyFailure) -> Failure {
    match e {
        VerifyFailure::Mismatch(v) => Failure::new(Exit::Invalid, reason::VERIFICATION_FAILED)
            .with_codes(v.errors.iter().map(|e| e.code)),
        VerifyFailure::Accounting(_) => Failure::new(Exit::Invalid, reason::VERIFICATION_FAILED),
        VerifyFailure::UnsupportedRevision { .. } => {
            Failure::new(Exit::Invalid, reason::PROTOCOL_UNSUPPORTED)
        }
    }
}

struct Context {
    snapshot: Option<CorpusSnapshot>,
    manifest: Option<RunManifest>,
}

fn not_applicable(option: &str) -> Failure {
    Failure::usage(
        reason::INVALID_OPTION_VALUE,
        &format!("{option} (not applicable to this kind)"),
    )
}

fn base(kind: DocumentKind, doc: &impl Document) -> Value {
    json!({
        "kind": kind.schema_file_stem(),
        "schemaVersion": doc.schema_version().to_string(),
        "semanticDigest": doc.claimed_digest().as_str(),
    })
}

fn protocol_value(p: &pii_eval_contracts::ProtocolIdentity) -> Value {
    json!({"revision": p.version, "legacy": p.is_legacy()})
}

/// Execute `pii-eval validate`.
pub fn validate(args: &ValidateArgs) -> Result<Report, Failure> {
    let wanted = args.kind.as_deref().map(kind_from_option).transpose()?;
    let bytes = read_input(
        Path::new(&args.file),
        ParseLimits::default().max_bytes,
        "document",
    )?;
    let value = parse_strict(&bytes, &ParseLimits::default())
        .map_err(|e| from_contract_error("document", &e))?;
    let detected = value
        .get("schema")
        .and_then(Value::as_str)
        .and_then(DocumentKind::from_schema_id);
    let kind = match (wanted, detected) {
        (Some(w), Some(d)) if w != d => {
            return Err(Failure::new(Exit::Invalid, reason::KIND_MISMATCH)
                .with_codes([ReasonCode::SchemaKindMismatch]));
        }
        // An explicit kind lets the typed parse report the contract's own codes.
        (Some(w), _) => w,
        (None, Some(d)) => d,
        (None, None) => {
            let code = match value.get("schema") {
                _ if !value.is_object() => ReasonCode::NotAnObject,
                None => ReasonCode::MissingSchema,
                Some(_) => ReasonCode::UnknownSchema,
            };
            return Err(Failure::new(Exit::Invalid, reason::DOCUMENT_INVALID)
                .with_detail("document")
                .with_codes([code]));
        }
    };
    drop(value);
    let stem = kind.schema_file_stem();

    // Optional context documents, read only when an option names them.
    let ctx = Context {
        snapshot: match &args.snapshot {
            Some(p) => Some(read_document::<CorpusSnapshot>(Path::new(p), "snapshot")?.0),
            None => None,
        },
        manifest: match &args.manifest {
            Some(p) => Some(read_document::<RunManifest>(Path::new(p), "manifest")?.0),
            None => None,
        },
    };
    if args.projection_roster.is_some() && kind != DocumentKind::PublicSyntheticArtifact {
        return Err(not_applicable("projection-roster"));
    }
    let limits = ParseLimits::default();
    // Protected documents are handled only inside a custodian job context, and
    // their counts are withheld (ADR 0010 C6).
    let mut protected = ctx
        .snapshot
        .as_ref()
        .is_some_and(|s| s.semantic.population.visibility == Visibility::Protected)
        || ctx
            .manifest
            .as_ref()
            .is_some_and(|m| m.semantic.run_class == RunClass::Protected);
    let mut bindings: Vec<&'static str> = Vec::new();
    let (mut semantic, legacy, verification) = match kind {
        DocumentKind::CorpusSnapshot => {
            if ctx.snapshot.is_some() {
                return Err(not_applicable("snapshot"));
            }
            if ctx.manifest.is_some() {
                return Err(not_applicable("manifest"));
            }
            let d: CorpusSnapshot =
                parse(&bytes, &limits).map_err(|v| from_violations(stem, &v))?;
            protected |= d.semantic.population.visibility == Visibility::Protected;
            let mut s = base(kind, &d);
            let body = &d.semantic;
            s["visibility"] = json!(wire(&body.population.visibility));
            s["cases"] = json!(body.cases.len());
            s["variants"] = json!(body.cases.iter().map(|c| c.variants.len()).sum::<usize>());
            (s, false, "not-applicable")
        }
        DocumentKind::RunManifest => {
            if ctx.manifest.is_some() {
                return Err(not_applicable("manifest"));
            }
            let d: RunManifest = parse(&bytes, &limits).map_err(|v| from_violations(stem, &v))?;
            if let Some(snapshot) = &ctx.snapshot {
                validate_manifest_against_snapshot(&d, snapshot)
                    .map_err(|v| from_binding(stem, &v))?;
                bindings.push("snapshot");
            }
            let mut s = base(kind, &d);
            protected |= d.semantic.run_class == RunClass::Protected;
            s["runClass"] = json!(wire(&d.semantic.run_class));
            s["protocol"] = protocol_value(&d.semantic.protocol);
            s["scanners"] = json!(d.semantic.scanners.len());
            (s, d.semantic.protocol.is_legacy(), "not-applicable")
        }
        DocumentKind::ObservationSet => {
            let d: ObservationSet =
                parse(&bytes, &limits).map_err(|v| from_violations(stem, &v))?;
            if let Some(manifest) = &ctx.manifest {
                validate_observation_against_manifest(&d, manifest)
                    .map_err(|v| from_binding(stem, &v))?;
                bindings.push("manifest");
            }
            if let Some(snapshot) = &ctx.snapshot {
                validate_observation_against_snapshot(&d, snapshot)
                    .map_err(|v| from_binding(stem, &v))?;
                bindings.push("snapshot");
            }
            let mut s = base(kind, &d);
            s["protocol"] = protocol_value(&d.semantic.protocol);
            s["status"] = json!(wire(&d.semantic.status));
            s["inputs"] = json!(d.semantic.inputs.len());
            (s, d.semantic.protocol.is_legacy(), "not-applicable")
        }
        DocumentKind::RunArtifact => {
            let d: RunArtifact = parse(&bytes, &limits).map_err(|v| from_violations(stem, &v))?;
            if let Some(manifest) = &ctx.manifest {
                validate_artifact_against_manifest(&d, manifest)
                    .map_err(|v| from_binding(stem, &v))?;
                bindings.push("manifest");
            }
            let legacy = d.semantic.protocol.is_legacy();
            let mut verification = "not-run";
            if let Some(snapshot) = &ctx.snapshot {
                validate_artifact_against_snapshot(&d, snapshot)
                    .map_err(|v| from_binding(stem, &v))?;
                bindings.push("snapshot");
                if !legacy {
                    verify_run_artifact_accounting(&d, snapshot).map_err(verify_failure)?;
                    verification = "verified";
                }
            }
            if legacy {
                verification = "not-verifiable-legacy";
            }
            protected |= d.semantic.run_class == RunClass::Protected;
            let mut s = base(kind, &d);
            s["protocol"] = protocol_value(&d.semantic.protocol);
            s["runClass"] = json!(wire(&d.semantic.run_class));
            s["scanners"] = scanner_states(
                d.semantic
                    .scanners
                    .iter()
                    .map(|x| (x.identity.scanner_id.as_str(), wire(&x.status))),
            );
            s["completeness"] = json!(wire(&d.semantic.completeness));
            (s, legacy, verification)
        }
        DocumentKind::PublicSyntheticArtifact => {
            if ctx.manifest.is_some() {
                return Err(not_applicable("manifest"));
            }
            let d: PublicSyntheticArtifact =
                parse(&bytes, &limits).map_err(|v| from_violations(stem, &v))?;
            let legacy = d.semantic.protocol.is_legacy();
            let mut verification = "not-run";
            // The product projection (schema 1.2): structure and bindings were
            // checked by the typed parse; with a roster and a snapshot the block
            // is recomputed from the authored population.
            let mut projection = d.semantic.product_projection.as_ref().map(|_| "structural");
            if args.projection_roster.is_some() && ctx.snapshot.is_none() {
                return Err(Failure::usage(
                    reason::MISSING_REQUIRED_OPTION,
                    "snapshot (needed with projection-roster)",
                ));
            }
            if let Some(snapshot) = &ctx.snapshot {
                validate_public_artifact_against_snapshot(&d, snapshot)
                    .map_err(|v| from_binding(stem, &v))?;
                bindings.push("snapshot");
                if !legacy {
                    verify_public_artifact_accounting(&d, snapshot).map_err(verify_failure)?;
                    verification = "verified";
                    if let Some(path) = &args.projection_roster {
                        let roster =
                            crate::projection::load_roster(Path::new(path), snapshot, None)?;
                        verify_public_projection(&d, snapshot, &roster).map_err(verify_failure)?;
                        projection = Some("recomputed");
                    }
                }
            }
            if legacy {
                verification = "not-verifiable-legacy";
            }
            let mut s = base(kind, &d);
            s["protocol"] = protocol_value(&d.semantic.protocol);
            s["scanners"] = scanner_states(
                d.semantic
                    .scanners
                    .iter()
                    .map(|x| (x.identity.scanner_id.as_str(), wire(&x.status))),
            );
            s["completeness"] = json!(wire(&d.semantic.completeness));
            if let Some(p) = projection {
                s["productProjection"] = json!(p);
            }
            (s, legacy, verification)
        }
    };
    let mut paths: Vec<&Path> = vec![Path::new(&args.file)];
    paths.extend(args.snapshot.as_deref().map(Path::new));
    paths.extend(args.manifest.as_deref().map(Path::new));
    paths.extend(args.projection_roster.as_deref().map(Path::new));
    confine(protected, args.job_context.as_deref(), &paths, None)?;
    if protected {
        if let Some(o) = semantic.as_object_mut() {
            o.remove("cases");
            o.remove("variants");
        }
    }
    semantic["bindingsChecked"] = json!(bindings);
    semantic["verification"] = json!(verification);
    let not_verifiable = legacy && verification == "not-verifiable-legacy";
    Ok(Report {
        exit: if not_verifiable {
            Exit::NotVerifiable
        } else {
            Exit::Success
        },
        state: if not_verifiable {
            "valid-legacy-not-verifiable"
        } else {
            "valid"
        },
        reason: not_verifiable.then_some(reason::LEGACY_NOT_VERIFIABLE),
        semantic,
        outputs: None,
    })
}

fn scanner_states<'a>(items: impl Iterator<Item = (&'a str, String)>) -> Value {
    Value::Array(
        items
            .map(|(id, status)| json!({"scannerId": id, "status": status}))
            .collect(),
    )
}
