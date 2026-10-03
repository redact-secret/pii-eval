//! `pii-eval compare`: a deterministic, descriptive diff of two run artifacts
//! (ADR 0010). It compares identities and metric states per scanner and per
//! metric, including withheld states. It is **not a ranking**: no output field
//! says that one artifact is better, and a metric is never reduced to a score.
//!
//! Two artifacts are comparable only when everything except the reported
//! subject is equal: the artifact kind, the protocol identity (revision 2), the
//! run class, the population binding and the accounting mechanics. The subject
//! is what the comparison is about: the engine version, the manifest, the
//! scanners' identities (version, artifact, adapter, product, configuration,
//! activation) and the measured states. Anything else that differs makes the
//! command exit 10 with the closed list of reasons; the diff is still printed
//! for the parts that can be stated.

use std::collections::BTreeMap;
use std::path::Path;

use pii_eval_contracts::{
    MetricResult, ParseLimits, PublicSyntheticArtifact, RunArtifact, ScannerMetrics, parse,
    parse_strict,
};
use serde_json::{Map, Value, json};

use crate::args::CompareArgs;
use crate::cmd_run::wire;
use crate::files::read_input;
use crate::status::{Exit, Failure, from_contract_error, from_violations, reason};
use crate::summary::Report;

struct Scanner {
    id: String,
    status: String,
    identity: Value,
    metrics: BTreeMap<String, Value>,
}

struct View {
    kind: &'static str,
    legacy: bool,
    engine: Value,
    protocol: Value,
    run_class: String,
    population: Value,
    mechanics: Value,
    manifest_digest: String,
    artifact_digest: String,
    scanners: BTreeMap<String, Scanner>,
}

fn v<T: serde::Serialize>(x: &T) -> Value {
    serde_json::to_value(x).unwrap_or(Value::Null)
}

fn metric_map(list: &[MetricResult]) -> BTreeMap<String, Value> {
    list.iter()
        .map(|m| {
            let mut value = v(m);
            let id = wire(&m.metric.id);
            if let Some(o) = value.as_object_mut() {
                o.remove("metric");
            }
            (id, value)
        })
        .collect()
}

fn scanner_metrics(all: &[ScannerMetrics], id: &str) -> BTreeMap<String, Value> {
    all.iter()
        .find(|m| m.scanner_id.as_str() == id)
        .map(|m| metric_map(&m.metrics))
        .unwrap_or_default()
}

fn load(path: &str) -> Result<View, Failure> {
    let bytes = read_input(
        Path::new(path),
        ParseLimits::default().max_bytes,
        "artifact",
    )?;
    let value = parse_strict(&bytes, &ParseLimits::default())
        .map_err(|e| from_contract_error("artifact", &e))?;
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let limits = ParseLimits::default();
    match schema {
        "pii-eval.run-artifact" => {
            let a: RunArtifact =
                parse(&bytes, &limits).map_err(|e| from_violations("artifact", &e))?;
            let s = &a.semantic;
            let scanners = s
                .scanners
                .iter()
                .map(|x| {
                    let id = x.identity.scanner_id.as_str().to_owned();
                    let metrics = if s.protocol.is_legacy() {
                        BTreeMap::new()
                    } else {
                        scanner_metrics(&s.scanner_metrics, &id)
                    };
                    (
                        id.clone(),
                        Scanner {
                            id,
                            status: wire(&x.status),
                            identity: v(&x.identity),
                            metrics,
                        },
                    )
                })
                .collect();
            Ok(View {
                kind: "run-artifact",
                legacy: s.protocol.is_legacy(),
                engine: v(&s.engine),
                protocol: v(&s.protocol),
                run_class: wire(&s.run_class),
                population: v(&s.population),
                mechanics: v(&s.mechanics),
                manifest_digest: s.manifest_digest.as_str().to_owned(),
                artifact_digest: a.semantic_digest.as_str().to_owned(),
                scanners,
            })
        }
        "pii-eval.public-synthetic-artifact" => {
            let a: PublicSyntheticArtifact =
                parse(&bytes, &limits).map_err(|e| from_violations("artifact", &e))?;
            let s = &a.semantic;
            let scanners = s
                .scanners
                .iter()
                .map(|x| {
                    let id = x.identity.scanner_id.as_str().to_owned();
                    let metrics = if s.protocol.is_legacy() {
                        BTreeMap::new()
                    } else {
                        scanner_metrics(&s.scanner_metrics, &id)
                    };
                    (
                        id.clone(),
                        Scanner {
                            id,
                            status: wire(&x.status),
                            identity: v(&x.identity),
                            metrics,
                        },
                    )
                })
                .collect();
            Ok(View {
                kind: "public-synthetic-artifact",
                legacy: s.protocol.is_legacy(),
                engine: v(&s.engine),
                protocol: v(&s.protocol),
                run_class: wire(&s.run_class),
                population: v(&s.population),
                mechanics: v(&s.mechanics),
                manifest_digest: s.manifest_digest.as_str().to_owned(),
                artifact_digest: a.semantic_digest.as_str().to_owned(),
                scanners,
            })
        }
        _ => Err(Failure::new(Exit::Invalid, reason::KIND_MISMATCH).with_detail("artifact")),
    }
}

/// Changed top-level keys of two JSON objects, each with both values.
fn changed_fields(a: &Value, b: &Value) -> Value {
    let (empty, empty2) = (Map::new(), Map::new());
    let (am, bm) = (
        a.as_object().unwrap_or(&empty),
        b.as_object().unwrap_or(&empty2),
    );
    let mut keys: Vec<&String> = am.keys().chain(bm.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut out = Map::new();
    for k in keys {
        if am.get(k) != bm.get(k) {
            let mut entry = Map::new();
            if let Some(x) = am.get(k) {
                entry.insert("base".into(), x.clone());
            }
            if let Some(x) = bm.get(k) {
                entry.insert("other".into(), x.clone());
            }
            out.insert(k.clone(), Value::Object(entry));
        }
    }
    Value::Object(out)
}

fn withheld(m: &Value) -> bool {
    m.pointer("/value/state").and_then(Value::as_str) == Some("withheld")
}

fn relation(base: Option<&Value>, other: Option<&Value>) -> &'static str {
    match (base, other) {
        (None, _) => "absent-in-base",
        (_, None) => "absent-in-other",
        (Some(b), Some(o)) => match (withheld(b), withheld(o)) {
            (true, true) => "withheld-in-both",
            (true, false) => "withheld-in-base",
            (false, true) => "withheld-in-other",
            (false, false) => {
                if b == o {
                    "identical"
                } else {
                    "changed"
                }
            }
        },
    }
}

fn pair_diff(base: &Scanner, other: &Scanner) -> Value {
    let mut ids: Vec<&String> = base.metrics.keys().chain(other.metrics.keys()).collect();
    ids.sort();
    ids.dedup();
    let metrics: Vec<Value> = ids
        .into_iter()
        .map(|id| {
            let (b, o) = (base.metrics.get(id), other.metrics.get(id));
            let mut entry = json!({
                "metric": id,
                "relation": relation(b, o),
                "identical": b == o,
            });
            if let Some(b) = b {
                entry["base"] = b.clone();
            }
            if let Some(o) = o {
                entry["other"] = o.clone();
            }
            entry
        })
        .collect();
    json!({
        "base": {"scannerId": base.id, "status": base.status},
        "other": {"scannerId": other.id, "status": other.status},
        "identityChanges": changed_fields(&base.identity, &other.identity),
        "metrics": metrics,
    })
}

/// Execute `pii-eval compare`.
pub fn compare(args: &CompareArgs) -> Result<Report, Failure> {
    let base = load(&args.base)?;
    let other = load(&args.other)?;

    let mut refusals: Vec<&'static str> = Vec::new();
    if base.kind != other.kind {
        refusals.push("artifact-kinds-differ");
    }
    if base.legacy || other.legacy {
        refusals.push("legacy-protocol-revision");
    }
    if base.protocol != other.protocol {
        refusals.push("protocol-differs");
    }
    if base.run_class != other.run_class {
        refusals.push("run-class-differs");
    }
    if base.population != other.population {
        refusals.push("population-differs");
    }
    if base.mechanics != other.mechanics {
        refusals.push("mechanics-differs");
    }

    // Pairing: by id, or the single scanner of each side.
    let same_ids = base.scanners.keys().eq(other.scanners.keys());
    let (pairing, pairs): (&str, Vec<(&Scanner, &Scanner)>) = if same_ids {
        (
            "by-id",
            base.scanners
                .iter()
                .map(|(id, b)| (b, &other.scanners[id]))
                .collect(),
        )
    } else if base.scanners.len() == 1 && other.scanners.len() == 1 {
        let (Some(b), Some(o)) = (
            base.scanners.values().next(),
            other.scanners.values().next(),
        ) else {
            return Err(Failure::new(Exit::Internal, reason::INTERNAL));
        };
        ("single-scanner", vec![(b, o)])
    } else {
        let common: Vec<(&Scanner, &Scanner)> = base
            .scanners
            .iter()
            .filter_map(|(id, b)| other.scanners.get(id).map(|o| (b, o)))
            .collect();
        if common.is_empty() {
            refusals.push("scanner-sets-not-pairable");
        }
        ("by-id-intersection", common)
    };
    let unpaired = |side: &View, paired_ids: Vec<&str>| {
        side.scanners
            .keys()
            .filter(|id| !paired_ids.contains(&id.as_str()))
            .cloned()
            .collect::<Vec<_>>()
    };
    let base_paired: Vec<&str> = pairs.iter().map(|(b, _)| b.id.as_str()).collect();
    let other_paired: Vec<&str> = pairs.iter().map(|(_, o)| o.id.as_str()).collect();

    let semantic = json!({
        "interpretation": "descriptive-only",
        "kind": base.kind,
        "refusals": refusals,
        "subject": {
            "engine": changed_fields(&base.engine, &other.engine),
            "manifestDigest": {
                "base": base.manifest_digest,
                "other": other.manifest_digest,
                "changed": base.manifest_digest != other.manifest_digest,
            },
            "artifactDigest": {"base": base.artifact_digest, "other": other.artifact_digest},
        },
        "population": base.population,
        "pairing": pairing,
        "scanners": pairs.iter().map(|(b, o)| pair_diff(b, o)).collect::<Vec<_>>(),
        "unpaired": {
            "base": unpaired(&base, base_paired),
            "other": unpaired(&other, other_paired),
        },
    });
    let comparable = refusals.is_empty();
    Ok(Report {
        exit: if comparable {
            Exit::Success
        } else {
            Exit::Incomparable
        },
        state: if comparable {
            "compared"
        } else {
            "incomparable"
        },
        reason: (!comparable).then_some(reason::INCOMPARABLE),
        semantic,
        outputs: None,
    })
}
