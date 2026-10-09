//! The run manifest (plan) for a mapped evidence population.
//!
//! The manifest binds the engine, the protocol, the one population (by digest),
//! the scope, the methods the population uses, the ten metrics, the neutral
//! mechanics, the execution bounds and the scanners with their adapter,
//! product, configuration and activation identities. The scanner plan comes
//! from the adapter the run configuration names; nothing is executed here.

use std::collections::BTreeSet;
use std::path::Path;

use pii_eval_adapters::redact_secret::parameters;
use pii_eval_contracts::{
    ActivationSelector, CorpusSnapshot, EngineIdentity, EngineName, ExecutionLimits, METRICS,
    Mechanics, MethodId, MethodRef, MetricRef, PopulationBinding, ProtocolIdentity, RunClass,
    RunManifest, RunManifestBody, ScannerConfiguration, ScannerPlan, Scope, VersionString, seal,
    validate, validate_manifest_against_snapshot,
};

use super::{EvidenceError, reason};
use crate::config::RunConfig;
use crate::scanners::build_adapter;

/// The execution bounds the evidence runs use (the quickstart's, which the
/// public synthetic runs of this repository share).
pub fn default_limits() -> ExecutionLimits {
    ExecutionLimits {
        workers: 2,
        per_scanner_parallelism: 1,
        pending_tasks: 4,
        batch_variants: 1,
        scanner_timeout_ms: 120_000,
        max_stdout_bytes: 16 << 20,
        max_stderr_bytes: 1 << 20,
        max_memory_bytes: 16 << 30,
        max_temporary_bytes: 4 << 30,
    }
}

fn bad(at: &str) -> EvidenceError {
    EvidenceError::invalid(reason::PLAN_INVALID, at)
}

/// The scanner configuration of the evidence runs: the adapter's closed
/// parameters and the activation of `pii:global` plus one selector per
/// jurisdiction the population names. Activation is a capability request; it
/// is not a policy.
pub fn scanner_configuration(
    snapshot: &CorpusSnapshot,
) -> Result<ScannerConfiguration, EvidenceError> {
    let mut selectors: BTreeSet<String> = BTreeSet::new();
    selectors.insert("pii:global".to_owned());
    for case in &snapshot.semantic.cases {
        if let Some(j) = &case.jurisdiction {
            selectors.insert(format!("pii:{}", j.as_str().to_ascii_lowercase()));
        }
    }
    Ok(ScannerConfiguration {
        parameters: parameters(),
        activation: selectors
            .into_iter()
            .map(|s| ActivationSelector::new(s).map_err(|_| bad("activation")))
            .collect::<Result<_, _>>()?,
    })
}

/// Build and seal the manifest of `snapshot` for `plans`.
pub fn manifest(
    snapshot: &CorpusSnapshot,
    mut plans: Vec<ScannerPlan>,
    limits: ExecutionLimits,
    replays: u32,
) -> Result<RunManifest, EvidenceError> {
    let methods: BTreeSet<MethodId> = snapshot.semantic.cases.iter().map(|c| c.method).collect();
    let mut methods: Vec<MethodRef> = methods.into_iter().map(MethodRef::frozen).collect();
    methods.sort_by_key(|m| m.id.as_str());
    let mut metrics: Vec<MetricRef> = METRICS.iter().map(|m| MetricRef::frozen(m.id)).collect();
    metrics.sort_by_key(|m| m.id.as_str());
    let languages: BTreeSet<_> = snapshot
        .semantic
        .cases
        .iter()
        .map(|c| c.language.clone())
        .collect();
    let jurisdictions: BTreeSet<_> = snapshot
        .semantic
        .cases
        .iter()
        .filter_map(|c| c.jurisdiction.clone())
        .collect();
    plans.sort_by(|a, b| a.identity.scanner_id.cmp(&b.identity.scanner_id));
    let mut manifest = RunManifest::unsealed(RunManifestBody {
        engine: EngineIdentity {
            name: EngineName::PiiEval,
            version: VersionString::new(pii_eval_contracts::ENGINE_VERSION)
                .map_err(|_| bad("engine"))?,
        },
        protocol: if snapshot.semantic.authors_evidence_semantics() {
            ProtocolIdentity::CANONICAL_V3
        } else {
            ProtocolIdentity::CANONICAL_V2
        },
        run_class: RunClass::PublicSynthetic,
        population: PopulationBinding {
            population_id: snapshot.semantic.population.population_id.clone(),
            visibility: snapshot.semantic.population.visibility,
            population_version: snapshot.semantic.population.population_version,
            population_digest: snapshot.semantic_digest.clone(),
        },
        scope: Scope {
            languages: languages.into_iter().collect(),
            jurisdictions: jurisdictions.into_iter().collect(),
        },
        methods,
        metrics,
        mechanics: Mechanics {
            replays,
            ..Mechanics::PII_V1
        },
        generation: snapshot.semantic.generation.clone(),
        limits,
        scanners: plans,
    });
    seal(&mut manifest).map_err(|_| bad("manifest"))?;
    validate(&manifest).map_err(|_| bad("manifest"))?;
    validate_manifest_against_snapshot(&manifest, snapshot).map_err(|_| bad("binding"))?;
    Ok(manifest)
}

/// Derive the scanner plans of every scanner in `config`, using `node` (the
/// absolute interpreter path) unless the configuration names one.
pub fn plans_from_config(
    config: &RunConfig,
    snapshot: &CorpusSnapshot,
    node: Option<&Path>,
) -> Result<Vec<ScannerPlan>, EvidenceError> {
    plans_from_config_with_activation(config, snapshot, node, None)
}

/// An explicit activation measures the whole population with a separately
/// reviewed scanner configuration. It never filters cases or expectations.
pub fn plans_from_config_with_activation(
    config: &RunConfig,
    snapshot: &CorpusSnapshot,
    node: Option<&Path>,
    activation: Option<&str>,
) -> Result<Vec<ScannerPlan>, EvidenceError> {
    let configuration = match activation {
        None => scanner_configuration(snapshot)?,
        Some(value) => explicit_configuration(value)?,
    };
    let mut plans = Vec::new();
    for scanner in &config.scanners {
        let node = scanner
            .node
            .as_deref()
            .or(node)
            .ok_or_else(|| bad("node"))?;
        let adapter = build_adapter(scanner, config.product, node)
            .map_err(|_| EvidenceError::identity(reason::PLAN_INVALID, "scanner"))?;
        plans.push(
            adapter
                .plan(configuration.clone())
                .map_err(|_| EvidenceError::identity(reason::PLAN_INVALID, "scanner-plan"))?,
        );
    }
    Ok(plans)
}

fn explicit_configuration(value: &str) -> Result<ScannerConfiguration, EvidenceError> {
    let mut selectors = BTreeSet::new();
    for value in value.split(',') {
        let selector = ActivationSelector::new(value.to_owned()).map_err(|_| bad("activation"))?;
        if !selectors.insert(selector)
            || selectors.len() > pii_eval_contracts::limits::MAX_ACTIVATION_SELECTORS
        {
            return Err(bad("activation"));
        }
    }
    Ok(ScannerConfiguration {
        parameters: parameters(),
        activation: selectors.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_activation_is_sorted_bounded_and_closed() {
        let configuration = explicit_configuration("pii:us,pii:global").unwrap();
        let selectors: Vec<_> = configuration
            .activation
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(selectors, ["pii:global", "pii:us"]);
        assert_eq!(configuration.parameters, parameters());
        for value in ["", "pii:us,", "pii:us,pii:us", " pii:us", "unknown!"] {
            assert!(explicit_configuration(value).is_err(), "{value:?}");
        }
        let over_limit = (0..257)
            .map(|n| format!("pii:global:family-{n}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(explicit_configuration(&over_limit).is_err());
    }
}
