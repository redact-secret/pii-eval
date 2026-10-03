//! Scanner identity, capability, configuration and activation contracts.
//!
//! A scanner run is identified by independent bindings: the scanner build, the
//! adapter and normalization version, the product identity (released or
//! candidate), the configuration, and the activation. None of them stands in
//! for another. Capability gaps are explicit states: an undeclared or
//! unsupported capability is never read as success.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::axes::kebab_enum;
use crate::canonical::semantic_digest_of;
use crate::check::{sorted_unique, within_limit};
use crate::ident::{
    ActivationSelector, ConfigKey, FamilyId, JurisdictionCode, ScannerId, Sha256Digest,
    VersionString,
};
use crate::limits::{
    MAX_ACTIVATION_SELECTORS, MAX_CAPABILITY_ENTRIES, MAX_CONFIG_PARAMETERS,
    MAX_CONFIG_STRING_BYTES, MAX_SAFE_INTEGER,
};
use crate::reason::{Collector, ContractError, Path, ReasonCode};

kebab_enum!(
    /// Outcome of one scanner run. Anything but `complete` means nothing was
    /// measured for that scanner; it is not a scan with no findings.
    ScannerStatus { Complete, Unsupported, Unavailable, Error, Unstable }
);

kebab_enum!(
    /// Whether a scanner declares a capability. `undeclared` is the default
    /// for anything not stated and is never treated as `supported`.
    CapabilityState { Supported, Unsupported, Undeclared }
);

kebab_enum!(
    /// What the scanner can say about action.
    ActionCapability { Unavailable, ReportedAction, SanitizedOutput }
);

/// Capability of one family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FamilyCapability {
    /// The family.
    pub family: FamilyId,
    /// Declared state.
    pub state: CapabilityState,
}

/// Capability of one jurisdiction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JurisdictionCapability {
    /// The jurisdiction.
    pub jurisdiction: JurisdictionCode,
    /// Declared state.
    pub state: CapabilityState,
}

/// What a scanner adapter declares it can report. Missing capability must stay
/// visible downstream as `not-measured`, never as a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScannerCapabilities {
    /// Reports byte ranges into the original input.
    pub ranges: CapabilityState,
    /// Reports a family for a finding.
    pub family_classification: CapabilityState,
    /// Reports a sensitivity classification for a finding.
    pub sensitivity_classification: CapabilityState,
    /// Reports a jurisdiction for a finding.
    pub jurisdiction_reporting: CapabilityState,
    /// Action evidence available.
    pub action: ActionCapability,
    /// Per-family declarations, ascending by family, unique.
    pub families: Vec<FamilyCapability>,
    /// Per-jurisdiction declarations, ascending by jurisdiction, unique.
    pub jurisdictions: Vec<JurisdictionCapability>,
}

impl ScannerCapabilities {
    /// Declared state for `family`. A family absent from the list is
    /// `unsupported` only when family classification is unsupported overall;
    /// otherwise it is `undeclared`, never `supported`.
    pub fn family_state(&self, family: &FamilyId) -> CapabilityState {
        match self.families.binary_search_by(|e| e.family.cmp(family)) {
            Ok(i) => self.families[i].state,
            Err(_) if self.family_classification == CapabilityState::Unsupported => {
                CapabilityState::Unsupported
            }
            Err(_) => CapabilityState::Undeclared,
        }
    }

    /// Declared state for `jurisdiction`, with the same rule as [`Self::family_state`].
    pub fn jurisdiction_state(&self, jurisdiction: &JurisdictionCode) -> CapabilityState {
        match self
            .jurisdictions
            .binary_search_by(|e| e.jurisdiction.cmp(jurisdiction))
        {
            Ok(i) => self.jurisdictions[i].state,
            Err(_) if self.jurisdiction_reporting == CapabilityState::Unsupported => {
                CapabilityState::Unsupported
            }
            Err(_) => CapabilityState::Undeclared,
        }
    }

    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        let families = path.field("families");
        if within_limit(self.families.len(), MAX_CAPABILITY_ENTRIES, &families, c) {
            sorted_unique(&self.families, |e| e.family.clone(), &families, c);
        }
        let jurisdictions = path.field("jurisdictions");
        if within_limit(
            self.jurisdictions.len(),
            MAX_CAPABILITY_ENTRIES,
            &jurisdictions,
            c,
        ) {
            sorted_unique(
                &self.jurisdictions,
                |e| e.jurisdiction.clone(),
                &jurisdictions,
                c,
            );
        }
    }
}

/// Product identity of the thing under test. Independent of the population's
/// visibility: a public-synthetic run of a candidate is candidate evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProductIdentity {
    /// A released build; the scanner version must be stated.
    Released,
    /// A candidate build, identified by the digest of its artifact.
    #[serde(rename_all = "camelCase")]
    Candidate {
        /// Digest of the candidate artifact.
        candidate_digest: Sha256Digest,
    },
}

/// Engine identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum EngineName {
    /// This engine.
    #[serde(rename = "pii-eval")]
    PiiEval,
}

/// Engine implementation identity bound into plans and artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineIdentity {
    /// Engine name.
    pub name: EngineName,
    /// Engine implementation version.
    pub version: VersionString,
}

/// Adapter identity: how scanner output was normalized into findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterIdentity {
    /// Adapter identifier.
    pub adapter_id: ScannerId,
    /// Adapter implementation version.
    pub adapter_version: VersionString,
    /// Version of the normalization contract the adapter applies.
    pub normalization_version: u32,
}

/// Everything that identifies one scanner run configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScannerIdentity {
    /// Scanner identifier.
    pub scanner_id: ScannerId,
    /// Scanner version, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner_version: Option<VersionString>,
    /// Digest of the scanner binary or package, when pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<Sha256Digest>,
    /// Adapter identity.
    pub adapter: AdapterIdentity,
    /// Released or candidate.
    pub product: ProductIdentity,
    /// Digest of the scanner configuration parameters.
    pub configuration_digest: Sha256Digest,
    /// Digest of the activation selectors.
    pub activation_digest: Sha256Digest,
}

impl ScannerIdentity {
    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        if self.product == ProductIdentity::Released && self.scanner_version.is_none() {
            c.push(ReasonCode::ProductIdentityInvalid, &path.field("product"));
        }
    }
}

/// A scalar configuration value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ConfigValue {
    /// Boolean.
    Bool(bool),
    /// Integer within +/-(2^53 - 1).
    Integer(i64),
    /// Short text, at most 256 bytes. Free text from a corpus never belongs here.
    Text(String),
}

/// One configuration parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigParameter {
    /// Parameter name.
    pub key: ConfigKey,
    /// Parameter value.
    pub value: ConfigValue,
}

/// Replay-safe scanner configuration and activation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScannerConfiguration {
    /// Parameters, ascending by key, unique.
    pub parameters: Vec<ConfigParameter>,
    /// Activation selectors (the enable set), ascending, unique.
    pub activation: Vec<ActivationSelector>,
}

const PARAMETERS_DOMAIN: &str = "pii-eval.scanner-parameters/1";
const ACTIVATION_DOMAIN: &str = "pii-eval.scanner-activation/1";

impl ScannerConfiguration {
    /// Digest the manifest and observations must bind as `configurationDigest`.
    pub fn configuration_digest(&self) -> Result<Sha256Digest, ContractError> {
        semantic_digest_of(PARAMETERS_DOMAIN, &self.parameters)
    }

    /// Digest the manifest and observations must bind as `activationDigest`.
    pub fn activation_digest(&self) -> Result<Sha256Digest, ContractError> {
        semantic_digest_of(ACTIVATION_DOMAIN, &self.activation)
    }

    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        let parameters = path.field("parameters");
        if within_limit(self.parameters.len(), MAX_CONFIG_PARAMETERS, &parameters, c) {
            sorted_unique(&self.parameters, |p| p.key.clone(), &parameters, c);
            for (i, p) in self.parameters.iter().enumerate() {
                let bad = match &p.value {
                    ConfigValue::Bool(_) => false,
                    ConfigValue::Integer(n) => n.unsigned_abs() > MAX_SAFE_INTEGER,
                    ConfigValue::Text(t) => t.len() > MAX_CONFIG_STRING_BYTES,
                };
                if bad {
                    c.push(
                        ReasonCode::LimitExceeded,
                        &parameters.index(i).field("value"),
                    );
                }
            }
        }
        let activation = path.field("activation");
        if within_limit(
            self.activation.len(),
            MAX_ACTIVATION_SELECTORS,
            &activation,
            c,
        ) {
            sorted_unique(&self.activation, |a| a.clone(), &activation, c);
        }
    }
}

/// One scanner in a run plan: identity plus the configuration it was derived from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScannerPlan {
    /// Bound identity.
    pub identity: ScannerIdentity,
    /// The configuration whose digests the identity binds.
    pub configuration: ScannerConfiguration,
}

impl ScannerPlan {
    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        self.identity.validate(&path.field("identity"), c);
        self.configuration.validate(&path.field("configuration"), c);
        let matches = |declared: &Sha256Digest, computed: Result<Sha256Digest, ContractError>| {
            computed.is_ok_and(|d| d == *declared)
        };
        if !matches(
            &self.identity.configuration_digest,
            self.configuration.configuration_digest(),
        ) {
            c.push(
                ReasonCode::ConfigurationDigestMismatch,
                &path.field("identity").field("configurationDigest"),
            );
        }
        if !matches(
            &self.identity.activation_digest,
            self.configuration.activation_digest(),
        ) {
            c.push(
                ReasonCode::ConfigurationDigestMismatch,
                &path.field("identity").field("activationDigest"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(top: CapabilityState) -> ScannerCapabilities {
        ScannerCapabilities {
            ranges: CapabilityState::Supported,
            family_classification: top,
            sensitivity_classification: CapabilityState::Undeclared,
            jurisdiction_reporting: top,
            action: ActionCapability::Unavailable,
            families: vec![FamilyCapability {
                family: FamilyId::new("pii:global:email").unwrap(),
                state: CapabilityState::Supported,
            }],
            jurisdictions: vec![],
        }
    }

    #[test]
    fn unlisted_families_are_never_supported() {
        let other = FamilyId::new("pii:global:phone").unwrap();
        let listed = FamilyId::new("pii:global:email").unwrap();
        let c = caps(CapabilityState::Supported);
        assert_eq!(c.family_state(&listed), CapabilityState::Supported);
        assert_eq!(c.family_state(&other), CapabilityState::Undeclared);
        let c = caps(CapabilityState::Unsupported);
        assert_eq!(c.family_state(&other), CapabilityState::Unsupported);
        let kr = JurisdictionCode::new("KR").unwrap();
        assert_eq!(c.jurisdiction_state(&kr), CapabilityState::Unsupported);
        assert_eq!(
            caps(CapabilityState::Supported).jurisdiction_state(&kr),
            CapabilityState::Undeclared
        );
    }
}
