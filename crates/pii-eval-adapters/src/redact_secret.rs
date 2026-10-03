//! Adapter for `@redact-secret/core` 0.1.0-beta.12, the only PII scoring path
//! in the oracle (`scanners/candidate.mjs` and `scripts/observe-pii-populations.mjs`
//! at oracle commit 4b846967346505baca11e0b98cab1475fbce6773).
//!
//! What is ported, as behavior and not as source:
//!
//! - activation through `initialize({ pii: [selectors] })`; selectors are
//!   `pii:global` or `pii:<jurisdiction>`;
//! - only findings whose detector is `pii-domain` are PII observations; other
//!   detectors (credentials) are counted as skipped and not reported;
//! - `piiFindingIdentity`: type `pii_global_<name>` maps to family
//!   `pii:global:<name>`, and `pii_jurisdiction_<cc>_<name>` to
//!   `pii:<cc>:<name>` with jurisdiction `<CC>`, underscores becoming hyphens;
//! - a PII finding is the product's redaction decision, so it is reported as a
//!   sensitive classification (the oracle's mapping, recorded here as adapter
//!   policy, not as a claim about context sensitivity).
//!
//! New in this adapter: the reported action word is kept (`redact` and
//! `block` replace text in the scanner's output; `warn` and `allow` leave it)
//! and the sanitized output digest is recorded, so reported action and actual
//! output are separate observations.
//!
//! Action mapping to the neutral kinds: `redact` -> `redact`; `warn`, `allow`
//! -> `preserve`; `block` -> `other` (it replaces text like `redact` but is a
//! different decision, so it is not folded into either neutral kind).

use std::path::PathBuf;
use std::sync::Arc;

use pii_eval_contracts::{
    ActionCapability, ActionKind, AdapterIdentity, CapabilityState, ConfigKey, ConfigParameter,
    ConfigValue, FamilyId, JurisdictionCode, ProductIdentity, ScannerCapabilities, ScannerId,
    Sha256Digest, VersionString, is_jurisdiction,
};
use pii_eval_kernel::OffsetUnit;

use crate::adapter::{ProcessAdapter, ProcessAdapterSpec};
use crate::error::{AdapterError, MalformedKind, SpecProblem};
use crate::limits::AdapterLimits;
use crate::pin::ArtifactPin;
use crate::vocab::{ActivationInfo, Mapped, MappedFinding, RawFinding, ScannerVocabulary};

/// Scanner identifier recorded in `ScannerIdentity`.
pub const SCANNER_ID: &str = "redact-secret-core";
/// Adapter identifier recorded in `AdapterIdentity`.
pub const ADAPTER_ID: &str = "redact-secret-core-node";
/// Adapter implementation version. Bump with any change to the shim, this
/// vocabulary or the parameters.
pub const ADAPTER_VERSION: &str = "1.0.0";
/// Normalization contract version this adapter applies.
pub const NORMALIZATION_VERSION: u32 = 1;
/// Oracle pin: the only released version with a PII scoring path.
pub const PINNED_VERSION: &str = "0.1.0-beta.12";
/// npm integrity of the pinned `@redact-secret/core` tarball, from the oracle
/// lockfile. Checked by npm at install time, not by this crate.
pub const NPM_INTEGRITY: &str = "sha512-fDVwt2U7VFSKb/0ixSuU5e+TOGVaUnyR1sIYwgS4S6gMndFnaq0M7ikaqac8wnTMYfYO/LS12JayXXeKbhE4aw==";
/// Tree digest (see [`crate::pin`]) of the extracted `@redact-secret/core@0.1.0-beta.12`
/// package directory, computed from the tarball whose integrity is
/// [`NPM_INTEGRITY`] installed with `--ignore-scripts`. The platform addon
/// (`@redact-secret/node-<platform>`) and the WebAssembly fallback are separate
/// packages and are pinned by the caller through `extra_artifacts`.
pub const RELEASED_PACKAGE_TREE_SHA256: &str =
    "726421636189573bc76024ecf23ec6bd1d71fef6d8272e5da1b3967dee036d03";
/// SHA-256 of `shims/node/redact-secret-core.mjs`. A test fails when the file
/// and this constant disagree.
pub const SHIM_SHA256: &str = "21664407345b099d3f5e44db26bcfb037b2e981635dec0a7b5383b42b737e0a8";
/// Path of the shim inside this crate's source tree, relative to the crate root.
pub const SHIM_RELATIVE_PATH: &str = "shims/node/redact-secret-core.mjs";
/// Entry file of the real package, relative to its directory.
pub const REAL_ENTRY_RELATIVE: &str = "dist/index.js";
/// Node major version prefix the shim and addon were validated on.
pub const NODE_VERSION_PREFIX: &str = "v22.";

/// Absolute path of the shim in the source tree this crate was built from.
/// Development and tests only: a deployed binary must be given an explicit,
/// verified shim path.
pub fn shim_path_in_source_tree() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SHIM_RELATIVE_PATH)
}

/// The closed configuration of this adapter, ascending by key. There is no
/// threshold or detector option to set: `@redact-secret/core` has no PII
/// threshold, and the configuration digest records exactly these fixed values.
pub fn parameters() -> Vec<ConfigParameter> {
    let text = |key: &str, value: &str| ConfigParameter {
        key: ConfigKey::new(key).expect("static key"),
        value: ConfigValue::Text(value.to_owned()),
    };
    vec![
        text("detectorProfile", "full"),
        text("findingSource", "pii-domain-only"),
        text("offsetUnit", "utf16-code-units"),
        ConfigParameter {
            key: ConfigKey::new("sanitizedOutput").expect("static key"),
            value: ConfigValue::Bool(true),
        },
    ]
}

/// Native-label policy for `@redact-secret/core`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactSecretVocabulary;

fn kebab_parts(rest: &str) -> Option<String> {
    let parts: Vec<&str> = rest.split('_').collect();
    let ok = parts.iter().all(|p| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    });
    ok.then(|| parts.join("-"))
}

/// The oracle's `piiFindingIdentity`: native type to (family, jurisdiction).
/// `None` when the type is not a PII type name or does not form a valid family.
fn pii_identity(kind: &str) -> Option<(FamilyId, Option<JurisdictionCode>)> {
    if let Some(rest) = kind.strip_prefix("pii_global_") {
        let family = FamilyId::new(format!("pii:global:{}", kebab_parts(rest)?)).ok()?;
        return Some((family, None));
    }
    let rest = kind.strip_prefix("pii_jurisdiction_")?;
    let (scope, name) = rest.split_once('_')?;
    if scope.len() != 2 || !scope.bytes().all(|b| b.is_ascii_lowercase()) {
        return None;
    }
    let code = scope.to_ascii_uppercase();
    if !is_jurisdiction(&code) {
        return None;
    }
    let family = FamilyId::new(format!("pii:{scope}:{}", kebab_parts(name)?)).ok()?;
    Some((family, JurisdictionCode::new(code).ok()))
}

impl ScannerVocabulary for RedactSecretVocabulary {
    fn valid_selector(&self, selector: &str) -> bool {
        match selector.strip_prefix("pii:") {
            Some("global") => true,
            Some(cc) => cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_lowercase()),
            None => false,
        }
    }

    fn selector_jurisdiction(&self, selector: &str) -> Option<JurisdictionCode> {
        let cc = selector.strip_prefix("pii:")?;
        if cc == "global" {
            return None;
        }
        JurisdictionCode::new(cc.to_ascii_uppercase()).ok()
    }

    fn base_capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            ranges: CapabilityState::Supported,
            family_classification: CapabilityState::Supported,
            sensitivity_classification: CapabilityState::Supported,
            jurisdiction_reporting: CapabilityState::Supported,
            action: ActionCapability::Unavailable,
            families: Vec::new(),
            jurisdictions: Vec::new(),
        }
    }

    fn parse_activation(&self, identity: &str) -> Result<ActivationInfo, MalformedKind> {
        let (mut credentials, mut selectors, mut families) = (None, None, None);
        for pair in identity.split(';') {
            let (key, value) = pair.split_once('=').ok_or(MalformedKind::Activation)?;
            let slot = match key {
                "credentials" => &mut credentials,
                "selectors" => &mut selectors,
                "families" => &mut families,
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(MalformedKind::Activation);
            }
        }
        // The configuration records `detectorProfile=full`; the scanner must agree.
        if credentials != Some("full") {
            return Err(MalformedKind::Activation);
        }
        let list = |v: &str| -> Vec<String> {
            if v.is_empty() || v == "off" {
                Vec::new()
            } else {
                v.split(',').map(str::to_owned).collect()
            }
        };
        let selectors = list(selectors.ok_or(MalformedKind::Activation)?);
        let families = list(families.ok_or(MalformedKind::Activation)?)
            .into_iter()
            .map(|f| FamilyId::new(f).map_err(|_| MalformedKind::Activation))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ActivationInfo {
            selectors,
            families,
        })
    }

    fn map_finding(&self, raw: &RawFinding) -> Result<Mapped, MalformedKind> {
        if raw.detector != "pii-domain" {
            return Ok(Mapped::Skip);
        }
        let action = match raw.action.as_deref() {
            None => None,
            Some("redact") => Some(ActionKind::Redact),
            Some("warn" | "allow") => Some(ActionKind::Preserve),
            Some("block") => Some(ActionKind::Other),
            Some(_) => return Err(MalformedKind::UnknownAction),
        };
        // An unmapped PII type keeps its range with no family: absence is "not
        // reported", never a guessed family.
        let (family, jurisdiction) = match pii_identity(&raw.kind) {
            Some((family, jurisdiction)) => (Some(family), jurisdiction),
            None => (None, None),
        };
        Ok(Mapped::Finding(MappedFinding {
            family,
            jurisdiction,
            sensitive: Some(true),
            action,
        }))
    }
}

/// Which `@redact-secret/core` build the adapter is pinned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorePin {
    /// Scanner version the process must report.
    pub version: VersionString,
    /// Tree digest of the package directory.
    pub package_tree_sha256: Sha256Digest,
    /// Released, or a candidate whose digest equals the package tree digest.
    pub product: ProductIdentity,
}

impl CorePin {
    /// The released 0.1.0-beta.12 package from the oracle lockfile.
    pub fn released_beta12() -> Self {
        Self {
            version: VersionString::new(PINNED_VERSION).expect("static version"),
            package_tree_sha256: Sha256Digest::new(RELEASED_PACKAGE_TREE_SHA256)
                .expect("static digest"),
            product: ProductIdentity::Released,
        }
    }

    /// A candidate build identified by the tree digest of its package directory.
    pub fn candidate(version: VersionString, package_tree_sha256: Sha256Digest) -> Self {
        Self {
            version,
            product: ProductIdentity::Candidate {
                candidate_digest: package_tree_sha256.clone(),
            },
            package_tree_sha256,
        }
    }
}

/// Paths and limits for one `@redact-secret/core` adapter.
#[derive(Debug, Clone)]
pub struct CoreAdapterConfig {
    /// Absolute path of the `node` executable.
    pub node: PathBuf,
    /// Absolute path of the shim file ([`shim_path_in_source_tree`] in development).
    pub shim: PathBuf,
    /// Absolute path of the extracted `@redact-secret/core` package directory.
    pub package_dir: PathBuf,
    /// Entry file relative to `package_dir`: [`REAL_ENTRY_RELATIVE`] for the
    /// real package. Tests use a synthetic package with another layout.
    pub entry_relative: PathBuf,
    /// The pinned build.
    pub pin: CorePin,
    /// Digest the shim must have. Use [`SHIM_SHA256`] for the shipped shim.
    pub shim_sha256: Sha256Digest,
    /// Further pinned files, for example the platform addon.
    pub extra_artifacts: Vec<ArtifactPin>,
    /// Process limits.
    pub limits: AdapterLimits,
}

/// Build the adapter. Nothing is executed or hashed until `start`.
pub fn core_adapter(config: CoreAdapterConfig) -> Result<ProcessAdapter, AdapterError> {
    let bad = AdapterError::InvalidSpec(SpecProblem::Identity);
    let entry = config.package_dir.join(&config.entry_relative);
    ProcessAdapter::new(ProcessAdapterSpec {
        executable: config.node,
        shim: ArtifactPin::file(config.shim, config.shim_sha256),
        scanner_artifact: ArtifactPin::tree(config.package_dir, config.pin.package_tree_sha256),
        scanner_entry: entry,
        extra_artifacts: config.extra_artifacts,
        scanner_id: ScannerId::new(SCANNER_ID).map_err(|_| bad)?,
        scanner_version: config.pin.version,
        product: config.pin.product,
        adapter: AdapterIdentity {
            adapter_id: ScannerId::new(ADAPTER_ID).map_err(|_| bad)?,
            adapter_version: VersionString::new(ADAPTER_VERSION).map_err(|_| bad)?,
            normalization_version: NORMALIZATION_VERSION,
        },
        runtime_name: "node".to_owned(),
        runtime_version_prefix: Some(NODE_VERSION_PREFIX.to_owned()),
        offset_unit: OffsetUnit::Utf16CodeUnits,
        inherit_env: Vec::new(),
        allowed_parameters: parameters(),
        return_output: true,
        limits: config.limits,
        vocabulary: Arc::new(RedactSecretVocabulary),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(kind: &str, detector: &str, action: Option<&str>) -> RawFinding {
        RawFinding {
            start: 0,
            end: 1,
            kind: kind.to_owned(),
            detector: detector.to_owned(),
            action: action.map(str::to_owned),
        }
    }

    #[test]
    fn pii_identity_follows_the_oracle_mapping() {
        let (family, jurisdiction) = pii_identity("pii_global_network_address").unwrap();
        assert_eq!(family.as_str(), "pii:global:network-address");
        assert_eq!(jurisdiction, None);
        let (family, jurisdiction) = pii_identity("pii_jurisdiction_us_ssn").unwrap();
        assert_eq!(family.as_str(), "pii:us:ssn");
        assert_eq!(jurisdiction.unwrap().as_str(), "US");
        for bad in [
            "pii_global_",
            "pii_global__x",
            "pii_global_X",
            "pii_jurisdiction_zz_ssn",
            "pii_jurisdiction_us",
            "pii_jurisdiction_usa_ssn",
            "aws_access_key_id",
        ] {
            assert!(pii_identity(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn only_pii_domain_findings_are_observations_and_actions_are_closed() {
        let v = RedactSecretVocabulary;
        assert_eq!(
            v.map_finding(&raw("jwt", "jwt", Some("redact"))),
            Ok(Mapped::Skip)
        );
        let Ok(Mapped::Finding(f)) =
            v.map_finding(&raw("pii_global_email", "pii-domain", Some("warn")))
        else {
            panic!("finding")
        };
        assert_eq!(f.action, Some(ActionKind::Preserve));
        assert_eq!(f.sensitive, Some(true));
        assert_eq!(
            v.map_finding(&raw("pii_global_email", "pii-domain", Some("explode"))),
            Err(MalformedKind::UnknownAction)
        );
        let Ok(Mapped::Finding(unmapped)) =
            v.map_finding(&raw("pii_novel", "pii-domain", Some("block")))
        else {
            panic!("finding")
        };
        assert_eq!(
            (unmapped.family, unmapped.action),
            (None, Some(ActionKind::Other))
        );
    }

    #[test]
    fn activation_identity_parses_and_rejects_drift() {
        let v = RedactSecretVocabulary;
        let ok = "credentials=full;selectors=pii:global,pii:us;families=pii:global:email,pii:us:ssn;vocabulary=pii-context/v2";
        let info = v.parse_activation(ok).unwrap();
        assert_eq!(info.selectors, ["pii:global", "pii:us"]);
        assert_eq!(info.families.len(), 2);
        let off = v
            .parse_activation("credentials=full;selectors=off;families=;vocabulary=pii-context/v2")
            .unwrap();
        assert!(off.selectors.is_empty() && off.families.is_empty());
        for bad in [
            "credentials=basic;selectors=off;families=",
            "selectors=off;families=",
            "credentials=full;selectors=off;selectors=off;families=",
            "credentials=full;selectors=off;families=zz",
            "credentials=full;selectors=off",
            "nonsense",
        ] {
            assert_eq!(
                v.parse_activation(bad),
                Err(MalformedKind::Activation),
                "{bad}"
            );
        }
    }

    #[test]
    fn selectors_are_validated_before_the_scanner_sees_them() {
        let v = RedactSecretVocabulary;
        for ok in ["pii:global", "pii:us", "pii:kr"] {
            assert!(v.valid_selector(ok));
        }
        for bad in [
            "pii:",
            "pii:USA",
            "pii:u",
            "PII:us",
            "pii:us;rm -rf",
            "pii-context:v2",
            "$(x)",
            "",
        ] {
            assert!(!v.valid_selector(bad), "{bad}");
        }
        assert_eq!(v.selector_jurisdiction("pii:kr").unwrap().as_str(), "KR");
        assert_eq!(v.selector_jurisdiction("pii:global"), None);
    }

    #[test]
    fn parameters_are_sorted_and_unique() {
        let p = parameters();
        assert!(p.windows(2).all(|w| w[0].key < w[1].key));
    }
}
