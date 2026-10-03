//! Scanner vocabulary: how one scanner's native labels become neutral findings.
//!
//! The shim forwards native values untouched (type label, detector id, action
//! word, offsets). Deciding what they mean is Rust-side adapter policy, kept in
//! one [`ScannerVocabulary`] per scanner so the shim stays a dumb transport and
//! the kernel never sees a native label.

use std::fmt;

use pii_eval_contracts::{ActionKind, FamilyId, JurisdictionCode, ScannerCapabilities};

use crate::error::MalformedKind;

/// One finding exactly as the shim reported it. Holds native labels and
/// offsets in the scanner's own unit; never the matched text.
#[derive(Clone, PartialEq, Eq)]
pub struct RawFinding {
    /// Start offset in the scanner's offset unit.
    pub start: u64,
    /// End offset (exclusive) in the scanner's offset unit.
    pub end: u64,
    /// Native finding type label.
    pub kind: String,
    /// Native detector identifier.
    pub detector: String,
    /// Native action word, when the scanner reports one.
    pub action: Option<String>,
}

impl fmt::Debug for RawFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Offsets and labels are not matched values, but nothing here is needed in logs.
        f.write_str("RawFinding(..)")
    }
}

/// The neutral meaning of one native finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedFinding {
    /// Reported family, when the label maps to one.
    pub family: Option<FamilyId>,
    /// Reported jurisdiction, when the label carries one.
    pub jurisdiction: Option<JurisdictionCode>,
    /// Reported sensitivity classification.
    pub sensitive: Option<bool>,
    /// Reported action.
    pub action: Option<ActionKind>,
}

/// Result of mapping one native finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mapped {
    /// Not a PII observation (for example a credential finding); counted, not reported.
    Skip,
    /// A PII observation.
    Finding(MappedFinding),
}

/// What a scanner says is active, parsed from its own activation identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationInfo {
    /// Selectors the scanner reports as active, ascending.
    pub selectors: Vec<String>,
    /// Families the scanner reports it can emit, ascending.
    pub families: Vec<FamilyId>,
}

/// Per-scanner mapping policy.
pub trait ScannerVocabulary: Send + Sync + fmt::Debug {
    /// Whether `selector` is well formed for this scanner. Checked before the
    /// scanner is started, so malformed selectors never reach it.
    fn valid_selector(&self, selector: &str) -> bool;

    /// Jurisdiction a selector requests, used to record a missing capability
    /// when the scanner rejects the selector.
    fn selector_jurisdiction(&self, selector: &str) -> Option<JurisdictionCode>;

    /// Capability flags that hold for every activation of this scanner
    /// (ranges, family, sensitivity, jurisdiction reporting). The action
    /// capability and the family and jurisdiction lists are filled in from the
    /// running scanner's activation, so the lists here are empty.
    fn base_capabilities(&self) -> ScannerCapabilities;

    /// Parse the scanner's activation identity string. Failure is malformed output.
    fn parse_activation(&self, identity: &str) -> Result<ActivationInfo, MalformedKind>;

    /// Map one native finding. An action word outside the scanner's closed
    /// vocabulary is [`MalformedKind::UnknownAction`], never guessed.
    fn map_finding(&self, raw: &RawFinding) -> Result<Mapped, MalformedKind>;
}
