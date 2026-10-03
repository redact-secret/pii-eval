//! Oracle parity support: the comparator, the report and the engine
//! end-to-end check. Test support only (ADR 0011).
#![allow(dead_code, clippy::too_many_arguments, clippy::type_complexity)]

pub mod compare;
pub mod engine;
pub mod json;
pub mod model;
pub mod report;
pub mod rows;

use pii_eval_contracts::{
    ActionCapability, CapabilityState, JurisdictionCapability, JurisdictionCode,
    ScannerCapabilities,
};

/// The capabilities every synthetic parity scanner declares: everything the
/// legacy protocol assumes (ranges, family, sensitivity, jurisdiction) is
/// supported, so the canonical matcher is compared with the legacy one where
/// the legacy protocol is promised (ADR 0004: D4, D5 and D11 are the
/// capability-aware differences and need a scanner that declares less).
pub fn capabilities() -> ScannerCapabilities {
    ScannerCapabilities {
        ranges: CapabilityState::Supported,
        family_classification: CapabilityState::Supported,
        sensitivity_classification: CapabilityState::Supported,
        jurisdiction_reporting: CapabilityState::Supported,
        action: ActionCapability::ReportedAction,
        families: Vec::new(),
        jurisdictions: vec![JurisdictionCapability {
            jurisdiction: JurisdictionCode::new("US").unwrap(),
            state: CapabilityState::Supported,
        }],
    }
}
