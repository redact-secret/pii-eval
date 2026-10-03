//! Measurement kernel for `pii-eval`.
//!
//! Implemented so far (P3): UTF-8 byte-range validation and the single
//! adapter offset-translation function ([`range`]), and the canonical
//! order-invariant matching and outcome-axis derivation ([`matching`]).
//! Methods, metric accounting and statistics do not exist yet. The kernel must
//! never spawn processes, use the network, publish, or encode product support
//! policy; the dependency guard in `pii-eval-cli/tests/dependency_policy.rs`
//! enforces the dependency side of that rule.
//!
//! The legacy first-overlapping-finding rule is deliberately not here; it is a
//! removable compatibility mode in `pii-eval-compat`.

pub mod matching;
pub mod range;

pub use matching::{
    AssessError, MATCHING_PROTOCOL_REVISION, MATCHING_RULE_ID, OccurrenceAssessment, ReportedSpan,
    ScannerView, SpanMatch, Subject, VariantAssessment, VariantInput, assess_variant, closeness,
    overlaps, range_state, relation,
};
pub use range::{
    OffsetUnit, RangeError, byte_to_unit_offset, translate_offset, translate_range, unit_length,
    validate_range, validate_range_bytes,
};

use pii_eval_contracts::{CrateIdentity, Role};

/// Identity of this crate.
pub const IDENTITY: CrateIdentity = CrateIdentity::new(
    Role::Kernel,
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_VERSION"),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_names_its_role() {
        assert_eq!(IDENTITY.role, Role::Kernel);
        assert_eq!(IDENTITY.package, "pii-eval-kernel");
    }
}
