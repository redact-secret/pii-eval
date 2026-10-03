//! Measurement kernel for `pii-eval`.
//!
//! Implemented so far (P3): UTF-8 byte-range validation and the single
//! adapter offset-translation function ([`range`]), and the canonical
//! order-invariant matching and outcome-axis derivation ([`matching`]).
//! Implemented in P4: indexed accounting of the ten metrics ([`accounting`]),
//! the exact Wilson statistics ([`stats`]) and the verifier that checks metric
//! values and counts against the outcome rows ([`verify`]). Implemented in P5:
//! the seven methods, deterministic variant ids, seeds and provenance, and the
//! two population views ([`methods`]). The kernel must
//! never spawn processes, use the network, publish, or encode product support
//! policy; the dependency guard in `pii-eval-cli/tests/dependency_policy.rs`
//! enforces the dependency side of that rule.
//!
//! The legacy first-overlapping-finding rule is deliberately not here; it is a
//! removable compatibility mode in `pii-eval-compat`.

pub mod accounting;
mod bigint;
pub mod matching;
pub mod methods;
pub mod output;
pub mod range;
pub mod stats;
pub mod verify;

pub use accounting::{
    ACCOUNTING_PROTOCOL_REVISION, ACCOUNTING_RULE_ID, AccountError, Accounting, AuthoredIndex,
    INTERVAL_INTERPRETATION, Limit, MAX_STRATA_PER_DIMENSION, MetricAccount, OutcomeRef,
    ResourceUse, SampleBasis, ScannerAccounting, ScannerInput, SnapshotDefect, StratumAccounting,
    UnmeasuredCause, account, account_outcomes,
};
pub use matching::{
    AssessError, MATCHING_PROTOCOL_REVISION, MATCHING_RULE_ID, OccurrenceAssessment, ReportedSpan,
    ScannerView, SpanMatch, Subject, VariantAssessment, VariantInput, assess_variant, closeness,
    overlaps, range_state, relation,
};
pub use output::{MAX_SANITIZED_BYTES, OutputAssessment, OutputError, verify_output};
pub use range::{
    OffsetUnit, RangeError, RangeTranslator, byte_to_unit_offset, translate_offset,
    translate_range, unit_length, validate_range, validate_range_bytes,
};
pub use stats::{
    STATS_REVISION, STATS_RULE_ID, StatsError, published_value, round_ratio, wilson_mantissa,
};
pub use verify::{
    VerifyFailure, verify_metric_result, verify_public_artifact_accounting,
    verify_run_artifact_accounting,
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
