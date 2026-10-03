//! The independent outcome axes and the outcome lattice.
//!
//! Type identity, sensitivity context, range and action are four separate
//! observations. None is derived from another: detection, a sensitivity
//! classification, a reported `redact` action and verified sanitized output
//! are different facts. Statuses are derived from states and are never stored
//! next to them, so a contradictory authored pair cannot be represented.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::reason::ReasonCode;
use crate::scanner::ScannerStatus;

macro_rules! kebab_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all = "kebab-case")]
        pub enum $name { $($(#[$vdoc])* $variant),+ }
    };
}
pub(crate) use kebab_enum;

kebab_enum!(
    /// Derived verdict of one axis. `review-required` and `not-measured` are
    /// distinct from `fail`: an unresolved or unmeasured axis is not a failure
    /// and not a success.
    AxisStatus { Pass, Fail, ReviewRequired, NotMeasured }
);

kebab_enum!(
    /// Whether the authored occurrence is a valid or an invalid instance of its family.
    ExpectedType { Valid, Invalid }
);

kebab_enum!(
    /// Authored sensitivity of an occurrence in its context.
    SensitivityExpectation { Sensitive, NonSensitive, NotEstablished }
);

kebab_enum!(
    /// Authored context frame of a variant, used for context-discrimination trios.
    ContextClass { Sensitive, Neutral, NonSensitive }
);

kebab_enum!(
    /// Whether context is needed to classify the occurrence as sensitive.
    ContextObligation { None, Reinforcing, RequiredForSensitiveClassification }
);

kebab_enum!(
    /// Authored expectation about the action a scanner should report.
    ActionExpectation { Redact, Preserve, NotSpecified }
);

kebab_enum!(
    /// Action a scanner reports for a finding, as a neutral kind. Adapter
    /// vocabulary maps onto these; anything else is `other`.
    ActionKind { Redact, Preserve, Other }
);

kebab_enum!(
    /// Result of verifying sanitized output where the scanner provides it.
    OutputVerification { Removed, ResidualPresent, CollateralChange }
);

kebab_enum!(
    /// Observed type-identity state for one occurrence.
    TypeState { Correct, Miss, InvalidCorrect, InvalidAccepted, WrongFamily, WrongJurisdiction, NotMeasured }
);

kebab_enum!(
    /// Observed sensitivity-context state for one occurrence.
    SensitivityState { Correct, Miss, FalsePositive, Unresolved, NotMeasured }
);

kebab_enum!(
    /// Relationship between the reported range and the expected range.
    RangeState { Exact, Overbroad, Partial, Miss, NotApplicable }
);

/// What was observed about action. Never inferred from a finding flag: removal
/// is asserted only by `output-verified`, which requires sanitized output.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ActionOutcome {
    /// The scanner cannot report action (or the scanner did not run): explicit, not success.
    NotMeasured,
    /// The scanner can report action and reported none for this occurrence.
    NoActionReported,
    /// The scanner reported this action; whether text actually changed is unknown.
    Reported {
        /// The reported action kind.
        action: ActionKind,
    },
    /// Sanitized output was available and verified.
    OutputVerified {
        /// Verification result.
        verification: OutputVerification,
    },
}

impl TypeState {
    /// Status is derived from state.
    pub const fn status(self) -> AxisStatus {
        match self {
            TypeState::NotMeasured => AxisStatus::NotMeasured,
            TypeState::Correct | TypeState::InvalidCorrect => AxisStatus::Pass,
            TypeState::Miss
            | TypeState::InvalidAccepted
            | TypeState::WrongFamily
            | TypeState::WrongJurisdiction => AxisStatus::Fail,
        }
    }

    /// States reachable under an authored type expectation. The rest cannot
    /// occur, which is not the same as a count of zero.
    pub const fn reachable(expected: ExpectedType) -> &'static [TypeState] {
        match expected {
            ExpectedType::Valid => &[
                TypeState::Correct,
                TypeState::Miss,
                TypeState::WrongFamily,
                TypeState::WrongJurisdiction,
                TypeState::NotMeasured,
            ],
            ExpectedType::Invalid => &[
                TypeState::InvalidCorrect,
                TypeState::InvalidAccepted,
                TypeState::NotMeasured,
            ],
        }
    }
}

impl SensitivityState {
    /// Status is derived from state.
    pub const fn status(self) -> AxisStatus {
        match self {
            SensitivityState::NotMeasured => AxisStatus::NotMeasured,
            SensitivityState::Unresolved => AxisStatus::ReviewRequired,
            SensitivityState::Correct => AxisStatus::Pass,
            SensitivityState::Miss | SensitivityState::FalsePositive => AxisStatus::Fail,
        }
    }

    /// States reachable under an authored sensitivity expectation.
    pub const fn reachable(expected: SensitivityExpectation) -> &'static [SensitivityState] {
        match expected {
            SensitivityExpectation::NotEstablished => {
                &[SensitivityState::Unresolved, SensitivityState::NotMeasured]
            }
            SensitivityExpectation::Sensitive => &[
                SensitivityState::Correct,
                SensitivityState::Miss,
                SensitivityState::NotMeasured,
            ],
            SensitivityExpectation::NonSensitive => &[
                SensitivityState::Correct,
                SensitivityState::FalsePositive,
                SensitivityState::NotMeasured,
            ],
        }
    }
}

/// Validate one occurrence outcome against its authored expectation and the
/// scanner status. A scanner that did not complete measured nothing: every axis
/// is `not-measured` / `not-applicable`.
pub fn validate_outcome_lattice(
    expected_type: ExpectedType,
    expected_sensitivity: SensitivityExpectation,
    scanner: ScannerStatus,
    type_state: TypeState,
    sensitivity_state: SensitivityState,
    range: RangeState,
    action: ActionOutcome,
) -> Result<(), ReasonCode> {
    if !TypeState::reachable(expected_type).contains(&type_state)
        || !SensitivityState::reachable(expected_sensitivity).contains(&sensitivity_state)
    {
        return Err(ReasonCode::OutcomeContradiction);
    }
    if scanner != ScannerStatus::Complete
        && (type_state != TypeState::NotMeasured
            || sensitivity_state != SensitivityState::NotMeasured
            || range != RangeState::NotApplicable
            || action != ActionOutcome::NotMeasured)
    {
        return Err(ReasonCode::OutcomeContradiction);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_derived_from_state() {
        assert_eq!(TypeState::Correct.status(), AxisStatus::Pass);
        assert_eq!(TypeState::InvalidAccepted.status(), AxisStatus::Fail);
        assert_eq!(TypeState::NotMeasured.status(), AxisStatus::NotMeasured);
        assert_eq!(
            SensitivityState::Unresolved.status(),
            AxisStatus::ReviewRequired
        );
        assert_eq!(SensitivityState::FalsePositive.status(), AxisStatus::Fail);
    }

    #[test]
    fn reachability_follows_the_authored_expectation() {
        assert!(!TypeState::reachable(ExpectedType::Valid).contains(&TypeState::InvalidCorrect));
        assert!(!TypeState::reachable(ExpectedType::Invalid).contains(&TypeState::Miss));
        assert!(
            SensitivityState::reachable(SensitivityExpectation::NotEstablished)
                .iter()
                .all(|s| matches!(
                    s,
                    SensitivityState::Unresolved | SensitivityState::NotMeasured
                ))
        );
    }

    #[test]
    fn lattice_rejects_contradictions() {
        let ok = validate_outcome_lattice(
            ExpectedType::Valid,
            SensitivityExpectation::Sensitive,
            ScannerStatus::Complete,
            TypeState::Correct,
            SensitivityState::Correct,
            RangeState::Exact,
            ActionOutcome::NoActionReported,
        );
        assert_eq!(ok, Ok(()));
        let unreachable = validate_outcome_lattice(
            ExpectedType::Invalid,
            SensitivityExpectation::Sensitive,
            ScannerStatus::Complete,
            TypeState::Miss,
            SensitivityState::Correct,
            RangeState::Miss,
            ActionOutcome::NotMeasured,
        );
        assert_eq!(unreachable, Err(ReasonCode::OutcomeContradiction));
        let failed_scanner_measured = validate_outcome_lattice(
            ExpectedType::Valid,
            SensitivityExpectation::Sensitive,
            ScannerStatus::Error,
            TypeState::Correct,
            SensitivityState::NotMeasured,
            RangeState::NotApplicable,
            ActionOutcome::NotMeasured,
        );
        assert_eq!(
            failed_scanner_measured,
            Err(ReasonCode::OutcomeContradiction)
        );
    }
}
