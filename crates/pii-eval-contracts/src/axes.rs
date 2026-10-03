//! The independent outcome axes and the outcome lattice.
//!
//! Type identity, sensitivity context, range and action are four separate
//! observations. None is derived from another: detection, a sensitivity
//! classification, a reported `redact` action and verified sanitized output
//! are different facts. Statuses are derived from states and are never stored
//! next to them, so a contradictory authored pair cannot be represented.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ident::{FamilyId, JurisdictionCode};
use crate::reason::ReasonCode;
use crate::scanner::{ActionCapability, CapabilityState, ScannerCapabilities, ScannerStatus};

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
///
/// Deserialization and the JSON Schema go through [`ActionOutcomeWire`], whose
/// variants are closed structs: serde would otherwise ignore extra keys on the
/// unit variants of an internally tagged enum.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "state", rename_all = "kebab-case", from = "ActionOutcomeWire")]
#[schemars(with = "ActionOutcomeWire")]
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

/// Closed wire form of [`ActionOutcome`].
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
#[schemars(rename = "ActionOutcome")]
pub enum ActionOutcomeWire {
    /// See [`ActionOutcome::NotMeasured`].
    NotMeasured {},
    /// See [`ActionOutcome::NoActionReported`].
    NoActionReported {},
    /// See [`ActionOutcome::Reported`].
    Reported {
        /// The reported action kind.
        action: ActionKind,
    },
    /// See [`ActionOutcome::OutputVerified`].
    OutputVerified {
        /// Verification result.
        verification: OutputVerification,
    },
}

impl From<ActionOutcomeWire> for ActionOutcome {
    fn from(wire: ActionOutcomeWire) -> Self {
        match wire {
            ActionOutcomeWire::NotMeasured {} => ActionOutcome::NotMeasured,
            ActionOutcomeWire::NoActionReported {} => ActionOutcome::NoActionReported,
            ActionOutcomeWire::Reported { action } => ActionOutcome::Reported { action },
            ActionOutcomeWire::OutputVerified { verification } => {
                ActionOutcome::OutputVerified { verification }
            }
        }
    }
}

impl ActionKind {
    /// The wire string; canonical collections sort by this, bytewise.
    pub const fn as_str(self) -> &'static str {
        match self {
            ActionKind::Redact => "redact",
            ActionKind::Preserve => "preserve",
            ActionKind::Other => "other",
        }
    }
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
///
/// A capability the scanner declares `unsupported` can never yield a measured
/// axis: missing capability is `not-measured`, never success.
pub fn validate_outcome_lattice(
    authored: &AuthoredAxes<'_>,
    scanner: ScannerStatus,
    capabilities: &ScannerCapabilities,
    row: &OutcomeRow,
) -> Result<(), ReasonCode> {
    if !TypeState::reachable(authored.expected_type).contains(&row.type_identity)
        || !SensitivityState::reachable(authored.sensitivity).contains(&row.sensitivity_context)
    {
        return Err(ReasonCode::OutcomeContradiction);
    }
    if scanner != ScannerStatus::Complete && !row.is_unmeasured() {
        return Err(ReasonCode::OutcomeContradiction);
    }
    // The expected family or jurisdiction itself being unsupported leaves the
    // type axis unmeasured.
    let unsupported_expected = capabilities.family_state(authored.family)
        == CapabilityState::Unsupported
        || authored
            .jurisdiction
            .is_some_and(|j| capabilities.jurisdiction_state(j) == CapabilityState::Unsupported);
    if unsupported_expected && row.type_identity != TypeState::NotMeasured {
        return Err(ReasonCode::OutcomeContradiction);
    }
    check_capability_rules(capabilities, row)
}

/// The authored side of an outcome row.
#[derive(Debug, Clone, Copy)]
pub struct AuthoredAxes<'a> {
    /// Authored type expectation.
    pub expected_type: ExpectedType,
    /// Authored sensitivity expectation.
    pub sensitivity: SensitivityExpectation,
    /// Expected family.
    pub family: &'a FamilyId,
    /// Case jurisdiction, or `None` for a global case.
    pub jurisdiction: Option<&'a JurisdictionCode>,
}

/// The four observed axes of one outcome row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutcomeRow {
    /// Type-identity axis.
    pub type_identity: TypeState,
    /// Sensitivity-context axis.
    pub sensitivity_context: SensitivityState,
    /// Range axis.
    pub range: RangeState,
    /// Action axis.
    pub action: ActionOutcome,
}

impl OutcomeRow {
    /// True when every axis is `not-measured` / `not-applicable`.
    pub fn is_unmeasured(&self) -> bool {
        self.type_identity == TypeState::NotMeasured
            && self.sensitivity_context == SensitivityState::NotMeasured
            && self.range == RangeState::NotApplicable
            && self.action == ActionOutcome::NotMeasured
    }
}

/// Rules that need only the scanner's declared capabilities: an axis whose
/// capability is `unsupported` (or, for action, `unavailable`) must be unmeasured.
pub fn check_capability_rules(
    capabilities: &ScannerCapabilities,
    row: &OutcomeRow,
) -> Result<(), ReasonCode> {
    let unsupported = |state: CapabilityState| state == CapabilityState::Unsupported;
    let violated = (unsupported(capabilities.ranges) && row.range != RangeState::NotApplicable)
        || (unsupported(capabilities.family_classification)
            && row.type_identity != TypeState::NotMeasured)
        || (unsupported(capabilities.jurisdiction_reporting)
            && row.type_identity == TypeState::WrongJurisdiction)
        || (unsupported(capabilities.sensitivity_classification)
            && row.sensitivity_context != SensitivityState::NotMeasured)
        || match row.action {
            ActionOutcome::NotMeasured => false,
            ActionOutcome::NoActionReported | ActionOutcome::Reported { .. } => {
                capabilities.action == ActionCapability::Unavailable
            }
            ActionOutcome::OutputVerified { .. } => {
                capabilities.action != ActionCapability::SanitizedOutput
            }
        };
    if violated {
        Err(ReasonCode::OutcomeContradiction)
    } else {
        Ok(())
    }
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

    fn caps(state: CapabilityState) -> ScannerCapabilities {
        ScannerCapabilities {
            ranges: state,
            family_classification: state,
            sensitivity_classification: state,
            jurisdiction_reporting: state,
            action: ActionCapability::ReportedAction,
            families: vec![],
            jurisdictions: vec![],
        }
    }

    fn row(t: TypeState, s: SensitivityState, r: RangeState, a: ActionOutcome) -> OutcomeRow {
        OutcomeRow {
            type_identity: t,
            sensitivity_context: s,
            range: r,
            action: a,
        }
    }

    fn check(
        expected: ExpectedType,
        sens: SensitivityExpectation,
        status: ScannerStatus,
        caps: &ScannerCapabilities,
        row: OutcomeRow,
    ) -> Result<(), ReasonCode> {
        let family = FamilyId::new("pii:global:email").unwrap();
        let authored = AuthoredAxes {
            expected_type: expected,
            sensitivity: sens,
            family: &family,
            jurisdiction: None,
        };
        validate_outcome_lattice(&authored, status, caps, &row)
    }

    #[test]
    fn lattice_rejects_contradictions() {
        let supported = caps(CapabilityState::Supported);
        let good = row(
            TypeState::Correct,
            SensitivityState::Correct,
            RangeState::Exact,
            ActionOutcome::NoActionReported,
        );
        let v = ExpectedType::Valid;
        let s = SensitivityExpectation::Sensitive;
        assert_eq!(
            check(v, s, ScannerStatus::Complete, &supported, good),
            Ok(())
        );
        let unreachable = row(
            TypeState::Miss,
            SensitivityState::Correct,
            RangeState::Miss,
            ActionOutcome::NotMeasured,
        );
        assert_eq!(
            check(
                ExpectedType::Invalid,
                s,
                ScannerStatus::Complete,
                &supported,
                unreachable
            ),
            Err(ReasonCode::OutcomeContradiction)
        );
        assert_eq!(
            check(v, s, ScannerStatus::Error, &supported, good),
            Err(ReasonCode::OutcomeContradiction)
        );
    }

    #[test]
    fn unsupported_capability_forces_not_measured_on_its_axis() {
        let v = ExpectedType::Valid;
        let s = SensitivityExpectation::Sensitive;
        let good = row(
            TypeState::Correct,
            SensitivityState::Correct,
            RangeState::Exact,
            ActionOutcome::Reported {
                action: ActionKind::Redact,
            },
        );
        let measured_except = |t, se, r| {
            row(
                t,
                se,
                r,
                ActionOutcome::Reported {
                    action: ActionKind::Redact,
                },
            )
        };
        let cases = [
            // ranges unsupported: range must be not-applicable
            (
                ScannerCapabilities {
                    ranges: CapabilityState::Unsupported,
                    ..caps(CapabilityState::Supported)
                },
                good,
                measured_except(
                    TypeState::Correct,
                    SensitivityState::Correct,
                    RangeState::NotApplicable,
                ),
            ),
            // family classification unsupported: type must be not-measured
            (
                ScannerCapabilities {
                    family_classification: CapabilityState::Unsupported,
                    ..caps(CapabilityState::Supported)
                },
                good,
                measured_except(
                    TypeState::NotMeasured,
                    SensitivityState::Correct,
                    RangeState::Exact,
                ),
            ),
            // sensitivity unsupported: sensitivity must be not-measured
            (
                ScannerCapabilities {
                    sensitivity_classification: CapabilityState::Unsupported,
                    ..caps(CapabilityState::Supported)
                },
                good,
                measured_except(
                    TypeState::Correct,
                    SensitivityState::NotMeasured,
                    RangeState::Exact,
                ),
            ),
            // action unavailable: action must be not-measured
            (
                ScannerCapabilities {
                    action: ActionCapability::Unavailable,
                    ..caps(CapabilityState::Supported)
                },
                good,
                row(
                    TypeState::Correct,
                    SensitivityState::Correct,
                    RangeState::Exact,
                    ActionOutcome::NotMeasured,
                ),
            ),
        ];
        for (c, bad, fixed) in cases {
            assert_eq!(
                check(v, s, ScannerStatus::Complete, &c, bad),
                Err(ReasonCode::OutcomeContradiction)
            );
            assert_eq!(check(v, s, ScannerStatus::Complete, &c, fixed), Ok(()));
        }
        // wrong-jurisdiction cannot be observed when jurisdiction is unsupported
        let c = ScannerCapabilities {
            jurisdiction_reporting: CapabilityState::Unsupported,
            ..caps(CapabilityState::Supported)
        };
        let wrong = row(
            TypeState::WrongJurisdiction,
            SensitivityState::Correct,
            RangeState::Exact,
            ActionOutcome::NoActionReported,
        );
        assert_eq!(
            check(v, s, ScannerStatus::Complete, &c, wrong),
            Err(ReasonCode::OutcomeContradiction)
        );
    }
}
