//! Generic validator observations: `synthetic-mod10` v1 and
//! `us-ssn-allocation` v1, reproduced from the oracle's `validators.ts`.
//!
//! A validator answers one mechanical question about one candidate string:
//! `valid`, `invalid`, or `unavailable`. That is an *observation*. It is never
//! a support decision, an activation gate or a threshold; those stay with the
//! downstream consumer (ADR 0007, "Boundaries").
//!
//! `unavailable` is a first-class state with a reason. An unknown validator, or
//! one registered at a different version than the authored case pins, is
//! reported as unavailable; it is never a clean `valid` or `invalid`.

use pii_eval_contracts::ValidatorRef;

/// Identifier of the synthetic checksum validator.
pub const SYNTHETIC_MOD10_ID: &str = "synthetic-mod10";
/// Identifier of the US SSN allocation validator.
pub const US_SSN_ALLOCATION_ID: &str = "us-ssn-allocation";
/// Version of both built-in validators at the oracle pin.
pub const VALIDATOR_VERSION: u32 = 1;

/// What a validator observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidatorState {
    /// The candidate satisfies the validator's mechanical rule.
    Valid,
    /// The candidate violates it.
    Invalid,
    /// No observation could be made.
    Unavailable,
}

impl ValidatorState {
    /// The oracle's wire string (`valid`, `invalid`, `unavailable`).
    pub const fn as_str(self) -> &'static str {
        match self {
            ValidatorState::Valid => "valid",
            ValidatorState::Invalid => "invalid",
            ValidatorState::Unavailable => "unavailable",
        }
    }
}

/// Why a validator observation is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnavailableReason {
    /// No validator with that id is registered.
    UnknownValidator,
    /// A validator with that id is registered at a different version.
    VersionMismatch,
    /// The validator itself reported it could not observe the value.
    ValidatorDeclined,
}

impl UnavailableReason {
    /// Stable reason string.
    pub const fn as_str(self) -> &'static str {
        match self {
            UnavailableReason::UnknownValidator => "unknown-validator",
            UnavailableReason::VersionMismatch => "validator-version-mismatch",
            UnavailableReason::ValidatorDeclined => "validator-declined",
        }
    }
}

/// One validator observation of one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorObservation {
    /// The validator that was asked (as authored).
    pub validator: ValidatorRef,
    /// What it observed.
    pub state: ValidatorState,
    /// Present exactly when `state` is [`ValidatorState::Unavailable`].
    pub unavailable: Option<UnavailableReason>,
}

/// A registered validator.
#[derive(Debug, Clone, Copy)]
pub struct ValidatorDef {
    /// Identifier.
    pub id: &'static str,
    /// Version.
    pub version: u32,
    /// The mechanical rule. Pure: the same string always gives the same answer.
    pub validate: fn(&str) -> ValidatorState,
}

/// `synthetic-mod10` v1: `^SYNTHETIC-[0-9]{4}$`, valid when the sum of the
/// first three digits modulo 10 equals the fourth.
pub fn synthetic_mod10(value: &str) -> ValidatorState {
    let Some(digits) = value.strip_prefix("SYNTHETIC-") else {
        return ValidatorState::Invalid;
    };
    let d = digits.as_bytes();
    if d.len() != 4 || !d.iter().all(u8::is_ascii_digit) {
        return ValidatorState::Invalid;
    }
    let n = |i: usize| u32::from(d[i] - b'0');
    if (n(0) + n(1) + n(2)) % 10 == n(3) {
        ValidatorState::Valid
    } else {
        ValidatorState::Invalid
    }
}

/// `us-ssn-allocation` v1: nine ASCII digits whose area is not 000, 666 or
/// 900 and above, whose group is not 00 and whose serial is not 0000.
pub fn us_ssn_allocation(value: &str) -> ValidatorState {
    let d = value.as_bytes();
    if d.len() != 9 || !d.iter().all(u8::is_ascii_digit) {
        return ValidatorState::Invalid;
    }
    let area = value[..3].parse::<u32>().unwrap_or(0);
    if area == 0 || area == 666 || area >= 900 || d[3..5] == *b"00" || d[5..] == *b"0000" {
        ValidatorState::Invalid
    } else {
        ValidatorState::Valid
    }
}

/// The two validators of the oracle, in registration order.
pub const BUILTIN_VALIDATORS: [ValidatorDef; 2] = [
    ValidatorDef {
        id: SYNTHETIC_MOD10_ID,
        version: VALIDATOR_VERSION,
        validate: synthetic_mod10,
    },
    ValidatorDef {
        id: US_SSN_ALLOCATION_ID,
        version: VALIDATOR_VERSION,
        validate: us_ssn_allocation,
    },
];

/// A closed set of validators. Lookup is by exact id and version.
#[derive(Debug, Clone)]
pub struct ValidatorRegistry {
    defs: Vec<ValidatorDef>,
}

impl ValidatorRegistry {
    /// The oracle's two validators.
    pub fn builtin() -> Self {
        Self {
            defs: BUILTIN_VALIDATORS.to_vec(),
        }
    }

    /// A registry with no validator: every observation is unavailable.
    pub fn empty() -> Self {
        Self { defs: Vec::new() }
    }

    /// Add a validator. Returns `false` (and adds nothing) when the id is
    /// already registered, so a registry never holds two rules for one id.
    pub fn register(&mut self, def: ValidatorDef) -> bool {
        if self.defs.iter().any(|d| d.id == def.id) {
            return false;
        }
        self.defs.push(def);
        true
    }

    /// Ask `validator` about `value`.
    pub fn observe(&self, validator: &ValidatorRef, value: &str) -> ValidatorObservation {
        let unavailable = |reason| ValidatorObservation {
            validator: validator.clone(),
            state: ValidatorState::Unavailable,
            unavailable: Some(reason),
        };
        let Some(def) = self.defs.iter().find(|d| d.id == validator.id.as_str()) else {
            return unavailable(UnavailableReason::UnknownValidator);
        };
        if def.version != validator.version {
            return unavailable(UnavailableReason::VersionMismatch);
        }
        match (def.validate)(value) {
            ValidatorState::Unavailable => unavailable(UnavailableReason::ValidatorDeclined),
            state => ValidatorObservation {
                validator: validator.clone(),
                state,
                unavailable: None,
            },
        }
    }
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}
