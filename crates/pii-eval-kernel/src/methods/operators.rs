//! Derivation operators: `invalidate-final-digit` v1 (the mutation operator of
//! the oracle's `operators.ts`) and the identities of the two operators the
//! other methods record in a variant's derivation.

use pii_eval_contracts::{ByteRange, ExpectedType, OperatorRef};

/// Identifier of the mutation operator.
pub const INVALIDATE_FINAL_DIGIT_ID: &str = "invalidate-final-digit";
/// Version of the mutation operator at the oracle pin.
pub const INVALIDATE_FINAL_DIGIT_VERSION: u32 = 1;
/// Operator recorded for variants derived from a context frame.
pub const CONTEXT_FRAME_ID: &str = "context-frame";
/// Version of the context-frame derivation.
pub const CONTEXT_FRAME_VERSION: u32 = 1;
/// Operator recorded for a variant held for review because its validator
/// observation was unavailable. It transforms nothing; the contract requires
/// an operator on every `review-required` variant, and this names the hold.
pub const REVIEW_HOLD_ID: &str = "review-hold";
/// Version of the review hold.
pub const REVIEW_HOLD_VERSION: u32 = 1;

/// Why a mutation could not be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorError {
    /// No operator with that id exists.
    Unknown,
    /// The operator exists at a different version.
    VersionMismatch,
    /// The candidate does not satisfy the operator's precondition.
    NotApplicable,
}

impl OperatorError {
    /// Stable reason string.
    pub const fn as_str(self) -> &'static str {
        match self {
            OperatorError::Unknown => "operator-unknown",
            OperatorError::VersionMismatch => "operator-version-mismatch",
            OperatorError::NotApplicable => "operator-not-applicable",
        }
    }
}

/// A mutated input and its expectation.
#[derive(Clone, PartialEq, Eq)]
pub struct Mutation {
    /// The full mutated text.
    pub text: String,
    /// The candidate range in the mutated text.
    pub candidate: ByteRange,
    /// Authored type expectation after the mutation.
    pub type_expectation: ExpectedType,
}

impl std::fmt::Debug for Mutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mutation")
            .field(
                "text",
                &format_args!("<redacted {} bytes>", self.text.len()),
            )
            .field("candidate", &self.candidate)
            .field("type_expectation", &self.type_expectation)
            .finish()
    }
}

/// Apply a mutation operator to `candidate` inside `text`.
///
/// `invalidate-final-digit` v1: the candidate must end in an ASCII digit `d`;
/// that digit becomes `(d + 1) mod 10`, so the byte length and range are
/// unchanged, and the authored type becomes `invalid`. The sensitivity
/// expectation is the case's own and is not touched here.
///
/// The range must already be validated against `text` (the generator does so).
pub fn apply_mutation(
    operator: &OperatorRef,
    text: &str,
    candidate: &ByteRange,
) -> Result<Mutation, OperatorError> {
    if operator.id.as_str() != INVALIDATE_FINAL_DIGIT_ID {
        return Err(OperatorError::Unknown);
    }
    if operator.version != INVALIDATE_FINAL_DIGIT_VERSION {
        return Err(OperatorError::VersionMismatch);
    }
    let end = match (
        usize::try_from(candidate.start),
        usize::try_from(candidate.end),
    ) {
        (Ok(s), Ok(e)) if s < e && e <= text.len() => e,
        _ => return Err(OperatorError::NotApplicable),
    };
    let mut bytes = text.as_bytes().to_vec();
    let last = end - 1;
    if !bytes[last].is_ascii_digit() {
        return Err(OperatorError::NotApplicable);
    }
    bytes[last] = b'0' + (bytes[last] - b'0' + 1) % 10;
    // Replacing one ASCII byte by another keeps the text valid UTF-8.
    let text = String::from_utf8(bytes).map_err(|_| OperatorError::NotApplicable)?;
    Ok(Mutation {
        text,
        candidate: ByteRange {
            start: candidate.start,
            end: candidate.end,
        },
        type_expectation: ExpectedType::Invalid,
    })
}
