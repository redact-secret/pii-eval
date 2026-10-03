//! The frozen exit-code table, the closed set of reason codes and the failure
//! type every command returns (ADR 0010, docs/cli.md).
//!
//! A [`Failure`] carries a fixed reason code, an optional detail that is built
//! only from names this program defines (a field, a document kind, an identity
//! slot) and contract reason codes. It never carries input text, a value from a
//! document, a path, scanner output or an operating-system message, so
//! formatting one cannot leak matched data.

use pii_eval_contracts::{ContractError, ReasonCode, Violations};

/// Process exit status. The numbers are part of the CLI contract: they are
/// never renumbered or reused (a retired status stays reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exit {
    /// The command did what was asked and every check passed.
    Success,
    /// A defect of this program (or a panic). Never caused by a scanner.
    Internal,
    /// The command line is not valid.
    Usage,
    /// An input (configuration, document, file) is invalid or unusable.
    Invalid,
    /// A pinned or bound identity does not match what was found.
    Provenance,
    /// The run finished and its documents were written, but at least one
    /// scanner did not complete: the measurement is incomplete, not "no findings".
    ScannerFailure,
    /// The run could not be executed (refused limits, unsupported platform,
    /// unusable adapter specification).
    Execution,
    /// The output location is unusable or a write failed.
    Output,
    /// The run was cancelled by a signal; nothing was committed.
    Cancelled,
    /// A protected run has no valid custodian job context, or its inputs lie
    /// outside the context.
    ProtectedContext,
    /// Two artifacts must not be compared.
    Incomparable,
    /// The document is a legacy (protocol revision 1) artifact: readable, but
    /// its metrics cannot be recomputed.
    NotVerifiable,
}

impl Exit {
    /// Every status, ascending by code.
    pub const ALL: [Exit; 12] = [
        Exit::Success,
        Exit::Internal,
        Exit::Usage,
        Exit::Invalid,
        Exit::Provenance,
        Exit::ScannerFailure,
        Exit::Execution,
        Exit::Output,
        Exit::Cancelled,
        Exit::ProtectedContext,
        Exit::Incomparable,
        Exit::NotVerifiable,
    ];

    /// The process exit code.
    pub const fn code(self) -> u8 {
        match self {
            Exit::Success => 0,
            Exit::Internal => 1,
            Exit::Usage => 2,
            Exit::Invalid => 3,
            Exit::Provenance => 4,
            Exit::ScannerFailure => 5,
            Exit::Execution => 6,
            Exit::Output => 7,
            Exit::Cancelled => 8,
            Exit::ProtectedContext => 9,
            Exit::Incomparable => 10,
            Exit::NotVerifiable => 11,
        }
    }

    /// The stable name used in summaries.
    pub const fn name(self) -> &'static str {
        match self {
            Exit::Success => "success",
            Exit::Internal => "internal-error",
            Exit::Usage => "usage-error",
            Exit::Invalid => "invalid-input",
            Exit::Provenance => "provenance-mismatch",
            Exit::ScannerFailure => "scanner-failure",
            Exit::Execution => "execution-refused",
            Exit::Output => "output-failure",
            Exit::Cancelled => "cancelled",
            Exit::ProtectedContext => "protected-context",
            Exit::Incomparable => "incomparable",
            Exit::NotVerifiable => "not-verifiable",
        }
    }
}

/// Reason codes of the CLI (the contract's own codes are reported separately,
/// in [`Failure::codes`]). Each is stable; a retired code stays reserved.
pub mod reason {
    // Usage (exit 2).
    pub const MISSING_COMMAND: &str = "missing-command";
    pub const UNKNOWN_COMMAND: &str = "unknown-command";
    pub const UNKNOWN_OPTION: &str = "unknown-option";
    pub const MISSING_VALUE: &str = "missing-value";
    pub const DUPLICATE_OPTION: &str = "duplicate-option";
    pub const MISSING_REQUIRED_OPTION: &str = "missing-required-option";
    pub const UNEXPECTED_ARGUMENT: &str = "unexpected-argument";
    pub const INVALID_OPTION_VALUE: &str = "invalid-option-value";
    // Invalid input (exit 3).
    pub const INPUT_UNREADABLE: &str = "input-unreadable";
    pub const INPUT_TOO_LARGE: &str = "input-too-large";
    pub const CONFIG_INVALID: &str = "config-invalid";
    pub const DOCUMENT_INVALID: &str = "document-invalid";
    pub const KIND_MISMATCH: &str = "kind-mismatch";
    pub const PROTOCOL_UNSUPPORTED: &str = "protocol-revision-unsupported";
    pub const REPLAY_ORIGINAL_REQUIRED: &str = "replay-original-required";
    pub const REPLAY_INCOMPLETE: &str = "replay-incomplete-observations";
    pub const VERIFICATION_FAILED: &str = "verification-failed";
    pub const ASSEMBLY_FAILED: &str = "measurement-assembly-failed";
    // Provenance (exit 4).
    pub const PROVENANCE_MISMATCH: &str = "provenance-mismatch";
    pub const REPLAY_DIVERGED: &str = "replay-diverged";
    // Scanner failure (exit 5).
    pub const SCANNER_FAILURE: &str = "scanner-failure";
    // Execution (exit 6).
    pub const EXECUTION_REFUSED: &str = "execution-refused";
    pub const PLATFORM_UNSUPPORTED: &str = "platform-unsupported";
    pub const ADAPTER_INVALID: &str = "adapter-invalid";
    // Output (exit 7).
    pub const OUTPUT_UNUSABLE: &str = "output-unusable";
    pub const OUTPUT_EXISTS: &str = "output-exists";
    pub const OUTPUT_WRITE_FAILED: &str = "output-write-failed";
    pub const OUTPUT_NOT_DURABLE: &str = "output-committed-not-durable";
    pub const OUTPUT_PARTIAL: &str = "output-partial";
    // Cancelled (exit 8).
    pub const CANCELLED: &str = "cancelled";
    // Protected context (exit 9).
    pub const PROTECTED_CONTEXT_REQUIRED: &str = "protected-context-required";
    pub const PROTECTED_CONTEXT_INVALID: &str = "protected-context-invalid";
    pub const PROTECTED_CONTEXT_MISMATCH: &str = "protected-context-mismatch";
    pub const PROTECTED_PATH_OUTSIDE: &str = "protected-path-outside-context";
    // Incomparable (exit 10).
    pub const INCOMPARABLE: &str = "incomparable";
    // Not verifiable (exit 11).
    pub const LEGACY_NOT_VERIFIABLE: &str = "legacy-not-verifiable";
    // Internal (exit 1).
    pub const INTERNAL: &str = "internal-error";
    pub const ARTIFACT_VERIFICATION_FAILED: &str = "artifact-verification-failed";

    /// Every reason code, for the documentation test.
    pub const ALL: &[&str] = &[
        MISSING_COMMAND,
        UNKNOWN_COMMAND,
        UNKNOWN_OPTION,
        MISSING_VALUE,
        DUPLICATE_OPTION,
        MISSING_REQUIRED_OPTION,
        UNEXPECTED_ARGUMENT,
        INVALID_OPTION_VALUE,
        INPUT_UNREADABLE,
        INPUT_TOO_LARGE,
        CONFIG_INVALID,
        DOCUMENT_INVALID,
        KIND_MISMATCH,
        PROTOCOL_UNSUPPORTED,
        REPLAY_ORIGINAL_REQUIRED,
        REPLAY_INCOMPLETE,
        VERIFICATION_FAILED,
        ASSEMBLY_FAILED,
        PROVENANCE_MISMATCH,
        REPLAY_DIVERGED,
        SCANNER_FAILURE,
        EXECUTION_REFUSED,
        PLATFORM_UNSUPPORTED,
        ADAPTER_INVALID,
        OUTPUT_UNUSABLE,
        OUTPUT_EXISTS,
        OUTPUT_WRITE_FAILED,
        OUTPUT_NOT_DURABLE,
        OUTPUT_PARTIAL,
        CANCELLED,
        PROTECTED_CONTEXT_REQUIRED,
        PROTECTED_CONTEXT_INVALID,
        PROTECTED_CONTEXT_MISMATCH,
        PROTECTED_PATH_OUTSIDE,
        INCOMPARABLE,
        LEGACY_NOT_VERIFIABLE,
        INTERNAL,
        ARTIFACT_VERIFICATION_FAILED,
    ];
}

/// Why a command did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Exit status.
    pub exit: Exit,
    /// Stable reason code ([`reason`]).
    pub reason: &'static str,
    /// Where it happened, from a closed vocabulary: a configuration field name,
    /// a document kind, an identity slot. Never a value.
    pub detail: Option<String>,
    /// Contract reason codes, ascending and unique, at most [`MAX_CODES`].
    pub codes: Vec<&'static str>,
}

/// Most contract reason codes a failure carries.
pub const MAX_CODES: usize = 16;

impl Failure {
    /// A failure with no detail.
    pub fn new(exit: Exit, reason: &'static str) -> Self {
        Self {
            exit,
            reason,
            detail: None,
            codes: Vec::new(),
        }
    }

    /// Add a detail (a name this program defines, never a value).
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Add contract reason codes.
    #[must_use]
    pub fn with_codes(mut self, codes: impl IntoIterator<Item = ReasonCode>) -> Self {
        let mut all: Vec<&'static str> = codes.into_iter().map(ReasonCode::as_str).collect();
        all.sort_unstable();
        all.dedup();
        all.truncate(MAX_CODES);
        self.codes = all;
        self
    }

    /// A usage error.
    pub fn usage(reason: &'static str, detail: &str) -> Self {
        Failure::new(Exit::Usage, reason).with_detail(detail)
    }

    /// A configuration error at a named field.
    pub fn config(field: &str) -> Self {
        Failure::new(Exit::Invalid, reason::CONFIG_INVALID).with_detail(field)
    }

    /// A provenance mismatch in a named identity slot.
    pub fn provenance(slot: &str) -> Self {
        Failure::new(Exit::Provenance, reason::PROVENANCE_MISMATCH).with_detail(slot)
    }

    /// The one-line human diagnostic for stderr. Fixed vocabulary only.
    pub fn human(&self) -> String {
        let mut line = format!(
            "pii-eval: {} ({}, exit {})",
            self.reason,
            self.exit.name(),
            self.exit.code()
        );
        if let Some(detail) = &self.detail {
            line.push_str(": ");
            line.push_str(detail);
        }
        if !self.codes.is_empty() {
            line.push_str(" [");
            line.push_str(&self.codes.join(", "));
            line.push(']');
        }
        line
    }
}

/// Contract reasons that mean "this document does not bind to what it must
/// bind to" rather than "this document is malformed".
const BINDING_CODES: &[ReasonCode] = &[
    ReasonCode::PopulationBindingMismatch,
    ReasonCode::RunClassMismatch,
    ReasonCode::GenerationBindingMismatch,
    ReasonCode::EngineBindingMismatch,
    ReasonCode::ProtocolBindingMismatch,
    ReasonCode::UnknownScanner,
    ReasonCode::ConfigurationBindingMismatch,
    ReasonCode::UnknownVariant,
    ReasonCode::InputDigestMismatch,
];

/// A failure for a document that failed parsing or its own validation: always
/// invalid input (exit 3), with the contract reason codes.
pub fn from_violations(kind: &str, v: &Violations) -> Failure {
    Failure::new(Exit::Invalid, reason::DOCUMENT_INVALID)
        .with_detail(kind)
        .with_codes(v.errors.iter().map(|e| e.code))
}

/// A failure for a document that does not bind to the document it must bind to
/// (snapshot, manifest, observation set): provenance mismatch (exit 4) when a
/// binding reason is present, invalid input otherwise.
pub fn from_binding(kind: &str, v: &Violations) -> Failure {
    if v.errors.iter().any(|e| BINDING_CODES.contains(&e.code)) {
        Failure::provenance(kind).with_codes(v.errors.iter().map(|e| e.code))
    } else {
        from_violations(kind, v)
    }
}

/// A failure for a single contract error.
pub fn from_contract_error(kind: &str, e: &ContractError) -> Failure {
    from_violations(kind, &Violations::single(e.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_ascending_and_names_are_unique() {
        let codes: Vec<u8> = Exit::ALL.iter().map(|e| e.code()).collect();
        assert_eq!(codes, (0..12).collect::<Vec<u8>>());
        let mut names: Vec<&str> = Exit::ALL.iter().map(|e| e.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 12);
    }

    #[test]
    fn reason_codes_are_unique_kebab_case() {
        let mut all = reason::ALL.to_vec();
        all.sort_unstable();
        let before = all.len();
        all.dedup();
        assert_eq!(all.len(), before);
        for r in reason::ALL {
            assert!(
                r.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{r}"
            );
        }
    }

    #[test]
    fn binding_reasons_are_provenance_and_others_are_invalid() {
        let bind = Violations::single(ContractError::root(ReasonCode::PopulationBindingMismatch));
        assert_eq!(from_binding("manifest", &bind).exit, Exit::Provenance);
        assert_eq!(from_violations("manifest", &bind).exit, Exit::Invalid);
        let bad = Violations::single(ContractError::root(ReasonCode::SchemaViolation));
        assert_eq!(from_binding("manifest", &bad).exit, Exit::Invalid);
    }
}
