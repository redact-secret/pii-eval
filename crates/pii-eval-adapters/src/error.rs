//! Adapter failure states.
//!
//! Each way an adapter can fail to produce findings is a distinct variant, and
//! each maps to a contract [`FailureCode`] (and through it a [`ScannerStatus`]).
//! None of them can be confused with a scan that returned no findings: a scan
//! returns `Ok(ScanOutput)` or one of these.
//!
//! Errors carry fixed enums and nothing else. They never hold a line of shim
//! output, an input fragment, an OS error message, a path or an offset, so
//! formatting one with `Display` or `Debug` cannot leak a matched value.

use std::fmt;

use pii_eval_contracts::{FailureCode, ScannerStatus};

macro_rules! fixed_enum {
    ($(#[$doc:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($variant),+ }

        impl $name {
            /// Stable kebab-case name.
            pub const fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }
        }
    };
}

fixed_enum!(
    /// A caller-supplied specification that cannot be used. A caller bug, not a
    /// scanner measurement failure.
    SpecProblem {
        Limits => "limits",
        Executable => "executable",
        ArtifactPath => "artifact-path",
        Parameters => "parameters",
        Selector => "selector",
        Environment => "environment",
        Identity => "identity",
        Vocabulary => "vocabulary",
    }
);

fixed_enum!(
    /// Which identity or pin did not match. Raised before the scanner receives any input.
    PinKind {
        PlanIdentity => "plan-identity",
        Configuration => "configuration",
        ShimDigest => "shim-digest",
        ArtifactDigest => "artifact-digest",
        ArtifactNotRegularFile => "artifact-not-regular-file",
        ArtifactUnreadable => "artifact-unreadable",
        ArtifactTooLarge => "artifact-too-large",
        ScannerId => "scanner-id",
        ScannerVersion => "scanner-version",
        Runtime => "runtime",
        OffsetUnit => "offset-unit",
        Protocol => "protocol",
        Activation => "activation",
    }
);

fixed_enum!(
    /// A capability the scanner does not have, as reported at initialization.
    MissingCapability {
        SelectorUnsupported => "selector-unsupported",
        ConfigurationRejected => "configuration-rejected",
    }
);

fixed_enum!(
    /// Where startup failed.
    StartupStage {
        Spawn => "spawn",
        ExitedBeforeReady => "exited-before-ready",
        ScannerInitialization => "scanner-initialization",
        Write => "write",
    }
);

fixed_enum!(
    /// Which call timed out.
    CallPhase { Startup => "startup", Scan => "scan" }
);

fixed_enum!(
    /// A failure the scanner itself reported through the fixed code vocabulary.
    ScannerErrorCode {
        ScanFailed => "scan-failed",
        InputLimit => "input-limit",
        ProtocolError => "protocol-error",
    }
);

fixed_enum!(
    /// Which limit was exceeded.
    LimitKind { Line => "line", Findings => "findings" }
);

fixed_enum!(
    /// What was wrong with the shim output.
    MalformedKind {
        NotUtf8 => "not-utf8",
        NotJson => "not-json",
        Structure => "structure",
        UnknownField => "unknown-field",
        WrongType => "wrong-type",
        WrongSequence => "wrong-sequence",
        UnexpectedMessage => "unexpected-message",
        InvalidRange => "invalid-range",
        UnknownAction => "unknown-action",
        UnknownErrorCode => "unknown-error-code",
        Activation => "activation",
        Output => "output",
        Truncated => "truncated",
        UnexpectedEof => "unexpected-eof",
    }
);

/// Why an adapter did not produce an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterError {
    /// The specification or limits are invalid. Not a measurement failure.
    InvalidSpec(SpecProblem),
    /// The input exceeds the configured text bound. Not a measurement failure.
    InputTooLarge,
    /// A pin did not match; nothing was executed (or, for runtime identity,
    /// nothing was sent to the scanner).
    PinMismatch(PinKind),
    /// The scanner lacks a requested capability.
    MissingCapability(MissingCapability),
    /// The scanner process could not be started or initialized.
    StartupFailure(StartupStage),
    /// A call exceeded its deadline; the process was killed.
    Timeout(CallPhase),
    /// The process ended abnormally (non-zero exit or signal) mid-session.
    Crashed,
    /// The scanner reported a failure through the fixed code vocabulary.
    ScannerError(ScannerErrorCode),
    /// A size limit was exceeded; the process was killed.
    OutputLimit(LimitKind),
    /// The output violated the protocol.
    MalformedOutput(MalformedKind),
    /// The session already failed or was closed.
    SessionClosed,
}

impl AdapterError {
    /// Contract failure code, or `None` for caller errors that say nothing
    /// about the scanner.
    pub const fn failure_code(self) -> Option<FailureCode> {
        match self {
            AdapterError::InvalidSpec(_) | AdapterError::InputTooLarge => None,
            AdapterError::SessionClosed => None,
            AdapterError::PinMismatch(_) => Some(FailureCode::Unavailable),
            AdapterError::MissingCapability(_) => Some(FailureCode::Unsupported),
            AdapterError::StartupFailure(_) => Some(FailureCode::Unavailable),
            AdapterError::Timeout(_) => Some(FailureCode::Timeout),
            AdapterError::Crashed | AdapterError::ScannerError(_) => {
                Some(FailureCode::ExecutionError)
            }
            AdapterError::OutputLimit(_) => Some(FailureCode::OutputLimitExceeded),
            AdapterError::MalformedOutput(_) => Some(FailureCode::MalformedOutput),
        }
    }

    /// Status the scanner record takes, derived from the failure code so the two
    /// always satisfy [`FailureCode::allowed_for`].
    pub const fn scanner_status(self) -> Option<ScannerStatus> {
        match self.failure_code() {
            None => None,
            Some(FailureCode::Unsupported) => Some(ScannerStatus::Unsupported),
            Some(FailureCode::Unavailable) => Some(ScannerStatus::Unavailable),
            Some(_) => Some(ScannerStatus::Error),
        }
    }

    /// Stable top-level kind.
    pub const fn kind(self) -> &'static str {
        match self {
            AdapterError::InvalidSpec(_) => "invalid-spec",
            AdapterError::InputTooLarge => "input-too-large",
            AdapterError::PinMismatch(_) => "pin-mismatch",
            AdapterError::MissingCapability(_) => "missing-capability",
            AdapterError::StartupFailure(_) => "startup-failure",
            AdapterError::Timeout(_) => "timeout",
            AdapterError::Crashed => "crashed",
            AdapterError::ScannerError(_) => "scanner-error",
            AdapterError::OutputLimit(_) => "output-limit",
            AdapterError::MalformedOutput(_) => "malformed-output",
            AdapterError::SessionClosed => "session-closed",
        }
    }

    /// Stable sub-kind, empty when the kind has none.
    pub const fn detail(self) -> &'static str {
        match self {
            AdapterError::InvalidSpec(d) => d.as_str(),
            AdapterError::PinMismatch(d) => d.as_str(),
            AdapterError::MissingCapability(d) => d.as_str(),
            AdapterError::StartupFailure(d) => d.as_str(),
            AdapterError::Timeout(d) => d.as_str(),
            AdapterError::ScannerError(d) => d.as_str(),
            AdapterError::OutputLimit(d) => d.as_str(),
            AdapterError::MalformedOutput(d) => d.as_str(),
            AdapterError::InputTooLarge | AdapterError::Crashed | AdapterError::SessionClosed => "",
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = self.detail();
        if detail.is_empty() {
            f.write_str(self.kind())
        } else {
            write!(f, "{}: {}", self.kind(), detail)
        }
    }
}

impl std::error::Error for AdapterError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_code_is_allowed_for_its_derived_status() {
        let samples = [
            AdapterError::PinMismatch(PinKind::ArtifactDigest),
            AdapterError::MissingCapability(MissingCapability::SelectorUnsupported),
            AdapterError::StartupFailure(StartupStage::Spawn),
            AdapterError::Timeout(CallPhase::Scan),
            AdapterError::Crashed,
            AdapterError::ScannerError(ScannerErrorCode::ScanFailed),
            AdapterError::OutputLimit(LimitKind::Line),
            AdapterError::MalformedOutput(MalformedKind::NotJson),
        ];
        for e in samples {
            let code = e.failure_code().expect("measurement failure");
            let status = e.scanner_status().expect("status");
            assert!(code.allowed_for(status), "{e}");
        }
        assert_eq!(AdapterError::InputTooLarge.failure_code(), None);
        assert_eq!(
            AdapterError::InvalidSpec(SpecProblem::Limits).scanner_status(),
            None
        );
    }

    #[test]
    fn display_is_fixed_text() {
        assert_eq!(
            AdapterError::MalformedOutput(MalformedKind::InvalidRange).to_string(),
            "malformed-output: invalid-range"
        );
        assert_eq!(AdapterError::Crashed.to_string(), "crashed");
    }
}
