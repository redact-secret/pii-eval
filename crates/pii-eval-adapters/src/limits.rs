//! Explicit resource limits of one adapter process.
//!
//! Every value has a documented ceiling so a plan or a caller cannot request an
//! unbounded adapter. The ceilings reuse the contract's execution bounds where
//! one exists. Pool-level bounds (worker count, pending tasks, memory,
//! temporary storage) belong to the executor (P7), not to one adapter process.

use std::time::Duration;

use pii_eval_contracts::limits::{MAX_FINDINGS_PER_INPUT, MAX_TEXT_BYTES, execution};

use crate::error::{AdapterError, SpecProblem};

/// Largest configurable shim output line, in bytes. Stricter than the
/// contract's 1 GiB capture bound. One result carries at most 10,000 findings
/// (about 1.5 MiB) and sanitized output of at most the 1 MiB input, which
/// JSON escaping can expand six-fold for control characters; 8 MiB (the
/// default) covers that worst case and 16 MiB is the ceiling.
///
/// Memory bound per call: the line (at most `max_line_bytes`), the same bytes
/// again as the parsed tree (the finding count is checked before the parse, so
/// the tree holds at most `max_findings` findings), and the range tables of
/// the kernel translator (at most 8 MiB).
pub const MAX_LINE_BYTES_CEILING: usize = 16 * 1024 * 1024;
/// Smallest useful line bound (a handshake or an empty result fits).
pub const MIN_LINE_BYTES: usize = 1024;
/// Largest stderr byte count the adapter tracks.
pub const MAX_STDERR_BYTES_CEILING: usize = 16 * 1024 * 1024;

/// Bounds for one adapter process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterLimits {
    /// Time allowed from spawn to the `ready` message.
    pub startup_timeout: Duration,
    /// Time allowed for one scan call.
    pub call_timeout: Duration,
    /// Largest accepted output line. A longer line is a limit failure, never truncated.
    pub max_line_bytes: usize,
    /// Stderr bytes counted (and discarded) before the count saturates. Stderr
    /// is drained so the child cannot block on a full pipe; it is never stored
    /// or surfaced.
    pub max_stderr_bytes: usize,
    /// Most findings accepted for one input.
    pub max_findings: usize,
    /// Largest input text sent to the scanner, in UTF-8 bytes.
    pub max_text_bytes: usize,
}

impl Default for AdapterLimits {
    fn default() -> Self {
        Self {
            startup_timeout: Duration::from_secs(30),
            call_timeout: Duration::from_secs(30),
            max_line_bytes: 8 * 1024 * 1024,
            max_stderr_bytes: 64 * 1024,
            max_findings: MAX_FINDINGS_PER_INPUT,
            max_text_bytes: MAX_TEXT_BYTES,
        }
    }
}

impl AdapterLimits {
    /// Check every field against its floor and ceiling.
    pub fn validate(&self) -> Result<(), AdapterError> {
        let max_timeout = Duration::from_millis(execution::MAX_TIMEOUT_MS);
        let ok = !self.startup_timeout.is_zero()
            && self.startup_timeout <= max_timeout
            && !self.call_timeout.is_zero()
            && self.call_timeout <= max_timeout
            && (MIN_LINE_BYTES..=MAX_LINE_BYTES_CEILING).contains(&self.max_line_bytes)
            && (1..=MAX_STDERR_BYTES_CEILING).contains(&self.max_stderr_bytes)
            && (1..=MAX_FINDINGS_PER_INPUT).contains(&self.max_findings)
            && (1..=MAX_TEXT_BYTES).contains(&self.max_text_bytes);
        if ok {
            Ok(())
        } else {
            Err(AdapterError::InvalidSpec(SpecProblem::Limits))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_zero_or_oversize_values_are_not() {
        assert_eq!(AdapterLimits::default().validate(), Ok(()));
        let zero = AdapterLimits {
            call_timeout: Duration::ZERO,
            ..AdapterLimits::default()
        };
        assert!(zero.validate().is_err());
        let huge = AdapterLimits {
            max_line_bytes: MAX_LINE_BYTES_CEILING + 1,
            ..AdapterLimits::default()
        };
        assert!(huge.validate().is_err());
        let slow = AdapterLimits {
            startup_timeout: Duration::from_millis(execution::MAX_TIMEOUT_MS + 1),
            ..AdapterLimits::default()
        };
        assert!(slow.validate().is_err());
    }
}
