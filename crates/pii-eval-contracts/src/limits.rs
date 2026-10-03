//! Explicit resource limits for contract parsing and validation.
//!
//! Every list, string and document the contracts accept has a stated bound so
//! that a hostile or corrupt input fails with a stable reason code (see
//! [`crate::ReasonCode::LimitExceeded`]) instead of exhausting memory. The
//! values are part of the schema 1.x protocol: raising one is an optional
//! (minor) change, lowering one is breaking (see ADR 0002).

/// Largest accepted serialized document, in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 128 * 1024 * 1024;
/// Deepest accepted JSON nesting. Contract documents nest less than 16 levels.
pub const MAX_NESTING_DEPTH: usize = 32;
/// Largest integer magnitude any contract number may carry (2^53 - 1), the
/// largest integer every JSON consumer reads exactly.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Most authored cases in one snapshot.
pub const MAX_CASES: usize = 1_000_000;
/// Most variants in one case.
pub const MAX_VARIANTS_PER_CASE: usize = 64;
/// Most expected occurrences in one variant.
pub const MAX_EXPECTATIONS_PER_VARIANT: usize = 16;
/// Largest variant text, in UTF-8 bytes.
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Most competing families in one collision declaration.
pub const MAX_COMPETING_FAMILIES: usize = 32;

/// Most scanners in one run.
pub const MAX_SCANNERS: usize = 32;
/// Most configuration parameters for one scanner.
pub const MAX_CONFIG_PARAMETERS: usize = 64;
/// Most activation selectors for one scanner.
pub const MAX_ACTIVATION_SELECTORS: usize = 256;
/// Longest string configuration value, in bytes.
pub const MAX_CONFIG_STRING_BYTES: usize = 256;
/// Most per-family or per-jurisdiction capability entries.
pub const MAX_CAPABILITY_ENTRIES: usize = 1024;

/// Most findings reported for one input.
pub const MAX_FINDINGS_PER_INPUT: usize = 10_000;
/// Most inputs in one observation set.
pub const MAX_INPUTS_PER_OBSERVATION_SET: usize = 4_000_000;
/// Most outcome rows in one run artifact.
pub const MAX_OUTCOMES: usize = 16_000_000;
/// Most failure records in one run artifact.
pub const MAX_FAILURES: usize = 4096;

/// Most violations one validation pass reports before it stops collecting.
pub const MAX_VIOLATIONS: usize = 64;
/// Longest rendered location path in an error, in bytes.
pub const MAX_PATH_BYTES: usize = 256;

/// Upper bounds for the execution limits a plan may request.
pub mod execution {
    /// Most worker threads or processes.
    pub const MAX_WORKERS: u32 = 256;
    /// Most pending tasks queued across workers.
    pub const MAX_PENDING_TASKS: u32 = 65_536;
    /// Most variants processed in one batch.
    pub const MAX_BATCH_VARIANTS: u32 = 65_536;
    /// Longest per-scanner timeout, in milliseconds (one hour).
    pub const MAX_TIMEOUT_MS: u64 = 3_600_000;
    /// Largest captured scanner stdout or stderr, in bytes (1 GiB).
    pub const MAX_OUTPUT_BYTES: u64 = 1 << 30;
    /// Largest memory budget, in bytes (1 TiB).
    pub const MAX_MEMORY_BYTES: u64 = 1 << 40;
    /// Largest temporary storage budget, in bytes (1 TiB).
    pub const MAX_TEMPORARY_BYTES: u64 = 1 << 40;
}
