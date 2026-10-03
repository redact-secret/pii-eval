//! The worker-job reason codes. A closed, fixed vocabulary: none carries a
//! value, a path, an entry name or scanner output. Exit statuses are the frozen
//! table of docs/cli.md; no status is added (docs/worker-job.md has the table).

use crate::status::{Exit, Failure};

macro_rules! reasons {
    ($($name:ident = $text:literal,)*) => {
        $(pub const $name: &str = $text;)*
        /// Every worker-job reason code, for the documentation test.
        pub const ALL: &[&str] = &[$($name),*];
    };
}

reasons! {
    // Invalid input (exit 3).
    JOB_UNREADABLE = "job-unreadable",
    JOB_TOO_LARGE = "job-too-large",
    JOB_INVALID = "job-invalid",
    ENTRIES_TOO_MANY = "entries-too-many",
    ENTRY_NAME_INVALID = "entry-name-invalid",
    ENTRIES_DUPLICATE = "entries-duplicate",
    ROSTER_MISMATCH = "roster-mismatch",
    WORKER_CONFIG_INVALID = "worker-config-invalid",
    WORKER_CONFIG_TOO_LARGE = "worker-config-too-large",
    ENTRY_UNREADABLE = "entry-unreadable",
    ENTRY_NOT_REGULAR = "entry-not-regular",
    ENTRY_TOO_LARGE = "entry-too-large",
    ENTRIES_TOO_LARGE = "entries-too-large",
    ENTRY_INVALID = "entry-invalid",
    BUNDLE_INVALID = "bundle-invalid",
    SCANNER_COUNT_UNSUPPORTED = "scanner-count-unsupported",
    // Identity, binding and population mismatches (exit 4).
    JOB_DOMAIN_MISMATCH = "job-domain-mismatch",
    JOB_PROTOCOL_MISMATCH = "job-protocol-mismatch",
    ENTRIES_LISTING_MISMATCH = "entries-listing-mismatch",
    STAGED_FILE_INVALID = "staged-file-invalid",
    ENGINE_DIGEST_MISMATCH = "engine-digest-mismatch",
    ADAPTER_BUNDLE_DIGEST_MISMATCH = "adapter-bundle-digest-mismatch",
    CANDIDATE_BUNDLE_DIGEST_MISMATCH = "candidate-bundle-digest-mismatch",
    PACKAGE_TREE_DIGEST_MISMATCH = "package-tree-digest-mismatch",
    RUNTIME_DIGEST_MISMATCH = "runtime-digest-mismatch",
    SHIM_DIGEST_MISMATCH = "shim-digest-mismatch",
    POPULATION_BINDING_MISMATCH = "population-binding-mismatch",
    RUN_CLASS_MISMATCH = "run-class-mismatch",
    MANIFEST_BINDING_MISMATCH = "manifest-binding-mismatch",
    SCANNER_PLAN_MISMATCH = "scanner-plan-mismatch",
    // Execution refused (exit 6).
    CONTRACT_NOT_FINAL = "contract-not-final",
    // Output failure (exit 7).
    BUNDLE_EXTRACT_FAILED = "bundle-extract-failed",
    RESULT_TOO_LARGE = "result-too-large",
    AGGREGATES_TOO_LARGE = "aggregates-too-large",
    AGGREGATES_ROSTER_VIOLATION = "aggregates-roster-violation",
    AGGREGATE_LABEL_INVALID = "aggregate-label-invalid",
    AGGREGATES_CHANNEL_FAILED = "aggregates-channel-failed",
}

/// A failure of the worker-job command: a fixed reason, an exit status and a
/// closed detail (a slot, an artifact name, a bounded cause), never a value.
pub fn fail(exit: Exit, reason: &'static str, detail: &str) -> Failure {
    let f = Failure::new(exit, reason);
    if detail.is_empty() {
        f
    } else {
        f.with_detail(detail)
    }
}

/// Exit 3.
pub fn invalid(reason: &'static str, detail: &str) -> Failure {
    fail(Exit::Invalid, reason, detail)
}

/// Exit 4.
pub fn mismatch(reason: &'static str, detail: &str) -> Failure {
    fail(Exit::Provenance, reason, detail)
}

/// Exit 7.
pub fn output(reason: &'static str, detail: &str) -> Failure {
    fail(Exit::Output, reason, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_reasons_are_unique_kebab_case_and_do_not_reuse_a_cli_code() {
        let mut all = ALL.to_vec();
        all.sort_unstable();
        let n = all.len();
        all.dedup();
        assert_eq!(all.len(), n);
        for r in ALL {
            assert!(
                r.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{r}"
            );
            assert!(!crate::status::reason::ALL.contains(r), "{r} is a CLI code");
        }
    }
}
