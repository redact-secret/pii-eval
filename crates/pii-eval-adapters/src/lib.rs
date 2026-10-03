//! Scanner adapters for `pii-eval`.
//!
//! An adapter runs one pinned scanner and returns normalized observations. It
//! never scores: expected labels, ranges and case identities do not exist at
//! this layer, and the only data that crosses the process boundary toward the
//! scanner is run configuration and input text (see [`wire`]).
//!
//! - [`adapter`]: the [`ScannerAdapter`]/[`ScanSession`] boundary and the
//!   process adapter (pin verification, startup identity checks, bounded I/O);
//! - [`wire`]: the `pii-eval-adapter/1` JSON-lines protocol;
//! - [`normalize`]: native findings to contract findings, with the kernel's
//!   single offset translation;
//! - [`vocab`]: per-scanner mapping policy (labels, actions, activation);
//! - [`redact_secret`]: the `@redact-secret/core` 0.1.0-beta.12 adapter;
//! - [`inventory`]: every legacy scanner and its disposition;
//! - [`pin`], [`limits`], [`error`]: digests, bounds, distinct failure states.
//!
//! - [`control`]: process-group cleanup of a scanner's whole process tree and a
//!   sampling supervisor for resident-set and scratch-directory limits (P7).
//!   Process hygiene, not a sandbox.
//!
//! Status: one bounded session per process, with tree cleanup and resource
//! limits (P7). Worker pools, replay scheduling and artifact writing are the
//! executor's, in `pii-eval-cli`. Decisions:
//! `docs/adr/0006-scanner-adapter-boundary.md`, `docs/adr/0009-bounded-execution-and-artifact-writing.md`.

pub mod adapter;
pub mod control;
pub mod error;
pub mod inventory;
pub mod limits;
pub mod normalize;
pub mod pin;
mod process;
pub mod redact_secret;
pub mod vocab;
pub mod wire;

pub use adapter::{
    INHERITABLE_ENV, ProcessAdapter, ProcessAdapterSpec, RuntimeRecord, SanitizedOutput,
    ScanOutput, ScanSession, ScannerAdapter, SessionStats, StartFailure, StartOptions,
};
pub use control::{
    AbortHandle, AbortReason, Supervisor, SupervisorError, TREE_CLEANUP_SUPPORTED, WatchGuard,
    WatchLimits,
};
pub use error::AdapterError;
pub use limits::AdapterLimits;
pub use pin::{ArtifactPin, PinTarget, sha256_of_file, sha256_of_tree};
pub use vocab::{ActivationInfo, Mapped, MappedFinding, RawFinding, ScannerVocabulary};
pub use wire::PROTOCOL;

use pii_eval_contracts::{CrateIdentity, Role};

/// Identity of this crate.
pub const IDENTITY: CrateIdentity = CrateIdentity::new(
    Role::Adapters,
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_VERSION"),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_names_its_role() {
        assert_eq!(IDENTITY.role, Role::Adapters);
        assert_eq!(IDENTITY.package, "pii-eval-adapters");
    }
}
