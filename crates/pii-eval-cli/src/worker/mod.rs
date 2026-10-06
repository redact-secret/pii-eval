//! The worker-job launcher: the engine side of the private-custodian worker
//! protocol v1 (docs/worker-job.md, ADR 0015).
//!
//! The custodian starts `/stage/engine --job /job/job.json` inside its sandbox.
//! This module reads that job, verifies the staged world, assembles the
//! population from the staged entries, runs the SAME pipeline as the standalone
//! `pii-eval run` (`crate::run`, the bounded executor, the verifying writer) and
//! prints exactly one `private-custodian.worker-result/1` document.
//!
//! The five production adapters follow private-custodian ADR 0133. Proposed
//! or TestOnly adapters still fail closed under the production policy.
//! `WorkerOutput.result` carries the embedded aggregates object on stdout.
//!
//! Nothing here measures anything: numerators and denominators come from the
//! kernel's accounting through the run artifact the writer has verified.

pub mod aggregates;
pub mod bundle;
pub mod config;
pub mod contract;
pub mod digest;
pub mod entry;
pub mod job;
pub mod launch;
pub mod reason;
pub mod stage;
#[cfg(feature = "worker-test-adapters")]
pub mod test_adapters;

pub mod production;
