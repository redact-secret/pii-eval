//! The worker-job launcher: the engine side of the private-custodian worker
//! protocol v1 (docs/worker-job.md, ADR 0015).
//!
//! The custodian starts `/stage/engine --job /job/job.json` inside its sandbox.
//! This module reads that job, verifies the staged world, assembles the
//! population from the staged entries, runs the SAME pipeline as the standalone
//! `pii-eval run` (`crate::run`, the bounded executor, the verifying writer) and
//! prints exactly one `private-custodian.worker-result/1` document.
//!
//! What the custodian has decided is implemented as stated. What it has not
//! decided lives behind the adapters of [`contract`], each with a
//! [`contract::ContractStatus`]; the production wiring has none of them and
//! refuses with `contract-not-final` before reading any entry
//! (docs/custodian-contract-status.md).
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
