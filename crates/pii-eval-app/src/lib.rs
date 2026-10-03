//! GitHub-independent core of the internal pii-eval GitHub App (P11, ADR 0011).
//!
//! The crate turns an authenticated webhook delivery into at most one bounded,
//! deterministic job, runs public synthetic jobs through the CLI library on a
//! small worker pool, and publishes only sanitized, schema-fixed Check
//! summaries. It owns no measurement, no corpus and no authorization authority:
//! the allowlist is deployment policy, protected profiles are only ever handed
//! to private-custodian through [`ports::CustodianRouter`], and a comment or a
//! label alone grants nothing.
//!
//! Not in this crate (deployment follow-ups, `docs/github-app.md`): an HTTP
//! server, the GitHub REST client, App JWT signing and installation tokens. Every
//! one of them sits behind a trait in [`ports`], so none is needed to build or
//! test the core, and the CLI never depends on this crate.
//!
//! The Rust API is internal; the documented contracts are `docs/github-app.md`
//! and the Check summary text.

pub mod checks;
pub mod cli_runner;
pub mod dedupe;
#[cfg(unix)]
pub mod external_runner;
pub mod hmac;
pub mod jobs;
pub mod policy;
pub mod ports;
pub mod queue;
pub mod reason;
pub mod request;
pub mod secret;
pub mod service;
pub mod staging;
pub mod testing;
pub mod webhook;

pub use service::{App, Services, WorkerPool};
