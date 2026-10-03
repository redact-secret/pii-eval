//! The seam between what the custodian has decided and what it has not.
//!
//! Every undecided item of the worker contract is one [`Slot`], reached through
//! an adapter trait. Each adapter reports a [`ContractStatus`]. The production
//! wiring ([`Adapters::production`]) holds NO adapter for any slot, so
//! `worker-job` refuses with `contract-not-final: <slot>` before it reads
//! anything protected. There is no flag, environment variable or configuration
//! field that installs an adapter: the only way in is the Rust API, and the test
//! adapters exist only in builds with the cargo feature `worker-test-adapters`.
//!
//! When the custodian decides a slot, enabling it means implementing a
//! [`ContractStatus::Decided`] adapter for it, with tests, and installing it in
//! [`Adapters::production`]. Nothing else changes.
//!
//! Decided items need no slot: the job and result documents (A4, A5), the digest
//! syntax (A10) and the stage names (A2) are implemented as stated
//! ([`DECIDED`]).

use std::path::{Path, PathBuf};

use pii_eval_contracts::Case;

use crate::status::{Exit, Failure};
use crate::worker::reason;

/// How final an adapter's contract is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractStatus {
    /// The custodian's code and documents state it and test it.
    Decided,
    /// This repository's proposal; the custodian has not agreed.
    Proposed,
    /// Exists for tests only; never part of a production wiring.
    TestOnly,
}

impl ContractStatus {
    /// Stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ContractStatus::Decided => "decided",
            ContractStatus::Proposed => "proposed",
            ContractStatus::TestOnly => "test-only",
        }
    }
}

/// The adapters the worker needs for items the custodian has not decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Where Node, the shim and the package live in the staged set (Q9).
    StageLayout,
    /// How a package tree travels as one staged file (Q4).
    BundleFormat,
    /// What an input entry holds (Q1).
    EntryFormat,
    /// How the aggregates document reaches the custodian (Q2).
    AggregatesChannel,
    /// Which strata and metric labels the disclosure policy allows (Q3).
    AggregateLabels,
}

impl Slot {
    /// Every slot, in the order a refusal names the first unconfigured one.
    pub const ALL: [Slot; 5] = [
        Slot::StageLayout,
        Slot::BundleFormat,
        Slot::EntryFormat,
        Slot::AggregatesChannel,
        Slot::AggregateLabels,
    ];

    /// The fixed name used in `contract-not-final: <slot>`.
    pub const fn name(self) -> &'static str {
        match self {
            Slot::StageLayout => "stage-layout",
            Slot::BundleFormat => "bundle-format",
            Slot::EntryFormat => "entry-format",
            Slot::AggregatesChannel => "aggregates-channel",
            Slot::AggregateLabels => "aggregate-labels",
        }
    }

    /// The open question of docs/custodian-contract-status.md.
    pub const fn question(self) -> &'static str {
        match self {
            Slot::StageLayout => "Q9",
            Slot::BundleFormat => "Q4",
            Slot::EntryFormat => "Q1",
            Slot::AggregatesChannel => "Q2",
            Slot::AggregateLabels => "Q3",
        }
    }

    /// The custodian-side status of the item. Every slot is `Proposed` today.
    pub const fn contract_status(self) -> ContractStatus {
        ContractStatus::Proposed
    }
}

/// Items implemented as the custodian decided them (no slot).
pub const DECIDED: [&str; 3] = ["job-document/1", "result-document/1", "digest-syntax"];

/// The fixed names of staged files (A2).
pub mod staged {
    /// The engine itself.
    pub const ENGINE: &str = "engine";
    /// The adapter bundle (the Node shim).
    pub const ADAPTER: &str = "adapter";
    /// The candidate bundle (the scanner package).
    pub const CANDIDATE: &str = "candidate";
    /// The worker configuration.
    pub const CONFIG: &str = "config";
    /// The pinned Node runtime (`scanner-0`).
    pub const RUNTIME: &str = "scanner-0";
}

/// Where the sandbox puts things. In the custodian's sandbox: `/stage`,
/// `/input`, `/scratch` (A1); the job file is the `--job` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerLayout {
    /// Read-only directory of staged artifacts.
    pub stage: PathBuf,
    /// Read-only directory of flat entry files.
    pub input: PathBuf,
    /// The only writable directory.
    pub scratch: PathBuf,
}

/// A bundle could not be read or extracted. Closed causes, no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// The header or the framing is not the format.
    Malformed,
    /// A member path is unsafe (absolute, `..`, backslash, control, too long or deep).
    Path,
    /// A path appears twice, or a path is both a file and a directory.
    Duplicate,
    /// A count, size or depth bound is exceeded.
    Limit,
    /// A member's bytes do not hash to its header entry.
    MemberDigest,
    /// The destination could not be written.
    Extract,
}

impl BundleError {
    /// The closed cause named in the failure detail.
    pub const fn name(self) -> &'static str {
        match self {
            BundleError::Malformed => "malformed",
            BundleError::Path => "path",
            BundleError::Duplicate => "duplicate",
            BundleError::Limit => "limit",
            BundleError::MemberDigest => "member-digest",
            BundleError::Extract => "extract",
        }
    }
}

/// An entry is not valid. No content is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryError;

/// The aggregates document could not be delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelError;

/// Layout adapter (Q9).
pub trait StageLayoutAdapter: Send + Sync {
    /// Status of this adapter.
    fn status(&self) -> ContractStatus;
    /// The directories of this run.
    fn layout(&self) -> WorkerLayout;
}

/// Bundle adapter (Q4): the only extractor of a staged archive.
pub trait BundleFormatAdapter: Send + Sync {
    /// Status of this adapter.
    fn status(&self) -> ContractStatus;
    /// Extract the bundle `bytes` into the new directory `dest` under the format's
    /// bounds. The launcher passes the very bytes whose digest it checked.
    fn extract(&self, bytes: &[u8], dest: &Path) -> Result<(), BundleError>;
}

/// Entry adapter (Q1): one entry is one authored case.
pub trait EntryFormatAdapter: Send + Sync {
    /// Status of this adapter.
    fn status(&self) -> ContractStatus;
    /// Decode the bytes of the entry named `name`.
    fn decode(&self, name: &str, bytes: &[u8]) -> Result<Case, EntryError>;
}

/// Aggregates channel adapter (Q2).
pub trait AggregatesChannelAdapter: Send + Sync {
    /// Status of this adapter.
    fn status(&self) -> ContractStatus;
    /// Hand the complete aggregates document to the custodian.
    fn deliver(&self, layout: &WorkerLayout, document: &[u8]) -> Result<(), ChannelError>;
}

/// Label adapter (Q3).
pub trait AggregateLabelsAdapter: Send + Sync {
    /// Status of this adapter.
    fn status(&self) -> ContractStatus;
    /// The stratum of the overall population.
    fn overall_stratum(&self) -> &str;
    /// The label of a `pii-v1` metric id, or `None` when the policy does not
    /// publish that metric (the metric is then left out of the aggregates).
    fn metric(&self, id: &str) -> Option<String>;
}

/// Which statuses a wiring may contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterPolicy {
    /// Only [`ContractStatus::Decided`] adapters. What the binary always uses.
    Production,
    /// Also [`ContractStatus::TestOnly`]. Exists only in test-adapter builds.
    #[cfg(feature = "worker-test-adapters")]
    AllowTestOnly,
}

impl AdapterPolicy {
    fn admits(self, status: ContractStatus) -> bool {
        match status {
            ContractStatus::Decided => true,
            ContractStatus::Proposed => false,
            ContractStatus::TestOnly => match self {
                AdapterPolicy::Production => false,
                #[cfg(feature = "worker-test-adapters")]
                AdapterPolicy::AllowTestOnly => true,
            },
        }
    }
}

/// The adapters of a wiring. A slot with no adapter is unconfigured.
#[derive(Default)]
pub struct Adapters {
    stage_layout: Option<Box<dyn StageLayoutAdapter>>,
    bundle_format: Option<Box<dyn BundleFormatAdapter>>,
    entry_format: Option<Box<dyn EntryFormatAdapter>>,
    aggregates_channel: Option<Box<dyn AggregatesChannelAdapter>>,
    aggregate_labels: Option<Box<dyn AggregateLabelsAdapter>>,
}

/// The adapters of a wiring that passed [`Adapters::resolve`].
pub struct Resolved<'a> {
    /// Layout.
    pub stage_layout: &'a dyn StageLayoutAdapter,
    /// Bundle format.
    pub bundle_format: &'a dyn BundleFormatAdapter,
    /// Entry format.
    pub entry_format: &'a dyn EntryFormatAdapter,
    /// Aggregates channel.
    pub aggregates_channel: &'a dyn AggregatesChannelAdapter,
    /// Labels.
    pub aggregate_labels: &'a dyn AggregateLabelsAdapter,
}

impl Adapters {
    /// The production wiring: every undecided slot is unconfigured, so a
    /// release binary refuses with `contract-not-final`.
    pub fn production() -> Self {
        Self::default()
    }

    /// Install a layout adapter.
    pub fn with_stage_layout(mut self, a: Box<dyn StageLayoutAdapter>) -> Self {
        self.stage_layout = Some(a);
        self
    }

    /// Install a bundle adapter.
    pub fn with_bundle_format(mut self, a: Box<dyn BundleFormatAdapter>) -> Self {
        self.bundle_format = Some(a);
        self
    }

    /// Install an entry adapter.
    pub fn with_entry_format(mut self, a: Box<dyn EntryFormatAdapter>) -> Self {
        self.entry_format = Some(a);
        self
    }

    /// Install a channel adapter.
    pub fn with_aggregates_channel(mut self, a: Box<dyn AggregatesChannelAdapter>) -> Self {
        self.aggregates_channel = Some(a);
        self
    }

    /// Install a label adapter.
    pub fn with_aggregate_labels(mut self, a: Box<dyn AggregateLabelsAdapter>) -> Self {
        self.aggregate_labels = Some(a);
        self
    }

    /// The status of the adapter in `slot`, or `None` when unconfigured.
    pub fn status(&self, slot: Slot) -> Option<ContractStatus> {
        match slot {
            Slot::StageLayout => self.stage_layout.as_ref().map(|a| a.status()),
            Slot::BundleFormat => self.bundle_format.as_ref().map(|a| a.status()),
            Slot::EntryFormat => self.entry_format.as_ref().map(|a| a.status()),
            Slot::AggregatesChannel => self.aggregates_channel.as_ref().map(|a| a.status()),
            Slot::AggregateLabels => self.aggregate_labels.as_ref().map(|a| a.status()),
        }
    }

    /// The first slot (in [`Slot::ALL`] order) that is unconfigured or whose
    /// adapter the policy does not admit.
    pub fn first_not_final(&self, policy: AdapterPolicy) -> Option<Slot> {
        Slot::ALL
            .into_iter()
            .find(|s| !self.status(*s).is_some_and(|st| policy.admits(st)))
    }

    /// Refuse (`contract-not-final: <slot>`, exit 6) unless every slot holds an
    /// adapter the policy admits. Nothing is read or touched before this.
    pub fn resolve(&self, policy: AdapterPolicy) -> Result<Resolved<'_>, Failure> {
        if let Some(slot) = self.first_not_final(policy) {
            return Err(
                Failure::new(Exit::Execution, reason::CONTRACT_NOT_FINAL).with_detail(slot.name())
            );
        }
        match (
            self.stage_layout.as_deref(),
            self.bundle_format.as_deref(),
            self.entry_format.as_deref(),
            self.aggregates_channel.as_deref(),
            self.aggregate_labels.as_deref(),
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e)) => Ok(Resolved {
                stage_layout: a,
                bundle_format: b,
                entry_format: c,
                aggregates_channel: d,
                aggregate_labels: e,
            }),
            _ => Err(Failure::new(
                Exit::Internal,
                crate::status::reason::INTERNAL,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_wiring_has_no_adapter_and_names_the_first_slot() {
        let a = Adapters::production();
        for slot in Slot::ALL {
            assert_eq!(a.status(slot), None);
            assert_eq!(slot.contract_status(), ContractStatus::Proposed);
        }
        assert_eq!(
            a.first_not_final(AdapterPolicy::Production),
            Some(Slot::StageLayout)
        );
        let Err(f) = a.resolve(AdapterPolicy::Production) else {
            panic!("production must refuse");
        };
        assert_eq!(
            (f.exit, f.reason),
            (Exit::Execution, reason::CONTRACT_NOT_FINAL)
        );
        assert_eq!(f.detail.as_deref(), Some("stage-layout"));
    }

    #[test]
    fn slot_names_and_questions_are_distinct() {
        let mut names: Vec<_> = Slot::ALL.iter().map(|s| s.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 5);
        let mut qs: Vec<_> = Slot::ALL.iter().map(|s| s.question()).collect();
        qs.sort_unstable();
        qs.dedup();
        assert_eq!(qs, ["Q1", "Q2", "Q3", "Q4", "Q9"]);
    }

    struct Proposed;
    impl StageLayoutAdapter for Proposed {
        fn status(&self) -> ContractStatus {
            ContractStatus::Proposed
        }
        fn layout(&self) -> WorkerLayout {
            unreachable!()
        }
    }

    #[test]
    fn a_proposed_adapter_is_never_admitted_even_when_installed() {
        let a = Adapters::production().with_stage_layout(Box::new(Proposed));
        assert_eq!(a.status(Slot::StageLayout), Some(ContractStatus::Proposed));
        assert_eq!(
            a.first_not_final(AdapterPolicy::Production),
            Some(Slot::StageLayout)
        );
    }
}
