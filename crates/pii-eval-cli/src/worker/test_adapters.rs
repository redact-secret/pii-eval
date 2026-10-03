//! TEST-ONLY adapters for every undecided slot. This module exists only in
//! builds with the cargo feature `worker-test-adapters`; the default build, and
//! the engine artifact CI publishes, do not contain it (a test and a CI step
//! check for [`MARKER`]). No flag, environment variable or configuration field
//! selects these adapters: tests install them through the Rust API.
//!
//! They delegate to the format codecs of this crate (`bundle`, `entry`) and
//! report [`ContractStatus::TestOnly`], which the production policy refuses.

use std::path::Path;

use pii_eval_contracts::Case;

use crate::worker::bundle;
use crate::worker::contract::{
    AdapterPolicy, Adapters, AggregateLabelsAdapter, AggregatesChannelAdapter, BundleError,
    BundleFormatAdapter, ChannelError, ContractStatus, EntryError, EntryFormatAdapter,
    StageLayoutAdapter, WorkerLayout,
};
use crate::worker::entry;

/// A string present in a binary only when these adapters are compiled in.
pub const MARKER: &str = "pii-eval-worker-test-adapters";

/// The feature name, as `--version` prints it. Derived from [`MARKER`] so the
/// marker is always linked into a build that says it has the feature.
pub fn feature_name() -> &'static str {
    MARKER.strip_prefix("pii-eval-").unwrap_or(MARKER)
}

/// Fixed directories of one test run.
pub struct TestLayout(pub WorkerLayout);

impl StageLayoutAdapter for TestLayout {
    fn status(&self) -> ContractStatus {
        ContractStatus::TestOnly
    }
    fn layout(&self) -> WorkerLayout {
        self.0.clone()
    }
}

/// `pii-eval-bundle/1`.
pub struct TestBundle;

impl BundleFormatAdapter for TestBundle {
    fn status(&self) -> ContractStatus {
        ContractStatus::TestOnly
    }
    fn extract(&self, archive: &Path, dest: &Path) -> Result<(), BundleError> {
        bundle::extract(archive, dest)
    }
}

/// `pii-eval-worker-entry/1`.
pub struct TestEntry;

impl EntryFormatAdapter for TestEntry {
    fn status(&self) -> ContractStatus {
        ContractStatus::TestOnly
    }
    fn decode(&self, name: &str, bytes: &[u8]) -> Result<Case, EntryError> {
        entry::decode(name, bytes)
    }
}

/// A file channel: the aggregates document is written, once, to
/// `<scratch>/aggregates.json`.
pub struct FileChannel {
    /// Refuse every delivery (for the failure test).
    pub fail: bool,
}

/// Name of the channel file under the scratch directory.
pub const CHANNEL_FILE: &str = "aggregates.json";

impl AggregatesChannelAdapter for FileChannel {
    fn status(&self) -> ContractStatus {
        ContractStatus::TestOnly
    }
    fn deliver(&self, layout: &WorkerLayout, document: &[u8]) -> Result<(), ChannelError> {
        use std::io::Write;
        if self.fail {
            return Err(ChannelError);
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options
            .open(layout.scratch.join(CHANNEL_FILE))
            .map_err(|_| ChannelError)?;
        file.write_all(document).map_err(|_| ChannelError)
    }
}

/// The metric the test labels leave out: its unit is the axis assertion, so on
/// a roster counted in entries (one case each) its denominator can exceed
/// `observed` and the launcher would refuse the whole document (see
/// `worker::aggregates`). Whether a policy publishes it is the custodian's
/// decision (Q3).
pub const UNPUBLISHED_METRIC: &str = "measurable-share";

/// Stratum `overall` and the metric ids as they are, except
/// [`UNPUBLISHED_METRIC`].
pub struct TestLabels;

impl AggregateLabelsAdapter for TestLabels {
    fn status(&self) -> ContractStatus {
        ContractStatus::TestOnly
    }
    fn overall_stratum(&self) -> &str {
        "overall"
    }
    fn metric(&self, id: &str) -> Option<String> {
        (id != UNPUBLISHED_METRIC).then(|| id.to_owned())
    }
}

/// Stratum `overall` and ALL ten metric ids: the proposal of
/// docs/custodian-contract-status.md Q3, which the launcher refuses on a
/// population where `measurable-share` exceeds the roster.
pub struct AllMetricLabels;

impl AggregateLabelsAdapter for AllMetricLabels {
    fn status(&self) -> ContractStatus {
        ContractStatus::TestOnly
    }
    fn overall_stratum(&self) -> &str {
        "overall"
    }
    fn metric(&self, id: &str) -> Option<String> {
        Some(id.to_owned())
    }
}

/// A complete test wiring over `layout`.
pub fn adapters(layout: WorkerLayout) -> Adapters {
    Adapters::production()
        .with_stage_layout(Box::new(TestLayout(layout)))
        .with_bundle_format(Box::new(TestBundle))
        .with_entry_format(Box::new(TestEntry))
        .with_aggregates_channel(Box::new(FileChannel { fail: false }))
        .with_aggregate_labels(Box::new(TestLabels))
}

/// The policy that admits these adapters.
pub const POLICY: AdapterPolicy = AdapterPolicy::AllowTestOnly;
