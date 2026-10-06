//! Reference adoption of private-custodian issue 37; no test adapter selection.
use super::contract::*;
use super::{bundle, entry};
use pii_eval_contracts::Case;
use std::path::Path;

pub const METRICS: [&str; 9] = [
    "type-miss-rate",
    "wrong-family-rate",
    "wrong-jurisdiction-rate",
    "sensitive-miss-rate",
    "non-sensitive-flag-rate",
    "context-discrimination-rate",
    "benign-suppression-rate",
    "jurisdiction-collision-rate",
    "range-collateral-rate",
];
struct Layout;
impl StageLayoutAdapter for Layout {
    fn status(&self) -> ContractStatus {
        ContractStatus::Decided
    }
    fn layout(&self) -> WorkerLayout {
        WorkerLayout {
            stage: "/stage".into(),
            input: "/input".into(),
            scratch: "/scratch".into(),
        }
    }
}
struct Bundle;
impl BundleFormatAdapter for Bundle {
    fn status(&self) -> ContractStatus {
        ContractStatus::Decided
    }
    fn extract(&self, bytes: &[u8], dest: &Path) -> Result<(), BundleError> {
        bundle::extract_bytes(bytes, dest)
    }
}
struct Entry;
impl EntryFormatAdapter for Entry {
    fn status(&self) -> ContractStatus {
        ContractStatus::Decided
    }
    fn decode(&self, name: &str, bytes: &[u8]) -> Result<Case, EntryError> {
        entry::decode(name, bytes)
    }
}
// Delivery is exclusively render_result_with_aggregates in launch.rs. No file or stderr channel.
struct Embedded;
impl AggregatesChannelAdapter for Embedded {
    fn status(&self) -> ContractStatus {
        ContractStatus::Decided
    }
    fn deliver(&self, _: &WorkerLayout, _: &[u8]) -> Result<(), ChannelError> {
        Ok(())
    }
}
struct Labels;
impl AggregateLabelsAdapter for Labels {
    fn status(&self) -> ContractStatus {
        ContractStatus::Decided
    }
    fn overall_stratum(&self) -> &str {
        "overall"
    }
    fn metric(&self, id: &str) -> Option<String> {
        METRICS.contains(&id).then(|| id.to_owned())
    }
}
pub fn adapters() -> Adapters {
    Adapters::default()
        .with_stage_layout(Box::new(Layout))
        .with_bundle_format(Box::new(Bundle))
        .with_entry_format(Box::new(Entry))
        .with_aggregates_channel(Box::new(Embedded))
        .with_aggregate_labels(Box::new(Labels))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_resolves_and_labels_are_closed() {
        let a = adapters();
        let r = a.resolve(AdapterPolicy::Production).unwrap();
        assert_eq!(r.stage_layout.layout().stage, Path::new("/stage"));
        for m in METRICS {
            assert_eq!(r.aggregate_labels.metric(m).as_deref(), Some(m));
        }
        assert_eq!(r.aggregate_labels.metric("measurable-share"), None);
        assert_eq!(r.aggregate_labels.metric("unknown-metric"), None);
    }
}
