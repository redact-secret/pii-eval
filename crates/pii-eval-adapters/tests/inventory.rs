//! The adapter inventory matches the ownership map's legacy scanner list, and
//! only the scanner with a PII scoring path in the oracle has an adapter.

use pii_eval_adapters::inventory::{Disposition, INVENTORY};
use pii_eval_adapters::redact_secret::{ADAPTER_ID, PINNED_VERSION};

fn map_rows() -> Vec<String> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/migration/ownership-map.md");
    std::fs::read_to_string(path)
        .expect("ownership map")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn inventory_matches_the_ownership_map_scanner_list() {
    let rows = map_rows();
    // (row marker in the map's scanner table, version token, inventory name)
    let expected = [
        ("| `redact-secret`", "`0.1.0-beta.12`", "redact-secret"),
        ("| `flare-redact`", "`1.6.1`", "flare-redact"),
        ("| `@openredaction/core`", "`1.1.5`", "openredaction"),
        ("| `gitleaks`", "`8.30.1`", "gitleaks"),
        ("| `trufflehog`", "`3.97.4`", "trufflehog"),
    ];
    assert_eq!(INVENTORY.len(), expected.len());
    for (entry, (marker, version, name)) in INVENTORY.iter().zip(expected) {
        let row = rows
            .iter()
            .find(|r| r.starts_with(marker))
            .unwrap_or_else(|| panic!("no map row for {name}"));
        assert!(
            row.contains(version),
            "{name}: version {version} not in its map row"
        );
        assert_eq!(entry.scanner, name);
        assert!(
            entry.pin.ends_with(version.trim_matches('`')),
            "{name}: inventory pin {} differs from the map",
            entry.pin
        );
    }
    assert!(PINNED_VERSION == "0.1.0-beta.12");
}

#[test]
fn exactly_one_legacy_scanner_has_a_pii_observation_adapter() {
    let adapters: Vec<_> = INVENTORY
        .iter()
        .filter_map(|e| match e.disposition {
            Disposition::PiiObservation { adapter_id } => Some((e.scanner, adapter_id)),
            Disposition::OutOfScope { .. } => None,
        })
        .collect();
    assert_eq!(adapters, [("redact-secret", ADAPTER_ID)]);
    for entry in &INVENTORY {
        if let Disposition::OutOfScope { reason } = entry.disposition {
            assert!(
                reason.len() > 40,
                "{}: the reason must say why",
                entry.scanner
            );
        }
    }
}
