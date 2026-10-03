//! The frozen registry must agree with the inventory in
//! `docs/migration/ownership-map.md`, which was taken from the pinned oracle.

use pii_eval_contracts::{METHODS, METRICS};

fn ownership_map() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/migration/ownership-map.md"
    ))
    .expect("ownership map")
}

fn cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|c| c.trim().trim_matches('`').to_owned())
        .collect()
}

#[test]
fn methods_match_the_inventory() {
    let doc = ownership_map();
    for m in METHODS {
        let id = m.id.as_str();
        let row = doc
            .lines()
            .find(|l| l.starts_with(&format!("| `{id}` |")))
            .unwrap_or_else(|| panic!("no inventory row for {id}"));
        assert_eq!(cells(row)[1], m.version.to_string(), "{id}");
    }
}

#[test]
fn metrics_match_the_inventory() {
    let doc = ownership_map();
    for m in METRICS {
        let id = m.id.as_str();
        let row = doc
            .lines()
            .find(|l| {
                l.starts_with(&format!("| `{id}` |")) && l.contains("scanner-source")
                    || l.starts_with(&format!("| `{id}` |")) && l.contains("all scanner")
            })
            .unwrap_or_else(|| panic!("no inventory row for {id}"));
        let c = cells(row);
        let direction = serde_json::to_value(m.direction).unwrap();
        let applicability = serde_json::to_value(m.applicability).unwrap();
        assert_eq!(c[1], direction.as_str().unwrap(), "{id} direction");
        assert_eq!(c[2], applicability.as_str().unwrap(), "{id} applicability");
        // Labels are verbatim, apart from the multiplication sign the map renders as an ASCII x.
        assert_eq!(
            c[3].replace('×', "x"),
            m.population.replace('×', "x"),
            "{id} population"
        );
        assert_eq!(c[4], m.numerator, "{id} numerator");
        assert_eq!(c[5], m.denominator, "{id} denominator");
    }
}
