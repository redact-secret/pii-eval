//! The hand-written parity documents state the identities and numbers the
//! repository currently has (P9, ADR 0012), so they cannot go stale silently.

mod parity;

use parity::compare::{Class, compare};
use parity::json::*;
use parity::model::*;
use pii_eval_adapters::redact_secret::{
    ADAPTER_ID, ADAPTER_VERSION, NPM_INTEGRITY, RELEASED_PACKAGE_TREE_SHA256, SHIM_SHA256,
};
use pii_eval_contracts::Sha256Digest;

fn read_repo(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path)).unwrap_or_else(|_| panic!("missing {path}"))
}

fn sha(path: &str) -> String {
    Sha256Digest::of_bytes(&read_repo(path)).as_str().to_owned()
}

fn doc(path: &str) -> String {
    String::from_utf8(read_repo(path)).unwrap()
}

#[test]
fn the_handoff_names_the_current_identities() {
    let ds = Dataset::load();
    let spec: serde_json::Value =
        serde_json::from_slice(&read_repo("tools/oracle-parity/oracle-files.json")).unwrap();
    let handoff = doc("docs/migration/benchmarks-handoff-664.md");
    let node = text(get(get(&ds.export, "provenance"), "runtime"), "node").to_owned();
    let needed = [
        text(&spec, "pin").to_owned(),
        text(&spec, "treeDigest").to_owned(),
        sha("fixtures/oracle-parity/input.json"),
        sha("fixtures/oracle-parity/oracle-export.json"),
        sha("fixtures/oracle-parity/real-core-export.json"),
        sha("Cargo.lock"),
        sha("rust-toolchain.toml"),
        "`1.98.1`".to_owned(),
        "MSRV `1.85`".to_owned(),
        NPM_INTEGRITY.to_owned(),
        RELEASED_PACKAGE_TREE_SHA256.to_owned(),
        SHIM_SHA256.to_owned(),
        ADAPTER_ID.to_owned(),
        format!("`{ADAPTER_VERSION}`"),
        pii_eval_kernel::MATCHING_RULE_ID.to_owned(),
        pii_eval_kernel::ACCOUNTING_RULE_ID.to_owned(),
        pii_eval_kernel::STATS_RULE_ID.to_owned(),
        pii_eval_compat::legacy::LEGACY_RULE_ID.to_owned(),
        pii_eval_compat::legacy_accounting::LEGACY_ACCOUNTING_RULE_ID.to_owned(),
        node,
    ];
    for item in needed {
        assert!(handoff.contains(&item), "the handoff does not state {item}");
    }
    // The compared counts the handoff quotes are the comparator's.
    let cmp = compare(&ds);
    for (layer, n) in [
        ("outcome-compat", "540"),
        ("accounting-compat", "181"),
        ("statistics-compat", "660"),
    ] {
        assert_eq!(cmp.compared[layer].to_string(), n, "{layer}");
        assert!(handoff.contains(n), "{layer}");
    }
}

#[test]
fn adr_0012_quotes_the_report_census() {
    let ds = Dataset::load();
    let cmp = compare(&ds);
    let adr = doc("docs/adr/0012-oracle-parity-and-migration-evidence.md");
    let count = |c: Class| cmp.differences.iter().filter(|d| d.class() == c).count();
    let census = format!(
        "{} intended versioned revision, {} old bug, {} compatibility",
        count(Class::IntendedRevision),
        count(Class::OldBug),
        count(Class::Compatibility)
    );
    assert!(
        adr.contains(&census),
        "ADR 0012 quotes another census than the report: {census}"
    );
    let variants: u64 = list(&ds.export, "cases")
        .iter()
        .map(|c| list(c, "variants").len() as u64)
        .sum();
    assert!(adr.contains(&format!("over {variants} variants")));
    assert!(adr.contains(&format!("{variants} variants")));
    assert_eq!(count(Class::Unexplained), 0);
}
