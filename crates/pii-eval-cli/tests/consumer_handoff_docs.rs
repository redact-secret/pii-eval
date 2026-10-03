//! The consumer example and the handoff documents state what the repository
//! actually has (P12): the example's hard-coded format constants equal the
//! engine's, its documented reason codes equal the program's, and the handoff
//! names the current identities. No Node needed (the example's source is read as
//! text).

use std::collections::BTreeSet;
use std::path::PathBuf;

use pii_eval_contracts::{
    DIGEST_CONSTRUCTION, DocumentKind, ENGINE_VERSION, METRICS, ProtocolIdentity, SCHEMA_MAJOR,
    SCHEMA_MINOR,
};

fn read(path: &str) -> String {
    let root = std::fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .expect("repository root");
    std::fs::read_to_string(root.join(path)).unwrap_or_else(|_| panic!("missing {path}"))
}

fn const_string(source: &str, name: &str) -> String {
    let marker = format!("export const {name} = \"");
    let start = source.find(&marker).unwrap_or_else(|| panic!("{name}")) + marker.len();
    source[start..].split('"').next().unwrap().to_owned()
}

/// The quoted strings of `export const NAME = [ ... ];`.
fn string_list<'a>(source: &'a str, name: &str) -> BTreeSet<&'a str> {
    let marker = format!("export const {name} = [");
    source
        .split(&marker)
        .nth(1)
        .unwrap_or_else(|| panic!("{name}"))
        .split("];")
        .next()
        .unwrap()
        .split('"')
        .skip(1)
        .step_by(2)
        .collect()
}

#[test]
fn the_consumers_format_constants_equal_the_engines() {
    let src = read("examples/consumer/consume.mjs");
    assert_eq!(
        const_string(&src, "DIGEST_CONSTRUCTION"),
        DIGEST_CONSTRUCTION
    );
    assert_eq!(
        const_string(&src, "PUBLIC_SCHEMA"),
        DocumentKind::PublicSyntheticArtifact.schema_id()
    );
    assert_eq!(
        const_string(&src, "INTERNAL_SCHEMA"),
        DocumentKind::RunArtifact.schema_id()
    );
    assert!(src.contains("export const MAX_DOCUMENT_BYTES = 32 * 1024 * 1024;"));
    // The ten metric ids of the frozen protocol.
    let in_consumer = string_list(&src, "METRIC_IDS");
    let in_engine: BTreeSet<&str> = METRICS.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(in_consumer, in_engine);
    assert_eq!(in_engine.len(), 10);
}

#[test]
fn the_documented_reason_codes_are_exactly_the_programs() {
    // The program's own list (a Node test checks that list against every code its
    // source can emit); here the README must equal it.
    let src = read("examples/consumer/consume.mjs");
    let in_code = string_list(&src, "REASON_CODES");
    assert!(in_code.len() > 25);
    let readme = read("examples/consumer/README.md");
    let section = readme
        .split("## Reason codes")
        .nth(1)
        .unwrap()
        .trim_start()
        // The list is the first paragraph; later paragraphs explain some codes.
        .split("\n\n")
        .next()
        .unwrap();
    let documented: BTreeSet<&str> = section.split('`').skip(1).step_by(2).collect();
    assert_eq!(documented, in_code);
}

#[test]
fn the_handoff_names_the_current_artifact_identities() {
    let doc = read("docs/migration/consumer-handoff-665-666.md");
    let protocol = ProtocolIdentity::CANONICAL_V2;
    let rules = protocol.rules.expect("revision 2 has rules");
    let needed = [
        DocumentKind::PublicSyntheticArtifact.schema_id().to_owned(),
        DocumentKind::RunArtifact.schema_id().to_owned(),
        format!("{SCHEMA_MAJOR}.{SCHEMA_MINOR}"),
        DIGEST_CONSTRUCTION.to_owned(),
        format!("`{ENGINE_VERSION}`"),
        format!("`pii-v1` revision {}", protocol.version),
        rules.matching.id.as_str().to_owned(),
        rules.accounting.id.as_str().to_owned(),
        rules.statistics.id.as_str().to_owned(),
        "pii-eval-job-context/1".to_owned(),
        "pii-eval-summary/1".to_owned(),
        "pii-eval-consumer-pins/1".to_owned(),
    ];
    for item in needed {
        assert!(doc.contains(&item), "the handoff lacks `{item}`");
    }
}
