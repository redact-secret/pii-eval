//! The deterministic parity report: machine-readable JSON
//! (`fixtures/oracle-parity/report.json`) and the human-readable Markdown
//! (`docs/migration/oracle-parity-report.md`), both generated from one
//! [`Comparison`]. No timestamps, host paths or scanner values: only synthetic
//! case ids, enumerated states and integers.
#![allow(dead_code)]

use std::collections::BTreeMap;

use pii_eval_compat::legacy::{LEGACY_PROTOCOL_REVISION, LEGACY_RULE_ID};
use pii_eval_compat::legacy_accounting::LEGACY_ACCOUNTING_RULE_ID;
use pii_eval_contracts::{
    ENGINE_VERSION, METHODS, METRICS, PROTOCOL_ID, ProtocolIdentity, Sha256Digest,
};
use pii_eval_kernel::{
    ACCOUNTING_PROTOCOL_REVISION, ACCOUNTING_RULE_ID, MATCHING_PROTOCOL_REVISION, MATCHING_RULE_ID,
    STATS_REVISION, STATS_RULE_ID,
};
use serde_json::{Map, Value, json};

use super::compare::{Class, Comparison, EXPLANATIONS, class_of, view_of_oracle};
use super::json::*;
use super::model::Dataset;

pub const REPORT_SCHEMA: &str = "pii-eval-parity-report/1";

/// What this corpus cannot exercise or does not compare, with the reason and the
/// place that covers it. Open items are listed, never hidden.
pub const NOT_COMPARED: &[(&str, &str)] = &[
    (
        "0004/D2",
        "A stored ObservationSet carries findings in canonical order, so legacy over a stored set can pick another first finding than the oracle did. The parity corpus feeds the legacy mode the emission order the oracle saw; replay of stored sets for a legacy comparison needs the emission order carried (open item for benchmarks #664).",
    ),
    (
        "0004/D4, D5, D11",
        "Capability-aware differences need a scanner that declares less than full support. The parity scanners declare every capability the legacy protocol assumes, so these are covered by crates/pii-eval-compat/tests/differences.rs and crates/pii-eval-kernel/tests/conformance.rs, not by the oracle export.",
    ),
    (
        "0005/A5, A7",
        "The oracle's evidence, benignByControlClass, evidenceByClass, contextByLanguage and contextRoster projections are not carried by schema 1.x and are not compared; the ten metrics, their counts, effective N, statuses, intervals and withheld states are.",
    ),
    (
        "0005/A9",
        "Equal by construction (case jurisdiction is the oracle's scope); covered by crates/pii-eval-compat/tests/accounting_oracle.rs.",
    ),
    (
        "0007/D2, D3, D5-D9",
        "Method refusals, unknown validators and references, seeds under pii-seed-v1 and the evidence-corpus checks are covered by crates/pii-eval-kernel/tests/methods_oracle.rs; the parity corpus carries no evidence entry and uses the legacy seed rule.",
    ),
    (
        "population identity",
        "The oracle accounting carries no population identity beyond sourceCaseCount and rowCount (and an unresolved input commitment); only those counts are compared. The Rust population binding (id, version, visibility, semantic digest) is verified by the engine end-to-end check.",
    ),
    (
        "action axis",
        "The oracle has no action axis (ADR 0004 D7); it is not compared.",
    ),
    (
        "protected corpora",
        "No protected corpus was run. Protected parity is only through approved receipts under the custodian contract (private-custodian), out of scope here.",
    ),
    (
        "real scanner",
        "The live Rust run over the real package is opt-in and not part of CI (it needs the registry and a platform addon); its committed synthetic observation is compared in CI (section above). One platform (the export's) and one pinned version were observed.",
    ),
];

fn class_counts(cmp: &Comparison) -> BTreeMap<&'static str, u64> {
    let mut m: BTreeMap<&'static str, u64> = BTreeMap::new();
    for c in [
        Class::IntendedRevision,
        Class::OldBug,
        Class::NewBug,
        Class::Compatibility,
        Class::Unresolved,
        Class::Unexplained,
    ] {
        m.insert(c.as_str(), 0);
    }
    for d in &cmp.differences {
        *m.entry(d.class().as_str()).or_default() += 1;
    }
    m
}

pub fn build(ds: &Dataset, cmp: &Comparison, real: Option<(&Dataset, &Comparison)>) -> Value {
    let provenance = get(&ds.export, "provenance");
    let oracle = get(provenance, "oracle");
    let runtime = get(provenance, "runtime");
    let export_digest = Sha256Digest::of_bytes(&ds.export_bytes);
    let input_digest = Sha256Digest::of_bytes(&ds.input_bytes);

    let mut aggregated: BTreeMap<(String, String, String), (u64, Vec<Value>, Vec<&'static str>)> =
        BTreeMap::new();
    for d in &cmp.differences {
        let key = (d.layer.to_owned(), d.ids.join("+"), d.aspect.clone());
        let e = aggregated
            .entry(key)
            .or_insert((0, Vec::new(), d.ids.clone()));
        e.0 += 1;
        if e.1.len() < 2 {
            e.1.push(json!({
                "scanner": d.scanner,
                "subject": d.subject,
                "oracle": d.oracle,
                "rust": d.rust,
            }));
        }
    }
    let differences: Vec<Value> = aggregated
        .into_iter()
        .map(|((layer, ids, aspect), (count, examples, id_list))| {
            let class = id_list
                .iter()
                .map(|i| class_of(i))
                .min()
                .unwrap_or(Class::Unexplained);
            json!({
                "layer": layer,
                "aspect": aspect,
                "ids": id_list,
                "idsKey": ids,
                "class": class.as_str(),
                "count": count,
                "examples": examples,
            })
        })
        .collect();

    let mut census_by_id = Map::new();
    let exercised = cmp.ids_exercised();
    for (id, class, what) in EXPLANATIONS {
        census_by_id.insert(
            (*id).to_owned(),
            json!({
                "class": class.as_str(),
                "what": what,
                "differences": exercised.get(id).copied().unwrap_or(0),
            }),
        );
    }

    let layers: Vec<Value> = cmp
        .compared
        .iter()
        .map(|(layer, compared)| {
            let diffs: Vec<_> = cmp
                .differences
                .iter()
                .filter(|d| d.layer == *layer)
                .collect();
            let mut by_class: BTreeMap<&str, u64> = BTreeMap::new();
            for d in &diffs {
                *by_class.entry(d.class().as_str()).or_default() += 1;
            }
            json!({
                "layer": layer,
                "compared": compared,
                "differences": diffs.len(),
                "byClass": by_class,
            })
        })
        .collect();

    let canonical = ProtocolIdentity::CANONICAL_V2;
    let _ = canonical;
    json!({
        "schema": REPORT_SCHEMA,
        "mode": "same-observation (identical frozen observations fed to the oracle and to the Rust engine)",
        "identities": {
            "oracle": {
                "repository": text(oracle, "repository"),
                "commit": text(oracle, "commit"),
                "filesTreeDigest": text(oracle, "filesTreeDigest"),
                "engineVersion": text(oracle, "engineVersion"),
                "node": text(runtime, "node"),
                "icu": text(runtime, "icu"),
                "adaptations": get(provenance, "adaptations"),
            },
            "engine": {
                "name": "pii-eval",
                "version": ENGINE_VERSION,
                "protocol": PROTOCOL_ID.to_owned() + "",
            },
            "compatibilityProtocol": {
                "revision": LEGACY_PROTOCOL_REVISION,
                "matching": LEGACY_RULE_ID,
                "accounting": LEGACY_ACCOUNTING_RULE_ID,
            },
            "canonicalProtocol": {
                "revision": MATCHING_PROTOCOL_REVISION,
                "matching": MATCHING_RULE_ID,
                "accounting": ACCOUNTING_RULE_ID,
                "accountingRevision": ACCOUNTING_PROTOCOL_REVISION,
                "statistics": STATS_RULE_ID,
                "statisticsRevision": STATS_REVISION,
            },
            "methods": METHODS.iter().map(|m| json!({"id": m.id.as_str(), "version": m.version})).collect::<Vec<_>>(),
            "metrics": METRICS.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            "inputSha256": input_digest.as_str(),
            "oracleExportSha256": export_digest.as_str(),
            "scriptDigests": get(provenance, "scripts"),
        },
        "population": {
            "id": text(get(&ds.input, "population"), "id"),
            "version": uint(get(&ds.input, "population"), "version"),
            "visibility": text(get(&ds.input, "population"), "visibility"),
            "cases": list(&ds.input, "cases").len(),
            "variants": cmp.compared.get("variant").copied().unwrap_or(0),
            "scanners": cmp.scanners.len(),
            "accountingVectors": cmp.vectors.len(),
        },
        "compared": cmp.compared,
        "layers": layers,
        "census": {
            "byClass": class_counts(cmp),
            "byId": census_by_id,
            "unexplained": cmp.unexplained().len(),
            "compatibilityLayerDifferences": cmp.compat_differences().len(),
        },
        "scanners": cmp.scanners.iter().map(|s| json!({
            "id": s.id,
            "oracleStatus": s.status,
            "variants": s.variants,
            "canonicalRefusedVariants": s.canonical_refused,
            "canonicalAccounted": s.canonical_accounted,
        })).collect::<Vec<_>>(),
        "vectors": cmp.vectors.iter().map(|v| json!({
            "id": v.id,
            "oracleThrows": v.oracle_throws,
            "metricsDifferingInTheAccountingRule": v.metrics_differing,
        })).collect::<Vec<_>>(),
        "differences": differences,
        "notCompared": NOT_COMPARED.iter().map(|(k, v)| json!({"item": k, "reason": v})).collect::<Vec<_>>(),
        "realScanner": real.map_or(Value::Null, |(rds, rcmp)| real_section(rds, rcmp)),
    })
}

const REAL_ID: &str = "redact-secret-core";

fn real_section(ds: &Dataset, cmp: &Comparison) -> Value {
    let provenance = Dataset::real_provenance();
    let export = &list(&ds.export, "scanners")[0];
    let observed: usize = list(export, "returned")
        .iter()
        .map(|r| list(r, "findings").len())
        .sum();
    let with_findings = list(export, "returned")
        .iter()
        .filter(|r| !list(r, "findings").is_empty())
        .count();
    let mut by_layer: BTreeMap<String, BTreeMap<&str, u64>> = BTreeMap::new();
    for d in cmp.differences.iter().filter(|d| d.scanner == REAL_ID) {
        *by_layer
            .entry(d.layer.to_owned())
            .or_default()
            .entry(d.class().as_str())
            .or_default() += 1;
    }
    let oracle_metrics = get(get(export, "accounting"), "metrics");
    let canonical = &cmp.canonical[REAL_ID];
    let metrics: Vec<Value> = canonical
        .iter()
        .map(|(m, view)| {
            let name = word(m);
            let oracle = view_of_oracle(get(oracle_metrics, &name), 6).expect("oracle metric");
            let ids: Vec<&str> = cmp
                .differences
                .iter()
                .filter(|d| {
                    d.layer == "accounting-canonical" && d.scanner == REAL_ID && d.aspect == name
                })
                .flat_map(|d| d.ids.iter().copied())
                .collect();
            json!({
                "metric": name,
                "oracle": oracle.describe(),
                "rust": view.describe(),
                "equal": oracle == *view,
                "ids": ids,
            })
        })
        .collect();
    json!({
        "package": text(&provenance, "package"),
        "version": text(&provenance, "version"),
        "platform": text(&provenance, "platform"),
        "lockSha256": text(&provenance, "lockSha256"),
        "packages": get(&provenance, "packages"),
        "adapter": text(&provenance, "adapter"),
        "install": text(&provenance, "install"),
        "selectors": get(&provenance, "selectors"),
        "variants": list(export, "returned").len(),
        "observedFindings": observed,
        "variantsWithFindings": with_findings,
        "differencesByLayer": by_layer,
        "unexplained": cmp.differences.iter().filter(|d| d.scanner == REAL_ID && d.class() == Class::Unexplained).count(),
        "metrics": metrics,
    })
}

pub fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("report serializes");
    s.push('\n');
    s
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
}

/// The Markdown rendering of the report JSON.
pub fn markdown(r: &Value) -> String {
    let mut o = String::new();
    let ident = get(r, "identities");
    let oracle = get(ident, "oracle");
    let canon = get(ident, "canonicalProtocol");
    let compat = get(ident, "compatibilityProtocol");
    o.push_str("# Oracle parity report (P9)\n\n");
    o.push_str("<!-- Generated by `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test oracle_parity` from `fixtures/oracle-parity/report.json`. Do not edit by hand. -->\n\n");
    o.push_str("Status: generated, deterministic, synthetic only. It states what was compared and how every difference was classified; it is measurement evidence, not a qualification, a support decision or a cutover decision. See [ADR 0012](../adr/0012-oracle-parity-and-migration-evidence.md) for the method and the classification rules and [the handoff for benchmarks #664](benchmarks-handoff-664.md) for how to consume it.\n\n");
    let census = get(r, "census");
    let by_class = get(census, "byClass");
    o.push_str("## Result\n\n");
    o.push_str(&format!(
        "- Unexplained differences: **{}**. Differences in the compatibility layers (which promise equality): **{}**.\n",
        uint(census, "unexplained"),
        uint(census, "compatibilityLayerDifferences")
    ));
    o.push_str("- Mode: identical frozen observations fed to the pinned oracle's own code and to the Rust engine (same-observation parity). It is not a real-scanner run and not a protected run.\n");
    o.push_str("- The compatibility protocol (`pii-v1` revision 1, legacy matching and legacy accounting) reproduces the oracle's outcomes, ten metrics, counts, effective N, statuses, withheld states and intervals exactly; every difference of the canonical revision 2 is classified below.\n\n");
    o.push_str("## Pinned identities\n\n| Item | Value |\n| --- | --- |\n");
    let row =
        |o: &mut String, k: &str, v: String| o.push_str(&format!("| {k} | {} |\n", md_escape(&v)));
    row(
        &mut o,
        "Oracle repository",
        format!("`{}`", text(oracle, "repository")),
    );
    row(
        &mut o,
        "Oracle commit",
        format!("`{}`", text(oracle, "commit")),
    );
    row(
        &mut o,
        "Oracle files tree digest",
        format!("`{}`", text(oracle, "filesTreeDigest")),
    );
    row(
        &mut o,
        "Oracle engine version",
        format!("`{}`", text(oracle, "engineVersion")),
    );
    row(
        &mut o,
        "Node / ICU of the export",
        format!("`{}` / `{}`", text(oracle, "node"), text(oracle, "icu")),
    );
    row(
        &mut o,
        "pii-eval engine",
        format!(
            "`{}` ({})",
            text(get(ident, "engine"), "version"),
            text(get(ident, "engine"), "name")
        ),
    );
    row(
        &mut o,
        "Compatibility protocol",
        format!(
            "`pii-v1` revision {}: matching `{}`, accounting `{}`",
            uint(compat, "revision"),
            text(compat, "matching"),
            text(compat, "accounting")
        ),
    );
    row(
        &mut o,
        "Canonical protocol",
        format!(
            "`pii-v1` revision {}: matching `{}`, accounting `{}` revision {}, statistics `{}` revision {}",
            uint(canon, "revision"),
            text(canon, "matching"),
            text(canon, "accounting"),
            uint(canon, "accountingRevision"),
            text(canon, "statistics"),
            uint(canon, "statisticsRevision")
        ),
    );
    row(
        &mut o,
        "Methods",
        list(ident, "methods")
            .iter()
            .map(|m| format!("`{}` v{}", text(m, "id"), uint(m, "version")))
            .collect::<Vec<_>>()
            .join(", "),
    );
    row(
        &mut o,
        "Metrics",
        list(ident, "metrics")
            .iter()
            .map(|m| format!("`{}`", m.as_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join(", "),
    );
    row(
        &mut o,
        "Parity input SHA-256",
        format!("`{}`", text(ident, "inputSha256")),
    );
    row(
        &mut o,
        "Oracle export SHA-256",
        format!("`{}`", text(ident, "oracleExportSha256")),
    );
    row(&mut o, "Population", {
        let p = get(r, "population");
        format!(
            "`{}` v{} ({}): {} authored cases, {} variants, {} scanners, {} accounting vectors",
            text(p, "id"),
            uint(p, "version"),
            text(p, "visibility"),
            uint(p, "cases"),
            uint(p, "variants"),
            uint(p, "scanners"),
            uint(p, "accountingVectors")
        )
    });
    o.push_str("\nOracle-side adaptations (loading only, no oracle logic): ");
    o.push_str(
        &list(oracle, "adaptations")
            .iter()
            .map(|a| a.as_str().unwrap_or("").to_owned())
            .collect::<Vec<_>>()
            .join("; "),
    );
    o.push_str(".\n\n");

    o.push_str("## What was compared\n\n| Layer | Compared | Differences | By class |\n| --- | ---: | ---: | --- |\n");
    for l in list(r, "layers") {
        let classes = get(l, "byClass")
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| format!("{k}: {}", v.as_u64().unwrap_or(0)))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        o.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            text(l, "layer"),
            uint(l, "compared"),
            uint(l, "differences"),
            if classes.is_empty() {
                "-".to_owned()
            } else {
                classes
            }
        ));
    }
    o.push_str("\nLayers: `variant` (the seven methods: generated variants), `outcome-compat` (oracle outcomes against the legacy mode), `outcome` (legacy against the canonical matcher), `accounting-compat` (oracle metrics against the legacy accounting), `accounting-rule` (oracle against the kernel accounting on the same rows), `accounting-canonical` (the full canonical path), `statistics-compat` and `statistics` (Wilson interval grid), `population` (case and row counts). A compared item is one outcome row, one metric of one scanner or vector, one variant, or one numerator/denominator pair.\n\n");

    o.push_str("## Difference census by class\n\n| Class | Differences |\n| --- | ---: |\n");
    if let Some(m) = by_class.as_object() {
        for (k, v) in m {
            o.push_str(&format!("| {k} | {} |\n", v.as_u64().unwrap_or(0)));
        }
    }
    o.push_str("\n| Id | Class | Differences | What |\n| --- | --- | ---: | --- |\n");
    if let Some(m) = get(census, "byId").as_object() {
        for (id, v) in m {
            o.push_str(&format!(
                "| `{id}` | {} | {} | {} |\n",
                text(v, "class"),
                uint(v, "differences"),
                md_escape(text(v, "what"))
            ));
        }
    }
    o.push_str("\nIds are `<ADR>/<row>`: ADR 0004 D1-D11 (matching), ADR 0005 A2-A9 and S1 (accounting and statistics), ADR 0007 D1-D9 (methods), ADR 0008 R1-R7 (revision 2; the any-to-all decision A8 is `0008/R3`). The classes are defined in ADR 0012. A difference counts once per compared item and aspect, so one row that differs on two axes is two differences.\n\n");

    o.push_str("## Differences\n\nEvery difference of every layer, aggregated by layer, aspect and explanation, with up to two examples (synthetic ids only).\n\n| Layer | Aspect | Explanation | Class | Count | Example (oracle / Rust) |\n| --- | --- | --- | --- | ---: | --- |\n");
    for d in list(r, "differences") {
        let ex = list(d, "examples")
            .first()
            .map(|e| {
                format!(
                    "{} {}: {} / {}",
                    text(e, "scanner"),
                    text(e, "subject"),
                    md_escape(&trunc(text(e, "oracle"))),
                    md_escape(&trunc(text(e, "rust")))
                )
            })
            .unwrap_or_default();
        let ids = text(d, "idsKey");
        o.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            text(d, "layer"),
            md_escape(text(d, "aspect")),
            if ids.is_empty() {
                "**none**".to_owned()
            } else {
                format!("`{ids}`")
            },
            text(d, "class"),
            uint(d, "count"),
            ex
        ));
    }

    o.push_str("\n## Scanners and vectors\n\n| Scanner | Oracle status | Variants | Canonical accounting |\n| --- | --- | ---: | --- |\n");
    for s in list(r, "scanners") {
        let note = if get(s, "canonicalAccounted").as_bool() == Some(true) {
            "compared".to_owned()
        } else {
            format!(
                "not computed: {} variant(s) refused by the canonical matcher (`0004/D6`)",
                uint(s, "canonicalRefusedVariants")
            )
        };
        o.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            text(s, "id"),
            text(s, "oracleStatus"),
            uint(s, "variants"),
            note
        ));
    }
    o.push_str("\n| Accounting vector | Oracle | Metrics that differ in the accounting rule |\n| --- | --- | ---: |\n");
    for v in list(r, "vectors") {
        o.push_str(&format!(
            "| `{}` | {} | {} |\n",
            text(v, "id"),
            if get(v, "oracleThrows").as_bool() == Some(true) {
                "throws"
            } else {
                "accounts"
            },
            uint(v, "metricsDifferingInTheAccountingRule")
        ));
    }

    let real = get(r, "realScanner");
    if real.is_object() {
        o.push_str("\n## Real-scanner dual run (same pinned scanner)\n\n");
        o.push_str(&format!(
            "The oracle's own adapter observed the real `{}` {} (platform `{}`) over the same frozen population through a hermetic install: `{}`; lockfile SHA-256 `{}`; selectors {}. The synthetic observation it produced ({} findings over {} of {} variants, PII findings only) is committed in `fixtures/oracle-parity/real-core-export.json` and is fed through the same comparator and the same engine pipeline as the synthetic scanners in CI, with no scanner running. Differences of this scanner: **{} unexplained**.\n\n",
            text(real, "package"),
            text(real, "version"),
            text(real, "platform"),
            md_escape(text(real, "install")),
            text(real, "lockSha256"),
            list(real, "selectors").iter().map(|v| format!("`{}`", v.as_str().unwrap_or(""))).collect::<Vec<_>>().join(", "),
            uint(real, "observedFindings"),
            uint(real, "variantsWithFindings"),
            uint(real, "variants"),
            uint(real, "unexplained"),
        ));
        o.push_str("| Package (lockfile entry) | Integrity |\n| --- | --- |\n");
        for p in list(real, "packages") {
            o.push_str(&format!(
                "| `{}@{}`{} | `{}` |\n",
                text(p, "name"),
                text(p, "lockVersion"),
                if get(p, "installedVersion").is_string() {
                    " (installed)"
                } else {
                    ""
                },
                text(p, "integrity")
            ));
        }
        o.push_str("\n| Metric | Oracle (the oracle's accounting) | Rust canonical accounting | Equal |\n| --- | --- | --- | --- |\n");
        for m in list(real, "metrics") {
            o.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                text(m, "metric"),
                md_escape(text(m, "oracle")),
                md_escape(text(m, "rust")),
                if get(m, "equal").as_bool() == Some(true) {
                    "yes".to_owned()
                } else {
                    format!(
                        "no, classified {}",
                        list(m, "ids")
                            .iter()
                            .map(|i| format!("`{}`", i.as_str().unwrap_or("")))
                            .collect::<Vec<_>>()
                            .join(" + ")
                    )
                }
            ));
        }
        o.push_str("\nThe live check (opt-in, not in CI) runs the Rust adapter, the Node shim and the engine over the same installed package and requires the observed findings of every variant to equal the oracle adapter's and the engine's metrics to equal the canonical accounting above: `tools/oracle-parity/real-scanner/run.sh <scratch>` prints the command. Its result is recorded in ADR 0012 and the benchmarks handoff.\n");
    }
    o.push_str("\n## Not compared, not exercised, open\n\n| Item | Reason and where it is covered |\n| --- | --- |\n");
    for n in list(r, "notCompared") {
        o.push_str(&format!(
            "| {} | {} |\n",
            md_escape(text(n, "item")),
            md_escape(text(n, "reason"))
        ));
    }
    o.push_str("\n## Reproduction\n\n");
    o.push_str("CI runs the comparison from the committed oracle export and fails on any difference that is not classified, any difference in a compatibility layer, a stale export manifest or a stale report. Regenerating the export is a manual step that needs read access to the oracle repository: `tools/oracle-parity/regenerate.sh <scratch> [--update]` (it fetches the pinned files, verifies the commit, the git blob ids and the tree digest, runs the oracle twice and requires byte-identical output). After a reviewed change run `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test oracle_parity` to rewrite this report and `fixtures/oracle-parity/report.json`. See `tools/oracle-parity/README.md`.\n");
    o
}

fn trunc(s: &str) -> String {
    const MAX: usize = 150;
    if s.len() <= MAX {
        s.to_owned()
    } else {
        let mut end = MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}
