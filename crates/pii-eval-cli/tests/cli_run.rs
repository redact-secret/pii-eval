//! End-to-end tests of `run` through the built binary and the inert fake
//! scanner package: provenance, configuration and output handling, scanner
//! failure, determinism, protected runs and summaries. Needs Node and `ps`
//! (CI sets `PII_EVAL_REQUIRE_NODE=1`). Synthetic only.
#![cfg(unix)]

mod cli_support;
mod common;

use std::path::{Path, PathBuf};

use cli_support::*;
use pii_eval_contracts::{
    CorpusSnapshot, RunClass, RunManifest, Visibility, parse_default, seal, to_pretty_json,
};
use serde_json::Value;

const FILES: [&str; 4] = [
    "manifest.json",
    "observation-redact-secret-core.json",
    "public-synthetic-artifact.json",
    "run-artifact.json",
];

fn reason(v: &Value) -> &str {
    v["error"]["reason"].as_str().unwrap_or_default()
}

fn detail(v: &Value) -> &str {
    v["error"]["detail"].as_str().unwrap_or_default()
}

fn files_of(dir: &Path) -> Vec<(String, Vec<u8>)> {
    list_dir(dir)
        .into_iter()
        .map(|n| {
            let bytes = std::fs::read(dir.join(&n)).unwrap();
            (n, bytes)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The happy path and the contract of its outputs
// ---------------------------------------------------------------------------

#[test]
fn an_exploratory_public_run_writes_private_documents_and_a_deterministic_summary() {
    let node = node_or_return!();
    let ws = Workspace::new("run-ok", &node);
    let out = ws.out("out");
    let result = ws.run(&out);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    assert!(stderr(&result).is_empty(), "no diagnostics on success");
    let v = summary(&result);
    assert_eq!(v["command"], "run");
    assert_eq!(v["state"], "complete");
    assert_eq!(v["semantic"]["mode"], "exploratory");
    assert_eq!(v["semantic"]["product"], "candidate");
    assert_eq!(v["semantic"]["runClass"], "public-synthetic");
    assert_eq!(v["semantic"]["scanners"][0]["status"], "complete");
    assert_eq!(v["semantic"]["scanners"][0]["replays"]["count"], 2);
    assert_eq!(v["semantic"]["completeness"], "complete");
    assert_eq!(list_dir(&out), FILES);
    // The summary names the files with their sizes and digests, and no path.
    let listed: Vec<&str> = v["outputs"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(listed, FILES);
    let text = v.to_string();
    assert!(!text.contains(s(&ws.tmp.0)), "no path in the summary");
    // Directory 0700, files 0600.
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        for name in FILES {
            let mode = std::fs::metadata(out.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }
    // Every output validates, binds and verifies through the CLI itself.
    let artifact = out.join("run-artifact.json");
    let check = run_cli(&[
        "validate",
        s(&artifact),
        "--snapshot",
        s(&ws.snapshot),
        "--manifest",
        s(&out.join("manifest.json")),
    ]);
    assert_eq!(code(&check), 0, "{}", stderr(&check));
    assert_eq!(summary(&check)["semantic"]["verification"], "verified");
    let public = run_cli(&[
        "validate",
        s(&out.join("public-synthetic-artifact.json")),
        "--snapshot",
        s(&ws.snapshot),
    ]);
    assert_eq!(code(&public), 0);
    // The recorded manifest is the one that was run.
    assert_eq!(
        std::fs::read(out.join("manifest.json")).unwrap(),
        std::fs::read(&ws.manifest).unwrap()
    );
}

#[test]
fn the_same_inputs_give_byte_identical_documents_and_summaries_at_one_and_many_workers() {
    let node = node_or_return!();
    let ws = Workspace::new("run-determinism", &node);
    let (a, b, c) = (ws.out("a"), ws.out("b"), ws.out("c"));
    let first = ws.run(&a);
    let second = ws.run(&b);
    assert_eq!(code(&first), 0);
    assert_eq!(first.stdout, second.stdout, "summaries are byte-identical");
    assert_eq!(files_of(&a), files_of(&b));
    // One worker versus four: only the host cap changes, never the result.
    let tmp_config = ws.tmp.0.join("config-one.json");
    let mut spec = ConfigSpec::new(&ws.snapshot, &ws.manifest, &ws.package);
    spec.max_workers = 1;
    std::fs::write(&tmp_config, spec.json()).unwrap();
    let one = run_cli(&[
        "run",
        "--config",
        s(&tmp_config),
        "--node",
        s(&node),
        "--out",
        s(&c),
    ]);
    assert_eq!(code(&one), 0, "{}", stderr(&one));
    assert_eq!(first.stdout, one.stdout);
    assert_eq!(files_of(&a), files_of(&c));
    let many_config = ws.tmp.0.join("config-many.json");
    spec.max_workers = 8;
    std::fs::write(&many_config, spec.json()).unwrap();
    let d = ws.out("d");
    let many = run_cli(&[
        "run",
        "--config",
        s(&many_config),
        "--node",
        s(&node),
        "--out",
        s(&d),
    ]);
    assert_eq!(first.stdout, many.stdout);
    assert_eq!(files_of(&a), files_of(&d));
}

#[test]
fn host_diagnostics_never_change_the_semantic_part() {
    let node = node_or_return!();
    let ws = Workspace::new("run-diagnostics", &node);
    let plain = ws.out("plain");
    let timed = ws.out("timed");
    let first = ws.run(&plain);
    let config = ws.tmp.0.join("config-diag.json");
    let mut spec = ConfigSpec::new(&ws.snapshot, &ws.manifest, &ws.package);
    spec.extra_top = r#","output": {"overwrite": "refuse"}"#;
    let text = spec.json().replace(
        r#""resources": "enforce""#,
        r#""resources": "enforce", "diagnostics": true"#,
    );
    std::fs::write(&config, text).unwrap();
    let second = run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(&node),
        "--out",
        s(&timed),
    ]);
    assert_eq!(code(&second), 0, "{}", stderr(&second));
    assert_eq!(summary(&first)["semantic"], summary(&second)["semantic"]);
    // The artifact carries timing only outside its digested body.
    let with: Value =
        serde_json::from_slice(&std::fs::read(timed.join("run-artifact.json")).unwrap()).unwrap();
    let without: Value =
        serde_json::from_slice(&std::fs::read(plain.join("run-artifact.json")).unwrap()).unwrap();
    assert!(with.get("diagnostics").is_some() && without.get("diagnostics").is_none());
    assert_eq!(with["semanticDigest"], without["semanticDigest"]);
    assert_eq!(with["semantic"], without["semantic"]);
}

#[test]
fn an_official_run_with_every_identity_pinned_succeeds() {
    let node = node_or_return!();
    let ws = Workspace::new("run-official", &node);
    let snapshot = read_snapshot(&ws.snapshot);
    let manifest: RunManifest = parse_default(&std::fs::read(&ws.manifest).unwrap()).unwrap();
    let mut spec = ConfigSpec::new(&ws.snapshot, &ws.manifest, &ws.package);
    spec.mode = "official";
    spec.snapshot_digest = Some(snapshot.semantic_digest.as_str());
    spec.manifest_digest = Some(manifest.semantic_digest.as_str());
    let extra = pins_extra(pii_eval_contracts::ENGINE_VERSION, 2);
    spec.extra_top = &extra;
    let config = ws.tmp.0.join("official.json");
    std::fs::write(&config, spec.json()).unwrap();
    let out = ws.out("official-out");
    let result = run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(&node),
        "--out",
        s(&out),
    ]);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    assert_eq!(summary(&result)["semantic"]["mode"], "official");
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

struct Pinned {
    ws: Workspace,
    snapshot_digest: String,
    manifest_digest: String,
}

fn pinned(label: &str, node: &Path) -> Pinned {
    let ws = Workspace::new(label, node);
    let snapshot = read_snapshot(&ws.snapshot);
    let manifest: RunManifest = parse_default(&std::fs::read(&ws.manifest).unwrap()).unwrap();
    Pinned {
        snapshot_digest: snapshot.semantic_digest.as_str().to_owned(),
        manifest_digest: manifest.semantic_digest.as_str().to_owned(),
        ws,
    }
}

/// Run an official configuration with the given pins and extra top-level JSON.
fn official_run(p: &Pinned, sd: &str, md: &str, extra: &str, out: &Path) -> std::process::Output {
    let mut spec = ConfigSpec::new(&p.ws.snapshot, &p.ws.manifest, &p.ws.package);
    spec.mode = "official";
    spec.snapshot_digest = Some(sd);
    spec.manifest_digest = Some(md);
    spec.extra_top = extra;
    let config = p.ws.tmp.0.join(format!(
        "cfg-{}.json",
        out.file_name().unwrap().to_string_lossy()
    ));
    std::fs::write(&config, spec.json()).unwrap();
    run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(&p.ws.node),
        "--out",
        s(out),
    ])
}

fn pins_extra(engine: &str, revision: u32) -> String {
    format!(
        r#","engineVersion": "{engine}","protocol": {{"id": "pii-v1", "revision": {revision}}}"#
    )
}

#[test]
fn every_provenance_mismatch_is_exit_4_before_any_scanner_starts() {
    let node = node_or_return!();
    let p = pinned("run-provenance", &node);
    let good = pins_extra(pii_eval_contracts::ENGINE_VERSION, 2);
    let zero = "0".repeat(64);
    let cases: Vec<(&str, std::process::Output)> = vec![
        (
            "snapshot-digest",
            official_run(&p, &zero, &p.manifest_digest, &good, &p.ws.out("o1")),
        ),
        (
            "manifest-digest",
            official_run(&p, &p.snapshot_digest, &zero, &good, &p.ws.out("o2")),
        ),
        (
            "engine",
            official_run(
                &p,
                &p.snapshot_digest,
                &p.manifest_digest,
                &pins_extra("9.9.9", 2),
                &p.ws.out("o3"),
            ),
        ),
        (
            "protocol",
            official_run(
                &p,
                &p.snapshot_digest,
                &p.manifest_digest,
                &pins_extra(pii_eval_contracts::ENGINE_VERSION, 1),
                &p.ws.out("o4"),
            ),
        ),
    ];
    for (slot, out) in cases {
        assert_eq!(
            code(&out),
            4,
            "{slot}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let v = summary(&out);
        assert_eq!(reason(&v), "provenance-mismatch");
        assert_eq!(detail(&v), slot);
    }
    // No output directory was left behind by any of them.
    for name in ["o1", "o2", "o3", "o4"] {
        assert!(!p.ws.out(name).exists(), "{name}");
    }
}

#[test]
fn run_class_and_product_are_independent_identities_each_checked_against_the_manifest() {
    let node = node_or_return!();
    let ws = Workspace::new("run-axes", &node);
    // The manifest is a public-synthetic candidate run.
    let mut spec = ConfigSpec::new(&ws.snapshot, &ws.manifest, &ws.package);
    spec.product = "released";
    let released = ws.tmp.0.join("released.json");
    std::fs::write(&released, spec.json()).unwrap();
    let out = run_cli(&[
        "run",
        "--config",
        s(&released),
        "--node",
        s(&node),
        "--out",
        s(&ws.out("r")),
    ]);
    assert_eq!(code(&out), 4, "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(detail(&summary(&out)), "product");
    // A (self-consistent) protected manifest where the configuration claims a
    // public-synthetic run.
    let mut manifest: RunManifest = parse_default(&std::fs::read(&ws.manifest).unwrap()).unwrap();
    manifest.semantic.run_class = RunClass::Protected;
    manifest.semantic.population.visibility = Visibility::Protected;
    seal(&mut manifest).unwrap();
    let protected_manifest = ws.tmp.0.join("protected-manifest.json");
    std::fs::write(&protected_manifest, to_pretty_json(&manifest).unwrap()).unwrap();
    let spec = ConfigSpec::new(&ws.snapshot, &protected_manifest, &ws.package);
    let config = ws.tmp.0.join("class.json");
    std::fs::write(&config, spec.json()).unwrap();
    let out = run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(&node),
        "--out",
        s(&ws.out("c")),
    ]);
    assert_eq!(code(&out), 4);
    assert_eq!(detail(&summary(&out)), "run-class");
}

#[test]
fn a_manifest_for_another_population_scanner_configuration_or_artifact_is_refused() {
    let node = node_or_return!();
    let ws = Workspace::new("run-bindings", &node);
    // Another population than the manifest binds.
    let mut other: CorpusSnapshot = read_snapshot(&ws.snapshot);
    other.semantic.population.population_version += 1;
    seal(&mut other).unwrap();
    let other_path = ws.tmp.0.join("other.json");
    std::fs::write(&other_path, to_pretty_json(&other).unwrap()).unwrap();
    let config = ws.tmp.0.join("pop.json");
    std::fs::write(
        &config,
        ConfigSpec::new(&other_path, &ws.manifest, &ws.package).json(),
    )
    .unwrap();
    let out = run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(&node),
        "--out",
        s(&ws.out("p")),
    ]);
    assert_eq!(code(&out), 4);
    assert!(
        summary(&out)["error"]["codes"]
            .to_string()
            .contains("population-binding-mismatch")
    );

    // A manifest whose scanner identity the adapter does not derive: another
    // adapter version, or configuration parameters the adapter does not accept.
    let tampered = |name: &str, edit: &dyn Fn(&mut RunManifest)| {
        let mut manifest: RunManifest =
            parse_default(&std::fs::read(&ws.manifest).unwrap()).unwrap();
        edit(&mut manifest);
        seal(&mut manifest).unwrap();
        let path = ws.tmp.0.join(format!("{name}-manifest.json"));
        std::fs::write(&path, to_pretty_json(&manifest).unwrap()).unwrap();
        let config = ws.tmp.0.join(format!("{name}.json"));
        std::fs::write(
            &config,
            ConfigSpec::new(&ws.snapshot, &path, &ws.package).json(),
        )
        .unwrap();
        run_cli(&[
            "run",
            "--config",
            s(&config),
            "--node",
            s(&node),
            "--out",
            s(&ws.out(name)),
        ])
    };
    let adapter_version = tampered("adapter", &|m| {
        m.semantic.scanners[0].identity.adapter.adapter_version =
            pii_eval_contracts::VersionString::new("9.9.9").unwrap();
    });
    assert_eq!(
        code(&adapter_version),
        4,
        "{}",
        String::from_utf8_lossy(&adapter_version.stdout)
    );
    assert_eq!(detail(&summary(&adapter_version)), "scanner-plan");
    let parameters = tampered("parameters", &|m| {
        let params = &mut m.semantic.scanners[0].configuration.parameters;
        params[0].value = pii_eval_contracts::ConfigValue::Text("basic".into());
        m.semantic.scanners[0].identity.configuration_digest = m.semantic.scanners[0]
            .configuration
            .configuration_digest()
            .unwrap();
    });
    assert_eq!(code(&parameters), 4);
    assert_eq!(detail(&summary(&parameters)), "scanner-plan");

    // A scanner package that is not the one the manifest pins: its identity differs.
    let variant = ws.tmp.0.join("variant-package");
    copy_dir(&ws.package, &variant);
    std::fs::write(
        variant.join("lib/extra.txt"),
        "not part of the pinned package",
    )
    .unwrap();
    let config = ws.tmp.0.join("pkg.json");
    std::fs::write(
        &config,
        ConfigSpec::new(&ws.snapshot, &ws.manifest, &variant).json(),
    )
    .unwrap();
    let out = run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(&node),
        "--out",
        s(&ws.out("k")),
    ]);
    assert_eq!(code(&out), 4);
    assert_eq!(detail(&summary(&out)), "scanner-plan");
    for name in ["p", "adapter", "parameters", "k", "r", "c"] {
        assert!(!ws.out(name).exists());
    }
}

#[test]
fn a_changed_pinned_file_is_caught_by_the_preflight_hash_not_by_a_later_failure() {
    let node = node_or_return!();
    let ws = Workspace::new("run-preflight", &node);
    // The config pins the original tree digest; the package then changes.
    std::fs::write(ws.package.join("lib/index.js"), "// tampered\n").unwrap();
    let out = run_cli(&[
        "run",
        "--config",
        s(&ws.config),
        "--node",
        s(&node),
        "--out",
        s(&ws.out("o")),
    ]);
    // The configuration was generated before the change, so its tree digest is
    // the original: the pin fails before any scanner starts.
    assert_eq!(code(&out), 4, "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(detail(&summary(&out)), "scanner-artifact");
    assert!(!ws.out("o").exists());
    // The same for the shim: a copy with different bytes is not the shipped shim.
    let ws = Workspace::new("run-shim", &node);
    let shim = ws.tmp.0.join("shim.mjs");
    std::fs::copy(shim_path(), &shim).unwrap();
    let mut text = std::fs::read_to_string(&shim).unwrap();
    text.push_str("\n// changed\n");
    std::fs::write(&shim, text).unwrap();
    let config = std::fs::read_to_string(&ws.config)
        .unwrap()
        .replace(s(&shim_path()), s(&shim));
    let config_path = ws.tmp.0.join("shim.json");
    std::fs::write(&config_path, config).unwrap();
    let out = run_cli(&[
        "run",
        "--config",
        s(&config_path),
        "--node",
        s(&node),
        "--out",
        s(&ws.out("s")),
    ]);
    assert_eq!(code(&out), 4);
    assert_eq!(detail(&summary(&out)), "shim");
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[test]
fn invalid_configurations_are_exit_3_naming_the_field_and_never_echoing_values() {
    let node = node_or_return!();
    let ws = Workspace::new("run-config", &node);
    let good = std::fs::read_to_string(&ws.config).unwrap();
    let marker = "ZQMARKER7731";
    let cases: Vec<(String, &str)> = vec![
        (
            good.replace(
                "\"mode\": \"exploratory\"",
                &format!("\"mode\": \"{marker}\""),
            ),
            "mode",
        ),
        (
            good.replace(
                "\"schema\": \"pii-eval-run-config/1\"",
                &format!("\"{marker}\": 1, \"schema\": \"pii-eval-run-config/1\""),
            ),
            "unknown field",
        ),
        (
            good.replace("\"maxWorkers\": 2", "\"maxWorkers\": 0"),
            "host.maxWorkers",
        ),
        (good.replace("\"maxWorkers\": 2", "\"maxWorkers\": 2.5"), ""),
        (
            good.replace("\"resources\": \"enforce\"", "\"resources\": null"),
            "",
        ),
        (
            good.replace(
                "\"adapter\": \"redact-secret-core\"",
                &format!("\"adapter\": \"{marker}\""),
            ),
            "adapter",
        ),
        (
            good.replace("\"entry\": \"lib/index.js\"", "\"entry\": \"../x.js\""),
            "entry",
        ),
        (format!("{marker} not json"), ""),
        ("[]".to_owned(), ""),
        (
            good.replacen("\"mode\"", "\"mode\": \"official\", \"mode\"", 1),
            "",
        ),
    ];
    for (i, (text, expect)) in cases.into_iter().enumerate() {
        let path = ws.tmp.0.join(format!("bad-{i}.json"));
        std::fs::write(&path, text).unwrap();
        let out = run_cli(&[
            "run",
            "--config",
            s(&path),
            "--node",
            s(&node),
            "--out",
            s(&ws.out("x")),
        ]);
        assert_eq!(
            code(&out),
            3,
            "case {i}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let v = summary(&out);
        assert_eq!(reason(&v), "config-invalid", "case {i}");
        if !expect.is_empty() {
            assert!(detail(&v).contains(expect), "case {i}: {}", detail(&v));
        }
        let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
        assert!(!all.contains(marker), "case {i} echoed a value");
        assert!(
            !ws.out("x").exists(),
            "case {i} created an output directory"
        );
    }
    // Missing and unreadable configuration files.
    let out = run_cli(&[
        "run",
        "--config",
        s(&ws.tmp.0.join("missing.json")),
        "--node",
        s(&node),
        "--out",
        s(&ws.out("x")),
    ]);
    assert_eq!(code(&out), 3);
    assert_eq!(reason(&summary(&out)), "input-unreadable");
}

#[test]
fn official_runs_require_every_pin_enforced_resources_and_no_overwrite() {
    let node = node_or_return!();
    let ws = Workspace::new("run-official-rules", &node);
    let base = ConfigSpec::new(&ws.snapshot, &ws.manifest, &ws.package);
    let mut cases: Vec<(String, &str)> = Vec::new();
    let mut spec = ConfigSpec::new(&ws.snapshot, &ws.manifest, &ws.package);
    spec.mode = "official";
    cases.push((spec.json(), "required"));
    spec.resources = "unenforced";
    cases.push((spec.json(), ""));
    let _ = base;
    for (i, (text, expect)) in cases.into_iter().enumerate() {
        let path = ws.tmp.0.join(format!("official-{i}.json"));
        std::fs::write(&path, text).unwrap();
        let out = run_cli(&[
            "run",
            "--config",
            s(&path),
            "--node",
            s(&node),
            "--out",
            s(&ws.out("x")),
        ]);
        assert_eq!(code(&out), 3, "{i}");
        assert!(detail(&summary(&out)).contains(expect));
    }
}

#[test]
fn node_must_be_given_explicitly_and_absolutely() {
    let node = node_or_return!();
    let ws = Workspace::new("run-node", &node);
    let out = run_cli(&["run", "--config", s(&ws.config), "--out", s(&ws.out("x"))]);
    assert_eq!(code(&out), 3);
    assert!(detail(&summary(&out)).starts_with("node"));
    let out = run_cli(&[
        "run",
        "--config",
        s(&ws.config),
        "--node",
        "node",
        "--out",
        s(&ws.out("x")),
    ]);
    assert_eq!(code(&out), 3);
    // Another interpreter would run the JavaScript shim as its own language
    // (a shell would execute its lines as commands): refused before any launch.
    let out = run_cli(&[
        "run",
        "--config",
        s(&ws.config),
        "--node",
        "/bin/sh",
        "--out",
        s(&ws.out("x")),
    ]);
    assert_eq!(code(&out), 3);
    assert!(detail(&summary(&out)).contains("named node"));
    assert!(!ws.out("x").exists());
    let out = run_cli(&[
        "run",
        "--config",
        s(&ws.config),
        "--node",
        "/nonexistent/node",
        "--out",
        s(&ws.out("x")),
    ]);
    assert_eq!(code(&out), 6, "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(reason(&summary(&out)), "adapter-invalid");
    assert!(!ws.out("x").exists());
}

// ---------------------------------------------------------------------------
// Output handling
// ---------------------------------------------------------------------------

#[test]
fn writer_temporaries_of_a_crashed_earlier_run_are_removed_from_the_output_directory() {
    let node = node_or_return!();
    let ws = Workspace::new("run-stale", &node);
    let out = ws.out("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join(".pii-eval-tmp.4242.0.run-artifact.json"), b"half").unwrap();
    std::fs::write(out.join("notes.txt"), b"mine").unwrap();
    let result = ws.run(&out);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    let names = list_dir(&out);
    assert!(
        !names.iter().any(|n| n.starts_with(".pii-eval-tmp.")),
        "{names:?}"
    );
    assert!(
        names.contains(&"notes.txt".to_owned()),
        "other files are left alone"
    );
}

#[test]
fn an_existing_result_is_never_overwritten_and_replace_is_explicit() {
    let node = node_or_return!();
    let ws = Workspace::new("run-existing", &node);
    let out = ws.out("out");
    assert_eq!(code(&ws.run(&out)), 0);
    let before = files_of(&out);
    let again = ws.run(&out);
    assert_eq!(code(&again), 7);
    assert_eq!(reason(&summary(&again)), "output-exists");
    assert_eq!(files_of(&out), before, "nothing was touched");
    // An unrelated file in the directory does not block a fresh run elsewhere.
    std::fs::write(out.join("notes.txt"), "mine").unwrap();
    // Explicit replace (exploratory only).
    let text = std::fs::read_to_string(&ws.config).unwrap().replace(
        "\n}\n",
        ",\n  \"output\": {\"overwrite\": \"replace\"}\n}\n",
    );
    let config = ws.tmp.0.join("replace.json");
    std::fs::write(&config, text).unwrap();
    let replaced = run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(&node),
        "--out",
        s(&out),
    ]);
    assert_eq!(code(&replaced), 0, "{}", stderr(&replaced));
    assert_eq!(
        std::fs::read_to_string(out.join("notes.txt")).unwrap(),
        "mine"
    );
    assert_eq!(files_of(&out).len(), before.len() + 1);
    for (name, bytes) in &before {
        assert_eq!(&std::fs::read(out.join(name)).unwrap(), bytes, "{name}");
    }
}

#[test]
fn output_paths_that_are_symlinks_files_missing_parents_or_read_only_are_refused_early() {
    let node = node_or_return!();
    let ws = Workspace::new("run-output-paths", &node);
    // A symlink to a directory.
    let real = ws.out("real");
    std::fs::create_dir(&real).unwrap();
    let link = ws.out("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let out = ws.run(&link);
    assert_eq!(code(&out), 7);
    assert_eq!(detail(&summary(&out)), "symlink");
    assert!(list_dir(&real).is_empty());
    // A file where the directory belongs.
    let file = ws.out("file");
    std::fs::write(&file, b"x").unwrap();
    let out = ws.run(&file);
    assert_eq!(code(&out), 7);
    assert_eq!(detail(&summary(&out)), "not-a-directory");
    // A missing parent.
    let out = ws.run(&ws.out("no/such/parent"));
    assert_eq!(code(&out), 7);
    assert_eq!(detail(&summary(&out)), "parent-missing");
    // A destination file that is a symlink (even under replace) is not followed.
    let dir = ws.out("with-link");
    std::fs::create_dir(&dir).unwrap();
    let victim = ws.out("victim.txt");
    std::fs::write(&victim, "keep").unwrap();
    std::os::unix::fs::symlink(&victim, dir.join("run-artifact.json")).unwrap();
    let out = ws.run(&dir);
    assert_eq!(code(&out), 7);
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    // A directory nobody can write to: refused before the scanners run.
    let ro = ws.out("read-only");
    std::fs::create_dir(&ro).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        let writable_anyway = std::fs::write(ro.join(".probe"), b"").is_ok();
        let _ = std::fs::remove_file(ro.join(".probe"));
        if !writable_anyway {
            let out = ws.run(&ro);
            assert_eq!(code(&out), 7, "{}", String::from_utf8_lossy(&out.stdout));
            assert_eq!(detail(&summary(&out)), "not-writable");
        }
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn an_output_directory_created_for_a_run_that_fails_early_is_removed_again() {
    let node = node_or_return!();
    // A manifest whose per-session memory share is below the floor: refused
    // before any scanner starts, after the output directory was prepared.
    let mut tight = limits(2, 1);
    tight.max_memory_bytes = 64 << 20;
    let ws = Workspace::with(
        "run-refused",
        &node,
        tight,
        2,
        pii_eval_adapters::redact_secret::PINNED_VERSION,
    );
    let out = ws.out("out");
    let result = ws.run(&out);
    assert_eq!(
        code(&result),
        6,
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let v = summary(&result);
    assert_eq!(reason(&v), "execution-refused");
    assert_eq!(detail(&v), "budget-too-small");
    assert!(!out.exists());
}

// ---------------------------------------------------------------------------
// Scanner failure is not a clean success
// ---------------------------------------------------------------------------

#[test]
fn a_scanner_that_cannot_start_exits_5_with_the_documents_and_never_as_zero_findings() {
    let node = node_or_return!();
    // The manifest pins a scanner version the package does not report: the
    // startup identity check fails, so the scanner measured nothing.
    let ws = Workspace::with("run-failure", &node, limits(2, 1), 2, "9.9.9");
    let out = ws.out("out");
    let result = ws.run(&out);
    assert_eq!(
        code(&result),
        5,
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(stderr(&result).lines().count(), 1, "one diagnostic line");
    assert!(stderr(&result).contains("scanner-failure"));
    let v = summary(&result);
    assert_eq!(v["state"], "incomplete");
    assert_eq!(reason(&v), "scanner-failure");
    let scanner = &v["semantic"]["scanners"][0];
    assert_eq!(scanner["status"], "unavailable");
    assert_eq!(scanner["failure"]["code"], "unavailable");
    assert_eq!(v["semantic"]["failureCodes"][0], "unavailable");
    // The documents exist and say the same: no finding rows read as success.
    assert_eq!(list_dir(&out), FILES);
    let artifact: Value =
        serde_json::from_slice(&std::fs::read(out.join("run-artifact.json")).unwrap()).unwrap();
    assert_eq!(artifact["semantic"]["scanners"][0]["status"], "unavailable");
    assert!(artifact["semantic"]["failures"][0]["code"] == "unavailable");
    let check = run_cli(&[
        "validate",
        s(&out.join("run-artifact.json")),
        "--snapshot",
        s(&ws.snapshot),
    ]);
    assert_eq!(
        code(&check),
        0,
        "an artifact that records a failure is still a valid artifact"
    );
    // Every metric of the unavailable scanner is withheld, never a zero rate.
    let compare = run_cli(&[
        "compare",
        "--base",
        s(&out.join("run-artifact.json")),
        "--other",
        s(&out.join("run-artifact.json")),
    ]);
    let metrics = summary(&compare)["semantic"]["scanners"][0]["metrics"].clone();
    for m in metrics.as_array().unwrap() {
        if m["metric"] == "measurable-share" {
            // The share of occurrences that were measured is zero: stated as
            // such (a measurement about coverage), not as a clean result.
            assert_eq!(m["base"]["counts"]["measured"], 0);
            assert_eq!(m["base"]["status"], "unresolved");
        } else {
            assert_eq!(m["base"]["value"]["state"], "withheld", "{m}");
        }
    }
    // Replaying the failed run reports the same state.
    let replay = run_cli(&[
        "replay",
        "--snapshot",
        s(&ws.snapshot),
        "--manifest",
        s(&out.join("manifest.json")),
        "--observation",
        s(&out.join("observation-redact-secret-core.json")),
        "--original",
        s(&out.join("run-artifact.json")),
        "--out",
        s(&ws.out("replayed")),
    ]);
    assert_eq!(code(&replay), 5);
    assert_eq!(
        std::fs::read(ws.out("replayed").join("run-artifact.json")).unwrap(),
        std::fs::read(out.join("run-artifact.json")).unwrap()
    );
}

// ---------------------------------------------------------------------------
// Run, replay and compare agree
// ---------------------------------------------------------------------------

#[test]
fn a_replay_of_a_real_run_reproduces_it_and_a_changed_scanner_compares_as_a_subject_change() {
    let node = node_or_return!();
    let ws = Workspace::new("run-replay-compare", &node);
    let out = ws.out("run");
    assert_eq!(code(&ws.run(&out)), 0);
    let replayed = ws.out("replay");
    let replay = run_cli(&[
        "replay",
        "--snapshot",
        s(&ws.snapshot),
        "--manifest",
        s(&out.join("manifest.json")),
        "--observation",
        s(&out.join("observation-redact-secret-core.json")),
        "--original",
        s(&out.join("run-artifact.json")),
        "--out",
        s(&replayed),
    ]);
    assert_eq!(code(&replay), 0, "{}", stderr(&replay));
    assert_eq!(
        files_of(&out),
        files_of(&replayed),
        "same observations, same bytes"
    );
    let run_summary = summary(&ws.run(&ws.out("again")));
    assert_eq!(
        summary(&replay)["semantic"]["runArtifactDigest"],
        run_summary["semantic"]["runArtifactDigest"]
    );
    // A different scanner build over the same population: the fake package with
    // one detector removed. Same population, protocol and mechanics: comparable;
    // the identities and some metric states differ.
    let variant = ws.tmp.0.join("variant-package");
    copy_dir(&fake_core_dir(), &variant);
    let index = std::fs::read_to_string(variant.join("lib/index.js")).unwrap();
    std::fs::write(
        variant.join("lib/index.js"),
        index.replace("if (selectors.includes('pii:us')) add(", "if (false) add("),
    )
    .unwrap();
    let snapshot = read_snapshot(&ws.snapshot);
    let manifest = manifest_for(&snapshot, &variant, &node, limits(2, 1), 2);
    let manifest_path = ws.tmp.0.join("variant-manifest.json");
    write_manifest(&manifest_path, &manifest);
    let config = ws.tmp.0.join("variant.json");
    std::fs::write(
        &config,
        ConfigSpec::new(&ws.snapshot, &manifest_path, &variant).json(),
    )
    .unwrap();
    let variant_out = ws.out("variant-run");
    let result = run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(&node),
        "--out",
        s(&variant_out),
    ]);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    let compared = run_cli(&[
        "compare",
        "--base",
        s(&out.join("run-artifact.json")),
        "--other",
        s(&variant_out.join("run-artifact.json")),
    ]);
    assert_eq!(
        code(&compared),
        0,
        "{}",
        String::from_utf8_lossy(&compared.stdout)
    );
    let v = summary(&compared);
    let scanner = &v["semantic"]["scanners"][0];
    assert!(scanner["identityChanges"].get("artifactDigest").is_some());
    assert!(scanner["identityChanges"].get("product").is_some());
    assert_eq!(v["semantic"]["subject"]["manifestDigest"]["changed"], true);
    let changed: Vec<&str> = scanner["metrics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["identical"] == false)
        .map(|m| m["metric"].as_str().unwrap())
        .collect();
    assert!(
        !changed.is_empty(),
        "some metric state differs: counts or values"
    );
    // The comparison is deterministic.
    let again = run_cli(&[
        "compare",
        "--base",
        s(&out.join("run-artifact.json")),
        "--other",
        s(&variant_out.join("run-artifact.json")),
    ]);
    assert_eq!(compared.stdout, again.stdout);
}

#[test]
fn artifacts_of_different_populations_are_refused_by_compare() {
    let node = node_or_return!();
    let ws = Workspace::new("run-compare-populations", &node);
    let a = ws.out("a");
    assert_eq!(code(&ws.run(&a)), 0);
    // A second population (one more version) measured by the same scanner.
    let mut snapshot = read_snapshot(&ws.snapshot);
    snapshot.semantic.population.population_version += 1;
    seal(&mut snapshot).unwrap();
    let snap2 = ws.tmp.0.join("snapshot2.json");
    std::fs::write(&snap2, to_pretty_json(&snapshot).unwrap()).unwrap();
    let manifest2 = ws.tmp.0.join("manifest2.json");
    write_manifest(
        &manifest2,
        &manifest_for(&snapshot, &ws.package, &node, limits(2, 1), 2),
    );
    let config = ws.tmp.0.join("config2.json");
    std::fs::write(
        &config,
        ConfigSpec::new(&snap2, &manifest2, &ws.package).json(),
    )
    .unwrap();
    let b = ws.out("b");
    let run2 = run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(&node),
        "--out",
        s(&b),
    ]);
    assert_eq!(code(&run2), 0, "{}", stderr(&run2));
    let compared = run_cli(&[
        "compare",
        "--base",
        s(&a.join("run-artifact.json")),
        "--other",
        s(&b.join("run-artifact.json")),
    ]);
    assert_eq!(code(&compared), 10);
    assert!(
        summary(&compared)["semantic"]["refusals"]
            .to_string()
            .contains("population-differs")
    );
    // The public projections are refused for the same reason.
    let public = run_cli(&[
        "compare",
        "--base",
        s(&a.join("public-synthetic-artifact.json")),
        "--other",
        s(&b.join("public-synthetic-artifact.json")),
    ]);
    assert_eq!(code(&public), 10);
}

// ---------------------------------------------------------------------------
// Protected runs
// ---------------------------------------------------------------------------

struct Protected {
    ws: Workspace,
    input_root: PathBuf,
    output_root: PathBuf,
    snapshot: PathBuf,
    manifest: PathBuf,
    config: PathBuf,
}

fn protected(label: &str, node: &Path) -> Protected {
    let ws = Workspace::new(label, node);
    let input_root = ws.tmp.0.join("custodian-in");
    let output_root = ws.tmp.0.join("custodian-out");
    std::fs::create_dir_all(&input_root).unwrap();
    std::fs::create_dir_all(&output_root).unwrap();
    let mut snapshot: CorpusSnapshot = read_snapshot(&ws.snapshot);
    snapshot.semantic.population.visibility = Visibility::Protected;
    seal(&mut snapshot).unwrap();
    let snapshot_path = input_root.join("snapshot.json");
    std::fs::write(&snapshot_path, to_pretty_json(&snapshot).unwrap()).unwrap();
    let mut manifest: RunManifest = parse_default(&std::fs::read(&ws.manifest).unwrap()).unwrap();
    manifest.semantic.run_class = RunClass::Protected;
    manifest.semantic.population.visibility = Visibility::Protected;
    manifest.semantic.population.population_digest = snapshot.semantic_digest.clone();
    seal(&mut manifest).unwrap();
    let manifest_path = input_root.join("manifest.json");
    std::fs::write(&manifest_path, to_pretty_json(&manifest).unwrap()).unwrap();
    let mut spec = ConfigSpec::new(&snapshot_path, &manifest_path, &ws.package);
    spec.mode = "official";
    spec.run_class = "protected";
    spec.snapshot_digest = Some(snapshot.semantic_digest.as_str());
    spec.manifest_digest = Some(manifest.semantic_digest.as_str());
    let extra = pins_extra(pii_eval_contracts::ENGINE_VERSION, 2);
    spec.extra_top = &extra;
    let config = ws.tmp.0.join("protected.json");
    std::fs::write(&config, spec.json()).unwrap();
    Protected {
        ws,
        input_root,
        output_root,
        snapshot: snapshot_path,
        manifest: manifest_path,
        config,
    }
}

fn job_context(p: &Protected, edit: impl FnOnce(String) -> String, mode: u32) -> PathBuf {
    let snapshot = read_snapshot(&p.snapshot);
    let manifest: RunManifest = parse_default(&std::fs::read(&p.manifest).unwrap()).unwrap();
    let text = format!(
        r#"{{
  "schema": "pii-eval-job-context/1",
  "jobId": "job-0001",
  "custodian": "synthetic-custodian",
  "runClass": "protected",
  "populationDigest": "{}",
  "manifestDigest": "{}",
  "candidateDigest": "{}",
  "inputRoot": "{}",
  "outputRoot": "{}"
}}
"#,
        snapshot.semantic_digest.as_str(),
        manifest.semantic_digest.as_str(),
        pii_eval_adapters::sha256_of_tree(&p.ws.package)
            .unwrap()
            .as_str(),
        s(&std::fs::canonicalize(&p.input_root).unwrap()),
        s(&std::fs::canonicalize(&p.output_root).unwrap()),
    );
    let path = p.ws.tmp.0.join("job.json");
    std::fs::write(&path, edit(text)).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn run_protected(p: &Protected, job: Option<&Path>, out: &Path) -> std::process::Output {
    let mut args = vec![
        "run",
        "--config",
        s(&p.config),
        "--node",
        s(&p.ws.node),
        "--out",
        s(out),
    ];
    if let Some(j) = job {
        args.push("--job-context");
        args.push(s(j));
    }
    run_cli(&args)
}

#[test]
fn a_protected_run_without_a_job_context_is_refused_before_any_input_is_read() {
    let node = node_or_return!();
    let p = protected("protected-none", &node);
    let out = p.output_root.join("out");
    let result = run_protected(&p, None, &out);
    assert_eq!(code(&result), 9);
    assert_eq!(reason(&summary(&result)), "protected-context-required");
    assert!(!out.exists());
    // Proof that nothing was read: the snapshot named by the configuration does
    // not even exist, and the refusal is the same.
    std::fs::remove_file(&p.snapshot).unwrap();
    let result = run_protected(&p, None, &out);
    assert_eq!(code(&result), 9);
    assert_eq!(reason(&summary(&result)), "protected-context-required");
}

#[test]
fn a_valid_job_context_binds_the_run_and_grants_nothing() {
    let node = node_or_return!();
    let p = protected("protected-ok", &node);
    let out = p.output_root.join("out");
    let job = job_context(&p, |t| t, 0o600);
    let result = run_protected(&p, Some(&job), &out);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    let v = summary(&result);
    assert_eq!(v["semantic"]["runClass"], "protected");
    // A protected run produces no public projection, and the summary says none.
    assert!(!out.join("public-synthetic-artifact.json").exists());
    assert!(v["semantic"].get("publicArtifactDigest").is_none());
    assert!(v["semantic"].get("populationCounts").is_none());
    assert_eq!(
        list_dir(&out),
        [
            "manifest.json",
            "observation-redact-secret-core.json",
            "run-artifact.json"
        ]
    );
    // The environment variable names the context too (the option wins).
    let out2 = p.output_root.join("out2");
    let result = run_cli_env(
        &[
            "run",
            "--config",
            s(&p.config),
            "--node",
            s(&node),
            "--out",
            s(&out2),
        ],
        &[("PII_EVAL_JOB_CONTEXT", s(&job))],
    );
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    // The context grants no access: an unreadable protected input stays unreadable.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p.snapshot, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(
            std::fs::read(&p.snapshot).is_err(),
            "this test needs a user that mode 000 binds: do not run the suite as root"
        );
        let result = run_protected(&p, Some(&job), &p.output_root.join("out3"));
        assert_eq!(code(&result), 3);
        assert_eq!(reason(&summary(&result)), "input-unreadable");
        std::fs::set_permissions(&p.snapshot, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn invalid_or_mismatched_job_contexts_and_paths_outside_it_are_refused_with_exit_9() {
    let node = node_or_return!();
    let p = protected("protected-bad", &node);
    let out = p.output_root.join("out");
    let digest = "0".repeat(64);
    let cases: Vec<(&str, PathBuf, &str)> = vec![
        (
            "world-writable",
            job_context(&p, |t| t, 0o666),
            "protected-context-invalid",
        ),
        (
            "not-json",
            job_context(&p, |_| "nope".into(), 0o600),
            "protected-context-invalid",
        ),
        (
            "wrong-class",
            job_context(
                &p,
                |t| {
                    t.replace(
                        "\"runClass\": \"protected\"",
                        "\"runClass\": \"public-synthetic\"",
                    )
                },
                0o600,
            ),
            "protected-context-invalid",
        ),
        (
            "unknown-field",
            job_context(
                &p,
                |t| t.replace("\"jobId\"", "\"extra\": 1, \"jobId\""),
                0o600,
            ),
            "protected-context-invalid",
        ),
        (
            "missing-root",
            job_context(
                &p,
                |t| t.replace("custodian-in", "custodian-missing"),
                0o600,
            ),
            "protected-context-invalid",
        ),
        (
            "relative-root",
            job_context(
                &p,
                |t| {
                    t.replacen(
                        s(&std::fs::canonicalize(&p.input_root).unwrap()),
                        "relative/dir",
                        1,
                    )
                },
                0o600,
            ),
            "protected-context-invalid",
        ),
    ];
    for (name, job, expected) in cases {
        let result = run_protected(&p, Some(&job), &out);
        assert_eq!(
            code(&result),
            9,
            "{name}: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        assert_eq!(reason(&summary(&result)), expected, "{name}");
        assert!(!out.exists(), "{name}");
    }
    // A context for another population or manifest, or another candidate.
    let pop = snapshot_digest_of(&p);
    for (name, from, expected) in [
        ("population", pop.clone(), "protected-context-mismatch"),
        (
            "manifest",
            manifest_digest_of(&p),
            "protected-context-mismatch",
        ),
    ] {
        let job = job_context(&p, |t| t.replace(&from, &digest), 0o600);
        let result = run_protected(&p, Some(&job), &out);
        assert_eq!(code(&result), 9, "{name}");
        assert_eq!(reason(&summary(&result)), expected, "{name}");
    }
    let candidate = pii_eval_adapters::sha256_of_tree(&p.ws.package).unwrap();
    let job = job_context(&p, |t| t.replace(candidate.as_str(), &digest), 0o600);
    assert_eq!(code(&run_protected(&p, Some(&job), &out)), 9);
    // Inputs outside the context's input root; an output outside its output root.
    let job = job_context(&p, |t| t, 0o600);
    let elsewhere = p.ws.tmp.0.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::copy(&p.snapshot, elsewhere.join("snapshot.json")).unwrap();
    let text = std::fs::read_to_string(&p.config)
        .unwrap()
        .replace(s(&p.snapshot), s(&elsewhere.join("snapshot.json")));
    let moved = p.ws.tmp.0.join("moved.json");
    std::fs::write(&moved, text).unwrap();
    let result = run_cli(&[
        "run",
        "--config",
        s(&moved),
        "--node",
        s(&node),
        "--out",
        s(&out),
        "--job-context",
        s(&job),
    ]);
    assert_eq!(code(&result), 9);
    assert_eq!(reason(&summary(&result)), "protected-path-outside-context");
    assert_eq!(detail(&summary(&result)), "input");
    let result = run_protected(&p, Some(&job), &p.ws.tmp.0.join("outside-out"));
    assert_eq!(code(&result), 9);
    assert_eq!(detail(&summary(&result)), "output");
    // A traversal through `..` that resolves outside is outside.
    let sneaky = p.output_root.join("../outside-too");
    assert_eq!(code(&run_protected(&p, Some(&job), &sneaky)), 9);
    // And a protected run is always official.
    let text = std::fs::read_to_string(&p.config)
        .unwrap()
        .replace("\"official\"", "\"exploratory\"");
    let exploratory = p.ws.tmp.0.join("exploratory.json");
    std::fs::write(&exploratory, text).unwrap();
    let result = run_cli(&[
        "run",
        "--config",
        s(&exploratory),
        "--node",
        s(&node),
        "--out",
        s(&out),
        "--job-context",
        s(&job),
    ]);
    assert_eq!(code(&result), 3);
}

fn snapshot_digest_of(p: &Protected) -> String {
    read_snapshot(&p.snapshot)
        .semantic_digest
        .as_str()
        .to_owned()
}

fn manifest_digest_of(p: &Protected) -> String {
    let m: RunManifest = parse_default(&std::fs::read(&p.manifest).unwrap()).unwrap();
    m.semantic_digest.as_str().to_owned()
}

// ---------------------------------------------------------------------------
// Summary snapshots
// ---------------------------------------------------------------------------

fn snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots")
}

fn assert_snapshot(name: &str, actual: &str) {
    let path = snapshot_dir().join(name);
    if std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(snapshot_dir()).unwrap();
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing snapshot {name}; run with PII_EVAL_UPDATE_FIXTURES=1"));
    assert_eq!(expected, actual, "summary snapshot {name} drifted");
}

#[test]
fn run_summaries_match_their_committed_snapshots() {
    let node = node_or_return!();
    // The example run: deterministic digests, no paths, no timestamps.
    let out = run_cli(&[
        "run",
        "--config",
        s(&example_dir().join("run-config.json")),
        "--node",
        s(&node),
        "--out",
        s(&Workspace::new("snapshot-run", &node).out("out")),
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_snapshot(
        "run-quickstart.json",
        &String::from_utf8(out.stdout).unwrap(),
    );
    // A scanner failure.
    let ws = Workspace::with("snapshot-failure", &node, limits(2, 1), 2, "9.9.9");
    let failed = ws.run(&ws.out("out"));
    assert_eq!(code(&failed), 5);
    let text = String::from_utf8(failed.stdout).unwrap();
    assert_snapshot("run-unavailable-scanner.json", &text);
}
