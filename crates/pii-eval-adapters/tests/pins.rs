//! Pin verification happens before anything is executed. These tests use a
//! `sh` script as the "interpreter" that creates a marker file when (and only
//! when) it is spawned, so a missing marker proves nothing ran. Unix only; no
//! Node needed.
#![cfg(unix)]

mod common;

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use common::*;
use pii_eval_adapters::error::{PinKind, SpecProblem, StartupStage};
use pii_eval_adapters::pin::{MAX_ARTIFACT_BYTES, MAX_TREE_FILES};
use pii_eval_adapters::redact_secret::{SHIM_SHA256, shim_path_in_source_tree};
use pii_eval_adapters::{
    AdapterError, ArtifactPin, ProcessAdapter, ScannerAdapter, sha256_of_file, sha256_of_tree,
};
use pii_eval_contracts::{ProductIdentity, Sha256Digest};

fn marker_script(scratch: &Scratch) -> (std::path::PathBuf, std::path::PathBuf) {
    let marker = scratch.path().join("SPAWNED");
    let script = scratch.path().join("interpreter.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (script, marker)
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn adapter_with(
    interpreter: &Path,
    edit: impl FnOnce(&mut pii_eval_adapters::ProcessAdapterSpec),
) -> ProcessAdapter {
    // `node` is never run here, so any absolute path stands in for it.
    let mut spec = fake_spec(interpreter, startup_param("normal"), fast_limits());
    edit(&mut spec);
    ProcessAdapter::new(spec).expect("spec")
}

fn start_error(adapter: &ProcessAdapter) -> AdapterError {
    let plan = adapter
        .plan(configuration("normal", &["pii:global"]))
        .unwrap();
    match adapter.start(&plan) {
        Ok(_) => panic!("start must fail"),
        Err(f) => f.error,
    }
}

#[test]
fn wrong_pins_fail_before_the_interpreter_is_spawned() {
    let scratch = Scratch::new("pins");
    let (script, marker) = marker_script(&scratch);
    let wrong = Sha256Digest::of_bytes(b"not the pinned bytes");

    let bad_shim = adapter_with(&script, |s| s.shim.sha256 = wrong.clone());
    assert_eq!(
        start_error(&bad_shim),
        AdapterError::PinMismatch(PinKind::ShimDigest)
    );

    let bad_artifact = adapter_with(&script, |s| s.scanner_artifact.sha256 = wrong.clone());
    assert_eq!(
        start_error(&bad_artifact),
        AdapterError::PinMismatch(PinKind::ArtifactDigest)
    );

    let extra = ArtifactPin::file(fake_scanner(), wrong.clone());
    let bad_extra = adapter_with(&script, |s| s.extra_artifacts = vec![extra]);
    assert_eq!(
        start_error(&bad_extra),
        AdapterError::PinMismatch(PinKind::ArtifactDigest)
    );
    assert!(
        !marker.exists(),
        "the interpreter ran before a pin was verified"
    );

    // Positive control: with correct pins the script is spawned (and then, not
    // being a scanner, exits before `ready`).
    let good = adapter_with(&script, |_| {});
    assert_eq!(
        start_error(&good),
        AdapterError::StartupFailure(StartupStage::ExitedBeforeReady)
    );
    assert!(marker.exists());
}

#[test]
fn a_changed_candidate_tree_is_rejected_before_use() {
    let scratch = Scratch::new("candidate");
    let (script, marker) = marker_script(&scratch);
    let tree = scratch.path().join("candidate");
    copy_tree(&fake_core_dir(), &tree);
    let pinned = sha256_of_tree(&tree).unwrap();
    let make = |tree: &Path| {
        adapter_with(&script, |s| {
            s.scanner_artifact = ArtifactPin::tree(tree, pinned.clone());
            s.scanner_entry = tree.join("lib/index.js");
            s.product = ProductIdentity::Candidate {
                candidate_digest: pinned.clone(),
            };
        })
    };
    // Tampered file content.
    std::fs::write(tree.join("lib/index.js"), "export const VERSION = '9';\n").unwrap();
    assert_eq!(
        start_error(&make(&tree)),
        AdapterError::PinMismatch(PinKind::ArtifactDigest)
    );
    // Restore, then add a file.
    copy_tree(&fake_core_dir(), &tree);
    assert_eq!(sha256_of_tree(&tree).unwrap(), pinned);
    std::fs::write(tree.join("lib/extra.js"), "x").unwrap();
    assert_eq!(
        start_error(&make(&tree)),
        AdapterError::PinMismatch(PinKind::ArtifactDigest)
    );
    assert!(!marker.exists());
}

#[test]
fn symlinks_are_rejected_in_pinned_files_and_trees() {
    let scratch = Scratch::new("symlinks");
    let (script, marker) = marker_script(&scratch);
    let link = scratch.path().join("shim-link.mjs");
    symlink(fake_scanner(), &link).unwrap();
    assert_eq!(
        sha256_of_file(&link).unwrap_err(),
        AdapterError::PinMismatch(PinKind::ArtifactNotRegularFile)
    );
    let linked_shim = adapter_with(&script, |s| {
        s.shim = ArtifactPin::file(&link, sha256_of_file(&fake_scanner()).unwrap());
    });
    assert_eq!(
        start_error(&linked_shim),
        AdapterError::PinMismatch(PinKind::ArtifactNotRegularFile)
    );

    let tree = scratch.path().join("tree");
    copy_tree(&fake_core_dir(), &tree);
    symlink("/etc/hosts", tree.join("lib/link.js")).unwrap();
    assert_eq!(
        sha256_of_tree(&tree).unwrap_err(),
        AdapterError::PinMismatch(PinKind::ArtifactNotRegularFile)
    );
    assert!(!marker.exists());
}

#[test]
fn pin_reads_are_bounded() {
    let scratch = Scratch::new("bounds");
    let big = scratch.path().join("big.bin");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(MAX_ARTIFACT_BYTES + 1).unwrap();
    assert_eq!(
        sha256_of_file(&big).unwrap_err(),
        AdapterError::PinMismatch(PinKind::ArtifactTooLarge)
    );
    let many = scratch.path().join("many");
    std::fs::create_dir_all(&many).unwrap();
    for i in 0..=MAX_TREE_FILES {
        std::fs::write(many.join(format!("f{i}")), b"").unwrap();
    }
    assert_eq!(
        sha256_of_tree(&many).unwrap_err(),
        AdapterError::PinMismatch(PinKind::ArtifactTooLarge)
    );
    assert_eq!(
        sha256_of_file(Path::new("relative.txt")).unwrap_err(),
        AdapterError::InvalidSpec(SpecProblem::ArtifactPath)
    );
}

#[test]
fn tree_digest_follows_the_documented_construction() {
    // Listing of "<file sha256>  <relative path>\n", sorted bytewise by path.
    let dir = fake_core_dir();
    let line = |rel: &str| {
        let bytes = std::fs::read(dir.join(rel)).unwrap();
        format!("{}  {rel}\n", Sha256Digest::of_bytes(&bytes))
    };
    let listing = format!("{}{}", line("lib/index.js"), line("package.json"));
    assert_eq!(
        sha256_of_tree(&dir).unwrap(),
        Sha256Digest::of_bytes(listing.as_bytes())
    );
}

#[test]
fn the_shipped_shim_matches_its_pinned_digest() {
    assert_eq!(
        sha256_of_file(&shim_path_in_source_tree())
            .unwrap()
            .as_str(),
        SHIM_SHA256,
        "shims/node/redact-secret-core.mjs changed: bump ADAPTER_VERSION and SHIM_SHA256 together"
    );
}

#[test]
fn plan_identity_is_checked_against_the_plans_own_configuration() {
    let scratch = Scratch::new("planid");
    let (script, marker) = marker_script(&scratch);
    let adapter = adapter_with(&script, |_| {});
    let plan = adapter
        .plan(configuration("normal", &["pii:global"]))
        .unwrap();

    let mut wrong_config_digest = plan.clone();
    wrong_config_digest.identity.configuration_digest = Sha256Digest::of_bytes(b"x");
    let mut wrong_activation = plan.clone();
    wrong_activation.configuration.activation = selectors(&["pii:global", "pii:us"]);
    let mut wrong_version = plan.clone();
    wrong_version.identity.scanner_version =
        Some(pii_eval_contracts::VersionString::new("2.0.0").unwrap());
    let mut wrong_product = plan.clone();
    wrong_product.identity.product = ProductIdentity::Candidate {
        candidate_digest: Sha256Digest::of_bytes(b"x"),
    };
    let mut wrong_artifact = plan.clone();
    wrong_artifact.identity.artifact_digest = Some(Sha256Digest::of_bytes(b"x"));
    let mut wrong_adapter = plan;
    wrong_adapter.identity.adapter.normalization_version = 2;
    for tampered in [
        wrong_config_digest,
        wrong_activation,
        wrong_version,
        wrong_product,
        wrong_artifact,
        wrong_adapter,
    ] {
        match adapter.start(&tampered) {
            Ok(_) => panic!("tampered plan must not start"),
            Err(f) => assert_eq!(f.error, AdapterError::PinMismatch(PinKind::PlanIdentity)),
        }
    }
    assert!(!marker.exists());

    // A configuration outside the adapter's closed parameter set never gets a plan.
    let mut cfg = configuration("normal", &["pii:global"]);
    cfg.parameters = startup_param("different");
    assert_eq!(
        adapter.plan(cfg).unwrap_err(),
        AdapterError::InvalidSpec(SpecProblem::Parameters)
    );
}
