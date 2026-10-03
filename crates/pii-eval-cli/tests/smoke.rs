//! Bootstrap smoke test: touches every crate boundary and the synthetic
//! fixture. It asserts identity and fixture hygiene only; it makes no
//! measurement, accuracy or performance claim.

use std::path::PathBuf;
use std::process::Command;

use pii_eval_contracts::Role;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/smoke")
        .join(name)
}

#[test]
fn every_crate_boundary_reports_its_own_role() {
    let identities = [
        pii_eval_contracts::IDENTITY,
        pii_eval_kernel::IDENTITY,
        pii_eval_adapters::IDENTITY,
        pii_eval_cli::IDENTITY,
        pii_eval_compat::IDENTITY,
    ];
    let roles = [
        Role::Contracts,
        Role::Kernel,
        Role::Adapters,
        Role::Cli,
        Role::Compat,
    ];
    for (identity, role) in identities.iter().zip(roles) {
        assert_eq!(identity.role, role);
        assert_eq!(identity.package, format!("pii-eval-{}", role.as_str()));
        assert_eq!(identity.version, pii_eval_contracts::ENGINE_VERSION);
    }
}

#[test]
fn smoke_fixture_is_valid_utf8_and_marked_synthetic() {
    let bytes = std::fs::read(fixture("synthetic-smoke-v0.txt")).expect("fixture is committed");
    let text = std::str::from_utf8(&bytes).expect("fixture is UTF-8");
    assert!(text.starts_with("synthetic-fixture: true\n"));
    // Only the reserved example domain may appear as an address.
    for token in text.split_whitespace().filter(|t| t.contains('@')) {
        assert!(token.ends_with("@example.invalid") || token.ends_with(".invalid"));
    }
}

#[test]
fn binary_prints_identity_for_version_flag_and_rejects_incomplete_commands() {
    let binary = env!("CARGO_BIN_EXE_pii-eval");

    let ok = Command::new(binary)
        .arg("--version")
        .output()
        .expect("binary runs");
    assert!(ok.status.success());
    assert_eq!(
        String::from_utf8(ok.stdout).expect("utf-8"),
        format!("{}\n", pii_eval_cli::version_line())
    );

    let rejected = Command::new(binary)
        .arg("run")
        .output()
        .expect("binary runs");
    // `run` needs its options: a usage error (exit 2) with the JSON summary on
    // stdout and the usage text on stderr (docs/cli.md).
    assert_eq!(rejected.status.code(), Some(2));
    let stdout = String::from_utf8(rejected.stdout).expect("utf-8");
    assert!(stdout.contains("\"reason\":\"missing-required-option\""));
    assert!(
        String::from_utf8(rejected.stderr)
            .expect("utf-8")
            .contains("usage:")
    );
}
