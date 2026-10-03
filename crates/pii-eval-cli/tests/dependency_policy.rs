//! Dependency guard: `pii-eval-contracts` and `pii-eval-kernel` must stay free
//! of process, network and other third-party dependencies unless a crate is
//! explicitly reviewed and added to the allowlist below (with a matching entry
//! in docs/dependency-policy.md). It inspects `cargo tree` output, so it needs
//! no extra crate and no network.

use std::collections::BTreeSet;
use std::process::Command;

/// Third-party crates the pure crates may depend on (normal dependencies,
/// transitive closure). Empty until a reviewed, justified addition.
const ALLOWED_THIRD_PARTY: &[&str] = &[];

/// Crates the pure layers must never reach, even if someone widens the
/// allowlist by mistake. Substring match on the crate name.
const FORBIDDEN_FRAGMENTS: &[&str] = &[
    "tokio",
    "reqwest",
    "hyper",
    "ureq",
    "curl",
    "isahc",
    "surf",
    "h2",
    "rustls",
    "openssl",
    "native-tls",
    "socket2",
    "mio",
    "duct",
    "subprocess",
    "nix",
    "libc",
    "git2",
    "octocrab",
];

const PURE_CRATES: &[&str] = &["pii-eval-contracts", "pii-eval-kernel"];
const WORKSPACE_CRATES: &[&str] = &[
    "pii-eval-contracts",
    "pii-eval-kernel",
    "pii-eval-adapters",
    "pii-eval-cli",
    "pii-eval-compat",
];

fn normal_closure(package: &str) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "--locked",
            "--offline",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--package",
            package,
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree failed for {package}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn pure_crates_have_no_unreviewed_dependencies() {
    for package in PURE_CRATES {
        let closure = normal_closure(package);
        assert!(
            closure.contains(*package),
            "{package} missing from its own tree"
        );
        for name in &closure {
            let allowed = WORKSPACE_CRATES.contains(&name.as_str())
                || ALLOWED_THIRD_PARTY.contains(&name.as_str());
            assert!(allowed, "{package} depends on unreviewed crate `{name}`");
            assert!(
                !FORBIDDEN_FRAGMENTS.iter().any(|f| name.contains(f)),
                "{package} depends on forbidden crate `{name}`"
            );
        }
    }
}

#[test]
fn kernel_and_contracts_do_not_depend_on_adapters_cli_or_compat() {
    for package in PURE_CRATES {
        let closure = normal_closure(package);
        for upward in ["pii-eval-adapters", "pii-eval-cli", "pii-eval-compat"] {
            assert!(!closure.contains(upward), "{package} depends on {upward}");
        }
    }
    // Contracts is the root of the graph: it may not depend on the kernel.
    assert!(!normal_closure("pii-eval-contracts").contains("pii-eval-kernel"));
}

#[test]
fn only_the_cli_test_graph_reaches_compat() {
    for package in ["pii-eval-adapters", "pii-eval-kernel", "pii-eval-cli"] {
        assert!(
            !normal_closure(package).contains("pii-eval-compat"),
            "{package} depends on removable compat crate"
        );
    }
}
