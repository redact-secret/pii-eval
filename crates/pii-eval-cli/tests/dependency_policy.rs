//! Dependency guard: `pii-eval-contracts` and `pii-eval-kernel` must stay free
//! of process, network and other third-party dependencies unless a crate is
//! explicitly reviewed and added to the allowlist below (with a matching entry
//! in docs/dependency-policy.md). It inspects `cargo tree` output, so it needs
//! no extra crate and no network.

use std::collections::BTreeSet;
use std::process::Command;

/// Third-party crates the pure crates may depend on (normal dependencies,
/// transitive closure). Each entry is justified in docs/dependency-policy.md.
/// Direct: serde, serde_json, schemars, sha2. The rest is their reviewed
/// transitive closure (proc-macro support, hashing primitives, CPU feature
/// detection); none spawns processes or opens sockets.
const ALLOWED_THIRD_PARTY: &[&str] = &[
    "block-buffer",
    "cfg-if",
    "cpufeatures",
    "crypto-common",
    "digest",
    "dyn-clone",
    "hybrid-array",
    "itoa",
    "libc",
    "memchr",
    "proc-macro2",
    "quote",
    "ref-cast",
    "ref-cast-impl",
    "schemars",
    "schemars_derive",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_derive_internals",
    "serde_json",
    "sha2",
    "syn",
    "typenum",
    "unicode-ident",
    "zmij",
];

/// Forbidden-fragment matches that are reviewed exceptions, as (crate, the
/// only crate allowed to depend on it). `libc` is reached solely through
/// `cpufeatures` (CPU feature detection for `sha2`); the guard verifies that
/// no other crate depends on it.
const FRAGMENT_EXCEPTIONS: &[(&str, &str)] = &[("libc", "cpufeatures")];

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
            "normal,build",
            "--target",
            "all",
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

/// Names of the crates that depend directly on `target` within `package`'s
/// normal dependency graph.
fn direct_dependents(package: &str, target: &str) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "--locked",
            "--offline",
            "--edges",
            "normal,build",
            "--target",
            "all",
            "--prefix",
            "none",
            "--depth",
            "1",
            "--invert",
            target,
            "--package",
            package,
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree runs");
    assert!(output.status.success(), "cargo tree --invert failed");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .skip(1)
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
            if let Some((_, only)) = FRAGMENT_EXCEPTIONS.iter().find(|(c, _)| c == name) {
                assert_eq!(
                    direct_dependents(package, name),
                    BTreeSet::from([(*only).to_owned()]),
                    "{package}: `{name}` must be reached only through `{only}`"
                );
                continue;
            }
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
