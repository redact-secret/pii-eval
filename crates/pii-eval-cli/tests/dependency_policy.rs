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
/// only crates allowed to depend on it) for the PURE crates. `libc` is reached
/// solely through `cpufeatures` (CPU feature detection for `sha2`); the guard
/// verifies that no other crate depends on it.
const FRAGMENT_EXCEPTIONS: &[(&str, &[&str])] = &[("libc", &["cpufeatures"])];

/// Third-party crates only the adapters crate may add (P7, ADR 0009): `rustix`
/// signals a process group and reads the peak RSS of waited-for children, safe
/// wrappers over syscalls `std` does not expose, so first-party crates keep
/// `forbid(unsafe_code)`. The rest is its reviewed closure (flag types, errno,
/// the Linux syscall table, the Windows import shims that `--target all`
/// lists). Each is justified in docs/dependency-policy.md. The pure crates may
/// not use any of them.
const ADAPTER_EXTRA_THIRD_PARTY: &[&str] = &[
    "bitflags",
    "errno",
    "linux-raw-sys",
    "rustix",
    "windows-link",
    "windows-sys",
];

/// Reviewed exceptions for the adapters: `libc` may also be reached through
/// `rustix` and `errno` (the libc backend on non-Linux Unix targets).
const ADAPTER_FRAGMENT_EXCEPTIONS: &[(&str, &[&str])] =
    &[("libc", &["cpufeatures", "errno", "rustix"])];

/// Third-party crates only the CLI crate may add (P8, ADR 0010): `signal-hook`
/// (flag-setting handlers for SIGINT and SIGTERM; `std` has no signal API and
/// first-party crates forbid `unsafe`) and its registry. Each is justified in
/// docs/dependency-policy.md. Contracts, kernel and adapters may not use them.
const CLI_EXTRA_THIRD_PARTY: &[&str] = &["signal-hook", "signal-hook-registry"];

/// Reviewed exceptions for the CLI: `libc` may also be reached through the
/// signal crates.
const CLI_FRAGMENT_EXCEPTIONS: &[(&str, &[&str])] = &[(
    "libc",
    &[
        "cpufeatures",
        "errno",
        "rustix",
        "signal-hook",
        "signal-hook-registry",
    ],
)];

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
    "pii-eval-app",
];

fn closure_with_edges(package: &str, edges: &str) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "--locked",
            "--edges",
            edges,
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

fn normal_closure(package: &str) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "--locked",
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
                    only.iter()
                        .map(|s| (*s).to_owned())
                        .collect::<BTreeSet<_>>(),
                    "{package}: `{name}` must be reached only through {only:?}"
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

/// The adapters crate spawns processes through `std` only. It may use the same
/// reviewed third-party set as the pure crates plus `rustix` and its closure
/// (P7, [`ADAPTER_EXTRA_THIRD_PARTY`]) and nothing else: no async runtime, HTTP
/// client, process helper or Git library.
#[test]
fn adapters_use_only_the_reviewed_crates_and_std_for_processes() {
    let package = "pii-eval-adapters";
    let closure = normal_closure(package);
    assert!(closure.contains(package));
    for name in &closure {
        let allowed = WORKSPACE_CRATES.contains(&name.as_str())
            || ALLOWED_THIRD_PARTY.contains(&name.as_str())
            || ADAPTER_EXTRA_THIRD_PARTY.contains(&name.as_str());
        assert!(allowed, "{package} depends on unreviewed crate `{name}`");
        if let Some((_, only)) = ADAPTER_FRAGMENT_EXCEPTIONS.iter().find(|(c, _)| c == name) {
            let dependents = direct_dependents(package, name);
            let allowed: BTreeSet<String> = only.iter().map(|s| (*s).to_owned()).collect();
            assert!(
                !dependents.is_empty() && dependents.is_subset(&allowed),
                "{package}: `{name}` must be reached only through {only:?}, found {dependents:?}"
            );
            continue;
        }
        assert!(
            !FORBIDDEN_FRAGMENTS.iter().any(|f| name.contains(f)),
            "{package} depends on forbidden crate `{name}`"
        );
    }
}

/// The CLI crate adds exactly the signal crates to the adapters' reviewed set and
/// nothing else, and those crates stay out of the contracts, kernel and adapters
/// closures (so the pure crates' guard above is unchanged).
#[test]
fn the_cli_adds_only_the_reviewed_signal_crates() {
    let package = "pii-eval-cli";
    let closure = normal_closure(package);
    assert!(closure.contains(package));
    for name in &closure {
        let allowed = WORKSPACE_CRATES.contains(&name.as_str())
            || ALLOWED_THIRD_PARTY.contains(&name.as_str())
            || ADAPTER_EXTRA_THIRD_PARTY.contains(&name.as_str())
            || CLI_EXTRA_THIRD_PARTY.contains(&name.as_str());
        assert!(allowed, "{package} depends on unreviewed crate `{name}`");
        if let Some((_, only)) = CLI_FRAGMENT_EXCEPTIONS.iter().find(|(c, _)| c == name) {
            let dependents = direct_dependents(package, name);
            let allowed: BTreeSet<String> = only.iter().map(|s| (*s).to_owned()).collect();
            assert!(
                !dependents.is_empty() && dependents.is_subset(&allowed),
                "{package}: `{name}` must be reached only through {only:?}, found {dependents:?}"
            );
            continue;
        }
        assert!(
            !FORBIDDEN_FRAGMENTS.iter().any(|f| name.contains(f)),
            "{package} depends on forbidden crate `{name}`"
        );
    }
    for lower in ["pii-eval-contracts", "pii-eval-kernel", "pii-eval-adapters"] {
        let lower_closure = normal_closure(lower);
        for extra in CLI_EXTRA_THIRD_PARTY {
            assert!(
                !lower_closure.contains(*extra),
                "{lower} must not depend on `{extra}`"
            );
        }
    }
}

/// The internal GitHub App crate (P11, ADR 0011) adds no third-party crate: its
/// closure is exactly the CLI's reviewed set (it uses the CLI library, `serde`,
/// `serde_json` and `sha2`). A transport crate (HTTP client or server, JWT/RSA
/// signing) therefore fails here until the guard and docs/dependency-policy.md
/// are changed deliberately; the forbidden fragments stay forbidden.
#[test]
fn the_app_adds_no_third_party_crate() {
    let package = "pii-eval-app";
    let closure = normal_closure(package);
    assert!(closure.contains(package));
    assert!(
        closure.contains("pii-eval-cli"),
        "the app runs jobs through the CLI library"
    );
    for name in &closure {
        let allowed = WORKSPACE_CRATES.contains(&name.as_str())
            || ALLOWED_THIRD_PARTY.contains(&name.as_str())
            || ADAPTER_EXTRA_THIRD_PARTY.contains(&name.as_str())
            || CLI_EXTRA_THIRD_PARTY.contains(&name.as_str());
        assert!(allowed, "{package} depends on unreviewed crate `{name}`");
        if let Some((_, only)) = CLI_FRAGMENT_EXCEPTIONS.iter().find(|(c, _)| c == name) {
            let dependents = direct_dependents(package, name);
            let allowed: BTreeSet<String> = only.iter().map(|s| (*s).to_owned()).collect();
            assert!(
                !dependents.is_empty() && dependents.is_subset(&allowed),
                "{package}: `{name}` must be reached only through {only:?}, found {dependents:?}"
            );
            continue;
        }
        assert!(
            !FORBIDDEN_FRAGMENTS.iter().any(|f| name.contains(f)),
            "{package} depends on forbidden crate `{name}`"
        );
    }
}

/// The dependency points one way: no other workspace crate reaches the app, by
/// any edge kind (normal, build or dev), so the CLI builds, tests and works with
/// the app crate absent from its closure (ADR 0011, D1).
#[test]
fn nothing_in_the_workspace_depends_on_the_app() {
    for package in [
        "pii-eval-contracts",
        "pii-eval-kernel",
        "pii-eval-adapters",
        "pii-eval-cli",
        "pii-eval-compat",
    ] {
        for edges in ["normal,build", "all"] {
            assert!(
                !closure_with_edges(package, edges).contains("pii-eval-app"),
                "{package} reaches pii-eval-app through {edges} edges"
            );
        }
    }
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
