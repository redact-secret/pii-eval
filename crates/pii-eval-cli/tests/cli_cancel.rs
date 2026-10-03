//! Cancellation by signal, with real processes: a scanner that blocks forever
//! and leaves a descendant behind must be killed (process tree included) when
//! the CLI receives SIGINT or SIGTERM; nothing is committed, the scratch
//! directories are gone and the exit code is 8. Needs Node and `ps`.
//!
//! Waits use generous bounds (60 s) and polling, never a short shared deadline:
//! the suite runs under CPU load in CI.
#![cfg(unix)]

mod cli_support;
mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use cli_support::*;
use pii_eval_contracts::{Sha256Digest, seal, to_pretty_json};

struct Hanging {
    ws: Workspace,
    pids: PathBuf,
    scratch: PathBuf,
}

/// A workspace whose scanner blocks forever on a marked input and spawns a
/// descendant first. The package copy writes `"<scanner pid> <child pid>"` to a
/// file outside the pinned tree.
fn hanging(label: &str, node: &Path) -> Hanging {
    let tmp = crate::common::TempDir::new(label);
    let pids = tmp.0.join("pids.txt");
    let scratch = tmp.0.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let package = tmp.0.join("package");
    copy_dir(&fake_core_dir(), &package);
    let index = std::fs::read_to_string(package.join("lib/index.js")).unwrap();
    let patched = format!(
        "import {{ appendFileSync }} from 'node:fs';\nimport {{ spawn }} from 'node:child_process';\n{}",
        index.replace(
            "export const scan = (text, options) => {",
            &format!(
                "export const scan = (text, options) => {{\n  if (text.includes('HANG-MARKER')) {{\n    const child = spawn('sleep', ['300'], {{ stdio: 'ignore' }});\n    appendFileSync('{}', `${{process.pid}} ${{child.pid}}\\n`);\n    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);\n  }}",
                pids.display()
            )
        )
    );
    assert!(patched.contains("HANG-MARKER"));
    std::fs::write(package.join("lib/index.js"), patched).unwrap();
    // A snapshot whose first variant carries the marker.
    let mut snapshot = read_snapshot(&example_dir().join("snapshot.json"));
    let variant = &mut snapshot.semantic.cases[0].variants[0];
    variant.text = "HANG-MARKER jane@example.test and more text".to_owned();
    variant.text_digest = Sha256Digest::of_bytes(variant.text.as_bytes());
    seal(&mut snapshot).unwrap();
    let snapshot_path = tmp.0.join("snapshot.json");
    std::fs::write(&snapshot_path, to_pretty_json(&snapshot).unwrap()).unwrap();
    let manifest = manifest_for(&snapshot, &package, node, limits(2, 1), 2);
    let manifest_path = tmp.0.join("manifest.json");
    write_manifest(&manifest_path, &manifest);
    let config = tmp.0.join("run-config.json");
    let text = ConfigSpec::new(&snapshot_path, &manifest_path, &package)
        .json()
        .replace(
            r#""resources": "enforce""#,
            &format!(
                r#""resources": "enforce", "scratchDir": "{}""#,
                scratch.display()
            ),
        );
    std::fs::write(&config, text).unwrap();
    Hanging {
        ws: Workspace {
            tmp,
            snapshot: snapshot_path,
            manifest: manifest_path,
            config,
            package,
            node: node.to_path_buf(),
        },
        pids,
        scratch,
    }
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn signal(pid: u32, name: &str) {
    let status = Command::new("kill")
        .args([&format!("-{name}"), &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

fn spawn_run(h: &Hanging, out: &Path) -> Child {
    Command::new(bin())
        .args([
            "run",
            "--config",
            s(&h.ws.config),
            "--node",
            s(&h.ws.node),
            "--out",
            s(out),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts")
}

/// The scanner and descendant pids once the scanner is blocked.
fn blocked_pids(h: &Hanging) -> (u32, u32) {
    let mut found = None;
    wait_until("the scanner to block", || {
        let text = std::fs::read_to_string(&h.pids).unwrap_or_default();
        let mut parts = text.lines().next().unwrap_or_default().split_whitespace();
        if let (Some(a), Some(b)) = (parts.next(), parts.next()) {
            if let (Ok(a), Ok(b)) = (a.parse(), b.parse()) {
                found = Some((a, b));
                return true;
            }
        }
        false
    });
    found.unwrap()
}

fn finish(mut child: Child) -> std::process::Output {
    let start = Instant::now();
    loop {
        match child.try_wait().unwrap() {
            Some(_) => return child.wait_with_output().unwrap(),
            None => {
                assert!(
                    start.elapsed() < Duration::from_secs(60),
                    "the run did not exit after the signal"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn assert_cancelled_cleanly(
    h: &Hanging,
    out: &Path,
    output: &std::process::Output,
    pids: (u32, u32),
) {
    assert_eq!(
        code(output),
        8,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let v = summary(output);
    assert_eq!(v["state"], "error");
    assert_eq!(v["error"]["reason"], "cancelled");
    assert_eq!(v["exit"]["name"], "cancelled");
    assert_eq!(stderr(output).lines().count(), 1);
    // Nothing was committed and no directory was left behind.
    assert!(!out.exists(), "{:?}", list_dir(out));
    // Every process of the scanner tree is gone.
    wait_until("the scanner process to end", || !alive(pids.0));
    wait_until("the scanner's descendant to end", || !alive(pids.1));
    // The scratch directories were removed.
    assert!(
        list_dir(&h.scratch).is_empty(),
        "scratch left behind: {:?}",
        list_dir(&h.scratch)
    );
}

#[test]
fn sigterm_cancels_the_run_kills_the_scanner_tree_and_commits_nothing() {
    let node = node_or_return!();
    let h = hanging("cancel-term", &node);
    let out = h.ws.out("out");
    let child = spawn_run(&h, &out);
    let pids = blocked_pids(&h);
    assert!(alive(pids.0) && alive(pids.1));
    signal(child.id(), "TERM");
    let output = finish(child);
    assert_cancelled_cleanly(&h, &out, &output, pids);
}

#[test]
fn sigint_cancels_the_run_the_same_way() {
    let node = node_or_return!();
    let h = hanging("cancel-int", &node);
    let out = h.ws.out("out");
    let child = spawn_run(&h, &out);
    let pids = blocked_pids(&h);
    signal(child.id(), "INT");
    let output = finish(child);
    assert_cancelled_cleanly(&h, &out, &output, pids);
}

#[test]
fn a_second_signal_still_ends_the_process_with_the_cancelled_status() {
    let node = node_or_return!();
    let h = hanging("cancel-twice", &node);
    let out = h.ws.out("out");
    let child = spawn_run(&h, &out);
    let pids = blocked_pids(&h);
    signal(child.id(), "TERM");
    signal(child.id(), "TERM");
    let output = finish(child);
    assert_eq!(code(&output), 8);
    // After an immediate exit the scanner tree is the custodian's to contain
    // (documented). In the common case the first signal already cleaned it; in
    // any case nothing was committed (an immediate exit can leave the empty
    // output directory that was prepared before the run), and we remove
    // stragglers ourselves.
    assert!(list_dir(&out).is_empty(), "{:?}", list_dir(&out));
    for pid in [pids.0, pids.1] {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
}
