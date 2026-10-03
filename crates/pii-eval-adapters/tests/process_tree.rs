//! Process-tree cleanup, outside aborts and resource limits (P7, ADR 0009),
//! against the inert fake scanner. Synthetic only.
//!
//! "No descendant is left" is checked by asking the operating system, not the
//! implementation: `ps` lists every process with its process group and state,
//! and a member counts as alive unless it is a zombie. The platform statement is
//! in `pii_eval_adapters::control`; these tests run on Unix only.
#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use pii_eval_adapters::error::{CallPhase, ResourceKind};
use pii_eval_adapters::{
    AbortReason, AdapterError, AdapterLimits, ScanSession, ScannerAdapter, StartOptions, Supervisor,
};

fn ps() -> PathBuf {
    ["/bin/ps", "/usr/bin/ps"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .expect("ps is available")
}

/// Live (non-zombie) members of a process group, as `(pid, state)`.
fn live_members(pgid: i32) -> Vec<(i32, String)> {
    let out = Command::new(ps())
        .args(["-A", "-o", "pgid=,pid=,stat="])
        .output()
        .expect("ps runs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let (g, p, s) = (f.next()?, f.next()?, f.next()?);
            Some((g.parse::<i32>().ok()?, p.parse::<i32>().ok()?, s.to_owned()))
        })
        .filter(|(g, _, s)| *g == pgid && !s.starts_with('Z'))
        .map(|(_, p, s)| (p, s))
        .collect()
}

fn pid_alive(pid: i32) -> bool {
    let out = Command::new(ps())
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    let state = String::from_utf8_lossy(&out.stdout);
    out.status.success() && !state.trim().is_empty() && !state.trim().starts_with('Z')
}

fn eventually(what: &str, timeout: Duration, mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < timeout, "timed out waiting for: {what}");
        thread::sleep(Duration::from_millis(25));
    }
}

fn pid_from(file: &Path) -> i32 {
    eventually("the descendant pid file", Duration::from_secs(10), || {
        file.exists()
            && std::fs::read_to_string(file).is_ok_and(|t| t.trim().parse::<i32>().is_ok())
    });
    std::fs::read_to_string(file)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn limits(call_timeout: Duration) -> AdapterLimits {
    AdapterLimits {
        startup_timeout: Duration::from_secs(10),
        call_timeout,
        ..AdapterLimits::default()
    }
}

fn start_with(node: &Path, call_timeout: Duration, options: &StartOptions) -> Box<dyn ScanSession> {
    let adapter = fake_adapter(node, "normal", limits(call_timeout));
    let plan = adapter
        .plan(configuration("normal", &["pii:global"]))
        .unwrap();
    adapter
        .start_with(&plan, options)
        .unwrap_or_else(|f| panic!("start failed: {}", f.error))
}

fn assert_tree_gone(pgid: i32, descendant: Option<i32>) {
    eventually(
        "the process tree to be gone",
        Duration::from_secs(10),
        || live_members(pgid).is_empty() && descendant.is_none_or(|p| !pid_alive(p)),
    );
}

#[test]
fn a_descendant_left_behind_is_killed_when_the_session_finishes() {
    let Some(node) = node_or_skip("a_descendant_left_behind_is_killed_when_the_session_finishes")
    else {
        return;
    };
    let dir = Scratch::new("tree-finish");
    let pidfile = dir.path().join("pid");
    let mut session = start_with(&node, Duration::from_secs(10), &StartOptions::default());
    let pgid = session.abort_handle().group_id().expect("a process group");
    let text = format!("#spawn {}", pidfile.display());
    session.scan(&text).expect("the scan itself succeeds");
    let descendant = pid_from(&pidfile);
    // While the session runs, the scanner and its descendant are both members.
    let members = live_members(pgid);
    assert!(members.len() >= 2, "scanner and descendant: {members:?}");
    assert!(members.iter().any(|(pid, _)| *pid == descendant));
    assert!(pid_alive(descendant));
    session.finish();
    assert_tree_gone(pgid, Some(descendant));
}

#[test]
fn a_timeout_kills_the_whole_tree_and_names_the_timeout() {
    let Some(node) = node_or_skip("a_timeout_kills_the_whole_tree_and_names_the_timeout") else {
        return;
    };
    let dir = Scratch::new("tree-timeout");
    let pidfile = dir.path().join("pid");
    let mut session = start_with(&node, Duration::from_millis(1500), &StartOptions::default());
    let pgid = session.abort_handle().group_id().unwrap();
    let text = format!("#spawnhang {}", pidfile.display());
    let error = session.scan(&text).unwrap_err();
    assert_eq!(error, AdapterError::Timeout(CallPhase::Scan));
    let descendant = pid_from(&pidfile);
    assert_tree_gone(pgid, Some(descendant));
    // The session is closed: never a clean result afterwards.
    assert_eq!(
        session.scan("later").unwrap_err(),
        AdapterError::SessionClosed
    );
}

#[test]
fn a_crash_does_not_leave_the_descendant_running() {
    let Some(node) = node_or_skip("a_crash_does_not_leave_the_descendant_running") else {
        return;
    };
    let dir = Scratch::new("tree-crash");
    let pidfile = dir.path().join("pid");
    let mut session = start_with(&node, Duration::from_secs(10), &StartOptions::default());
    let pgid = session.abort_handle().group_id().unwrap();
    let text = format!("#spawncrash {}", pidfile.display());
    let error = session.scan(&text).unwrap_err();
    assert_eq!(error, AdapterError::Crashed);
    let descendant = pid_from(&pidfile);
    assert_tree_gone(pgid, Some(descendant));
}

#[test]
fn a_descendant_holding_the_pipes_cannot_hang_the_caller() {
    let Some(node) = node_or_skip("a_descendant_holding_the_pipes_cannot_hang_the_caller") else {
        return;
    };
    let dir = Scratch::new("tree-holding");
    let pidfile = dir.path().join("pid");
    // The scanner exits at once, but its descendant keeps stdout open, so no
    // end-of-file ever arrives: the call deadline is the only way out.
    let mut session = start_with(&node, Duration::from_millis(1500), &StartOptions::default());
    let pgid = session.abort_handle().group_id().unwrap();
    let text = format!("#spawncrashholding {}", pidfile.display());
    let started = Instant::now();
    let error = session.scan(&text).unwrap_err();
    assert!(
        matches!(
            error,
            AdapterError::Timeout(CallPhase::Scan) | AdapterError::Crashed
        ),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    let descendant = pid_from(&pidfile);
    assert_tree_gone(pgid, Some(descendant));
}

#[test]
fn dropping_a_session_kills_the_tree() {
    let Some(node) = node_or_skip("dropping_a_session_kills_the_tree") else {
        return;
    };
    let dir = Scratch::new("tree-drop");
    let pidfile = dir.path().join("pid");
    let mut session = start_with(&node, Duration::from_secs(10), &StartOptions::default());
    let pgid = session.abort_handle().group_id().unwrap();
    session
        .scan(&format!("#spawn {}", pidfile.display()))
        .unwrap();
    let descendant = pid_from(&pidfile);
    assert!(pid_alive(descendant));
    drop(session);
    assert_tree_gone(pgid, Some(descendant));
}

#[test]
fn an_outside_cancel_unblocks_a_hung_call_and_is_named_cancelled() {
    let Some(node) = node_or_skip("an_outside_cancel_unblocks_a_hung_call_and_is_named_cancelled")
    else {
        return;
    };
    let mut session = start_with(&node, Duration::from_secs(60), &StartOptions::default());
    let handle = session.abort_handle();
    let pgid = handle.group_id().unwrap();
    let canceller = thread::spawn({
        let handle = handle.clone();
        move || {
            thread::sleep(Duration::from_millis(300));
            handle.trigger(AbortReason::Cancelled)
        }
    });
    let started = Instant::now();
    let error = session.scan("#hang").unwrap_err();
    assert!(canceller.join().unwrap(), "the cancel recorded its reason");
    assert_eq!(error, AdapterError::Cancelled);
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "unblocked long before the 60 s call deadline"
    );
    assert_eq!(handle.reason(), Some(AbortReason::Cancelled));
    assert_tree_gone(pgid, None);
    // A deadline that arrives after the cancel does not rewrite the cause.
    assert!(!handle.trigger(AbortReason::Timeout));
    assert_eq!(handle.reason(), Some(AbortReason::Cancelled));
}

#[test]
fn an_outside_deadline_is_named_a_total_timeout() {
    let Some(node) = node_or_skip("an_outside_deadline_is_named_a_total_timeout") else {
        return;
    };
    let mut session = start_with(&node, Duration::from_secs(60), &StartOptions::default());
    let handle = session.abort_handle();
    let pgid = handle.group_id().unwrap();
    let watchdog = thread::spawn({
        let handle = handle.clone();
        move || {
            thread::sleep(Duration::from_millis(300));
            handle.trigger(AbortReason::Timeout)
        }
    });
    let error = session.scan("#hang").unwrap_err();
    watchdog.join().unwrap();
    assert_eq!(error, AdapterError::Timeout(CallPhase::Total));
    assert_tree_gone(pgid, None);
}

fn supervised(
    max_rss: Option<u64>,
    scratch: Option<(&Path, u64)>,
) -> (StartOptions, Arc<Supervisor>) {
    let supervisor = Arc::new(Supervisor::start(Duration::from_millis(50)).expect("supervisor"));
    let options = StartOptions {
        scratch_dir: scratch.map(|(p, _)| p.to_path_buf()),
        supervisor: Some(Arc::clone(&supervisor)),
        max_rss_bytes: max_rss,
        max_scratch_bytes: scratch.map(|(_, n)| n),
    };
    (options, supervisor)
}

#[test]
fn a_session_over_its_memory_limit_is_aborted_and_named() {
    let Some(node) = node_or_skip("a_session_over_its_memory_limit_is_aborted_and_named") else {
        return;
    };
    // Node alone needs tens of MiB; the fake then holds 400 MiB. The limit sits
    // between the two, so the outcome does not depend on the host's baseline.
    let limit = 200 * 1024 * 1024;
    let (options, _supervisor) = supervised(Some(limit), None);
    let mut session = start_with(&node, Duration::from_secs(60), &options);
    let handle = session.abort_handle();
    let pgid = handle.group_id().unwrap();
    let error = session.scan("#mem 400").unwrap_err();
    assert_eq!(error, AdapterError::ResourceLimit(ResourceKind::Memory));
    assert!(
        handle.sampled_peak_rss_bytes() > limit,
        "the sampled peak is recorded: {}",
        handle.sampled_peak_rss_bytes()
    );
    assert_tree_gone(pgid, None);
}

#[test]
fn a_session_under_its_memory_limit_runs_and_reports_a_sampled_peak() {
    let Some(node) =
        node_or_skip("a_session_under_its_memory_limit_runs_and_reports_a_sampled_peak")
    else {
        return;
    };
    let (options, _supervisor) = supervised(Some(4 * 1024 * 1024 * 1024), None);
    let mut session = start_with(&node, Duration::from_secs(60), &options);
    // Slow enough for at least one sample (the interval is 50 ms).
    session.scan("#slow 400").expect("within limits");
    let stats = session.finish();
    assert!(
        stats.peak_rss_bytes > 1024 * 1024,
        "{}",
        stats.peak_rss_bytes
    );
    assert!(stats.pin_check.is_none());
}

#[test]
fn the_scanner_gets_the_scratch_directory_and_is_stopped_when_it_overfills_it() {
    let Some(node) =
        node_or_skip("the_scanner_gets_the_scratch_directory_and_is_stopped_when_it_overfills_it")
    else {
        return;
    };
    let root = Scratch::new("scratch");
    let dir = root.path().join("session");
    std::fs::create_dir(&dir).unwrap();
    let (options, _supervisor) = supervised(None, Some((&dir, 5 * 1024 * 1024)));
    // 1. TMPDIR is the session's scratch directory, whatever the parent had.
    let mut session = start_with(&node, Duration::from_secs(60), &options);
    let out = session.scan("#tmpdir").unwrap();
    let reported = out.sanitized_output.expect("output requested");
    assert_eq!(
        std::fs::canonicalize(reported.as_str()).unwrap(),
        std::fs::canonicalize(&dir).unwrap()
    );
    session.finish();
    // 2. Twenty MiB against a five MiB limit.
    let mut session = start_with(&node, Duration::from_secs(60), &options);
    let handle = session.abort_handle();
    let pgid = handle.group_id().unwrap();
    let error = session.scan("#tmpwrite 20").unwrap_err();
    assert_eq!(error, AdapterError::ResourceLimit(ResourceKind::Temporary));
    assert_tree_gone(pgid, None);
}
