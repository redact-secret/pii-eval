//! Process adapter behavior against the inert fake scanner shim: offsets,
//! observed actions, capabilities, failure states, pins, environment, injection
//! and leakage. Needs `node`; skipped with a printed reason when absent unless
//! `PII_EVAL_REQUIRE_NODE=1` (set in CI).

mod common;

use std::time::{Duration, Instant};

use common::*;
use pii_eval_adapters::error::{
    CallPhase, LimitKind, MalformedKind, MissingCapability, PinKind, ScannerErrorCode, SpecProblem,
    StartupStage,
};
use pii_eval_adapters::{AdapterError, AdapterLimits, ScannerAdapter, sha256_of_file};
use pii_eval_contracts::{
    ActionCapability, ActionKind, CapabilityState, FailureCode, JurisdictionCode, ScannerStatus,
    Sha256Digest,
};

macro_rules! node {
    () => {
        match node_or_skip(module_path!()) {
            Some(n) => n,
            None => return,
        }
    };
}

fn email_ranges(text: &str, session: &mut dyn pii_eval_adapters::ScanSession) -> Vec<(u64, u64)> {
    session
        .scan(text)
        .expect("scan")
        .findings
        .iter()
        .map(|f| (f.range.start, f.range.end))
        .collect()
}

#[test]
fn utf16_offsets_become_utf8_byte_ranges_for_unicode_crlf_and_combining_text() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let mut session = start(&adapter, "normal", &["pii:global"]);
    // (text, expected byte range of the email), derived by hand from UTF-8 widths:
    // Korean 3 bytes, emoji 4, CR/LF 1, U+0301 2.
    let cases: [(&str, (u64, u64)); 5] = [
        // 한글(6) + space(1) + emoji(4) + space(1) + "mail"(4) + space(1) = 17; email is 16 bytes.
        ("한글 😀 mail jane@example.org\r\nnext", (17, 33)),
        // "line1\r\n"(7) + "line2\r\n"(7) = 14; "bob@x.io" is 8 bytes.
        ("line1\r\nline2\r\nbob@x.io", (14, 22)),
        // e(1) + U+0301(2) + U+0301(2) + space(1) = 6; "a@b.co" is 6 bytes.
        ("e\u{301}\u{301} a@b.co", (6, 12)),
        // two emoji = 8 bytes; "x@y.zz" is 6 bytes.
        ("\u{1F600}\u{1F600}x@y.zz", (8, 14)),
        // 이메일(9) + ":"(1) = 10; "kim@ex.kr" is 9 bytes.
        ("이메일:kim@ex.kr", (10, 19)),
    ];
    for (text, (start, end)) in cases {
        let ranges = email_ranges(text, session.as_mut());
        assert_eq!(ranges, [(start, end)], "{}", text.len());
        let slice = &text.as_bytes()[start as usize..end as usize];
        assert!(std::str::from_utf8(slice).unwrap().contains('@'));
    }
    // The shim reported UTF-16 offsets (11..27 for the first case); the adapter
    // must not have passed them through.
    assert_ne!(
        email_ranges("한글 😀 mail jane@example.org", session.as_mut()),
        [(11, 27)]
    );
}

#[test]
fn reported_action_and_sanitized_output_are_separate_observations() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let mut session = start(&adapter, "normal", &["pii:global", "pii:us"]);
    let text = "mail ann@ex.org ssn 123-45-6789 end";
    let out = session.scan(text).expect("scan");
    // email: redact; ssn-shaped value: warn (reported, but the text is left in place).
    assert_eq!(out.findings.len(), 2);
    let (email, ssn) = (&out.findings[0], &out.findings[1]);
    assert_eq!((email.range.start, email.range.end), (5, 15));
    assert_eq!((ssn.range.start, ssn.range.end), (20, 31));
    assert_eq!(email.action, Some(ActionKind::Redact));
    assert_eq!(ssn.action, Some(ActionKind::Preserve));
    assert_eq!(email.family.as_ref().unwrap().as_str(), "pii:global:email");
    assert_eq!(ssn.family.as_ref().unwrap().as_str(), "pii:us:ssn");
    assert_eq!(ssn.jurisdiction.as_ref().unwrap().as_str(), "US");
    assert_eq!(email.jurisdiction, None);
    assert_eq!(ssn.sensitive, Some(true));
    // The output shows what remained, independent of the reported actions.
    let expected_output = "mail <R> ssn 123-45-6789 end";
    assert_eq!(
        out.sanitized_output.as_ref().unwrap().as_str(),
        expected_output
    );
    assert_eq!(
        out.sanitized_output_digest,
        Some(Sha256Digest::of_bytes(expected_output.as_bytes()))
    );
    assert_eq!(out.input_digest, Sha256Digest::of_bytes(text.as_bytes()));
    assert_eq!(
        session.capabilities().action,
        ActionCapability::SanitizedOutput
    );
    // The contract's observation form carries the digest, never the text.
    let observation = out.to_input_observation(pii_eval_contracts::Id::new("variant-one").unwrap());
    assert_eq!(
        observation.sanitized_output_digest,
        out.sanitized_output_digest
    );
}

#[test]
fn without_output_only_the_reported_action_is_available() {
    let node = node!();
    let mut spec = fake_spec(&node, startup_param("normal"), fast_limits());
    spec.return_output = false;
    let adapter = pii_eval_adapters::ProcessAdapter::new(spec).unwrap();
    let mut session = start(&adapter, "normal", &["pii:global"]);
    assert_eq!(
        session.capabilities().action,
        ActionCapability::ReportedAction
    );
    let out = session.scan("x ann@ex.org").unwrap();
    assert_eq!(out.findings[0].action, Some(ActionKind::Redact));
    assert_eq!(
        (out.sanitized_output_digest, out.sanitized_output),
        (None, None)
    );
}

#[test]
fn capabilities_come_from_the_running_scanner_and_unlisted_families_are_never_supported() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let session = start(&adapter, "normal", &["pii:global", "pii:us"]);
    let caps = session.capabilities();
    let us = JurisdictionCode::new("US").unwrap();
    let kr = JurisdictionCode::new("KR").unwrap();
    assert_eq!(caps.jurisdiction_state(&us), CapabilityState::Supported);
    assert_eq!(caps.jurisdiction_state(&kr), CapabilityState::Undeclared);
    let phone = pii_eval_contracts::FamilyId::new("pii:global:phone").unwrap();
    assert_eq!(caps.family_state(&phone), CapabilityState::Undeclared);
    assert_eq!(caps.ranges, CapabilityState::Supported);
    // Sorted, unique: the contract's canonical-order rule for capability lists.
    assert!(caps.families.windows(2).all(|w| w[0].family < w[1].family));
    // Without pii:us the scanner does not declare that family.
    let global = start(&adapter, "normal", &["pii:global"]);
    let ssn = pii_eval_contracts::FamilyId::new("pii:us:ssn").unwrap();
    assert_eq!(
        global.capabilities().family_state(&ssn),
        CapabilityState::Undeclared
    );
    // The runtime record repeats the pinned identities and adds what was observed.
    let rt = global.runtime();
    assert_eq!(rt.scanner_version, "1.0.0");
    assert_eq!(rt.runtime_name, "node");
    assert!(rt.activation_identity.contains("selectors=pii:global;"));
    assert_eq!(
        rt.activation_identity_digest,
        Sha256Digest::of_bytes(rt.activation_identity.as_bytes())
    );
}

#[test]
fn unsupported_jurisdiction_is_a_missing_capability_not_a_clean_scan() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let plan = adapter.plan(configuration("normal", &["pii:kr"])).unwrap();
    let Err(failure) = adapter.start(&plan) else {
        panic!("start must fail")
    };
    assert_eq!(
        failure.error,
        AdapterError::MissingCapability(MissingCapability::SelectorUnsupported)
    );
    assert_eq!(failure.error.failure_code(), Some(FailureCode::Unsupported));
    assert_eq!(
        failure.error.scanner_status(),
        Some(ScannerStatus::Unsupported)
    );
    let kr = JurisdictionCode::new("KR").unwrap();
    assert_eq!(
        failure.capabilities.jurisdiction_state(&kr),
        CapabilityState::Unsupported
    );
    // Nothing the scanner might report is declared supported.
    assert!(failure.capabilities.families.is_empty());
    assert_eq!(failure.capabilities.ranges, CapabilityState::Undeclared);

    // With several jurisdiction selectors the scanner does not say which one it
    // rejected, so none is marked unsupported.
    let plan = adapter
        .plan(configuration("normal", &["pii:kr", "pii:us"]))
        .unwrap();
    let Err(failure) = adapter.start(&plan) else {
        panic!("start must fail")
    };
    assert_eq!(
        failure.capabilities.jurisdiction_state(&kr),
        CapabilityState::Undeclared
    );
}

fn session_failure(adapter: &pii_eval_adapters::ProcessAdapter, text: &str) -> AdapterError {
    session_failure_within(adapter, text, Duration::from_secs(8))
}

fn session_failure_within(
    adapter: &pii_eval_adapters::ProcessAdapter,
    text: &str,
    bound: Duration,
) -> AdapterError {
    let mut session = start(adapter, "normal", &["pii:global"]);
    let started = Instant::now();
    let error = session.scan(text).expect_err("must fail");
    assert!(started.elapsed() < bound, "took {:?}", started.elapsed());
    // A failed session is closed; it never answers with a clean scan.
    assert_eq!(
        session.scan("ann@ex.org").unwrap_err(),
        AdapterError::SessionClosed
    );
    session.finish();
    assert_no_sentinel(&format!("{error}{error:?}"));
    error
}

#[test]
fn every_scan_failure_is_a_distinct_state_and_never_an_empty_result() {
    let node = node!();
    let small_line = AdapterLimits {
        max_line_bytes: 64 * 1024,
        ..fast_limits()
    };
    let slow = AdapterLimits {
        call_timeout: Duration::from_millis(500),
        ..fast_limits()
    };
    let few = AdapterLimits {
        max_findings: 5,
        ..fast_limits()
    };
    let normal = fake_adapter(&node, "normal", fast_limits());
    let m = AdapterError::MalformedOutput;
    let table: Vec<(&str, AdapterError)> = vec![
        ("#crash", AdapterError::Crashed),
        ("#exit0", m(MalformedKind::UnexpectedEof)),
        ("#truncated", m(MalformedKind::Truncated)),
        ("#malformed", m(MalformedKind::NotJson)),
        ("#null", m(MalformedKind::NotJson)),
        ("#dupkeys", m(MalformedKind::NotJson)),
        ("#extra", m(MalformedKind::UnknownField)),
        ("#wrongseq", m(MalformedKind::WrongSequence)),
        ("#badrange text", m(MalformedKind::InvalidRange)),
        ("#emptyrange text", m(MalformedKind::InvalidRange)),
        ("#invertedrange text", m(MalformedKind::InvalidRange)),
        ("#midpair \u{1F600} text", m(MalformedKind::InvalidRange)),
        ("#unknownaction text", m(MalformedKind::UnknownAction)),
        ("#badcode", m(MalformedKind::UnknownErrorCode)),
        ("#undeclared text", m(MalformedKind::Undeclared)),
        (
            "#scanerr",
            AdapterError::ScannerError(ScannerErrorCode::ScanFailed),
        ),
        (
            "#inputlimit",
            AdapterError::ScannerError(ScannerErrorCode::InputLimit),
        ),
        (
            "#findinglimit",
            AdapterError::OutputLimit(LimitKind::Findings),
        ),
    ];
    for (text, expected) in table {
        assert_eq!(session_failure(&normal, text), expected, "{text}");
    }
    let adapter = fake_adapter(&node, "normal", small_line);
    assert_eq!(
        session_failure(&adapter, "#huge"),
        AdapterError::OutputLimit(LimitKind::Line)
    );
    let adapter = fake_adapter(&node, "normal", slow);
    assert_eq!(
        session_failure_within(&adapter, "#hang", Duration::from_millis(3000)),
        AdapterError::Timeout(CallPhase::Scan)
    );
    let adapter = fake_adapter(&node, "normal", few);
    assert_eq!(
        session_failure(&adapter, "#toomany"),
        AdapterError::OutputLimit(LimitKind::Findings)
    );
    // Each variant maps to a contract failure code that explains a non-complete status.
    for e in [
        AdapterError::Crashed,
        m(MalformedKind::NotJson),
        AdapterError::OutputLimit(LimitKind::Line),
        AdapterError::Timeout(CallPhase::Scan),
    ] {
        let status = e.scanner_status().unwrap();
        assert_ne!(status, ScannerStatus::Complete);
        assert!(e.failure_code().unwrap().allowed_for(status));
    }
}

#[test]
fn oversized_input_is_refused_before_it_is_sent_and_does_not_end_the_session() {
    let node = node!();
    let limits = AdapterLimits {
        max_text_bytes: 1024,
        ..fast_limits()
    };
    let adapter = fake_adapter(&node, "normal", limits);
    let mut session = start(&adapter, "normal", &["pii:global"]);
    let big = "a".repeat(1025);
    assert_eq!(session.scan(&big).unwrap_err(), AdapterError::InputTooLarge);
    assert_eq!(AdapterError::InputTooLarge.failure_code(), None);
    assert!(session.scan("ok ann@ex.org").is_ok());
}

#[test]
fn startup_failures_are_distinct_from_each_other_and_from_scan_failures() {
    let node = node!();
    // Only the `hang` mode needs a short startup deadline. Every other mode
    // must finish well inside a generous one: a short shared deadline made the
    // table flaky when the machine was loaded (Node start-up plus pin hashing
    // can exceed 500 ms), turning an expected failure into Timeout(Startup).
    let hang_limits = AdapterLimits {
        startup_timeout: Duration::from_millis(500),
        ..fast_limits()
    };
    let patient_limits = AdapterLimits {
        startup_timeout: Duration::from_secs(30),
        ..fast_limits()
    };
    let table: Vec<(&str, AdapterError)> = vec![
        (
            "crash",
            AdapterError::StartupFailure(StartupStage::ExitedBeforeReady),
        ),
        (
            "exit0",
            AdapterError::StartupFailure(StartupStage::ExitedBeforeReady),
        ),
        (
            "bad-json",
            AdapterError::MalformedOutput(MalformedKind::NotJson),
        ),
        ("hang", AdapterError::Timeout(CallPhase::Startup)),
        (
            "init-error-initialization-failed",
            AdapterError::StartupFailure(StartupStage::ScannerInitialization),
        ),
        (
            "init-error-invalid-selector",
            AdapterError::MissingCapability(MissingCapability::ConfigurationRejected),
        ),
        (
            "init-error-unsupported-selector",
            AdapterError::MissingCapability(MissingCapability::SelectorUnsupported),
        ),
        (
            "init-error-scanner-error",
            AdapterError::StartupFailure(StartupStage::ScannerInitialization),
        ),
        ("wrong-id", AdapterError::PinMismatch(PinKind::ScannerId)),
        (
            "wrong-version",
            AdapterError::PinMismatch(PinKind::ScannerVersion),
        ),
        ("wrong-runtime", AdapterError::PinMismatch(PinKind::Runtime)),
        ("wrong-unit", AdapterError::PinMismatch(PinKind::OffsetUnit)),
        (
            "wrong-activation",
            AdapterError::PinMismatch(PinKind::Activation),
        ),
    ];
    for (mode, expected) in table {
        let limits = if mode == "hang" {
            hang_limits
        } else {
            patient_limits
        };
        let adapter = fake_adapter(&node, mode, limits);
        let plan = adapter.plan(configuration(mode, &["pii:global"])).unwrap();
        let Err(failure) = adapter.start(&plan) else {
            panic!("{mode}: start must fail")
        };
        assert_eq!(failure.error, expected, "{mode}");
        assert_no_sentinel(&format!("{:?}", failure));
    }
}

#[test]
fn a_binary_that_cannot_be_executed_is_a_spawn_failure() {
    let node = node!();
    // The shim script is a regular file without the execute bit: spawn fails.
    let mut spec = fake_spec(&node, startup_param("normal"), fast_limits());
    spec.executable = fake_scanner();
    let adapter = pii_eval_adapters::ProcessAdapter::new(spec).unwrap();
    let plan = adapter
        .plan(configuration("normal", &["pii:global"]))
        .unwrap();
    let Err(failure) = adapter.start(&plan) else {
        panic!("start must fail")
    };
    assert_eq!(
        failure.error,
        AdapterError::StartupFailure(StartupStage::Spawn)
    );
    assert_eq!(
        failure.error.scanner_status(),
        Some(ScannerStatus::Unavailable)
    );
}

#[test]
fn invalid_specs_are_rejected_before_anything_runs() {
    let node = node!();
    let relative = |mutate: &dyn Fn(&mut pii_eval_adapters::ProcessAdapterSpec)| {
        let mut spec = fake_spec(&node, startup_param("normal"), fast_limits());
        mutate(&mut spec);
        pii_eval_adapters::ProcessAdapter::new(spec).unwrap_err()
    };
    use pii_eval_adapters::ArtifactPin;
    assert_eq!(
        relative(&|s| s.executable = "node".into()),
        AdapterError::InvalidSpec(SpecProblem::Executable)
    );
    assert_eq!(
        relative(&|s| s.executable = "/definitely/not/here/node".into()),
        AdapterError::InvalidSpec(SpecProblem::Executable)
    );
    assert_eq!(
        relative(&|s| s.shim = ArtifactPin::file("relative/shim.mjs", s.shim.sha256.clone())),
        AdapterError::InvalidSpec(SpecProblem::ArtifactPath)
    );
    // The loaded entry must lie inside the verified artifact.
    assert_eq!(
        relative(&|s| s.scanner_entry = fake_scanner()),
        AdapterError::InvalidSpec(SpecProblem::ArtifactPath)
    );
    assert_eq!(
        relative(&|s| s.scanner_entry = fake_core_dir().join("lib/../package.json")),
        AdapterError::InvalidSpec(SpecProblem::ArtifactPath)
    );
    // Only names on the allowlist may be inherited; PATH and NODE_OPTIONS never.
    for name in ["PATH", "NODE_OPTIONS", "HOME", "LD_PRELOAD"] {
        assert_eq!(
            relative(&|s| s.inherit_env = vec![name.to_owned()]),
            AdapterError::InvalidSpec(SpecProblem::Environment),
            "{name}"
        );
    }
    // A candidate digest must be the artifact digest.
    assert_eq!(
        relative(&|s| {
            s.product = pii_eval_contracts::ProductIdentity::Candidate {
                candidate_digest: Sha256Digest::of_bytes(b"other"),
            }
        }),
        AdapterError::InvalidSpec(SpecProblem::Identity)
    );
    assert_eq!(
        relative(&|s| s.limits.call_timeout = Duration::ZERO),
        AdapterError::InvalidSpec(SpecProblem::Limits)
    );
}

#[test]
fn plan_rejects_unknown_parameters_and_malformed_selectors() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let mut cfg = configuration("normal", &["pii:global"]);
    cfg.parameters = vec![text_param("startup", "normal"), text_param("zextra", "1")];
    assert_eq!(
        adapter.plan(cfg).unwrap_err(),
        AdapterError::InvalidSpec(SpecProblem::Parameters)
    );
    let mut cfg = configuration("normal", &["pii:global"]);
    cfg.parameters = startup_param("other-mode");
    assert_eq!(
        adapter.plan(cfg).unwrap_err(),
        AdapterError::InvalidSpec(SpecProblem::Parameters)
    );
    // Valid per the contract's selector grammar, not for this scanner.
    for bad in ["pii-context:v2", "pii:us.x", "pii:usa"] {
        assert_eq!(
            adapter.plan(configuration("normal", &[bad])).unwrap_err(),
            AdapterError::InvalidSpec(SpecProblem::Selector),
            "{bad}"
        );
    }
}

const ENV_CHILD: &str = "PII_EVAL_ENV_HARNESS_CHILD";

/// Runs only inside the harness child spawned below; a no-op otherwise.
#[test]
fn env_harness_child() {
    if std::env::var_os(ENV_CHILD).is_none() {
        return;
    }
    let node = node!();
    // The hostile variables are really set in this process.
    for hostile in [
        "NODE_OPTIONS",
        "NODE_PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    ] {
        assert!(std::env::var_os(hostile).is_some(), "{hostile} not set");
    }
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let mut session = start(&adapter, "normal", &["pii:global"]);
    let out = session.scan("#env").unwrap();
    println!(
        "ENV-NAMES-BEGIN{}ENV-NAMES-END",
        out.sanitized_output.as_ref().unwrap().as_str()
    );
}

#[test]
fn environment_is_scrubbed_to_the_fixed_allowlist() {
    let _node = node!();
    // Launch this test binary as a child with hostile variables in its
    // environment; the child starts the adapter and reports what its shim saw.
    let exe = std::env::current_exe().unwrap();
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "env_harness_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENV_CHILD, "1")
        .env("NODE_OPTIONS", "--no-warnings")
        .env("NODE_PATH", "/nonexistent")
        .env("LD_PRELOAD", "")
        .env("LD_LIBRARY_PATH", "")
        .env("DYLD_INSERT_LIBRARIES", "")
        .env("DYLD_LIBRARY_PATH", "")
        .output()
        .expect("harness child runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "child failed: {stdout}");
    let json = stdout
        .split("ENV-NAMES-BEGIN")
        .nth(1)
        .and_then(|t| t.split("ENV-NAMES-END").next())
        .expect("child reported the shim environment");
    let names: Vec<String> = serde_json::from_str(json).unwrap();
    // The child itself had PATH, Cargo's variables and the hostile ones.
    assert!(std::env::var_os("PATH").is_some());
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    for forbidden in [
        "PATH",
        "HOME",
        "CARGO_MANIFEST_DIR",
        "NODE_OPTIONS",
        "NODE_PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        ENV_CHILD,
    ] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "{forbidden} leaked into the shim"
        );
    }
    // Only the protocol marker and a platform-injected variable may be present.
    for name in &names {
        assert!(
            name == "PII_EVAL_ADAPTER_PROTOCOL" || name == "__CF_USER_TEXT_ENCODING",
            "unexpected variable {name}"
        );
    }
    assert!(names.iter().any(|n| n == "PII_EVAL_ADAPTER_PROTOCOL"));
}

#[test]
fn a_shim_that_never_reads_stdin_cannot_block_the_caller() {
    let node = node!();
    let limits = AdapterLimits {
        call_timeout: Duration::from_millis(500),
        ..fast_limits()
    };
    let adapter = fake_adapter(&node, "noread", limits);
    let mut session = start(&adapter, "noread", &["pii:global"]);
    // Large texts fill the stdin pipe, so the writer thread stalls; the shim
    // pre-emitted answers to the first scans, so those return. A later send
    // finds the queue full and must time out instead of blocking forever.
    let text = "x".repeat(300 * 1024);
    let started = Instant::now();
    let mut outcome = None;
    for _ in 0..12 {
        match session.scan(&text) {
            Ok(_) => {}
            Err(e) => {
                outcome = Some(e);
                break;
            }
        }
    }
    assert_eq!(outcome, Some(AdapterError::Timeout(CallPhase::Scan)));
    assert!(
        started.elapsed() < Duration::from_millis(4000),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(session.scan("a").unwrap_err(), AdapterError::SessionClosed);
}

#[cfg(unix)]
fn process_exists(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(unix)]
fn shim_pid(session: &mut dyn pii_eval_adapters::ScanSession) -> String {
    let out = session.scan("#pid").unwrap();
    out.sanitized_output.unwrap().as_str().to_owned()
}

#[cfg(unix)]
fn assert_gone(pid: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while process_exists(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!process_exists(pid), "shim process {pid} is still alive");
}

#[cfg(unix)]
#[test]
fn the_shim_process_is_gone_after_timeout_failure_drop_and_finish() {
    let node = node!();
    let slow = AdapterLimits {
        call_timeout: Duration::from_millis(500),
        ..fast_limits()
    };
    let adapter = fake_adapter(&node, "normal", slow);

    let mut session = start(&adapter, "normal", &["pii:global"]);
    let pid = shim_pid(session.as_mut());
    assert!(process_exists(&pid), "positive control: the shim is alive");
    assert_eq!(
        session.scan("#hang").unwrap_err(),
        AdapterError::Timeout(CallPhase::Scan)
    );
    assert_gone(&pid);

    let mut session = start(&adapter, "normal", &["pii:global"]);
    let pid = shim_pid(session.as_mut());
    assert_eq!(session.scan("#crash").unwrap_err(), AdapterError::Crashed);
    assert_gone(&pid);

    let mut session = start(&adapter, "normal", &["pii:global"]);
    let pid = shim_pid(session.as_mut());
    assert!(process_exists(&pid));
    drop(session);
    assert_gone(&pid);

    let mut session = start(&adapter, "normal", &["pii:global"]);
    let pid = shim_pid(session.as_mut());
    session.finish();
    assert_gone(&pid);
}

#[test]
fn pins_are_rechecked_when_the_session_ends() {
    let node = node!();
    let scratch = Scratch::new("recheck");
    let tree = scratch.path().join("core");
    copy_dir(&fake_core_dir(), &tree);
    let mut spec = fake_spec(&node, startup_param("normal"), fast_limits());
    spec.scanner_artifact = pii_eval_adapters::ArtifactPin::tree(
        &tree,
        pii_eval_adapters::sha256_of_tree(&tree).unwrap(),
    );
    spec.scanner_entry = tree.join("lib/index.js");
    let adapter = pii_eval_adapters::ProcessAdapter::new(spec).unwrap();

    // Untouched: the end-of-session check passes.
    let mut session = start(&adapter, "normal", &["pii:global"]);
    session.scan("a ann@ex.org").unwrap();
    assert_eq!(session.finish().pin_check, None);

    // Swapped while the session runs: detected at the end.
    let mut session = start(&adapter, "normal", &["pii:global"]);
    session.scan("a ann@ex.org").unwrap();
    std::fs::write(tree.join("lib/index.js"), "// swapped\n").unwrap();
    assert_eq!(
        session.finish().pin_check,
        Some(AdapterError::PinMismatch(PinKind::ArtifactDigest))
    );
    // The adapter itself refuses a new session on the changed tree.
    let plan = adapter
        .plan(configuration("normal", &["pii:global"]))
        .unwrap();
    assert!(adapter.start(&plan).is_err());
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn inheritable_variables_are_passed_only_when_named() {
    let node = node!();
    let Some(tmpdir) = std::env::var_os("TMPDIR") else {
        eprintln!("SKIPPED inheritable_variables: TMPDIR is not set in this environment");
        return;
    };
    let mut spec = fake_spec(&node, startup_param("normal"), fast_limits());
    spec.inherit_env = vec!["TMPDIR".to_owned()];
    let adapter = pii_eval_adapters::ProcessAdapter::new(spec).unwrap();
    let mut session = start(&adapter, "normal", &["pii:global"]);
    let out = session.scan("#env").unwrap();
    let names: Vec<String> =
        serde_json::from_str(out.sanitized_output.as_ref().unwrap().as_str()).unwrap();
    assert!(names.iter().any(|n| n == "TMPDIR"), "{tmpdir:?}");
}

#[test]
fn configuration_text_is_inert_data_and_never_reaches_a_shell() {
    let node = node!();
    let scratch = Scratch::new("inject");
    let marker = scratch.path().join("MARKER");
    let hostile = format!(
        "$(touch {m}); `touch {m}` ; touch {m} | touch {m} && touch {m} > {m}\n--require x",
        m = marker.display()
    );
    let params = vec![
        text_param("startup", "normal"),
        text_param("zhostile", &hostile),
    ];
    let adapter =
        pii_eval_adapters::ProcessAdapter::new(fake_spec(&node, params.clone(), fast_limits()))
            .unwrap();
    let cfg = pii_eval_contracts::ScannerConfiguration {
        parameters: params,
        activation: selectors(&["pii:global"]),
    };
    let plan = adapter.plan(cfg).unwrap();
    let mut session = adapter.start(&plan).map_err(|f| f.error).expect("start");
    let out = session.scan("#params").unwrap();
    let echoed: serde_json::Value =
        serde_json::from_str(out.sanitized_output.as_ref().unwrap().as_str()).unwrap();
    // Delivered verbatim as a JSON string, executed by nothing.
    assert_eq!(echoed["zhostile"], hostile.as_str());
    assert!(!marker.exists());
    session.finish();
    assert!(!marker.exists());

    // A hostile value that is not the adapter's fixed parameter is rejected outright.
    let other = pii_eval_contracts::ScannerConfiguration {
        parameters: vec![
            text_param("startup", "normal"),
            text_param("zhostile", "$(id)"),
        ],
        activation: selectors(&["pii:global"]),
    };
    assert_eq!(
        adapter.plan(other).unwrap_err(),
        AdapterError::InvalidSpec(SpecProblem::Parameters)
    );
}

#[cfg(unix)]
#[test]
fn paths_with_shell_metacharacters_are_plain_arguments() {
    let node = node!();
    let scratch = Scratch::new("pathinject");
    let marker = scratch.path().join("MARKER");
    let dir = scratch.path().join(format!(
        "a b;touch {}",
        marker.display().to_string().replace('/', "_")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let shim = dir.join("shim $(x).mjs");
    std::fs::copy(fake_scanner(), &shim).unwrap();
    let mut spec = fake_spec(&node, startup_param("normal"), fast_limits());
    spec.shim = pii_eval_adapters::ArtifactPin::file(&shim, sha256_of_file(&shim).unwrap());
    let adapter = pii_eval_adapters::ProcessAdapter::new(spec).unwrap();
    let mut session = start(&adapter, "normal", &["pii:global"]);
    assert_eq!(session.scan("x ann@ex.org").unwrap().findings.len(), 1);
    assert!(!marker.exists());
}

#[test]
fn only_configuration_and_input_text_cross_the_boundary() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let mut session = start(&adapter, "normal", &["pii:global"]);
    session.scan("first ann@ex.org").unwrap();
    let out = session.scan("#audit").unwrap();
    // The fake recorded the key set of every message it received.
    let seen: Vec<Vec<String>> =
        serde_json::from_str(out.sanitized_output.as_ref().unwrap().as_str()).unwrap();
    assert_eq!(
        seen,
        vec![
            vec![
                "activation",
                "limits",
                "parameters",
                "protocol",
                "returnOutput",
                "type"
            ],
            vec!["seq", "text", "type"],
            vec!["seq", "text", "type"],
        ]
    );
}

#[test]
fn stderr_is_drained_counted_and_never_surfaced() {
    let node = node!();
    let limits = AdapterLimits {
        max_stderr_bytes: 4096,
        ..fast_limits()
    };
    let adapter = fake_adapter(&node, "stderr-flood", limits);
    let mut session = start(&adapter, "stderr-flood", &["pii:global"]);
    let out = session.scan("#stderr ann@ex.org").unwrap();
    assert_eq!(out.findings.len(), 1);
    let stats = session.finish();
    assert!(
        stats.stderr_bytes > 0 && stats.stderr_bytes <= 4096,
        "{stats:?}"
    );
    assert_no_sentinel(&format!("{out:?}{stats:?}"));
    assert_eq!(stats.scans, 1);
}

#[test]
fn matched_values_do_not_appear_in_debug_output() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let mut session = start(&adapter, "normal", &["pii:global"]);
    let text = format!("contact {SENTINEL}@example.org now");
    let out = session.scan(&text).unwrap();
    assert_eq!(out.findings.len(), 1);
    assert_no_sentinel(&format!("{out:?}"));
    assert_no_sentinel(&format!("{:?}", session.runtime()));
    assert_no_sentinel(&format!("{:?}", session.capabilities()));
}

#[test]
fn duplicate_and_unmapped_findings_are_kept_in_canonical_order() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let mut session = start(&adapter, "normal", &["pii:global"]);
    let out = session.scan("#dupfind abcdef").unwrap();
    assert_eq!(out.findings.len(), 2);
    assert_eq!(out.findings[0], out.findings[1]);
    // An unmapped PII type keeps its range and reports no family.
    let out = session.scan("#unmapped abcdef").unwrap();
    assert_eq!(out.findings.len(), 1);
    assert_eq!(out.findings[0].family, None);
    assert_eq!(out.findings[0].sensitive, Some(true));
    // Credential findings are counted, never reported as PII observations.
    let out = session
        .scan("key AKIAABCDEFGHIJKLMNOP and ann@ex.org")
        .unwrap();
    assert_eq!((out.findings.len(), out.skipped_findings), (1, 1));
    let sorted = out.findings.windows(2).all(|w| w[0] <= w[1]);
    assert!(sorted);
}

#[test]
fn repeated_and_concurrent_runs_are_identical() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let inputs = [
        "한글 😀 mail jane@example.org\r\nnext",
        "e\u{301} a@b.co and c@d.io ssn 123-45-6789",
        "nothing here",
        "line1\r\nline2\r\nbob@x.io",
    ];
    let run = || -> Vec<pii_eval_adapters::ScanOutput> {
        let mut s = start(&adapter, "normal", &["pii:global", "pii:us"]);
        let out = inputs.iter().map(|t| s.scan(t).unwrap()).collect();
        s.finish();
        out
    };
    let first = run();
    assert_eq!(first, run());
    // Same session, same text twice.
    let mut s = start(&adapter, "normal", &["pii:global", "pii:us"]);
    assert_eq!(s.scan(inputs[1]).unwrap(), s.scan(inputs[1]).unwrap());
    // Four sessions at once, results compared in input order.
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4).map(|_| scope.spawn(run)).collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for r in results {
        assert_eq!(r, first);
    }
}

#[test]
fn finish_stops_the_process_and_is_idempotent() {
    let node = node!();
    let adapter = fake_adapter(&node, "normal", fast_limits());
    let mut session = start(&adapter, "normal", &["pii:global"]);
    session.scan("a ann@ex.org").unwrap();
    let a = session.finish();
    let b = session.finish();
    assert_eq!((a.scans, b.scans), (1, 1));
    assert_eq!(
        session.scan("a ann@ex.org").unwrap_err(),
        AdapterError::SessionClosed
    );
}
