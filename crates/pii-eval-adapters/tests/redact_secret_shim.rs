//! The production shim (`shims/node/redact-secret-core.mjs`) and the
//! `@redact-secret/core` vocabulary, run end to end against an inert synthetic
//! package that mimics the API subset the shim calls. Hermetic: no scanner is
//! installed. A test against the real pinned package is opt-in (below).
//!
//! Needs `node` 22; skipped with a printed reason otherwise unless
//! `PII_EVAL_REQUIRE_NODE=1` (set in CI).

mod common;

use std::path::PathBuf;

use common::*;
use pii_eval_adapters::error::{LimitKind, MissingCapability, PinKind};
use pii_eval_adapters::redact_secret::{
    CoreAdapterConfig, CorePin, PINNED_VERSION, SHIM_SHA256, core_adapter, parameters,
    shim_path_in_source_tree,
};
use pii_eval_adapters::{
    AdapterError, AdapterLimits, ProcessAdapter, ScanSession, ScannerAdapter, sha256_of_tree,
};
use pii_eval_contracts::{
    ActionCapability, ActionKind, CapabilityState, JurisdictionCode, ScannerConfiguration,
    Sha256Digest, VersionString,
};

/// Node 22 (the version the shim is validated on), or `None` after printing why.
fn node22_or_skip(test: &str) -> Option<PathBuf> {
    let node = node_or_skip(test)?;
    let version = std::process::Command::new(&node)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    if version.trim_start().starts_with("v22.") {
        return Some(node);
    }
    assert!(
        std::env::var("PII_EVAL_REQUIRE_NODE").as_deref() != Ok("1"),
        "Node 22 is required (PII_EVAL_REQUIRE_NODE=1), found {}",
        version.trim()
    );
    eprintln!(
        "SKIPPED {test}: Node 22 required, found `{}`",
        version.trim()
    );
    None
}

macro_rules! node22 {
    () => {
        match node22_or_skip(module_path!()) {
            Some(n) => n,
            None => return,
        }
    };
}

fn fake_core_config(node: PathBuf, limits: AdapterLimits) -> CoreAdapterConfig {
    let dir = fake_core_dir();
    let tree = sha256_of_tree(&dir).unwrap();
    CoreAdapterConfig {
        node,
        shim: shim_path_in_source_tree(),
        package_dir: dir,
        entry_relative: "lib/index.js".into(),
        pin: CorePin::candidate(VersionString::new(PINNED_VERSION).unwrap(), tree),
        shim_sha256: Sha256Digest::new(SHIM_SHA256).unwrap(),
        extra_artifacts: Vec::new(),
        limits,
    }
}

fn core_configuration(activation: &[&str]) -> ScannerConfiguration {
    ScannerConfiguration {
        parameters: parameters(),
        activation: selectors(activation),
    }
}

fn open(adapter: &ProcessAdapter, activation: &[&str]) -> Box<dyn ScanSession> {
    let plan = adapter.plan(core_configuration(activation)).expect("plan");
    adapter
        .start(&plan)
        .unwrap_or_else(|f| panic!("start failed: {}", f.error))
}

#[test]
fn shim_reports_pinned_identities_and_activation() {
    let node = node22!();
    let adapter = core_adapter(fake_core_config(node, fast_limits())).unwrap();
    let session = open(&adapter, &["pii:global", "pii:us"]);
    let rt = session.runtime();
    assert_eq!(rt.scanner_version, PINNED_VERSION);
    assert_eq!(rt.runtime_name, "node");
    assert!(rt.runtime_version.starts_with("v22."));
    assert_eq!(
        rt.activation_identity,
        "credentials=full;selectors=pii:global,pii:us;families=pii:global:email,pii:us:ssn;vocabulary=pii-context/v2"
    );
    assert_eq!(rt.shim_digest.as_str(), SHIM_SHA256);
    let caps = session.capabilities();
    assert_eq!(caps.action, ActionCapability::SanitizedOutput);
    assert_eq!(caps.sensitivity_classification, CapabilityState::Supported);
    let us = JurisdictionCode::new("US").unwrap();
    assert_eq!(caps.jurisdiction_state(&us), CapabilityState::Supported);
}

#[test]
fn shim_converts_utf16_offsets_and_keeps_action_and_output_apart() {
    let node = node22!();
    let adapter = core_adapter(fake_core_config(node, fast_limits())).unwrap();
    let mut session = open(&adapter, &["pii:global", "pii:us"]);
    // Hand-derived: 한글(6) + " "(1) + emoji(4) + " "(1) + "mail"(4) + " "(1) = 17.
    let text = "한글 😀 mail jane@example.org\r\nssn 123-45-6789";
    let out = session.scan(text).unwrap();
    let ranges: Vec<_> = out
        .findings
        .iter()
        .map(|f| (f.range.start, f.range.end))
        .collect();
    // "한글 😀 mail jane@example.org\r\n" is 17 + 16 + 2 = 35 bytes; "ssn " adds 4.
    assert_eq!(ranges, [(17, 33), (39, 50)]);
    assert_eq!(out.findings[0].action, Some(ActionKind::Redact));
    assert_eq!(out.findings[1].action, Some(ActionKind::Preserve));
    assert_eq!(
        out.findings[1].family.as_ref().unwrap().as_str(),
        "pii:us:ssn"
    );
    // The synthetic package mimics the real placeholder style.
    let expected = "한글 😀 mail <SECRET_1>\r\nssn 123-45-6789";
    assert_eq!(out.sanitized_output.as_ref().unwrap().as_str(), expected);
    assert_eq!(
        out.sanitized_output_digest,
        Some(Sha256Digest::of_bytes(expected.as_bytes()))
    );
}

#[test]
fn credential_findings_are_not_pii_observations() {
    let node = node22!();
    let adapter = core_adapter(fake_core_config(node, fast_limits())).unwrap();
    let mut session = open(&adapter, &["pii:global"]);
    let out = session
        .scan("id AKIAABCDEFGHIJKLMNOP and ann@ex.org")
        .unwrap();
    assert_eq!((out.findings.len(), out.skipped_findings), (1, 1));
    // The credential replacement still shows in the output; it is not hidden by skipping.
    assert!(!out.sanitized_output.unwrap().as_str().contains("AKIA"));
}

#[test]
fn pii_off_is_a_valid_activation_with_no_declared_families() {
    let node = node22!();
    let adapter = core_adapter(fake_core_config(node, fast_limits())).unwrap();
    let mut session = open(&adapter, &[]);
    assert!(session.capabilities().families.is_empty());
    let out = session.scan("ann@ex.org").unwrap();
    assert!(out.findings.is_empty());
    // Not a failure: the scanner ran with PII off. Whether that is the right
    // configuration is the plan's decision, and the activation digest records it.
    assert!(
        session
            .runtime()
            .activation_identity
            .contains("selectors=off;")
    );
}

#[test]
fn a_maximum_size_input_with_worst_case_json_escaping_is_scanned() {
    let node = node22!();
    let adapter = core_adapter(fake_core_config(node, fast_limits())).unwrap();
    let mut session = open(&adapter, &["pii:global"]);
    // 1 MiB of text; every control character is escaped to six bytes on the wire.
    let max = pii_eval_contracts::limits::MAX_TEXT_BYTES;
    let tail = "ann@ex.org";
    let text = format!("{}{tail}", "\u{1}".repeat(max - tail.len()));
    assert_eq!(text.len(), max);
    let out = session.scan(&text).unwrap();
    assert_eq!(out.findings.len(), 1);
    assert_eq!(out.findings[0].range.end as usize, max);
}

#[test]
fn unsupported_selector_maps_to_missing_capability() {
    let node = node22!();
    let adapter = core_adapter(fake_core_config(node, fast_limits())).unwrap();
    let plan = adapter.plan(core_configuration(&["pii:kr"])).unwrap();
    let Err(failure) = adapter.start(&plan) else {
        panic!("must fail")
    };
    assert_eq!(
        failure.error,
        AdapterError::MissingCapability(MissingCapability::SelectorUnsupported)
    );
    let kr = JurisdictionCode::new("KR").unwrap();
    assert_eq!(
        failure.capabilities.jurisdiction_state(&kr),
        CapabilityState::Unsupported
    );
}

#[test]
fn scanner_finding_limit_is_an_output_limit_failure() {
    let node = node22!();
    let limits = AdapterLimits {
        max_findings: 2,
        ..fast_limits()
    };
    let adapter = core_adapter(fake_core_config(node, limits)).unwrap();
    let mut session = open(&adapter, &["pii:global"]);
    let err = session.scan("a@b.co c@d.co e@f.co").unwrap_err();
    assert_eq!(err, AdapterError::OutputLimit(LimitKind::Findings));
}

#[test]
fn the_released_pin_does_not_accept_a_different_package() {
    let node = node22!();
    let mut config = fake_core_config(node, fast_limits());
    config.pin = CorePin::released_beta12();
    let adapter = core_adapter(config).unwrap();
    let plan = adapter.plan(core_configuration(&["pii:global"])).unwrap();
    let Err(failure) = adapter.start(&plan) else {
        panic!("must fail")
    };
    assert_eq!(
        failure.error,
        AdapterError::PinMismatch(PinKind::ArtifactDigest)
    );

    let mut config = fake_core_config(find_node().unwrap(), fast_limits());
    config.shim_sha256 = Sha256Digest::of_bytes(b"other shim");
    let adapter = core_adapter(config).unwrap();
    let plan = adapter.plan(core_configuration(&["pii:global"])).unwrap();
    let Err(failure) = adapter.start(&plan) else {
        panic!("must fail")
    };
    assert_eq!(
        failure.error,
        AdapterError::PinMismatch(PinKind::ShimDigest)
    );
}

/// Opt-in: the real pinned package. Set `PII_EVAL_REDACT_SECRET_CORE_DIR` to an
/// extracted `@redact-secret/core@0.1.0-beta.12` package directory, installed
/// with `npm install --ignore-scripts` into a scratch directory outside this
/// repository. Never part of hermetic CI.
#[test]
fn real_pinned_package_when_provided() {
    let Some(dir) = std::env::var_os("PII_EVAL_REDACT_SECRET_CORE_DIR") else {
        eprintln!(
            "SKIPPED real_pinned_package_when_provided: set PII_EVAL_REDACT_SECRET_CORE_DIR to an \
             extracted @redact-secret/core@0.1.0-beta.12 package directory to run it"
        );
        return;
    };
    let node = node22!();
    let adapter = core_adapter(CoreAdapterConfig {
        node,
        shim: shim_path_in_source_tree(),
        package_dir: PathBuf::from(dir),
        entry_relative: "dist/index.js".into(),
        pin: CorePin::released_beta12(),
        shim_sha256: Sha256Digest::new(SHIM_SHA256).unwrap(),
        extra_artifacts: Vec::new(),
        limits: fast_limits(),
    })
    .unwrap();
    let mut session = open(&adapter, &["pii:global", "pii:us"]);
    // Public test values: the IBAN example of the standard and a well-known
    // invalid SSN-shaped specimen. Offsets are hand-checked by slicing back.
    let text = "ko 한글 😀 iban DE89370400440532013000 ssn 078-05-1120\r\nend";
    let out = session.scan(text).unwrap();
    let slices: Vec<(&str, String)> = out
        .findings
        .iter()
        .map(|f| {
            (
                &text[f.range.start as usize..f.range.end as usize],
                f.family.as_ref().map(|x| x.to_string()).unwrap_or_default(),
            )
        })
        .collect();
    assert!(
        slices.contains(&("DE89370400440532013000", "pii:global:iban".to_owned())),
        "{}",
        slices.len()
    );
    assert!(
        slices.contains(&("078-05-1120", "pii:us:ssn".to_owned())),
        "{}",
        slices.len()
    );
    assert_eq!(session.runtime().scanner_version, PINNED_VERSION);
}
