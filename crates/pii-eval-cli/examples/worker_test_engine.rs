//! TEST-ONLY engine for the real-Linux sandbox end to end (docs/worker-job.md,
//! tools/isolation/worker-e2e.mjs). Built only with the cargo feature
//! `worker-test-adapters` (`required-features`), so neither `cargo build` nor the
//! engine artifact ever contains it. SYNTHETIC data only.
//!
//! ```text
//! worker_test_engine --job FILE [--stage DIR --input DIR --scratch DIR]
//!     the launcher with the TestOnly adapter policy; inside the sandbox it is
//!     started as `/stage/engine --job /job/job.json` (the defaults are /stage,
//!     /input and /scratch). The aggregates channel is a TEST channel: the
//!     document is written to <scratch>/aggregates.json (a TestOnly copy; the
//!     delivery the custodian reads is the object embedded in the one stdout result)
//!     and also as ONE line on
//!     stderr (`pii-eval-worker-e2e-aggregates <json>`), because the sandbox's
//!     scratch is gone when the worker exits and the real channel is undecided (Q2).
//! worker_test_engine stage --out DIR --node PATH --scenario NAME [--entries N]
//!     builds the synthetic world with the REAL Node runtime as scanner-0 and a
//!     copy of THIS executable as engine: DIR/{stage,input,job}/ and DIR/pins.json.
//! worker_test_engine validate --dir DIR --stdout FILE --exit CODE|signal:NAME|timeout|output-limit
//!     [--aggregates FILE]
//!     the replica of the custodian's validate_result, outcome mapping and
//!     PrivateAggregates::decode (tests/worker_support/replica.rs); one JSON line.
//! ```
#![cfg(unix)]

#[path = "../tests/cli_support/mod.rs"]
#[allow(unused_imports)]
mod cli_support;
#[path = "../tests/common/mod.rs"]
#[allow(unused_imports)]
mod common;
#[path = "../tests/worker_support/mod.rs"]
#[allow(unused_imports)]
mod worker_support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pii_eval_cli::worker::contract::{
    Adapters, AggregatesChannelAdapter, ChannelError, ContractStatus, WorkerLayout,
};
use pii_eval_cli::worker::launch::{WorkerRequest, run_worker_job};
use pii_eval_cli::worker::test_adapters as t;
use serde_json::{Value, json};
use worker_support::replica::{Termination, report_json};
use worker_support::{HANG, Opts, World, sha};

/// Marker of the stderr line that carries the aggregates document.
const STDERR_PREFIX: &str = "pii-eval-worker-e2e-aggregates ";

/// Scenarios of `stage` (the expectation table is tools/isolation/worker-e2e.mjs).
const SCENARIOS: [&str; 10] = [
    "normal",
    "population-mismatch",
    "run-class-mismatch",
    "wrong-bundle-digest",
    "wrong-tree-digest",
    "wrong-runtime-digest",
    "scanner-crash",
    "scanner-hang",
    "stale-job",
    "staged-file-tampered",
];

/// The file channel plus the stderr line (see the module documentation).
struct E2eChannel;

impl AggregatesChannelAdapter for E2eChannel {
    fn status(&self) -> ContractStatus {
        ContractStatus::TestOnly
    }
    fn deliver(&self, layout: &WorkerLayout, document: &[u8]) -> Result<(), ChannelError> {
        t::FileChannel { fail: false }.deliver(layout, document)?;
        let text = std::str::from_utf8(document).map_err(|_| ChannelError)?;
        writeln!(std::io::stderr(), "{STDERR_PREFIX}{text}").map_err(|_| ChannelError)
    }
}

fn flags(args: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let key = k.strip_prefix("--").ok_or("not an option")?;
        let v = it.next().ok_or("missing value")?;
        if out.iter().any(|(n, _)| n == key) {
            return Err("duplicate option".into());
        }
        out.push((key.to_owned(), v.clone()));
    }
    Ok(out)
}

fn get<'a>(f: &'a [(String, String)], key: &str) -> Option<&'a str> {
    f.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

fn need<'a>(f: &'a [(String, String)], key: &str) -> Result<&'a str, String> {
    get(f, key).ok_or_else(|| format!("missing --{key}"))
}

fn engine(args: &[String]) -> ExitCode {
    let Ok(f) = flags(args) else {
        eprintln!("worker_test_engine: bad arguments");
        return ExitCode::from(2);
    };
    let Some(job) = get(&f, "job") else {
        eprintln!("worker_test_engine: missing --job");
        return ExitCode::from(2);
    };
    let layout = WorkerLayout {
        stage: PathBuf::from(get(&f, "stage").unwrap_or("/stage")),
        input: PathBuf::from(get(&f, "input").unwrap_or("/input")),
        scratch: PathBuf::from(get(&f, "scratch").unwrap_or("/scratch")),
    };
    let adapters = Adapters::production()
        .with_stage_layout(Box::new(t::TestLayout(layout)))
        .with_bundle_format(Box::new(t::TestBundle))
        .with_entry_format(Box::new(t::TestEntry))
        .with_aggregates_channel(Box::new(E2eChannel))
        .with_aggregate_labels(Box::new(t::TestLabels));
    let token = match pii_eval_cli::signals::install() {
        Ok(t) => t,
        Err(failure) => {
            eprintln!("{}", failure.human());
            return ExitCode::from(failure.exit.code());
        }
    };
    let result = run_worker_job(
        &WorkerRequest {
            job: Path::new(job),
            adapters: &adapters,
            policy: t::POLICY,
        },
        &token,
    );
    let rendered = pii_eval_cli::render_worker_result(result);
    let _ = std::io::stdout().write_all(rendered.stdout.as_bytes());
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().write_all(rendered.stderr.as_bytes());
    ExitCode::from(rendered.exit.code())
}

fn copy_file(from: &Path, to: &Path) -> Result<(), String> {
    // fs::copy keeps the permission bits (0500 and 0400 as staged by the world).
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|_| "copy failed".to_owned())
}

fn stage(args: &[String]) -> Result<Value, String> {
    let f = flags(args)?;
    let out = PathBuf::from(need(&f, "out")?);
    let node = PathBuf::from(need(&f, "node")?);
    let scenario = need(&f, "scenario")?;
    if !SCENARIOS.contains(&scenario) {
        return Err("unknown scenario".into());
    }
    let entries: usize =
        get(&f, "entries").map_or(Ok(3), |s| s.parse().map_err(|_| "bad --entries"))?;
    if !(3..=5000).contains(&entries) {
        return Err("--entries must be 3..=5000".into());
    }
    if out.exists() {
        return Err("--out must not exist".into());
    }
    let me = std::env::current_exe().map_err(|_| "no current exe")?;
    let mut opts = Opts {
        engine: Some(std::fs::read(&me).map_err(|_| "cannot read this executable")?),
        runtime: Some(std::fs::read(&node).map_err(|_| "cannot read node")?),
        entries: Some(entries),
        ..Opts::default()
    };
    match scenario {
        "scanner-crash" => opts.runtime = Some(b"#!/bin/sh\nexit 3\n".to_vec()),
        "scanner-hang" => {
            opts.trigger = Some(HANG);
            // Only the sandbox's wall clock may end it.
            opts.call_timeout_ms = Some(600_000);
        }
        _ => {}
    }
    let world = World::build(&format!("e2e-{scenario}"), &node, &opts);
    let zero = "0".repeat(64);
    match scenario {
        "population-mismatch" => world.edit_config(|c| c["population"]["digest"] = json!(zero)),
        "run-class-mismatch" => world.edit_config(|c| c["runClass"] = json!("public-synthetic")),
        "wrong-bundle-digest" => world.edit_config(|c| {
            c["artifacts"]["candidate"]["bundleDigest"] = json!(format!("sha256:{zero}"))
        }),
        "wrong-tree-digest" => {
            world.edit_config(|c| c["artifacts"]["candidate"]["treeDigest"] = json!(zero))
        }
        "wrong-runtime-digest" => world
            .edit_config(|c| c["artifacts"]["runtime"]["sha256"] = json!(sha(b"another runtime"))),
        "stale-job" => {
            let extra = world.input.join("zz-extra-entry");
            std::fs::write(&extra, b"{}").map_err(|_| "write failed")?;
            std::fs::set_permissions(&extra, std::os::unix::fs::PermissionsExt::from_mode(0o400))
                .map_err(|_| "chmod failed")?;
        }
        _ => {}
    }
    // The custodian freezes pins of the files as staged...
    let mut pins = world.pins();
    // ...and for this scenario something changes a staged file afterwards.
    if scenario == "staged-file-tampered" {
        let mut bytes = world.stage_bytes("candidate");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        world.stage_put("candidate", &bytes, 0o500);
    }
    let roster = world.entries.len();
    for d in ["stage", "input", "job"] {
        std::fs::create_dir_all(out.join(d)).map_err(|_| "mkdir failed")?;
    }
    for (name, _) in &pins {
        copy_file(&world.stage.join(name), &out.join("stage").join(name))?;
    }
    for entry in std::fs::read_dir(&world.input).map_err(|_| "read input")? {
        let entry = entry.map_err(|_| "read input")?;
        copy_file(&entry.path(), &out.join("input").join(entry.file_name()))?;
    }
    copy_file(&world.job, &out.join("job/job.json"))?;
    pins.sort();
    let pins_doc = json!({
        "schema": "pii-eval-worker-e2e-pins/1",
        "pins": pins.iter().map(|(n, d)| (n.clone(), json!(d))).collect::<serde_json::Map<_, _>>(),
        "roster": roster,
    });
    std::fs::write(out.join("pins.json"), pins_doc.to_string()).map_err(|_| "write pins")?;
    Ok(json!({"scenario": scenario, "entries": entries, "roster": roster}))
}

fn validate(args: &[String]) -> Result<Value, String> {
    let f = flags(args)?;
    let dir = PathBuf::from(need(&f, "dir")?);
    let pins: Value =
        serde_json::from_slice(&std::fs::read(dir.join("pins.json")).map_err(|_| "no pins.json")?)
            .map_err(|_| "bad pins.json")?;
    let roster = pins["roster"].as_u64().ok_or("bad roster")?;
    let stdout = std::fs::read(need(&f, "stdout")?).map_err(|_| "cannot read stdout file")?;
    let termination = Termination::parse(need(&f, "exit")?).ok_or("bad --exit")?;
    let aggregates = match get(&f, "aggregates") {
        Some(p) => Some(std::fs::read(p).map_err(|_| "cannot read aggregates file")?),
        None => None,
    };
    Ok(report_json(
        &termination,
        &stdout,
        aggregates.as_deref(),
        roster,
    ))
}

fn print(result: Result<Value, String>) -> ExitCode {
    match result {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("worker_test_engine: {message}");
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--job") => engine(&args),
        Some("stage") => print(stage(&args[1..])),
        Some("validate") => print(validate(&args[1..])),
        _ => {
            // The marker names this binary as test code (and keeps it linked).
            eprintln!(
                "usage ({}): worker_test_engine --job FILE | stage ... | validate ...",
                t::MARKER
            );
            ExitCode::from(2)
        }
    }
}
