//! Performance measurement driver (P10, ADR 0013). Not part of the product:
//! it is built and run in release mode by `tools/perf/run.mjs`, one process per
//! trial, so the orchestrator can measure CPU time and peak RSS from outside.
//!
//! ```text
//! perf generate --workload W --observations O [--repeat R]
//! perf replay   --workload W --observations O [--repeat R]
//! perf compat   --workload W --observations O [--repeat R]
//! perf engine   --workload W --observations O [--repeat R] [--workers N] [--batch B] [--per-scanner P] [--replays R]
//! perf emit     --workload W --observations O --dir D [--workers N]
//! perf parse    --doc FILE --kind snapshot|observation|artifact|manifest [--stage full|strict|typed|validate] [--repeat R]
//! perf scanner  --package DIR --pin candidate|released [--texts N] [--sessions S]
//! perf emit-cli --workload W --observations O --dir D --package DIR --pin candidate|released [--workers N] [--replays R]
//! perf prepare  --workload W --observations O          (the baseline whose process cost is subtracted)
//! ```
//! Output: one JSON object on stdout. Bounds: repeat <= 50, workers <= 256.

#[path = "../tests/parity/mod.rs"]
mod parity;
#[path = "../tests/perf/mod.rs"]
mod perf;
#[path = "../tests/perf/scanner.rs"]
mod scanner;

use std::path::PathBuf;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: perf <mode> [options] (see the module documentation)");
        std::process::exit(2);
    }
    let mode = args.remove(0);
    let mut opt = |name: &str| -> Option<String> {
        let i = args.iter().position(|a| a == name)?;
        let v = args.get(i + 1)?.clone();
        args.drain(i..=i + 1);
        Some(v)
    };
    let number = |v: Option<String>, dflt: u64, max: u64| -> u64 {
        v.map_or(dflt, |s| s.parse::<u64>().expect("an integer option"))
            .clamp(1, max)
    };
    let repeat = number(opt("--repeat"), 1, perf::MAX_REPEAT as u64) as usize;
    let workers = number(opt("--workers"), 4, u64::from(perf::MAX_WORKERS)) as u32;
    let batch = number(opt("--batch"), 2, 1024) as u32;
    let per_scanner = opt("--per-scanner");
    let replays = number(opt("--replays"), 2, 16) as u32;
    let workload = opt("--workload").map(PathBuf::from);
    let observations = opt("--observations").map(PathBuf::from);
    let dir = opt("--dir").map(PathBuf::from);
    let doc = opt("--doc").map(PathBuf::from);
    let kind = opt("--kind");
    let stage = opt("--stage").unwrap_or_else(|| "full".to_owned());
    let package = opt("--package").map(PathBuf::from);
    let pin = opt("--pin");
    let texts = number(opt("--texts"), 200, 100_000) as usize;
    let sessions = number(opt("--sessions"), 1, 16) as usize;
    let load = || {
        perf::load(
            workload.as_deref().expect("--workload"),
            observations.as_deref().expect("--observations"),
        )
        .unwrap_or_else(|e| {
            eprintln!("invalid workload: {e}");
            std::process::exit(3);
        })
    };
    let tmp = perf::scratch_dir();
    let out = match mode.as_str() {
        "generate" => perf::measure_generate(&load(), repeat),
        "replay" => perf::measure_replay(&load(), repeat, &tmp),
        "compat" => perf::measure_compat(&load(), repeat),
        "engine" => perf::measure_engine(
            &load(),
            repeat,
            workers,
            batch,
            per_scanner.map_or(workers.min(2), |v| v.parse().expect("an integer option")),
            replays,
        ),
        "prepare" => perf::measure_prepare(&load()),
        "emit" => perf::emit_documents(&load(), dir.as_deref().expect("--dir"), workers),
        "parse" => perf::measure_parse(
            doc.as_deref().expect("--doc"),
            kind.as_deref().expect("--kind"),
            &stage,
            repeat,
        ),
        "scanner" => scanner::measure_scanner(
            package.as_deref().expect("--package"),
            pin.as_deref().expect("--pin"),
            texts,
            sessions,
            workload.as_deref().zip(observations.as_deref()),
        ),
        "emit-cli" => scanner::emit_cli(
            &load(),
            dir.as_deref().expect("--dir"),
            package.as_deref().expect("--package"),
            pin.as_deref().expect("--pin"),
            workers,
            replays,
        ),
        other => {
            eprintln!("unknown mode {other}");
            std::process::exit(2);
        }
    };
    println!("{out}");
}
