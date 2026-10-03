# Performance: measurement, scaling, memory ceilings and budgets

Status: implemented for P10 (issue #11); subject to review.
Decisions and their reasons: [ADR 0013](adr/0013-performance-measurement-budgets-and-optimizations.md).
Raw results: [docs/perf/results/](perf/results/). Budgets: [docs/perf/budgets.json](perf/budgets.json).
Tooling: `tools/perf/`, `crates/pii-eval-cli/examples/perf.rs`, `crates/pii-eval-cli/tests/perf/`.

This document reports what was measured, how, on which host, with what
uncertainty, and what is **not** claimed. Nothing here is a throughput promise: a
number is a measurement of one build, on one shared development host, on
synthetic workloads, and it only means something next to the baseline it was taken
against. Every table below is generated from the committed raw results by
`node tools/perf/report.mjs docs/perf/results/<suite>.json`, never typed by hand.

## Host, toolchain and conditions

| Item | Value |
| --- | --- |
| Machine | Apple M4, 10 logical CPUs (4 performance, 6 efficiency), 24 GiB, macOS 26.5.2 (arm64), on AC power |
| Rust | rustc 1.98.1 (48a229cea 2026-09-01) (host: aarch64-apple-darwin, LLVM version: 22.1.8), cargo 1.98.1 (797e8a9bc 2026-08-05); `rust-toolchain.toml` sha256 `887f9be066a1`; RUSTFLAGS unset |
| Build profile | workspace [profile.release]: overflow-checks = true; defaults otherwise (opt-level 3, no LTO, 16 codegen units, panic unwind) |
| Node | v22.16.0 (V8 12.4.254.21-node.26, ICU 77.1) |
| Oracle | `redact-secret-benchmarks` `4b846967346505baca11e0b98cab1475fbce6773` (tree digest verified before every run) |
| Repository | base commit `6bb0e75` plus the uncommitted P10 working tree (the binaries' sha256 are in each result) |
| Collector | `/usr/bin/time -l`; idle fraction from the kernel tick counters before each trial |
| Conditions | **Shared host.** Other agents' builds and test runs ran throughout; the one-minute load average was between 9 and 26 when the suites started. 160 of 1074 recorded trials (15%) found less than 40% idle CPU and are flagged `noisy` in the results (kept). Results were produced on 2026-10-03 in six suites: `scaling`, `pipeline`, `memory`, `replay-lookup`, `real-scanner`, `ceilings`. |
| Protocol | 5 trials by default (per-cell values in the tables), 1 discarded warm-up trial, 3 in-process repetitions, interleaved measures, minimum warm repetition per trial, median and MAD over trials |
| Resumed run | The `scaling` suite was interrupted once (the first oracle run at 25,600 cases was too slow to repeat; load average 26 at that start) and resumed with that cell split into a Rust cell and a single-trial oracle cell; the cell `findings-001024` was re-run with a harness build that records the writer's refusal instead of aborting (`rerun` in the result) |
| Discarded run | `pipeline` and `real-scanner` were run twice. The first run, taken while the host was far busier, overstated wall times, session starts and per-scan latency by 2x to 4x (instruction counts agreed); only the second run is kept. `scaling`, `memory`, `replay-lookup` and `ceilings` ran once (in-process minima and process memory ratios are insensitive to this). |

## What is measured, and what is kept apart

[ARCHITECTURE.md](../ARCHITECTURE.md) asks for kernel replay cost, scanner
startup and scan cost, materialization, serialization and total wall time to be
separated. Three layers are measured separately, each in its own process so that
CPU time and peak RSS belong to one thing:

| Layer | What runs | Where the scanner is |
| --- | --- | --- |
| Kernel replay | Accounting and verification over frozen observations: matching, ten metrics, observation sets, artifact, public projection, seals, verification, serialization, parse | Absent (frozen findings) |
| Scanner startup and execution | `ProcessAdapter` plan, spawn, handshake and per-scan latency through the real adapter and shim; the same scanner package called directly in Node as the lower bound | The inert fake package, and (opt-in) the real `@redact-secret/core` 0.1.0-beta.12 |
| Full pipeline | `pii-eval run` and `pii-eval replay` end to end (executor, scanner processes, assembly, validation, atomic write), and the in-process executor with a stand-in scanner | Both |

The pinned TypeScript oracle (`redact-secret-benchmarks` at
`4b846967346505baca11e0b98cab1475fbce6773`, fetched and verified by
`tools/oracle-parity/fetch-oracle.mjs`, run unmodified under Node 22) is measured
on the same workloads on the same host. What each side's phases cover, so that
nothing is compared with something it does not do:

| Phase | What it includes |
| --- | --- |
| Oracle `generate` | its seven methods over the authored cases (variant generation only) |
| Oracle `execute` | `executePiiEvaluation`: generation again, writing every input to a scratch directory, scanner replays over frozen findings, normalization, outcome interpretation, result assembly, artifact digest |
| Oracle `account` | `piiAccountingRowsFromEvaluation` and `accountPiiRows` (the ten metrics) for every scanner |
| Rust `generate` | the kernel's seven methods over the same authored cases |
| Rust `compat` | the oracle-faithful path: the legacy first-overlap rule and the oracle's accounting port (`pii-eval-compat`). Its metric counts equal the oracle's on every workload the oracle could evaluate once (`verification` in each result cell; 23 cells including 1,024 overlapping findings per variant and Korean text) |
| Rust `kernel` | the production canonical kernel: range validation, order-invariant matching, accounting (`assembleKernel`) |
| Rust `assemble` | the kernel plus the materialization the oracle's `execute` also pays: rows, observation sets, the artifact, the public projection and their seals |
| Rust `engine run` | the executor (worker pool, replay passes, batching, a stand-in scanner that looks up frozen findings and hashes the text) plus `assemble`; the like-for-like counterpart of oracle `execute` + `account` |
| Rust `verify`, `serialize`, `parse` | accounting verification, pretty-JSON serialization, and `parse_default` (strict tree, typed parse, validation, digest) of the run artifact. The oracle does none of these (its JSON-schema checks are stubbed in the parity harness and it writes no artifact in these runs) |

The oracle's `execute` includes the input-file writes that the in-process Rust path
does not have; the Rust engine includes hashing every text. Both effects are small
next to the differences below, and are the reason the comparison names three Rust
columns rather than one.

## Method

### Workloads (frozen, synthetic, described by a few integers)

A workload is a handful of integer parameters
(`tools/perf/make-workload.mjs`, schema `pii-eval-perf-workload/1`); the data is
derived deterministically and never committed (only a 23 KB smoke workload and its
oracle observations are, for CI). Same parameters give a byte-identical file; the
sha256 of the file is the identity of a workload and is recorded in the suite and
in every result. Axes: `cases` (population size), `scanners`, `findings` (findings
per variant: the behaviour's own plus overlapping noise around the candidate, so
many overlapping findings per variant), `koShare` (percent of Korean text, so
multi-byte UTF-8 ranges), `padBytes` (text size), scanner `replays`, executor
`workers` and `batch`. All values are the documented synthetic or public-test
values of the parity input; no real identifier or protected corpus exists in any
workload. The oracle accepts a context-discrimination case only under the id of one
of its two committed evidence groups, so every workload with at least two cases
contains exactly those two context groups (8 and 11 variants) and all other cases
are single-variant kinds: variants are about one per case.

Inputs are validated before anything is measured: `node tools/perf/run.mjs plan`
generates every workload of a suite, compares its digest with the suite's record
and prints sizes; the Rust side refuses observations whose `workloadSha256`
differs from the workload and counts that disagree with the parameters; and an
untimed `verify` step has the oracle evaluate each workload once and requires the
Rust oracle-faithful path to reproduce all ten metrics' counts exactly, so both
sides are known to do the same work. A measure whose predicted time (extrapolated
from the smaller cells) exceeds the bound (`--max-measure-seconds`, default 300 per
trial) is skipped and recorded as skipped.

### Trials, noise controls, statistics

One fresh process per trial under `/usr/bin/time`; measures interleaved trial by
trial so slow drift of a shared host hits them alike; a discarded warm-up trial;
3 to 7 recorded trials (the cell's `trials` is in each table); inside a process the
first repetition is `cold` and the following ones `warm`, and the minimum of the
warm ones is used (contention only adds time). Before each trial the CPU idle
percentage over 500 ms is read from the kernel's tick counters and recorded with the
one-minute load average; a trial without a quiet machine is flagged `noisy` and
kept, never dropped. The spread is the median absolute deviation (MAD, unscaled)
and the minimum. No confidence interval is claimed: the trials are few and not
independent samples of a stationary process.

Process cost is reported **net of a baseline process** of the same tool that only
loads and prepares the workload (the oracle's `prepare` phase, Rust's `prepare`
mode), so wall time, CPU time, instructions and peak RSS above it belong to the
measured work and not to loading JSON and generating variants.

### Collection method and its limits

| Quantity | Method | Limit |
| --- | --- | --- |
| Phase wall time | `Instant` (Rust), `performance.now()` (Node) around each phase | Wall time of a loaded host; contention inflates it, so minima are used |
| Process wall, user, system time | `/usr/bin/time` | CPU time is quantized to 10 ms on macOS; the children of a process (Node scanner sessions) are included |
| Instructions retired | `/usr/bin/time -l` (Apple silicon) | **The evaluator process only: scanner child processes are not counted** (observed: constant while the number of Node sessions grows 32-fold). So it measures evaluator work and is not a time. macOS only |
| Peak RSS | maximum resident set size of `/usr/bin/time` | The largest process of the tree, not the sum; includes allocator caching and is bimodal by 20% to 40% for the same input from run to run (see the A/B and the parse table below) |
| Allocation counts | **not collected** | A counting allocator needs `unsafe`, which the workspace forbids; no allocator hook or profiler dependency was added. Allocation strategy is described below and cross-checked with RSS per row |
| Executor sampled tree RSS | `ps` every 250 ms (ADR 0009) | A lower bound; not used here |

## Results

### 1. Kernel replay against the pinned TypeScript oracle (suite `scaling`)

Reading guide for the tables: all times are milliseconds, the minimum of the warm
in-process repetitions, then the minimum over trials; `TS / x` divides the oracle's
`execute + account` by the Rust column. Net peak RSS and instruction columns are
medians net of the baseline process; the Rust replay process holds every document
and its serialization alive and also parses them back (the oracle does neither), so
the like-for-like memory comparison is the Rust engine column.

### Axis: cases

| value | variants | findings | text KiB | TS exec+account | TS generate | Rust generate | Rust compat (oracle rule) | Rust kernel (assess+account) | TS / compat | TS / engine run | Rust assemble | verify | serialize | parse | engine run | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | 117 | 204 | 5 | 33 | 3 | 0.3 | 0.09 | 0.36 | 358.7 | 1.7 | 2.1 | 0.3 | 0.4 | 1.3 | 19.9 | 7 |
| 400 | 417 | 729 | 17 | 112 | 8 | 1.1 | 0.34 | 0.78 | 324.6 | 4.3 | 6.6 | 0.5 | 1.1 | 4.0 | 25.9 | 7 |
| 1600 | 1617 | 2829 | 65 | 551 | 39 | 4.8 | 1.44 | 2.55 | 382.9 | 10.7 | 24.0 | 1.5 | 4.5 | 15.1 | 51.3 | 5 |
| 6400 | 6417 | 11229 | 258 | 3132 | 122 | 19.2 | 5.25 | 9.88 | 596.9 | 22.7 | 97.4 | 6.2 | 18.3 | 58.3 | 137.8 | 5 |
| 25600 | 25617 | 44829 | 1029 | 97963 | 1054 | 91.9 | 26.92 | 48.26 | 3639.0 | 158.3 | 462.3 | 35.1 | 84.4 | 283.3 | 618.9 | 5/1 |

| cell | TS net peak RSS MiB | Rust replay net peak RSS MiB | Rust engine net peak RSS MiB | TS net Minstr | Rust replay net Minstr |
| --- | --- | --- | --- | --- | --- |
| cases-000100 | 17.1 | 4.2 | 2.7 | 2130 | 544 |
| cases-000400 | 41.3 | 9.1 | 6.0 | 7629 | 1686 |
| cases-001600 | 75.3 | 31.3 | 19.1 | 34408 | 6276 |
| cases-006400 | 302.8 | 115.6 | 82.8 | 226093 | 24724 |
| cases-025600 | 523.5 | 913.0 | 398.0 | 2419248 | 98913 |

### Axis: scanners

| value | variants | findings | text KiB | TS exec+account | TS generate | Rust generate | Rust compat (oracle rule) | Rust kernel (assess+account) | TS / compat | TS / engine run | Rust assemble | verify | serialize | parse | engine run | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 817 | 715 | 35 | 187 | 16 | 2.3 | 0.33 | 0.73 | 561.5 | 6.9 | 6.2 | 0.5 | 1.1 | 3.8 | 27.1 | 3 |
| 2 | 817 | 1429 | 35 | 225 | 16 | 2.2 | 0.66 | 1.34 | 343.2 | 6.9 | 12.1 | 0.8 | 2.2 | 7.6 | 32.6 | 3 |
| 4 | 817 | 2859 | 35 | 328 | 16 | 2.2 | 1.30 | 2.60 | 252.0 | 7.1 | 24.2 | 1.5 | 4.5 | 15.3 | 46.4 | 3 |
| 8 | 817 | 5719 | 35 | 611 | 20 | 2.3 | 2.65 | 5.18 | 230.3 | 8.9 | 49.5 | 2.9 | 9.2 | 30.2 | 68.9 | 3 |
| 16 | 817 | 11438 | 35 | 1014 | 19 | 2.3 | 5.36 | 10.13 | 189.1 | 8.6 | 101.5 | 6.0 | 20.5 | 66.9 | 118.5 | 3 |

| cell | TS net peak RSS MiB | Rust replay net peak RSS MiB | Rust engine net peak RSS MiB | TS net Minstr | Rust replay net Minstr |
| --- | --- | --- | --- | --- | --- |
| scanners-000001 | 50.5 | 10.0 | 4.6 | 11865 | 1663 |
| scanners-000002 | 53.5 | 14.2 | 8.2 | 15936 | 3219 |
| scanners-000004 | 65.1 | 31.0 | 21.5 | 22159 | 6343 |
| scanners-000008 | 95.4 | 65.2 | 31.2 | 33783 | 12630 |
| scanners-000016 | 147.4 | 230.6 | 96.0 | 57411 | 25352 |

### Axis: findings

| value | variants | findings | text KiB | TS exec+account | TS generate | Rust generate | Rust compat (oracle rule) | Rust kernel (assess+account) | TS / compat | TS / engine run | Rust assemble | verify | serialize | parse | engine run | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 217 | 379 | 208 | 58 | 5 | 0.8 | 0.17 | 0.52 | 346.8 | 2.7 | 3.6 | 0.4 | 0.6 | 2.2 | 21.3 | 3 |
| 4 | 217 | 1681 | 208 | 67 | 5 | 0.8 | 0.23 | 0.70 | 288.6 | 2.9 | 4.7 | 0.4 | 0.7 | 2.3 | 23.3 | 3 |
| 16 | 217 | 6889 | 208 | 97 | 5 | 0.8 | 0.50 | 1.54 | 195.0 | 3.7 | 8.3 | 0.3 | 0.7 | 2.3 | 26.1 | 3 |
| 64 | 217 | 27721 | 208 | 224 | 5 | 0.8 | 1.54 | 4.74 | 145.2 | 4.7 | 24.1 | 0.3 | 0.7 | 2.3 | 47.3 | 3 |
| 256 | 217 | 111049 | 208 | 729 | 5 | 0.8 | 4.30 | 16.50 | 169.8 | 6.3 | 89.5 | 0.4 | 0.6 | 2.3 | 115.7 | 3 |
| 1024 | 217 | 444361 | 208 | 2739 | 6 | 0.8 | 16.55 | 61.75 | 165.5 | 7.6 | 347.9 | 0.4 | 0.6 | 2.3 | 362.7 | 3 |

| cell | TS net peak RSS MiB | Rust replay net peak RSS MiB | Rust engine net peak RSS MiB | TS net Minstr | Rust replay net Minstr |
| --- | --- | --- | --- | --- | --- |
| findings-000001 | 27.2 | 5.7 | 4.3 | 3949 | 936 |
| findings-000004 | 37.5 | 6.2 | 4.1 | 4684 | 1130 |
| findings-000016 | 42.3 | 19.4 | 10.2 | 6922 | 1799 |
| findings-000064 | 68.5 | 68.8 | 28.9 | 16055 | 4462 |
| findings-000256 | 233.9 | 280.6 | 125.0 | 52521 | 15103 |
| findings-001024 | 612.4 | 775.3 | 487.9 | 198130 | 41619 |

### Axis: language

| value | variants | findings | text KiB | TS exec+account | TS generate | Rust generate | Rust compat (oracle rule) | Rust kernel (assess+account) | TS / compat | TS / engine run | Rust assemble | verify | serialize | parse | engine run | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ko 0% | 817 | 1429 | 37 | 224 | 15 | 3.0 | 0.67 | 1.29 | 333.1 | 7.0 | 11.9 | 0.7 | 2.1 | 7.5 | 32.0 | 3 |
| ko 25% | 817 | 1429 | 37 | 232 | 17 | 2.3 | 0.72 | 1.36 | 321.3 | 6.5 | 12.4 | 0.8 | 2.2 | 7.6 | 35.8 | 3 |
| ko 50% | 817 | 1429 | 37 | 228 | 15 | 2.5 | 0.69 | 1.33 | 331.8 | 7.2 | 12.0 | 0.8 | 2.2 | 7.5 | 31.6 | 3 |
| ko 100% | 817 | 1429 | 36 | 226 | 16 | 2.4 | 0.69 | 1.35 | 328.8 | 6.8 | 12.5 | 0.8 | 2.3 | 7.8 | 33.1 | 3 |

| cell | TS net peak RSS MiB | Rust replay net peak RSS MiB | Rust engine net peak RSS MiB | TS net Minstr | Rust replay net Minstr |
| --- | --- | --- | --- | --- | --- |
| language-ko000000 | 53.2 | 17.3 | 7.6 | 15995 | 3219 |
| language-ko000025 | 53.5 | 15.1 | 8.0 | 16081 | 3226 |
| language-ko000050 | 53.0 | 17.5 | 8.3 | 15893 | 3226 |
| language-ko000100 | 53.8 | 14.9 | 10.2 | 15891 | 3219 |

### Axis: text

| value | variants | findings | text KiB | TS exec+account | TS generate | Rust generate | Rust compat (oracle rule) | Rust kernel (assess+account) | TS / compat | TS / engine run | Rust assemble | verify | serialize | parse | engine run | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 B | 117 | 204 | 5 | 32 | 3 | 0.8 | 0.09 | 0.38 | 358.9 | 1.3 | 2.2 | 0.3 | 0.4 | 1.3 | 24.2 | 3 |
| 1024 B | 117 | 204 | 103 | 32 | 3 | 0.7 | 0.20 | 0.38 | 158.6 | 1.2 | 2.2 | 0.3 | 0.4 | 1.2 | 26.8 | 3 |
| 16384 B | 117 | 204 | 1573 | 37 | 8 | 1.9 | 0.10 | 0.40 | 387.3 | 1.5 | 2.2 | 0.3 | 0.4 | 1.3 | 25.3 | 3 |
| 262144 B | 117 | 204 | 25093 | 133 | 88 | 24.0 | 0.09 | 0.37 | 1508.6 | 1.4 | 2.1 | 0.3 | 0.4 | 1.2 | 93.9 | 3 |

| cell | TS net peak RSS MiB | Rust replay net peak RSS MiB | Rust engine net peak RSS MiB | TS net Minstr | Rust replay net Minstr |
| --- | --- | --- | --- | --- | --- |
| text-000000 | 17.3 | 3.8 | 2.6 | 2087 | 544 |
| text-001024 | 17.3 | 3.8 | 2.5 | 2109 | 548 |
| text-016384 | 33.7 | 5.5 | 6.9 | 2427 | 625 |
| text-262144 | 87.3 | 28.1 | 137.3 | 7990 | 1829 |

### Axis: replays

| replay passes | variants | scanners | sessions per scanner | engine run ms (warm min over trials, ± MAD) | min | kernel ms | stand-in scanner ms (sum over workers) | scan calls | net peak RSS MiB | net Minstr | TS exec+account ms | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2 | 1617 | 2 | 2 | 48.7 ± 3.1 | 45.5 | 2.4 | 1.6 | 6468 | 12.0 | 2063 | 469 | 3 |
| 3 | 1617 | 2 | 2 | 50.6 ± 3.1 | 47.5 | 2.5 | 2.4 | 9702 | 13.3 | 2132 | 482 | 3 |
| 4 | 1617 | 2 | 2 | 49.9 ± 1.5 | 46.2 | 2.5 | 2.9 | 12936 | 12.6 | 2202 | 583 | 3 |
| 8 | 1617 | 2 | 2 | 53.4 ± 0.0 | 52.5 | 2.5 | 6.0 | 25872 | 17.2 | 2492 | 557 | 3 |

### Axis: workers

| workers (= per-scanner sessions) | variants | scanners | sessions per scanner | engine run ms (warm min over trials, ± MAD) | min | kernel ms | stand-in scanner ms (sum over workers) | scan calls | net peak RSS MiB | net Minstr | TS exec+account ms | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 6417 | 4 | 1 | 251.2 ± 1.6 | 235.7 | 18.1 | 7.1 | 51336 | 170.3 | 14497 | n/a | 3 |
| 2 | 6417 | 4 | 2 | 255.2 ± 0.5 | 254.7 | 18.1 | 11.7 | 51336 | 169.3 | 14870 | n/a | 3 |
| 4 | 6417 | 4 | 4 | 256.2 ± 0.0 | 256.2 | 18.2 | 14.3 | 51336 | 168.1 | 15041 | n/a | 3 |
| 8 | 6417 | 4 | 8 | 276.2 ± 2.0 | 274.2 | 18.3 | 16.6 | 51336 | 172.0 | 15566 | n/a | 3 |
| 16 | 6417 | 4 | 16 | 295.3 ± 2.2 | 293.1 | 17.9 | 15.5 | 51336 | 172.3 | 15966 | n/a | 3 |
| 32 | 6417 | 4 | 32 | 295.9 ± 1.1 | 293.4 | 18.3 | 15.8 | 51336 | 186.5 | 16132 | n/a | 3 |

### Axis: batch

| variants per batch | variants | scanners | sessions per scanner | engine run ms (warm min over trials, ± MAD) | min | kernel ms | stand-in scanner ms (sum over workers) | scan calls | net peak RSS MiB | net Minstr | TS exec+account ms | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 6417 | 2 | 2 | 142.9 ± 2.1 | 140.9 | 10.1 | 6.6 | 25668 | 81.2 | 8279 | n/a | 3 |
| 2 | 6417 | 2 | 2 | 144.9 ± 3.8 | 141.1 | 10.0 | 6.7 | 25668 | 99.6 | 8158 | n/a | 3 |
| 8 | 6417 | 2 | 2 | 143.8 ± 3.3 | 140.5 | 10.0 | 6.6 | 25668 | 82.6 | 7984 | n/a | 3 |
| 32 | 6417 | 2 | 2 | 147.2 ± 2.9 | 138.9 | 10.3 | 4.7 | 25668 | 83.1 | 7868 | n/a | 3 |
| 128 | 6417 | 2 | 2 | 148.7 ± 0.7 | 139.4 | 10.1 | 4.5 | 25668 | 81.3 | 7872 | n/a | 3 |

Scaling exponents on the cases axis (least-squares slope of log time on log cases, points of at least 1 ms; 1.0 is linear, 2.0 quadratic):

| phase | exponent | points used |
| --- | --- | --- |
| TS execute + account | 1.39 | 5 |
| TS generate | 1.04 | 5 |
| Rust generate | 1.05 | 4 |
| Rust compat (interpret + account) | 1.06 | 3 |
| Rust kernel (assess + account) | 1.06 | 3 |
| Rust assemble | 0.97 | 5 |
| Rust verify | 1.14 | 3 |
| Rust serialize | 1.03 | 4 |
| Rust parse | 0.97 | 5 |
| Rust engine run (4 workers, stand-in scanner) | 0.62 | 5 |

What the scaling tables show:

- **Shape.** Every Rust phase is linear in the number of variants (exponents 0.97 to
  1.14 over 117 to 25,617 variants; the engine run's 0.62 is a fixed per-run
  overhead of about 18 ms at the small end, see "fixed overhead" below). The oracle's
  `generate` is linear, its `execute` is linear up to about 6,400 cases and its
  `account` step is superlinear because it rescans the rows of every group: 10 ms at
  117 variants, 1.4 s at 6,417, 60 s at 25,617 (the slope between the last two sizes
  is 2.4 for `execute + account`). The 25,617-variant oracle value is one trial of
  three in-process repetitions in which `execute` took 18 to 48 s and `account` 60 to
  137 s; the minima are used, and the real ratio is likely larger, not smaller.
- **Against the oracle.** Like for like (`TS / engine run`) the Rust engine is 1.7x
  (117 variants, dominated by its fixed overhead), 4.3x, 10.7x, 22.7x and 158x faster
  as the population grows; against the Rust kernel alone it is 90x to 2,000x.
  Variant generation is 6x to 12x faster. These ratios are properties of these
  workloads and this oracle (including its file writes and its quadratic accounting
  step); they are not a claim that the oracle is slow in general.
- **Where the evaluator's own time goes.** The canonical kernel costs about 1.0 us
  per outcome row (the legacy rule plus the accounting port 0.54 us) and is about 10%
  of `assemble` (9.2 us per row). Everything else in the evaluator is document
  handling: per outcome row, validating the artifact 2.5 us, its semantic digest
  2.4 us, serializing it 1.8 us and parsing it back 5.7 us, verifying it 0.7 us.
  A `pii-eval run` or `replay` pays these several times (the writer validates,
  verifies, serializes and re-parses every document), which is why the full CLI
  needs 1.2 to 1.3 million evaluator instructions per variant (section 3) while the
  kernel needs a few thousand.
- **Overlapping findings.** The Rust kernel is linear in the number of findings
  (0.5 ms at 379 findings, 62 ms at 444,361; about 0.14 us per finding) and so is the
  oracle, at about 6 us per additional finding (a fixed cost of about 58 ms for these
  217 variants dominates its small end). At 1,024 findings per variant each
  observation set is about 42 MiB and the atomic writer refuses it (section 5).
- **EN and KO.** No difference beyond noise at any share of Korean text (0% to 100%)
  in any phase of either implementation.
- **Text size.** The kernel does not read the text beyond validating ranges (flat
  from 5 KiB to 25 MiB of text in total); generation scales with the bytes (Rust
  0.8 to 24 ms, oracle 3 to 88 ms), and the engine run pays one SHA-256 per scan
  (24 to 94 ms).
- **Scanners and replays.** Cost is linear in scanners (all Rust phases double with
  the scanner count) and the oracle's per-scanner cost is lower than its fixed
  cost, so its relative disadvantage falls from 560x to 190x of the compat path as
  scanners grow from 1 to 16. Replay passes add only the per-scan cost of the
  stand-in (about 0.24 microseconds per scan call): 2 to 8 passes change the engine
  run by 10%. For a real scanner replays dominate (section 3).
- **Fixed overhead of one executor run.** About 18 ms regardless of size (117
  variants: `assemble` 2.1 ms, engine run 19.9 ms). It is consistent with the
  watchdog thread's 15 ms sleep that `stop` joins (`exec.rs`); it was not isolated.
  One scanner session start costs 30 to 40 ms (section 2) and a run starts at
  least `replays` of them, so this is a minor part of any run that starts a scanner.
- **Workers and batch (stand-in scanner).** With a zero-cost scanner, more workers
  only add coordination: the run is 236 ms at 1 worker and 293 ms at 16 and 32 (+24%),
  with the same semantic output (a test asserts it). The batch size (1 to 128
  variants) changes nothing within noise.

### 2. Scanner startup and execution (suites `pipeline` and `real-scanner`)

The scanner is measured alone (a session through the real Rust adapter and shim,
and the same package called directly in Node as the lower bound), so scanner speed
is not confused with evaluator work.

**Scanner startup and per-scan latency (scanner-candidate; 2000 texts per session)**

| measure | package | session start ms | import ms | initialize ms | plan ms | scan all ms | per-scan median µs | finish ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| scanner-rust | candidate | 34.4 (min 29.8) | n/a | n/a | 0.0 (min 0.0) | 46.3 (min 46.2) | 21 | 7.7 (min 7.7) |
| scanner-node | candidate | n/a | 0.4 (min 0.4) | 0.1 (min 0.1) | n/a | 3.8 (min 3.8) | 1 | n/a |

**Scanner startup and per-scan latency (real-scanner-released; 2000 texts per session)**

| measure | package | session start ms | import ms | initialize ms | plan ms | scan all ms | per-scan median µs | finish ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| scanner-rust | released | 41.5 (min 37.4) | n/a | n/a | 0.0 (min 0.0) | 61.8 (min 61.8) | 29 | 8.8 (min 6.9) |
| scanner-node | released | n/a | 6.7 (min 6.0) | 1.6 (min 1.5) | n/a | 19.7 (min 19.5) | 9 | n/a |

- The process boundary costs about 20 microseconds per scan: 21 us through the
  adapter against 1 us in-process for the inert fake, 29 us against 9 us for the real
  scanner (medians of 2,000 scans). The real scanner is that fast; the protocol and
  pipes are most of what a scan costs through the adapter.
- A session costs about 30 to 40 ms to start through the adapter (34 ms median, 30
  ms best, for the inert package; 42 ms and 37 ms for the real one: a Node process
  boot, the pinned-artifact verification and the handshake), against 0.5 ms and 8 ms
  (6.7 import plus 1.6 initialize) in-process. Every replay pass starts fresh sessions
  (ADR 0009), so startup is paid `replays x workers` times.

### 3. Full pipeline (suites `pipeline` and `real-scanner`)

**Full CLI over the inert fake scanner package**

| cases | measure | wall ms (median ± MAD) | wall min | CPU ms (user+sys) | Minstr | peak RSS MiB | startup / scan / kernel / materialization / serialization / total ms (diagnostics, summed over sessions for startup and scan) | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 400 | cli-run-candidate-w4-r2 | 190 ± 0 | 180 | 330 ± 0 | 681 | 42 | 313 / 52 / 0 / 0 / 12 / 156 | 5 |
| 400 | cli-replay-candidate-w4-r2 | 60 ± 10 | 50 | 40 ± 10 | 561 | 11 |  | 5 |
| 1600 | cli-run-candidate-w4-r2 | 310 ± 0 | 290 | 530 ± 0 | 2259 | 46 | 282 / 163 / 1 / 1 / 45 / 232 | 5 |
| 1600 | cli-replay-candidate-w4-r2 | 150 ± 10 | 130 | 120 ± 10 | 1977 | 32 |  | 5 |
| 6400 | cli-run-candidate-w4-r2 | 700 ± 20 | 670 | 1310 ± 30 | 8626 | 122 | 285 / 564 / 4 / 7 / 178 / 508 | 3 |
| 6400 | cli-replay-candidate-w4-r2 | 460 ± 0 | 450 | 420 ± 0 | 7697 | 129 |  | 3 |
| 25600 | cli-run-candidate-w4-r2 | 2440 ± 80 | 2360 | 4960 ± 10 | 34214 | 610 | 261 / 2437 / 22 / 32 / 762 / 1861 | 3 |
| 25600 | cli-replay-candidate-w4-r2 | 1710 ± 30 | 1680 | 1670 ± 0 | 30777 | 628 |  | 3 |

**Real scanner: oracle in-process adapter against the Rust CLI**

| cases | measure | wall ms (median ± MAD) | wall min | CPU ms (user+sys) | Minstr | peak RSS MiB | startup / scan / kernel / materialization / serialization / total ms (diagnostics, summed over sessions for startup and scan) | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | oracle-real | 400 ± 20 | 360 | 480 ± 10 | 4972 | 154 |  | 5 |
| 100 | cli-run-released-w4-r2 | 320 ± 20 | 300 | 430 ± 10 | 656 | 49 | 795 / 27 / 0 / 0 / 4 / 266 | 5 |
| 100 | cli-run-released-w1-r2 | 300 ± 20 | 280 | 110 ± 0 | 341 | 49 | 184 / 9 / 0 / 0 / 4 / 239 | 5 |
| 400 | oracle-real | 740 ± 10 | 710 | 920 ± 10 | 10268 | 183 |  | 5 |
| 400 | cli-run-released-w4-r2 | 220 ± 20 | 200 | 460 ± 30 | 1026 | 49 | 366 / 59 / 0 / 0 / 12 / 177 | 5 |
| 400 | cli-run-released-w1-r2 | 230 ± 10 | 220 | 170 ± 0 | 725 | 49 | 75 / 25 / 0 / 0 / 12 / 179 | 5 |
| 1600 | oracle-real | 1980 ± 20 | 1960 | 2520 ± 10 | 32459 | 219 |  | 5 |
| 1600 | cli-run-released-w4-r2 | 340 ± 10 | 320 | 620 ± 20 | 2580 | 50 | 356 / 162 / 1 / 1 / 43 / 248 | 5 |
| 1600 | cli-run-released-w1-r2 | 330 ± 10 | 320 | 290 ± 20 | 2267 | 50 | 74 / 87 / 1 / 1 / 44 / 267 | 5 |
| 6400 | oracle-real | 8680 ± 30 | 8550 | 10110 ± 40 | 147133 | 428 |  | 3 |
| 6400 | cli-run-released-w4-r2 | 750 ± 10 | 740 | 1440 ± 20 | 8852 | 121 | 343 / 613 / 4 / 7 / 170 / 533 | 3 |
| 6400 | cli-run-released-w1-r2 | 890 ± 0 | 840 | 910 ± 10 | 8427 | 98 | 69 / 319 / 4 / 7 / 173 / 694 | 3 |

**Worker oversubscription (inert fake package, host has 10 logical CPUs)**

| workers | wall ms | wall min | CPU ms | Minstr | peak RSS MiB (largest process) | startup ms (sum) | scan ms (sum) | total phase ms | noisy/ok trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1710 ± 60 | 1650 | 910 ± 30 | 4358 | 57 | 248 | 721 | 1462 | 3/3 |
| 2 | 1520 ± 130 | 1340 | 900 ± 20 | 4361 | 51 | 952 | 612 | 1079 | 3/3 |
| 4 | 1140 ± 70 | 1070 | 1120 ± 10 | 4391 | 64 | 1419 | 1003 | 835 | 3/3 |
| 8 | 870 ± 40 | 830 | 1340 ± 10 | 4435 | 62 | 2579 | 961 | 642 | 2/3 |
| 16 | 930 ± 100 | 830 | 2000 ± 30 | 4540 | 64 | 6266 | 1359 | 709 | 0/3 |
| 32 | 950 ± 40 | 910 | 3380 ± 10 | 4752 | 50 | 10755 | 4867 | 747 | 0/3 |

**Worker oversubscription (real scanner, host has 10 logical CPUs)**

| workers | wall ms | wall min | CPU ms | Minstr | peak RSS MiB (largest process) | startup ms (sum) | scan ms (sum) | total phase ms | noisy/ok trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 350 ± 20 | 320 | 300 ± 10 | 2259 | 50 | 71 | 87 | 268 | 0/3 |
| 2 | 310 ± 10 | 300 | 390 ± 0 | 2365 | 50 | 150 | 99 | 240 | 0/3 |
| 4 | 310 ± 10 | 300 | 620 ± 0 | 2579 | 50 | 353 | 161 | 241 | 0/3 |
| 8 | 370 ± 0 | 360 | 1290 ± 20 | 2956 | 50 | 1028 | 318 | 293 | 0/3 |
| 16 | 480 ± 10 | 470 | 2240 ± 0 | 3802 | 50 | 3437 | 807 | 414 | 0/3 |
| 32 | 710 ± 20 | 690 | 4180 ± 90 | 5420 | 50 | 11912 | 2222 | 634 | 0/3 |

- **Evaluator overhead versus scanner time.** At 25,617 variants over the inert
  package (4 workers, 2 replays) the diagnostics phases are: kernel replay 22 ms,
  materialization 32 ms, serialization (validate, verify, serialize, round trip)
  0.76 s, against 0.26 s of scanner startup and 2.4 s of scanning summed over
  sessions (about 0.7 s of wall time at four workers); the run phase takes 1.86 s of a
  2.44 s process, the remainder being reading, parsing and validating a 31 MiB
  snapshot before and fsyncing the documents after. With the real scanner at 6,417
  variants the evaluator-owned phases are 0.18 s of a 0.53 s run phase and a 0.75 s
  process. The evaluator's own work per variant is constant (1.34 million
  instructions for `run` and 1.20 million for `replay` at 6,417 and 25,617 variants;
  1.4 million at 1,617 and 1.6 million at 417, where fixed costs show), so a run is
  linear in the population and the scanner's share shrinks as scans get cheaper
  than the evaluator's per-variant document handling.
- **Against the oracle with the real scanner** (full process wall time; the oracle
  runs the same pinned package in-process through its own adapter): 400 ms against
  320 ms at 117 variants (process starts dominate both), then 3.4x, 5.8x and 11.6x at
  417, 1,617 and 6,417 variants (8.7 s against 0.75 s at the largest). The two sides
  scan the same texts but their observations at this scale were not compared (the
  committed parity check covers the frozen population only).
- **Oversubscription (workers above the number of CPUs, which is 10 here).** For a
  scanner that starts a process per session, wall time is lowest at 2 to 4 workers
  (310 ms for 1,617 variants), then rises to 370 ms at 8, 480 ms at 16 and 710 ms at
  32, while CPU time rises from 300 ms at one worker to 4.2 s at 32 (14x), because the
  summed session start time grows from 71 ms to 11.9 s as 32 Node processes contend
  for 10 CPUs. With the inert package (3,200 variants) the gain from parallelism
  saturates at 8 workers (870 ms against 1.7 s at one) and 16 and 32 workers are no
  faster (930 and 950 ms) for 1.5x and 2.5x the CPU time. The evaluator's own
  instruction count also grows with the number of sessions (6 million instructions
  per extra session with the 4 KB inert package, 51 million with the real package),
  consistent with pinned-artifact re-verification per session (ADR 0006); that cause
  was not isolated by a profile. The manifest, not the host, sets parallelism (ADR
  0009); this is the measured cost of setting it far above the host's CPUs, not a
  change of any default.
- **Replay** (`pii-eval replay` of a sanitized-output run, which needs the original
  artifact) costs 0.87 to 0.90 of the original run's evaluator work and needs no
  scanner.

### 4. Memory: per row, per document byte, parse by stage

Peak RSS of the largest process (net of a baseline process), per input byte for
parsing, and per row or variant for runs:

- A run needs about 24 KB of peak RSS per variant (610 MiB at 25,617 variants;
  121 MiB at 6,417 with the real scanner) and a replay about 25 KB per variant, almost
  all of it the evaluator's documents, not scanner processes (a Node scanner is
  about 50 MiB each). The Rust replay process holds about 18.7 KB per outcome row.
- Parsing a document costs about the same multiple of its size at every size from
  0.2 MiB to 31 MiB, so memory is linear in the input:

### Parse peak memory by stage (peak RSS above a process that parses a 4 KB manifest, over the document's bytes)

| document | stage | document MiB (25600 cases) | peak RSS above baseline MiB | ratio at 400 cases | ratio at 1600 cases | ratio at 6400 cases | ratio at 25600 cases |
| --- | --- | --- | --- | --- | --- | --- | --- |
| snapshot | full | 30.7 | 250 | 11.6 | 11.4 | 11.6 | 8.1 |
| snapshot | strict | 30.7 | 167 | 4.7 | 5.3 | 5.4 | 5.4 |
| snapshot | typed | 30.7 | 73 | 1.9 | 2.2 | 2.3 | 2.4 |
| snapshot | validate | 30.7 | 224 | 7.6 | 7.9 | 7.5 | 7.3 |
| observation | full | 9.2 | 130 | 15.1 | 10.4 | 9.8 | 14.2 |
| observation | strict | 9.2 | 63 | 4.2 | 6.5 | 6.8 | 6.9 |
| observation | typed | 9.2 | 23 | 1.0 | 2.2 | 2.3 | 2.5 |
| observation | validate | 9.2 | 82 | 9.8 | 9.1 | 8.8 | 8.9 |
| artifact | full | 28.3 | 309 | 8.2 | 8.5 | 7.9 | 10.9 |
| artifact | strict | 28.3 | 157 | 4.9 | 5.4 | 5.5 | 5.5 |
| artifact | typed | 28.3 | 50 | 1.5 | 1.7 | 1.9 | 1.8 |
| artifact | validate | 28.3 | 193 | 7.5 | 7.4 | 7.2 | 6.8 |

  `full` (what `parse_default` does) peaks at 8 to 12 times the document for a
  snapshot or an artifact and 10 to 15 times for an observation set with many
  findings, and the same document alternates between such values from run to run (11.6
  times for the 7.7 MiB snapshot and 8.1 for the 31 MiB one in the run above): the allocator keeps the
  freed strict tree's pages in some runs and reuses them in others. The strict value
  tree alone is 4.2 to 6.9 times, the typed parse 1.0 to 2.5 times, and the typed
  parse plus validation (which builds a second value tree to recompute the digest)
  6.8 to 9.8 times. At the document cap the existing hand measurement (ADR 0008
  section 6, repeated: [parse-memory.txt](perf/results/parse-memory.txt)) gives 4.2x
  for a string-dominated document and 31.7x for one of about 300,000 tiny findings,
  against 4.1x and 31.8x in ADR 0008 (agreement within 1%).
- **Is a streaming or tighter parse warranted?** Not on this evidence. Removing the
  strict tree would lower the full-parse peak at best to the `validate` stage's 7 to 8
  times (9 to 10 times for observation sets), a saving of up to about a third (about
  100 MiB for a document at the cap) and sometimes nothing, and a validation that
  does not build a second value tree would be needed for more. Engine-produced
  documents at the cap need about 250 to 350 MiB to parse; only adversarial,
  node-dense documents reach the 1 GiB of ADR 0008. Nothing runs the evaluator under
  a lower limit, and the change would touch the error classification of 93 negative
  fixtures. It is recorded as a follow-up with a trigger (a custodian memory limit
  below about 1 GiB, or a raised document cap), not done here.

Allocation strategy (from the code, consistent with the RSS per row above): outcome
rows are built once per scanner and variant with their own `String` copies of four
identifiers; the artifact, each observation set and the public projection then hold
separate copies of the rows or findings; the writer serializes each document to a
`String`, parses it back through a strict value tree and a typed value, and
recomputes its digest through a second value tree. Memory is therefore several
copies of the run's rows at once plus the parse trees, and none of it is reduced
by the kernel's compact accounting state (4 bytes per group, ADR 0005).

### 5. Ceilings

The practical ceiling is the 32 MiB document cap (`MAX_DOCUMENT_BYTES`), not the
accounting limits of ADR 0005 (1,000,000 cases, 16,000,000 rows):

| cases | variants | outcome rows (2 scanners) | run artifact MiB (pretty JSON) | both observation sets MiB | document cap MiB | artifact parse | atomic writer |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 25600 | 25617 | 51234 | 28.4 | 18.3 | 32 | parses | written and round-tripped |
| 28000 | 28017 | 56034 | 31.1 | 20.0 | 32 | parses | written and round-tripped |
| 30000 | 30017 | 60034 | 33.3 | 21.5 | 32 | artifact does not parse (over the cap) | refused: a serialized document did not parse back |
| 32000 | 32017 | 64034 | 35.5 | 22.9 | 32 | artifact does not parse (over the cap) | refused: a serialized document did not parse back |

- A pretty-printed snapshot of 25,600 cases is 30.4 MiB, so a snapshot tops out at
  about 27,000 cases (1.2 KiB per case; computed from that measurement, not run). A pretty-printed run artifact is about 580
  bytes per outcome row, so it tops out at about 58,000 rows (for example 29,000
  variants and 2 scanners); the atomic writer refuses a larger one (its round-trip
  parse fails, `WriteError::RoundTrip`). An observation set is limited by its findings:
  about 195 bytes per finding when dense, so about 170,000 findings; 1,024 overlapping
  findings per variant over 217 variants is refused.
- The writer's refusal is the right outcome (nothing is written, a smaller
  population or fewer scanners per run works), but the error reason does not say the
  cap was hit. A compact serialization or a raised cap is a contract decision outside
  this phase. Within the cap the memory ceiling is about 900 MiB for a replay process
  at 51,000 rows and about 610 MiB for a CLI run at 25,600 variants.

### 6. The optimization: replay variant lookup

`pii-eval replay` of a sanitized-output run (the real `@redact-secret/core` always
returns sanitized output) looked up the variant of every observed input with an
iterator `nth` over all cases, so it was quadratic in the population. A `sample`
profile taken on a heavily loaded host attributed more than half of the samples to
that function; the controlled A/B below (two builds of the same CLI, same documents,
interleaved trials, quiet-ish host) shows the real effect: none up to 6,400 cases and
about 14% of the wall time (8% of the instructions) at 25,600, the largest size the
document cap allows (the 400-case row's 50 ms difference is process-start noise: its
instruction counts are equal, and CPU time is quantized to 10 ms). The profile overstated it because the walk is memory-latency
bound and a contended host inflates exactly that. The fix indexes a list built once
(ADR 0013 O1); the replayed documents are identical (same semantic digests, byte for
byte equal output directories on the 1,617 and 25,617-variant runs, and a test).

| cases | before wall ms | after wall ms | wall before/after | before CPU ms | after CPU ms | CPU before/after | before Minstr | after Minstr | instr before/after | before RSS MiB (min-max) | after RSS MiB (min-max) | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 400 | 110 ± 0 | 60 ± 10 | 1.8 | 30 ± 0 | 20 ± 0 | 1.5 | 563 | 560 | 1.0 | 10-12 | 9-11 | 5 |
| 1600 | 140 ± 10 | 130 ± 0 | 1.1 | 100 ± 0 | 100 ± 0 | 1.0 | 1984 | 1968 | 1.0 | 26-34 | 26-32 | 5 |
| 6400 | 460 ± 10 | 450 ± 20 | 1.0 | 430 ± 10 | 420 ± 10 | 1.0 | 7852 | 7661 | 1.0 | 105-133 | 103-132 | 5 |
| 12800 | 940 ± 10 | 880 ± 20 | 1.1 | 900 ± 20 | 830 ± 20 | 1.1 | 15989 | 15344 | 1.0 | 235-289 | 231-290 | 5 |
| 25600 | 2020 ± 70 | 1740 ± 40 | 1.2 | 1960 ± 60 | 1690 ± 40 | 1.2 | 33311 | 30743 | 1.1 | 537-647 | 530-645 | 5 |

### 7. Budgets

A budget is the largest value any trial of the reference cell produced
([docs/perf/budgets.json](perf/budgets.json), derived by `tools/perf/budget.mjs`):
no multiplier and no speedup target was applied, and none is claimed. In the JSON the value is
the `ceiling` key, not `budget`: `budget` is a private-custodian ledger field name that the public-release
tripwire (`public_release_hygiene.rs`) forbids in committed documents. The host was
shared, so the envelope includes that noise (the trials' spread is small, within 10% of
the median for every row below). A change is a regression when its median on a
comparable host and the same suite exceeds the budget; a faster result creates no new
target. Scaling exponents are budgeted as the largest slope between neighbouring
sizes (1.14 to 1.24 for the Rust phases; the oracle's 2.43 is a reference, not a
budget).

| id | reference | what | unit | measured median | budget (observed upper envelope) |
| --- | --- | --- | --- | --- | --- |
| `rust.assembleKernel.us-per-row` | cases-025600 | kernel assess+account | microseconds per outcome row | 0.966 | 1.015 |
| `rust.assemble.us-per-row` | cases-025600 | assemble (kernel, rows, observation sets, artifact, public projection, seals) | microseconds per outcome row | 9.216 | 9.703 |
| `rust.verify.us-per-row` | cases-025600 | verify accounting | microseconds per outcome row | 0.715 | 0.757 |
| `rust.validate.us-per-row` | cases-025600 | validate artifact | microseconds per outcome row | 2.463 | 2.557 |
| `rust.serialize.us-per-row` | cases-025600 | serialize artifact (pretty JSON) | microseconds per outcome row | 1.751 | 1.868 |
| `rust.parse.us-per-row` | cases-025600 | parse artifact (strict tree, typed, validate) | microseconds per outcome row | 5.69 | 6.238 |
| `rust.digest.us-per-row` | cases-025600 | semantic digest of the artifact | microseconds per outcome row | 2.407 | 2.558 |
| `rust.compat.us-per-row` | cases-025600 | legacy rule + oracle accounting port | microseconds per outcome row | 0.543 | 0.555 |
| `rust.replay.peak-rss-bytes-per-row` | cases-025600 | replay process peak RSS above the prepare baseline (all documents and their serialization alive) | bytes per outcome row | 18686 | 19316 |
| `rust.engine.us-per-row` | cases-025600 | executor + assemble with a stand-in scanner (4 workers, 2 replays) | microseconds per outcome row | 13.039 | 14.328 |
| `rust.kernel.scaling-exponent` | cases axis, sizes with phase >= 1 ms | largest log-log slope of assembleKernel against variants | exponent (1 = linear) | n/a | 1.14 |
| `rust.assemble.scaling-exponent` | cases axis, sizes with phase >= 1 ms | largest log-log slope of assemble against variants | exponent (1 = linear) | n/a | 1.24 |
| `rust.parse.scaling-exponent` | cases axis, sizes with phase >= 1 ms | largest log-log slope of parse against variants | exponent (1 = linear) | n/a | 1.24 |
| `rust.serialize.scaling-exponent` | cases axis, sizes with phase >= 1 ms | largest log-log slope of serialize against variants | exponent (1 = linear) | n/a | 1.22 |
| `cli.run.evaluator-instructions-per-variant` | pipeline-cases-025600 | pii-eval run (cli-run-candidate-w4-r2): instructions retired by the evaluator process (scanner children are not counted) | instructions per variant | 1335581 | 1336025 |
| `cli.run.peak-rss-bytes-per-variant` | pipeline-cases-025600 | pii-eval run: peak RSS of the largest process | bytes per variant | 24958 | 25236 |
| `cli.replay.evaluator-instructions-per-variant` | pipeline-cases-025600 | pii-eval replay (cli-replay-candidate-w4-r2): instructions retired by the evaluator process (scanner children are not counted) | instructions per variant | 1201443 | 1201939 |
| `cli.replay.peak-rss-bytes-per-variant` | pipeline-cases-025600 | pii-eval replay: peak RSS of the largest process | bytes per variant | 25706 | 26430 |
| `parse.artifact.full.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (artifact.full) | ratio | n/a | 11.7 |
| `parse.artifact.strict.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (artifact.strict) | ratio | n/a | 5.6 |
| `parse.artifact.typed.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (artifact.typed) | ratio | n/a | 1.9 |
| `parse.artifact.validate.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (artifact.validate) | ratio | n/a | 7.6 |
| `parse.observation.full.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (observation.full) | ratio | n/a | 15.8 |
| `parse.observation.strict.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (observation.strict) | ratio | n/a | 6.9 |
| `parse.observation.typed.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (observation.typed) | ratio | n/a | 2.5 |
| `parse.observation.validate.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (observation.validate) | ratio | n/a | 10 |
| `parse.snapshot.full.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (snapshot.full) | ratio | n/a | 12 |
| `parse.snapshot.strict.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (snapshot.strict) | ratio | n/a | 5.4 |
| `parse.snapshot.typed.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (snapshot.typed) | ratio | n/a | 2.4 |
| `parse.snapshot.validate.peak-rss-ratio` | memory suite, 4 sizes | peak RSS above the baseline process over document bytes (snapshot.validate) | ratio | n/a | 7.9 |

Reference only (binds nothing here): the oracle's `execute + account` slope between its two largest measured sizes is 2.43.

### 8. CI regression guard

`cargo test -p pii-eval-cli --test perf_harness` (part of `cargo test --workspace`)
runs the harness at tiny sizes on a committed 23 KB workload and its oracle
observations and asserts deterministic quantities only: every variant is scanned
exactly `replays` times by exactly one worker; at most the configured sessions are
alive at once and none leaks; sessions started are bounded by `replays x
per-scanner parallelism`; outcome rows equal scanners x variants; documents are
byte-identical across repeated runs; the executor path, the frozen-replay path and
every host worker cap (1 to 64) produce the same semantic digests; observations
must belong to the workload; the workload equals what its generator produces; a CLI
run and replay over the inert package reproduce the same digests. No assertion in
the repository depends on wall time. `node --test tools/perf/test/perf-tools.test.mjs`
checks the generator's determinism and the report parsers.

## Reproduce

```sh
# Oracle at the pin (needs gh with read access), scratch outside the repository:
node tools/oracle-parity/fetch-oracle.mjs "$SCRATCH"
# Release builds (the workspace release profile: overflow-checks on):
cargo build --release --locked --example perf -p pii-eval-cli
cargo build --release --locked -p pii-eval-cli
# Validate the inputs of a suite, then run it (minutes to an hour; one process per trial):
node tools/perf/run.mjs plan tools/perf/suites/scaling.json --scratch "$SCRATCH"
node tools/perf/run.mjs run  tools/perf/suites/scaling.json --scratch "$SCRATCH" --out scaling.json
node tools/perf/run.mjs verify tools/perf/suites/scaling.json --scratch "$SCRATCH" --out scaling.json
# A/B of two builds of the CLI (the optimization):
node tools/perf/run.mjs run tools/perf/suites/replay-lookup.json --scratch "$SCRATCH" --cli-bin <after> --cli-bin-before <before> --out replay-lookup.json
# Opt-in real scanner (hermetic install of tools/oracle-parity/real-scanner):
node tools/perf/run.mjs run tools/perf/suites/real-scanner.json --scratch "$SCRATCH" --real-package <pkg dir> --real-root <install root> --out real-scanner.json
node tools/perf/report.mjs scaling.json
node tools/perf/budget.mjs scaling.json pipeline.json memory.json
```

Suites are regenerated with `node tools/perf/suites/generate.mjs` (every cell records
its workload digest). The committed observations of the smoke workload are
regenerated with `node --experimental-strip-types --no-warnings --import tools/oracle-parity/register.mjs tools/perf/oracle-bench.mjs "$SCRATCH/oracle" fixtures/perf/smoke-workload.json --export fixtures/perf/smoke-observations.json`
(the workload file itself is `node tools/perf/make-workload.mjs '<its recorded parameters>' fixtures/perf/smoke-workload.json`;
a test asserts that the committed file is what the generator produces).

## What is not claimed

- No throughput, latency or capacity promise for any host, workload or scanner. The
  numbers are one macOS arm64 development host that was shared with other
  concurrent builds and test runs throughout; 15% of the recorded trials were flagged noisy
  (never dropped), the host's one-minute load average was 9 to 26 when suites started, and
  a quiet machine was never available. No Linux numbers exist (the Linux `time -v`
  parser is unit-tested against a sample only).
- No claim that the TypeScript oracle is slow in general: it is measured doing
  what it does on these workloads (including its file writes and an accounting step
  that is quadratic in the number of rows). Its 25,617-variant point is one trial.
- No claim about the real scanner beyond the one pinned package on this platform,
  and no comparison of the oracle's and the Rust adapter's observations at scale.
- No allocation counts; no profile-based attribution beyond the one `sample` run
  described in section 6; the 15 ms watchdog and the per-session pin re-verification
  are consistent explanations that were not isolated.
- Budgets are envelopes of what was measured on this host, not targets and not
  portable thresholds.
- Protected populations, custodian isolation and release decisions are outside this
  repository's measurement and untouched here.
