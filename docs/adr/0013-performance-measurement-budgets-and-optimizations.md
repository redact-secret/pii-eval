# ADR 0013: Performance measurement, budgets and the optimizations decided

- Status: accepted for P10 (issue #11); subject to review.
- Date: 2026-10-03
- Related: [ADR 0005](0005-indexed-accounting-and-metric-statistics.md),
  [ADR 0008](0008-protocol-revision-2-and-schema-1-1.md),
  [ADR 0009](0009-bounded-execution-and-artifact-writing.md),
  [ADR 0010](0010-standalone-cli-workflows.md),
  [ADR 0012](0012-oracle-parity-and-migration-evidence.md), epic #1.
  Report: [docs/performance.md](../performance.md). Raw results:
  [docs/perf/results/](../perf/results/). Tooling: `tools/perf/`,
  `crates/pii-eval-cli/examples/perf.rs`, `crates/pii-eval-cli/tests/perf/`,
  `crates/pii-eval-cli/tests/perf_harness.rs`.

## Context

ARCHITECTURE.md requires kernel replay, scanner startup and scan cost,
materialization, serialization and total time to be measured separately, with
inputs, toolchain, build profile, host, scanner versions and settings pinned,
uncertainty reported, and "no speed target justified without a baseline". P7
recorded that parse peak memory is 4.1x to 31.8x of a 28.6 MiB document and
deferred a streaming parser to this phase. This ADR records how the
measurements were made, what was optimized, what was deliberately not, and why.
It changes no contract, schema, protocol, digest, accounting or matching result.

## Decisions

### M1. One harness, test-support reuse, no new dependency and no `unsafe`

The measurement driver is `examples/perf.rs`; its code lives in
`crates/pii-eval-cli/tests/perf/` and reuses the parity test support
(`tests/parity/`: the corpus generation from authored cases, the frozen-finding
reader). The same module backs `tests/perf_harness.rs` (CI, tiny sizes). No crate
and no third-party dependency was added, so Cargo.lock, the toolchain, the MSRV
and the migration handoff identity table are unchanged. Allocation counts were
**not** collected: a counting allocator needs `unsafe`, which the workspace
forbids, and a standalone unsafe probe crate would add a second lockfile and a
code path outside the reviewed boundary for a number that peak RSS per row and the
described allocation strategy already bound. Peak RSS and instructions retired come
from `/usr/bin/time` around a fresh process per trial.

### M2. The baseline is the pinned oracle on the same host, workload and settings

The same synthetic workloads (`tools/perf/make-workload.mjs`, parameters and
digests only in the repository) are generated, run by the oracle's own code
(`tools/perf/oracle-bench.mjs`, pinned commit, tree digest verified, unmodified,
Node 22) and read by the Rust harness through the oracle's generated variants and
frozen findings (`--export`). Every comparison names what each side includes.
Rust is always the release build (workspace profile: `overflow-checks = true`,
otherwise cargo defaults).

### M3. Process cost is reported net of a prepare baseline; minima and MAD, not means

A trial is one fresh process; each measure is paired with a `prepare` process of
the same tool; the difference removes load and generation. Phase times inside a
process use the minimum of the warm repetitions (contention only adds time), the
spread across trials is the median absolute deviation, and the idle fraction of
the host is recorded per trial. The host was shared with other agents' builds and
tests throughout; waiting for a quiet machine was never possible, so noisy trials
are kept, flagged and not dropped (15% of the recorded trials). One suite pair
(`pipeline`, `real-scanner`) was run twice because the first run, taken while the host
was far busier, overstated wall times, session starts and per-scan latency by 2x to 4x
while its instruction counts agreed; only the second run is kept and the result says
so. Wall-clock values are therefore context; the per-row phase times (minima), the
instruction counts of the evaluator process and the memory ratios carry the
conclusions.

### M4. Budgets are the measured upper envelope, derived by a script

`tools/perf/budget.mjs` derives `docs/perf/budgets.json` from the committed results:
per-row cost of each Rust phase, process memory per row and per document byte,
scaling exponents. A budget is the largest value any trial of the reference cell
produced; no multiplier and no speedup target was applied. The JSON key is `ceiling`, not `budget`:
`budget` is a custody-ledger field name that the public-release tripwire forbids in committed documents
(found when P10 and P12 were combined). A change is a regression
when its median on a comparable host exceeds the budget; a smaller number never
creates a new target.

### M5. The CI guard counts work, it does not time it

`tests/perf_harness.rs` asserts deterministic quantities only: every variant is
scanned exactly `replays` times by exactly one worker; at most the configured
sessions are alive at once and none leaks; sessions started are bounded by
`replays x per-scanner parallelism`; rows equal scanners x variants; documents are
byte-identical across repeated runs; the semantic digests of the executor path,
the frozen-replay path and every host worker cap (1 to 64) are equal; observations
must belong to the workload; the committed workload equals what its generator
produces. There is no timing assertion anywhere in the repository's tests.

### O1. Optimized: the replay variant lookup (quadratic to linear)

`pii_eval_cli::replay::runs_from_observations` looked up the variant of every
observed input with `snapshot.cases.iter().flat_map(variants).nth(index)`, which
is O(cases) per input, so replaying a sanitized-output scanner (the real
`@redact-secret/core` always returns sanitized output) was quadratic in the
number of cases. The fix builds the list of variants in task order once
(`variants_in_task_order`) and indexes it. It was the only per-input linear walk
found by reading the CLI, kernel and contracts sources.

Measured effect (docs/performance.md section 6, interleaved A/B of the two builds,
same documents): none up to 6,400 cases; at 25,600 cases (the largest a snapshot
allows under the document cap) wall time 2.02 s to 1.74 s (-14%), CPU time -14%,
instructions -8%. A `sample` profile taken earlier on a heavily loaded host had
attributed more than half of the samples to the function; the A/B shows that this
overstated the effect (a memory-latency-bound walk is inflated by a contended host),
which is why the decision and the numbers rest on the A/B. The change is kept
because it removes the only superlinear term in the evaluator and cannot change a
result.

Evidence of identical output: the replayed documents are byte-identical before and
after on the 1,617 and 25,617-variant runs (`diff -r` of the output directories, the
previous binary against the new one); `replay_of_a_sanitized_output_run_reproduces_the_run`
(run, then replay without and with the original) and the whole CLI replay suite
pass; a unit test pins that the list is aligned with the executor's task indices.

### N1. Deliberately not optimized (each with its evidence in docs/performance.md)

- **Kernel accounting and matching.** Assessment plus accounting is about 1
  microsecond per outcome row and about 10% of `assemble`; the rest of the
  evaluator's time is document handling. Matching is linear in the number of
  findings (0.14 microseconds per finding, up to 444,361 findings). Nothing in the
  kernel is a hotspot.
- **Document layer (canonical serialization, digests, strict parse, validation).**
  This is where the evaluator's own time goes at scale (per outcome row: validation
  2.5, digest 2.4, serialization 1.8, parse 5.7 microseconds against 1.0 for the
  kernel; 1.2 to 1.3 million evaluator instructions per variant for a whole run), and
  the canonical string writer is the top self-time symbol of a post-fix profile (about
  12% of a replay). It is not changed here: every document is digested and parsed
  more than once on purpose (the writer proves that what it wrote parses back to
  itself and verifies it), removing a pass would weaken that verification, and a faster
  pass changes digest code that the frozen protocol depends on, for a gain bounded by
  that function's share of one profile (about 12% of a replay).
- **Streaming or tighter parse.** Measured by stage (peak RSS above a baseline
  process over document bytes): strict value tree 4.2 to 6.9x, typed parse 1.0 to
  2.5x, typed parse plus validation (a second value tree for the digest) 6.8 to 9.8x,
  the full parse 8 to 12x (10 to 15x for observation sets with many findings), varying
  run to run with the allocator's retention of the freed tree. At the cap the
  existing measurement reproduces ADR 0008 (4.2x and 31.7x against 4.1x and 31.8x).
  A streaming strict validator would lower the full peak at best to the validation
  stage, a saving of up to a third (about 100 MiB for a document at the cap) and
  sometimes nothing; more would need a streaming digest as well; and it would touch
  the error classification of 93 negative fixtures. Not warranted by data: engine
  documents at the cap need 250 to 350 MiB to parse, nothing runs the evaluator
  under a lower limit, and only adversarial node-dense documents reach the 1 GiB
  of ADR 0008. Follow-up trigger: a custodian memory limit below about 1 GiB, or a
  raised document cap.
- **Fixed per-run overhead of the executor** (about 18 ms; consistent with the
  watchdog's 15 ms sleep that `stop` joins, not isolated). One scanner session start
  costs 30 to 40 ms and a run starts at least `replays` of them.
- **Worker defaults and per-session pin verification.** Oversubscription beyond the
  host's CPUs was measured (wall time and CPU time both worsen: 14x CPU time at 32
  workers for a real scanner) and the evaluator's instruction count grows with the
  number of sessions (51 million per session with the real package, consistent with
  pinned-artifact re-verification, not isolated). The manifest, not the host, decides
  parallelism (ADR 0009), re-verification is a security property (ADR 0006), and no
  default was changed.

### C1. Ceilings are the document cap, not the accounting limits

The accounting state limits (ADR 0005: 16,000,000 rows) are never reached: the
32 MiB document cap binds first, at about 27,000 authored cases for a
pretty-printed snapshot (1.2 KiB per case; computed from the measured 30.4 MiB at
25,600 cases), about 58,000 outcome rows for a pretty-printed run artifact (580 bytes
per row; measured: 56,034 rows pass, 60,034 are refused) and about 170,000 findings
for a dense observation set (refused at 222,000). The writer refuses a larger
document through its round-trip check (`WriteError::RoundTrip`, nothing written),
which is the right outcome with an uninformative reason. Raising the cap, a compact
serialization or a more specific reason is a contract decision outside this phase.

## Consequences

- New: `tools/perf/`, `crates/pii-eval-cli/examples/perf.rs`,
  `crates/pii-eval-cli/tests/perf/`, `tests/perf_harness.rs`, `fixtures/perf/`
  (a 23 KB workload and its 55 KB oracle observations), `docs/performance.md`,
  `docs/perf/` (results, budgets), CI steps for the harness and the Node tooling.
- Changed: `crates/pii-eval-cli/src/replay.rs` (O1) only in code. Documentation and
  CI additions, minimal and additive: README status row, ARCHITECTURE and CONVENTIONS
  pointers, `docs/dependency-policy.md` (no dependency added), `.github/workflows/ci.yml`
  (two steps).
- Not changed: contracts, schemas, fixtures, digests, protocol, accounting,
  matching, dependencies, toolchain.
- The measurement suites are manual (they take tens of minutes and need the
  oracle through `gh`); CI runs the harness at tiny sizes.

## What is not claimed

No throughput, latency or capacity promise for any host or workload; no claim
about the real scanner beyond the one pinned package on one platform; no claim
that the TypeScript oracle is slow in general (it is measured doing what it does,
including file writes and an accounting step whose cost is consistent with O(groups x rows): exponent 2.4 between 6,417 and 25,617 variants); no allocation
counts; no Linux numbers (the Linux report parser is unit-tested against a sample
only); no measurement under a quiet machine (the host was shared).
