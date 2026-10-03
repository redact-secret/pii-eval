# ADR 0009: Bounded deterministic scanner execution and reproducible artifact writing

- Status: accepted for P7 (issue #8); subject to review.
- Date: 2026-10-03
- Related: [ADR 0006](0006-scanner-adapter-boundary.md) (D4, D12),
  [ADR 0008](0008-protocol-revision-2-and-schema-1-1.md),
  [SECURITY.md](../../SECURITY.md), epic #1. Implementation:
  `crates/pii-eval-adapters/src/control.rs`, `crates/pii-eval-adapters/src/process.rs`,
  `crates/pii-eval-cli/src/{exec,assemble,write,run}.rs`.

## Context

ADR 0006 D12 left to P7: a worker pool, descendant cleanup, limits, fresh
processes per realm, replay scheduling, ObservationSet assembly, sanitized-output
verification and artifact writing. This ADR records how they are built, what
the limits are, what is and is not provided on each platform, and why.

## What this is not

Rust process control is **not a security sandbox**. It bounds what an honest or
buggy scanner leaves behind or consumes. It does not stop a hostile scanner from
reading files the evaluator's user can read, using the network, escaping its
process group with `setsid`, or exceeding a memory limit between two samples.
Protected isolation (containers, cgroups, network namespaces, read-only
installs, pinned interpreter) is custodian-owned (SECURITY.md).

## Where things live

| Concern | Home | Why |
| --- | --- | --- |
| Process group, tree kill, resource sampling | `pii-eval-adapters::control` | it owns the child process; the pure crates stay free of process code |
| Pool, replays, cancellation, deadlines, assembly, writing | `pii-eval-cli` library | ARCHITECTURE.md assigns orchestration and limits to the CLI crate; no new crate was justified (P8 will call `pii_eval_cli::run`) |
| Output verification, accounting, verifier | `pii-eval-kernel` | pure, scanner-neutral protocol semantics |

## Decisions

### E1. Process groups and `rustix` (the only new third-party crate)

Every scanner process leads a new process group (`CommandExt::process_group(0)`,
`std`, no `unsafe`). Signalling a group needs `killpg(2)`, which `std` does not
expose and which first-party code may not call (`forbid(unsafe_code)`). Options
considered: `libc` (needs `unsafe`), `nix` (large, `nix` is a forbidden fragment),
shelling out to `/bin/sh -c kill` or `/bin/kill` (fragile across minimal
containers; failure would silently stop cleaning), and **`rustix` 1.1.5**
(Bytecode Alliance, safe wrappers, `default-features = false`, features `std` and
`process`). Chosen: it is the smallest vetted safe wrapper. It is a
dependency of `pii-eval-adapters` only, on Unix only
(`[target.'cfg(unix)'.dependencies]`); its closure is `bitflags`, `errno`,
`linux-raw-sys`, `libc`, `windows-sys`, `windows-link` (the last two appear
because the guard inspects `--target all`). The guard
(`crates/pii-eval-cli/tests/dependency_policy.rs`) allows these for the adapters
only, never for contracts or kernel, and `libc` only through `cpufeatures`,
`errno` or `rustix`. Resource sampling uses `ps`, not a crate (E4). MSRV 1.85
re-verified.

The group is signalled **before** the leader is reaped on every failure path
(timeout, limit, crash, drop, failed start), so its id cannot have been recycled;
after a graceful exit the group is signalled only while it still has members (a
group id cannot be reused while a member exists). The window that remains
(leader reaped, group emptied, id recycled by a new group leader within
microseconds) needs a full pid wrap and is accepted and documented.

Platform status: **Linux and macOS: implemented and tested** (macOS here; Linux
in CI). **Windows: not implemented.** There is no job-object code;
`TREE_CLEANUP_SUPPORTED` is `false`, an `AbortHandle` kills only the direct
child, `Supervisor::start` fails, and the executor refuses to run unless
`require_tree_cleanup` is turned off. Treat Windows as unsupported. If the
evaluator itself is killed (`SIGKILL`, power loss) the scanner group is not
cleaned up (a shim exits when its stdin closes, a descendant does not): the
custodian must contain the run.

### E2. Bounds and defaults

| Limit | Source | Default / rule |
| --- | --- | --- |
| Concurrent sessions | manifest `workers`, host cap `ExecutorConfig::max_workers` | `min` of both; the cap defaults to the logical CPU count, so a plan cannot oversubscribe the host |
| Sessions per scanner | manifest `per_scanner_parallelism` (at most `workers`) | scanners run at most `workers / per_scanner_parallelism` at a time |
| Pending tasks | manifest `pending_tasks` | bound of the channel between producer and workers |
| Batch | manifest `batch_variants` | variants per task |
| Scanner time | manifest `scanner_timeout_ms` | **total** budget of one scanner (all replays), enforced by a watchdog killing its trees; the per-call timeout stays the adapter's (`AdapterLimits::call_timeout`, 30 s default) |
| Memory | manifest `max_memory_bytes` | whole-run budget divided over the concurrent sessions; the share of one session must be at least 32 MiB (`MIN_SESSION_MEMORY_BYTES`); sampled sustained resident set of the whole tree, interval 250 ms |
| Temporary storage | manifest `max_temporary_bytes` | divided the same way; a private scratch directory (mode 0700) per session, set as `TMPDIR`/`TMP`/`TEMP`, measured each sample (at most 100,000 entries, more counts as over), removed when the session ends and when the run ends |
| Output | manifest `max_stdout_bytes`, `max_stderr_bytes` | must be at least what the adapter enforces (`ScannerAdapter::limits`); a smaller manifest bound is refused before anything runs. Line, finding and stderr bounds are ADR 0006 D4 |
| Raw buffers | design | only the first pass retains observations; replay passes keep one bit per input; sanitized output is verified at once and dropped |

Memory enforcement is **sampled** (one `ps -A -o pgid=,rss=` per interval for all
sessions): a process can exceed its limit between samples, so the limit bounds
sustained use and the sampled peak is recorded in `SessionStats::peak_rss_bytes`
(a lower bound of the true peak). `ResourcePolicy::Enforce` (default) refuses to
run when the host cannot sample (`ResourceMonitor` error); `Unenforced` is an
explicit opt-out. A scanner over a limit is a `resource-limit-exceeded` failure
(schema 1.1); a deadline is `timeout`; a cancel is `cancelled`.

### E3. Fresh process per realm; replays

Each scanner plan is one activation/configuration realm and has its own
processes; the package allows one activation per process, so there is never a
shared process between realms. Every pass over the inputs (`mechanics.replays`
passes, first included) starts **fresh** sessions, so process-local state cannot
hide instability. A pass that differs from the first (findings, input digest or
sanitized-output digest) marks that input; any marked input makes the scanner
`unstable` with a `replay-disagreement` failure counting the marked inputs; no
observation of an unstable scanner is kept. Replays add no samples (a test shows
identical counts for 2 and 5 passes). `ReplayRecord.count` is the planned number
of passes (the manifest binding requires it) and `agreed` is false only for an
unstable scanner.

### E4. Determinism

Tasks are indexed by snapshot order and results by manifest scanner order, never
by completion. A scanner's failure is the failure of the **lowest variant index**
among those attempted, and tasks below the lowest failure always run, so the
recorded code does not depend on which worker was faster (for a scanner whose
failures are themselves deterministic). `jobs=1` versus `jobs=N`, different
batch sizes and pending bounds, and diagnostics on or off give identical
artifact, observation and public digests for one manifest (tests with fake
scanners whose completion order is forced to differ, and with real Node
processes). The execution limits are part of the manifest (so of the manifest
digest), but everything measured (observations, rows, metrics, failures) is
independent of them. Cancellation and deadlines are inherently
timing-dependent and are recorded, not hidden.

### E5. Failure recording

A scanner that fails after others succeeded is recorded as such: the artifact is
complete about every row (rows of the failed scanner are `not-measured`) and
carries a failure with a sanitized code. Distinct states: `unsupported`,
`unavailable` (pin mismatch, start failure), `execution-error`, `timeout`,
`output-limit-exceeded`, `malformed-output`, `resource-limit-exceeded`,
`replay-disagreement`, `cancelled`. A session whose pins changed during the run
(`SessionStats::pin_check`) fails the scanner `unavailable`: its observations are
not trusted. A scanner that completes but declares ranges unsupported becomes
`unsupported`. Failures carry fixed enums only (ADR 0006 D7).

### E6. Artifact writing

`ArtifactWriter::write_run` validates every document and binding, **calls the
kernel accounting verifier on the internal artifact and on the public projection**
(ADR 0008), requires the projection to equal the projection of the artifact,
serializes and strictly re-parses each document to an equal value, writes
temporary files (`create_new`, mode 0600, `fsync`) and renames them into place:
observation sets, the public projection, the run artifact last (the commit
marker; it binds every observation by digest), then syncs the directory. The
default `OverwritePolicy::Refuse` never replaces an earlier result; a symlinked
destination or file is refused. A failure before the renames leaves nothing; a
failure during them rolls back what the call created or reports
`PartiallyCommitted` (always under `Replace`, which cannot restore overwritten
files). A hard crash can leave `.pii-eval-tmp.*` files (removable with
`cleanup_stale_temps`) but never a half-written final file or a commit marker for
an incomplete run (tested with a child that aborts before the last rename).
Diagnostics hold the separated phases `scanner-startup` and `scan` (summed over
sessions, so they can exceed wall time), `kernel-replay`, `materialization`,
`serialization` (validation, verification and serialization of the documents,
measured by the writer) and `total`, plus runtime provenance per observation set;
none enters a digest.

### E7. Runtime provenance

`RuntimeRecord` becomes `RuntimeProvenance` in the observation set's diagnostics
(runtime name and version, scanner version, offset unit, adapter protocol, shim
and artifact digests, activation-identity digest; the scanner's own activation
string is not copied). It describes the host runtime, so it is non-semantic by
the digest rule; the pinned scanner identity stays semantic.

## Limits per platform (summary)

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Process-group tree kill | yes (CI) | yes (developer host) | no |
| Memory and scratch limits | yes (`ps`) | yes (`ps`) | no (executor refuses) |
| Crash of the evaluator cleans the tree | no | no | no |
| Network/filesystem isolation | no (custodian) | no (custodian) | no (custodian) |

## Alternatives considered

- Async runtime or a process-management crate: unnecessary; `std` threads and
  channels are enough and the guard forbids them in the pure crates.
- Long-lived Node workers shared across passes or realms: rejected; fresh
  processes keep replay checks honest and isolate activations. Startup cost is
  measured in diagnostics and optimized in P10 with correctness checks on.
- Killing the whole run on the first failure: rejected; a failed scanner is data.
- `setrlimit` in the child (`pre_exec`): needs `unsafe`; sampling was chosen.

## Consequences

- `pii-eval-adapters` gains `rustix` (Unix) and `ScanSession::abort_handle`,
  `ScannerAdapter::start_with`/`limits`, `StartOptions`, `SanitizedOutput::new`,
  new `AdapterError` variants (`Cancelled`, `ResourceLimit`) and `CallPhase::Total`.
- `pii-eval-cli` gains a library API (`exec`, `assemble`, `write`, `run`); P8
  adds the commands on top of it.
- CI runs the new executor tests with Node and `ps`.
