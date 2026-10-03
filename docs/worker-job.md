# Worker job: the engine side of the custodian's worker protocol

Status: **implemented and tested with synthetic data; not deployed; fails
closed in every production build** because the custodian has not decided the
items listed under "Not decided". Decisions and alternatives:
[ADR 0015](adr/0015-worker-job-launcher-and-contract-adapters.md). What the
custodian has and has not decided, with evidence:
[custodian-contract-status.md](custodian-contract-status.md). The boundary and
the responsibilities of each side: [custodian-boundary.md](custodian-boundary.md).
The custodian's sandbox: [custodian-isolation-node.md](custodian-isolation-node.md)
(the Node-under-`RLIMIT_AS` measurement). This repository did not run, and does
not claim, any isolation.

This document is about a **delivery** of the engine to a sandbox the custodian
provides. The artifact CI of this repository ([ci-artifacts.md](ci-artifacts.md))
is a delivery path for the binary, not a sandbox, and protected evaluation never
runs in GitHub Actions.

## Invocation

```text
pii-eval worker-job --job FILE
pii-eval --job FILE            # the exact shape the custodian starts: /stage/engine --job /job/job.json
```

Nothing else is an alias: `--job=FILE`, extra arguments, other options and short
options are usage errors (exit 2). The command has no other option, no
configuration flag and no environment variable. **There is no flag, environment
variable or configuration field that selects a test adapter in any build.**

Stdout carries exactly one `private-custodian.worker-result/1` document (one
line, no trailing newline, at most 64 KiB) when a result exists, and **nothing**
when the launcher refuses. Stderr carries one fixed-vocabulary line on a refusal:
`pii-eval: <reason> (<exit name>, exit <code>)[: detail]`. Neither contains an
entry name, a value, a path or scanner output.

## What the custodian provides (decided, A1 to A3)

| Path in the sandbox | Content |
| --- | --- |
| `/stage/engine` | this binary |
| `/stage/adapter` | the adapter bundle (the Node shim) |
| `/stage/candidate` | the candidate bundle (the scanner package) |
| `/stage/scanner-0` | the pinned Node runtime |
| `/stage/config` | the worker configuration |
| `/input/<entry>` | flat regular files, name `[a-z0-9][a-z0-9._-]{0,63}`, at most 16 MiB each |
| `/job/job.json` | the job document |
| `/scratch` | a size-capped tmpfs, the only writable place |

The staged names, the 16 MiB bound, the label pattern and the rest of the
sandbox are the custodian's and are implemented as stated. **Which file holds
what** (`adapter`, `candidate`, `scanner-0`, `config`) is the engine's proposal
(Q9, below).

## Order of work

Each step before the next; no protected entry is read before step 6.

1. Every adapter slot must hold an adapter the policy admits, else
   `contract-not-final: <slot>` (exit 6) and **nothing is touched, not even the
   job file** (`worker_default.rs`).
2. Read the job: strict JSON, closed shape, at most 1 MiB, domain `pii`,
   protocol `pii-v1` version `2` (the contracts' `PROTOCOL_ID` and
   `PROTOCOL_VERSION`), `roster == entries.len()`, between 1 and 10 000 entries,
   names in the custodian's pattern, no duplicate.
3. Each staged file is a regular file: no symlink, no hard-link alias
   (`nlink == 1`), no group or other write bit.
4. Parse the configuration (below). Its run class must be `protected`
   (`run-class-mismatch` otherwise).
5. SHA-256 of each staged artifact equals its pin in the configuration, each with
   its own reason; both bundles are extracted into the scratch directory by the
   bundle reader (the only extractor); the extracted package TREE digest equals
   the tree pin; the extracted shim equals the digest compiled into this binary.
6. The entries listing equals the job's; each entry is a regular file of at most
   16 MiB (32 MiB in total), decoded and validated. Entries are read in name order.
7. The snapshot is assembled (header from the configuration, cases in canonical
   order) and its semantic digest must equal the population pin
   (`population-binding-mismatch`); the manifest must bind to it; exactly one
   scanner.
8. The scanner adapter is built from the staged runtime, the extracted shim and
   package; its derived plan must equal the manifest's.
9. The **same pipeline as `pii-eval run`** runs: `run::run_and_write` (the
   bounded executor, the kernel's matching and accounting, the verifying atomic
   writer), with every output file under `/scratch/pii-eval-worker/`.
10. The result and, for a complete measurement, the aggregates are built and
    bounded; the aggregates go through the channel adapter; then the result is
    printed.

Nothing here measures, scores or re-implements statistics. A test
(`worker_job.rs`, `worker_mode_measures_exactly_what_standalone_run_measures...`)
runs the standalone pipeline on the same population and requires the same run
artifact digest and the same numerators and denominators.

### Staleness

A job or a staged world is detected as stale or foreign only by **binding
mismatch**: the entries listing against `/input`, the roster, and the digests.
Neither the worker job nor `pii-eval-job-context/1` carries an expiry or
freshness field and none is added (Q8); time-based freshness stays with the
custodian, which checks freshness and revocation before it stages anything and
again before it releases.

## Result semantics

`roster.expected = roster.observed =` the number of entries (every entry was
read; a refusal before the run prints nothing). `roster.failed` is `0` when the
scanner measured every input and `expected` otherwise: **a scanner that did not
complete measured nothing** (`ScannerRun`), whether it crashed, timed out,
exceeded a resource limit, answered with something malformed or disagreed with
its own replays. The run artifact records the failure and the exit status is 0
(the custodian maps a clean exit with a failed item to `Partial`, A6).

The `status` field is a function of coverage only: `complete` iff
`observed == expected`. The custodian rejects a `partial` whose counters say
`observed == expected` (its `validate_result`; vector
`doc("credential","partial",5,5,0)` in `staging_result.rs`), so a failed
measurement is reported as `complete` with `failed > 0`, which the custodian maps
to `Partial` (`worker_custodian.rs` shows both). The open consequence is under
"What the custodian must decide".

## Exit codes and outcomes

The frozen table of [cli.md](cli.md) is reused; no code is added. `worker-job`
uses these (`5` is never used: a scanner failure is a result, not an exit):

| Exit | Cases | Stdout | What the custodian does (A6) |
| --- | --- | --- | --- |
| 0 | result printed: complete (`failed 0`), or a scanner failure (`failed == expected`) | the result | `Success`, or `Partial` (never releasable) |
| 2 | usage | a summary line (usage errors predate the launcher) | `Failed` |
| 3 | invalid job, configuration, entry or bundle | nothing | `Failed` |
| 4 | an identity, digest, binding, population or run-class mismatch | nothing | `Failed` |
| 6 | `contract-not-final`; refused limits; unusable adapter; no signal handler | nothing | `Failed` |
| 7 | the output could not be produced: write failure, extraction failure, a result or aggregates document that is over its bound, violates the roster, carries an invalid label or could not be delivered | nothing | `Failed` |
| 8 | cancelled (SIGINT, SIGTERM, SIGHUP): scanner trees killed, scratch removed | nothing | `Failed` or `Cancelled` (its own supervisor) |
| 1 | an internal defect, including a document this engine built that failed its own verification | nothing | `Failed` |

Exit 9 (protected context) is not used: the custodian's job document and the
sandbox take the place of `pii-eval-job-context/1` here, which `worker-job`
neither requires nor reads.

## Reason codes

All worker-job reasons (`reason.rs`); none carries a value. CLI reasons that also
occur (`cancelled`, `execution-refused`, `output-write-failed`, ...) are in
[cli.md](cli.md).

| Exit | Reasons |
| --- | --- |
| 3 | `job-unreadable`, `job-too-large`, `job-invalid`, `entries-too-many`, `entry-name-invalid`, `entries-duplicate`, `roster-mismatch`, `worker-config-invalid`, `worker-config-too-large`, `entry-unreadable`, `entry-not-regular`, `entry-too-large`, `entries-too-large`, `entry-invalid`, `bundle-invalid`, `scanner-count-unsupported` |
| 4 | `job-domain-mismatch`, `job-protocol-mismatch`, `entries-listing-mismatch`, `staged-file-invalid`, `engine-digest-mismatch`, `adapter-bundle-digest-mismatch`, `candidate-bundle-digest-mismatch`, `package-tree-digest-mismatch`, `runtime-digest-mismatch`, `shim-digest-mismatch`, `population-binding-mismatch`, `run-class-mismatch`, `manifest-binding-mismatch`, `scanner-plan-mismatch` |
| 6 | `contract-not-final` (detail: the slot) |
| 7 | `bundle-extract-failed`, `result-too-large`, `aggregates-too-large`, `aggregates-roster-violation`, `aggregate-label-invalid`, `aggregates-channel-failed` |

`population-binding-mismatch` and `run-class-mismatch` are the names the
custodian lists as pii-eval deliverables (`docs/benchmarks-integration.md`
section 4).

## Bounds

| Bound | Value | Where |
| --- | --- | --- |
| job document | 1 MiB, 10 000 entries | `job.rs` (the entry limit is the engine's; the custodian states none) |
| entry | 16 MiB (A3); all entries together 32 MiB (the contracts' document bound) | `entry.rs` |
| configuration | 1 MiB | `config.rs` |
| bundle | 4096 members, 32 MiB per member, 256 MiB in total, 2 MiB header, 255-byte paths of at most 8 components | `bundle.rs` |
| staged file hashed | 1 GiB (the custodian's staging bound) | `digest.rs` |
| result | 64 KiB (A5) | `job.rs` |
| aggregates | 256 cells, 64 KiB (A11) | `aggregates.rs` |
| workers, timeouts | the manifest's limits and `resources` of the configuration (at most 64 workers, 600 s timeouts); the executor's own explicit limits apply | `config.rs`, `exec.rs` |

Over any bound the launcher refuses; it never truncates or clamps.

## Formats the engine defines (engine-owned, opaque to the custodian)

### `pii-eval-worker-config/1`

The staged `config` file (the custodian pins its SHA-256 as the plan's
`config_digest`). Closed, strict JSON of at most 1 MiB:

```json
{
  "schema": "pii-eval-worker-config/1",
  "protocol": {"name": "pii-v1", "version": "2"},
  "runClass": "protected",
  "population": {"digest": "<64 hex: semantic digest of the assembled snapshot>"},
  "snapshot": {"population": {"populationId": "...", "populationVersion": 1, "visibility": "protected"},
               "generation": {"generator": "...", "generatorVersion": 1, "seedDerivation": "..."}},
  "manifest": { "a complete pii-eval.run-manifest document" },
  "product": "candidate",
  "artifacts": {
    "engine":    {"sha256": "sha256:<hex>"},
    "adapter":   {"bundleDigest": "sha256:<hex>"},
    "candidate": {"bundleDigest": "sha256:<hex>", "treeDigest": "<hex>",
                  "entry": "dist/index.js", "version": "0.1.0-beta.12"},
    "runtime":   {"sha256": "sha256:<hex>"}
  },
  "resources": {"maxWorkers": 2, "startupTimeoutMs": 30000, "callTimeoutMs": 30000}
}
```

It holds digests and numbers, never a path: every path comes from the layout and
the fixed staged names, so a hostile configuration can make the run fail but
cannot make it read outside stage, input or scratch (`worker_job.rs`,
`a_hostile_configuration_can_only_fail_the_run`). The snapshot is assembled at the
engine's current schema version, which is part of its digest: the population pin
is the digest of that assembled document.

### `pii-eval-bundle/1`

A deterministic archive of regular files; its reader is the only extractor
(`bundle.rs`, byte layout in the module documentation). One encoding exists for
a set of files: sorted members, a canonical compact header, member bytes
concatenated, nothing after them. No symlinks, directories, hard links or
permissions other than an executable flag can be expressed. Member paths follow
the custodian's `validate_member_path` (no absolute path, `..`, empty component,
backslash or control character) and the tree digest's name rule. The bundle
digest (the SHA-256 of the archive file) and the package tree digest are two
different typed digests.

### `pii-eval-worker-entry/1`

```json
{"schema": "pii-eval-worker-entry/1", "case": { "the contracts' Case" }}
```

One entry is one authored case with its variants and expectations. The entry's
file name is the case identifier byte for byte (an identifier is already
lower case and `[a-z][a-z0-9-]{1,79}`; one longer than 64 bytes cannot be an
entry and is `entry-invalid`). Closed: unknown fields, a different name, an
invalid range or digest, or a duplicate variant across entries is `entry-invalid`
before any scanner runs.

### Typed digests

`CustodianDigest` (`sha256:` plus 64 lowercase hex), `EngineDigest` (bare 64 hex),
`BundleDigest`, `TreeDigest` and `RuntimeDigest` have no `From`, `Into`, `Deref`
or `AsRef` between them (`digest.rs`; compile-fail doctests). A bundle digest
where a tree digest is required fails twice over: the syntax differs
(`worker-config-invalid`), and the same hex placed in the other slot fails its own
comparison (`package-tree-digest-mismatch` or `candidate-bundle-digest-mismatch`).

## Adapters and statuses

| Slot | Question | Status | Production wiring | Test adapter |
| --- | --- | --- | --- | --- |
| `stage-layout` | Q9 where Node, the shim and the package live | Proposed | unconfigured | `TestLayout` (directories of one test run) |
| `bundle-format` | Q4 how a package tree travels as one staged file | Proposed | unconfigured | `TestBundle` (`pii-eval-bundle/1`) |
| `entry-format` | Q1 what an entry holds | Proposed | unconfigured | `TestEntry` (`pii-eval-worker-entry/1`) |
| `aggregates-channel` | Q2 how the aggregates reach the custodian | Proposed | unconfigured | `FileChannel` (`<scratch>/aggregates.json`) |
| `aggregate-labels` | Q3 which strata and metric labels | Proposed | unconfigured | `TestLabels` (stratum `overall`, nine metric ids) |
| job document, result document | A4, A5 | **Decided** | implemented | n/a |
| digest syntax | A10 | **Decided** | implemented | n/a |
| staged names, limits | A2, A3 | **Decided** | implemented | n/a |

A production build admits only `Decided` adapters, so `worker-job` refuses with
`contract-not-final: stage-layout` and exits 6 before reading anything. When the
custodian decides a slot, enabling it means implementing a `Decided` adapter for
that slot with tests and installing it in `Adapters::production()`; nothing else
changes.

The test adapters are compiled only with the cargo feature
`worker-test-adapters` (off by default, never enabled by the engine artifact
build). They contain the marker string `pii-eval-worker-test-adapters`:

- `worker_default.rs` checks that the default binary does not contain the marker
  and refuses with `contract-not-final`, and (feature build) that the marker is
  present, so the check can fail;
- `.github/workflows/build-engine.yml` fails the build if the release binary
  contains the marker;
- `pii-eval --version` of a feature build says `pii-eval 0.0.0 (bootstrap;
  worker-test-adapters)`.

Even a feature build refuses at the command line: the binary always uses the
production wiring. Only the Rust API (`worker::launch::run_worker_job` with
`worker::test_adapters::adapters`) runs a job end to end, in tests.

## Not decided (what fails closed)

| Item | What the launcher does |
| --- | --- |
| Q1 roster unit | one entry is one authored case (proposed); every denominator must be at most `observed` or the launcher refuses (`aggregates-roster-violation`) |
| Q2 aggregates delivery | no production channel; a release build refuses (`contract-not-final: aggregates-channel`) |
| Q3 labels | `overall` and metric ids proposed; the policy decides |
| Q4 package identity | two typed digests, the bundle format is proposed |
| Q6 several scanners | one scanner per run (`scanner-count-unsupported`) |
| Q7 Node under `RLIMIT_AS` | measured separately ([custodian-isolation-node.md](custodian-isolation-node.md)); the launcher adds no Node flag and loosens no limit. Extension point: `ScannerConfig` (`crates/pii-eval-cli/src/config.rs`) and `build_adapter` (`scanners.rs`) are where a runtime option would be added after that measurement |
| Q8 freshness | none; binding mismatch only |
| Q9 stage layout | proposed above |

## What the custodian must decide (found while implementing)

1. **`measurable-share` over a case roster.** Its sample is the axis assertion
   (two per case on the synthetic population: 5 measured over 3 entries), so its
   denominator exceeds `observed` and the launcher refuses the whole document.
   Either the roster unit is finer than a case or the pii disclosure policy does
   not publish that metric. The test labels leave it out; publishing all ten is
   refused (`worker_job.rs`, `publishing_all_ten_metrics_over_a_case_roster...`).
2. **A partial result cannot become a receipt.** The custodian's
   `InternalReceipt` accepts `Partial` only with `observed < expected`; a failed
   measurement here has `observed == expected` and `failed > 0` (the only form its
   `validate_result` accepts for a clean-exit failure). Its documents already say
   such a result is a private failure record (`worker-isolation.md` section 7).
3. **Aggregates delivery (Q2)** and **the stage layout (Q9)**, **bundle (Q4)**,
   **entry (Q1)** and **labels (Q3)**: the proposals above, or others.

## Real sandbox end to end

The in-process tests above stage a wrapper script as `scanner-0`. The CI job
`worker-flow` (`.github/workflows/isolation.yml`, called by `ci.yml`) runs the
whole flow in a **real Linux bubblewrap sandbox with the real pinned Node
runtime**, on synthetic data, and fails on any violated expectation.

**Why not the production binary.** `pii-eval` always uses the production
adapters and refuses (`contract-not-final`), so it cannot run a job. The engine
inside the sandbox is the test example
`crates/pii-eval-cli/examples/worker_test_engine.rs`, which has
`required-features = ["worker-test-adapters"]`: it is not built by `cargo build`,
not by `cargo test` without the feature, and never part of the engine artifact
(the marker check in `build-engine.yml` and `worker_default.rs` prove the release
`pii-eval` contains no test code; `worker_example.rs` proves the example does). It
has three subcommands:

- `stage --out DIR --node PATH --scenario NAME [--entries N]`: builds the
  synthetic world by reusing `tests/worker_support` (included with `#[path]`, not
  forked), with the REAL Node binary as `scanner-0` and a copy of the example
  itself as `engine`, in the custodian's layout `DIR/{stage,input,job}/` plus
  `DIR/pins.json` (the plan-like `sha256:` pins of every staged file and the
  authorized roster);
- `--job FILE`: the launcher with the TestOnly adapter policy, started in the
  sandbox as `/stage/engine --job /job/job.json`. Its aggregates channel is a
  TEST channel (the document goes to `/scratch/aggregates.json` and, because the
  sandbox's scratch is gone when the worker exits, also as one stderr line); the
  real channel is undecided (Q2);
- `validate --dir DIR --stdout FILE --exit CODE|signal:NAME|timeout|output-limit
  [--aggregates FILE]`: the replica of the custodian's `validate_result`, the
  outcome mapping (A6) and `PrivateAggregates::decode`, one JSON line
  `{outcome, reason, roster, aggregatesOk}`.

`tools/isolation/worker-e2e.mjs` (standard library only, reusing
`bwrap-argv.mjs` and the controls of `matrix.mjs`) plays the dispatcher: stage;
a replica pre-run identity check (every staged file hashed against its pin; a
mismatch is `Rejected` before anything runs); run `/stage/engine --job
/job/job.json` with the dispatcher's mounts (`/stage`, `/input`, `/job`
read-only), its four environment variables and the custodian's normal quotas
(cpu 30 s, wall 20 s, storage 64 MiB, 32 processes, stdout 64 KiB) with memory
as the variable; a post-run re-hash (drift is `Rejected`); then `validate`. The
controls (limits applied, no capabilities, no egress, no host files, scrubbed
environment, writable scratch) run first and must pass.

| Scenario (memory) | Expected custodian outcome |
| --- | --- |
| `normal` (1024, 1536 MiB) | `Success`, `completed`, `observed == expected`, `failed 0`, aggregates decode |
| `normal` (512 MiB, the custodian's test profile) | **never `Success`** (Partial, Failed or Rejected): the Q7 conflict reproduced end to end; no limit is loosened to avoid it |
| `population-mismatch`, `run-class-mismatch`, `wrong-bundle-digest`, `wrong-tree-digest`, `wrong-runtime-digest`, `stale-job` (1024 MiB) | `Failed` `non_zero_exit`, empty stdout, the engine's own reason (`population-binding-mismatch`, `run-class-mismatch`, `candidate-bundle-digest-mismatch`, `package-tree-digest-mismatch`, `runtime-digest-mismatch`, `entries-listing-mismatch`), before any entry is read |
| `scanner-crash` (a runtime that dies) | `Partial` `engine_partial`, every entry failed |
| `scanner-hang` (wall clock 5 s, the only shortened quota) | `Failed` `timeout` |
| `staged-file-tampered` (a staged file differs from its pin) | `Rejected` `identity_mismatch`, the worker never starts |

A population sweep (20, 100 and 400 entries at 1024 and 1536 MiB, with a longer
wall and cpu budget) **records** whether the address-space need grows with the
population; nothing is asserted about growth. The report
(`pii-eval-worker-e2e/1`) is uploaded by the job and its summary is written to the
job summary. Measured numbers are in
[custodian-isolation-node.md](custodian-isolation-node.md).

**What this proves, and what it does not.** It shows how this engine behaves, in a
sandbox built from a replica of the custodian's launcher vector, under the
custodian's documented limits, with the real Node; and that the custodian's checks
as replicated here accept the engine's outputs and map each failure as A6 says.
It does not prove isolation on the production host (the custodian's startup
self-check is that evidence), it does not run the custodian's code (the replica
goes stale if the custodian changes), the aggregates channel is a test channel,
and the data is the synthetic quickstart population cloned to N entries.

## What needs verification after deployment

- The `ps`-based memory sampling and process-tree cleanup under the custodian's
  production sandbox (the CI job exercises the replica sandbox only).
- The custodian's own validation of a real result and aggregates (the tests use a
  replica, `tests/worker_support/replica.rs`, written from private-custodian at
  commit `142db34dd4bc02903f47cba951a054351bb55fde`; it is not its code and a
  later change there is not seen).
- That a staged Node binary above 32 MiB hashes within the sandbox's CPU limit
  (the digest is streamed, bounded at 1 GiB).

## Evidence

| Claim | Test |
| --- | --- |
| production refusal, no entry read, alias shape, no test adapter in the binary | `worker_default.rs` |
| complete run, determinism, parity with `run`, every refusal and partial path, cancellation | `worker_job.rs` (feature) |
| replica of the custodian's validation, conformance vectors, outcome mapping | `worker_custodian.rs` (feature) |
| bundle reader, job, configuration, digests, adapters | unit tests in `crates/pii-eval-cli/src/worker/` |
| the test engine example: `validate` equals the replica, `stage` layout and pins, the engine with real Node (unsandboxed), the marker | `worker_example.rs` (feature) |
| the whole flow in a real bubblewrap sandbox with real Node | CI job `worker-flow` (`tools/isolation/worker-e2e.mjs`; pure parts in `tools/isolation/test/worker-e2e.test.mjs`) |
