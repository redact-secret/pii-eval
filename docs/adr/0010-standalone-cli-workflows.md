# ADR 0010: Standalone CLI workflows (`run`, `replay`, `validate`, `compare`)

- Status: accepted for P8 (issue #9); subject to review.
- Date: 2026-10-03
- Related: [ADR 0002](0002-freeze-pii-contracts-v1.md),
  [ADR 0006](0006-scanner-adapter-boundary.md),
  [ADR 0008](0008-protocol-revision-2-and-schema-1-1.md),
  [ADR 0009](0009-bounded-execution-and-artifact-writing.md),
  [SECURITY.md](../../SECURITY.md), epic #1. The contract is
  [docs/cli.md](../cli.md). Implementation: `crates/pii-eval-cli/src/{args,config,status,summary,files,scanners,signals,replay,cmd_*}.rs`.

## Context

P7 left a library: `pii_eval_cli::run::{run, run_and_write}`, the executor, the
assembler and the writer, with no command. This ADR fixes the command-line
contract on top of it: syntax, configuration, frozen exit codes, the stdout and
stderr contract, how provenance is validated, how protected runs are gated, how
signals are handled, and what replay, validate and compare mean. It adds no
measurement semantics and changes no contract document.

## Decisions

### C1. Four commands, a hand-written argument parser

`run`, `replay`, `validate`, `compare` are the only commands (plus `--version`
and `--help`). Options are long-form with one value; a repeated option is a
usage error except `--observation`. Considered: `clap` (the usual choice). Not
added: it brings several crates (`clap_builder`, `clap_lex`, `anstyle`, `strsim`, and
the derive crates if used), each with its own MSRV and version drift under the
exact-lock policy, for four commands and a dozen flags that a short parser
covers with unit tests.
Errors name the option, never the value, which is easier to guarantee when the
parser is ours. Revisit if the command set grows.

### C2. A versioned JSON configuration for `run`; flags for the rest

`run` needs structured pins (a scanner package, extra artifacts, digests, host
settings), which do not fit flags and must be reviewable and diffable, so it
takes `pii-eval-run-config/1`, a closed, strictly parsed JSON document
(duplicate keys, `null`, floats, unknown fields and wrong types are rejected,
errors name only the field). The strict parser is the contracts' own
`parse_strict`. Relative paths resolve against the configuration's directory so
a checked-out example runs from anywhere. `replay`, `validate` and `compare` take
only file paths and digests and use flags. Only `--out`, `--node` and
`--job-context` can override or complete the configuration, because they do not
affect the measurement; digests, identities and limits cannot be overridden by a
flag. No new dependency: the configuration is read as a `serde_json::Value`
and checked field by field.

### C3. Exit codes: a frozen table

Twelve statuses (docs/cli.md), numbers never reused: 0 success, 1 internal, 2
usage, 3 invalid input, 4 provenance mismatch, 5 scanner failure (documents
written, measurement incomplete), 6 execution refused, 7 output failure, 8
cancelled, 9 protected context, 10 incomparable, 11 not verifiable. A scanner
failure is exit 5 with the documents written, never 0: "finding-zero" and
"scanner failed" cannot be confused by a script. `validate` of a legacy artifact
is exit 11 for the same reason (readable, not verified). A cross-document
binding failure (`population-binding-mismatch`, `input-digest-mismatch`, ...) is
exit 4; a malformed or self-inconsistent document is exit 3. A panic is exit 1
with a fixed message (the default panic text is suppressed because it could carry
input-derived text). A test pins the table against the documentation; exit 1 has
no end-to-end trigger (it is a defect state) and is covered by unit tests of the
rendering only.

### C4. Stdout is one JSON line, stderr one fixed-vocabulary line

Every invocation prints exactly one line of JSON on stdout
(`pii-eval-summary/1`), also on failure, so a wrapper never parses stderr.
Objects are ordered maps (`serde_json` without `preserve_order`), integers only,
no timestamps, durations or paths in the body, so the same inputs give the same
bytes. Stderr has one line built from reason codes, field names, document kinds
and identity slots and contract reason codes (a closed set), never input text,
values, paths, findings, scanner output or OS messages. Nothing is logged on
success. `--version` and `--help` keep their human text (documented exception).

### C5. Provenance and modes

`run` validates, in order and before anything is launched: the configuration;
for a protected run the job context (C6); the snapshot and manifest by contract
validation; the optional digest pins (snapshot, manifest) and the expected
engine version and protocol; run class (configuration against manifest and
against the population's visibility); product (configuration against every
scanner identity); the manifest against the snapshot (population, scope,
generation); the adapter-derived plan against the manifest's plan (scanner,
adapter, product, configuration and activation identities); the hash of every
pinned artifact (shim against the shipped digest, package tree, extra artifacts).
Run class (`public-synthetic` or `protected`) and product (`released` or
`candidate`) are two independent configuration fields, each checked.

`exploratory` and `official` differ only in what is mandatory: official requires
every pin, enforced resource limits and no overwrite. Neither changes
measurement semantics. The activation set is the manifest's (its configuration is
bound by digest, passed to the adapter, and the running scanner's activation
identity is verified at startup, ADR 0006), so a configuration cannot widen it.

Preflight hashing happens in the CLI before any process starts, so a changed
file is exit 4 with no output, instead of a scanner that later records
`unavailable`. The adapter still re-verifies at start, after ready and at the
end of each session (ADR 0006 D5); a swap between verification and use remains
possible and is the runner's to prevent.

### C6. Protected runs and the job context

A protected run needs a valid custodian job context (`pii-eval-job-context/1`).
The CLI validates it and binds the run to it; **it grants no access** and is not
an authorization (the custodian's isolation is). Minimal contract: job and
custodian ids, run class `protected`, the snapshot and manifest semantic digests
(and the candidate digest for a candidate), an input root and an output root.
Checks: a regular file that group and others cannot write; strict closed JSON;
digests match; the snapshot and manifest are read only from inside the input
root and the output directory is inside the output root (symlinks and `..`
resolved). The same confinement applies to `validate`, `compare` and `replay` of
protected documents (`--job-context`; protectedness is read from the parsed
visibility or run class, so the file is read before the refusal, which reports
nothing), and their summaries withhold case, variant and sample counts. Without a context the run is refused with a distinct exit code (9)
**before any input path is touched** (tested by pointing the configuration at a
missing snapshot). Stated limits: no signature or owner verification, no
isolation, and a protected run writes only the internal artifact. The reason
vocabulary carries no case identifiers, paths or values.

### C7. Signals: `signal-hook`, one new third-party crate

Scanners lead their own process groups (ADR 0009), so a terminal Ctrl-C reaches
only the CLI. `std` has no signal API and first-party crates forbid `unsafe`.
Options: `libc::sigaction` (needs `unsafe`), `nix` (large, a forbidden
fragment), `rustix` (no handler installation), a self-written `sigwait` thread
(needs libc), and `signal-hook` 0.4.4 with default features off (flag handlers
only; no channel or iterator machinery; it depends on `signal-hook-registry` and
`libc`, which is already in the graph). Chosen: `signal-hook`, in the CLI crate
only, Unix only, exact pin. `register_conditional_shutdown` and `register` set
the flag backing the run's `CancelToken` (new `CancelToken::from_flag`): the
first SIGINT, SIGTERM or SIGHUP cancels (a closed terminal must not leave
scanners attached), the executor kills every scanner tree, removes
scratch directories, nothing is committed, exit 8; a second signal exits at once
with status 8 and cleans nothing: scratch, `.pii-eval-tmp.*` temporaries, renamed
files without `run-artifact.json` and scanner trees may remain (documented).
A handler that cannot be registered fails closed (exit 6
`signal-handler-unavailable`). Writer temporaries in the output directory are
removed at the start of `run` and `replay` (the directory is the CLI's own). Handlers are installed only for
`run`. Tested with a real scanner that blocks forever and spawns a descendant:
the CLI exits 8, both processes are gone, scratch is empty, no output directory
remains.

### C8. Replay: observation sets in, artifact out, no scanner

`replay` rebuilds the executor's per-scanner results from observation sets
(`replay::runs_from_observations`) and feeds them to the unchanged assembler,
so it shares scoring, ordering and digests with `run`. It reaches no adapter or
process API (a source guard test, a test with a decoy `node` on a `PATH` that
holds nothing else, and nonexistent scanner paths). Inputs are rejected when
they change: observation sets are validated against the manifest and snapshot
(engine, protocol, population digest, scanner, adapter, product, configuration,
activation, input digests), the pinned digests are checked, every manifest
scanner needs exactly one set, and a legacy manifest is refused.

Two facts are not in an observation set: the `output-verified` verdicts (they
need the sanitized text, which observation sets deliberately never store) and
the failure code of a scanner that did not complete. They come from the
**original run artifact** (`--original`), which must pass the accounting
verifier, bind to these very observation sets by digest, and equal the replayed
artifact (otherwise exit 4 `replay-diverged`, nothing written). Without an
original, replay is refused (`replay-original-required`) whenever a scanner is
incomplete or returned sanitized output. `@redact-secret/core` always returns
sanitized output, so replaying its sets needs the original today.
`semantic.verification` states which parts were re-derived (matching, accounting,
metrics, review gate, artifact digest) and which were carried from the original
(output verdicts, failure codes), so `parity: identical` is not read as a fully
independent check. Replay writes
the same files as `run` and, when the original had no diagnostics, they are
byte-identical to it. A replay that needs no original would require the
verdicts in the observation contract (an optional field in schema 1.2): deferred,
not done silently here.

### C8a. The review gate belongs to the shared assembler

ADR 0007 requires every outcome row of a `review-required` variant to pass the
snapshot's review gate (type axis unmeasured) before accounting, and named the
run and replay paths as the callers. `assemble` (shared by `run` and `replay`)
now applies `ReviewGate::from_body(snapshot)` to every row it emits, so the
artifact rows, the metrics and the verifier's recomputation all see gated rows,
and a replay of a stored snapshot gates exactly as the run did (tests:
`cli_gate`). The kernel verifier re-applies the gate: a stored row that scores a
held variant's type axis as anything but not-measured is
`outcome-contradiction`, so `validate --snapshot` cannot call such an artifact
verified (`cli_review`). Fixtures without held variants are unchanged byte for
byte.

### C9. Compare: descriptive only

`compare` takes two artifacts of one kind, revision 2, and reports identity
changes and, per scanner and metric, both full results and a relation
(`identical`, `changed`, withheld on either side, absent). It never ranks,
scores or prefers, never turns a withheld metric into a number, and has no
threshold. Comparable means equal in everything except the subject (engine
version, manifest, scanner identities, measured states): the artifact kind,
protocol, run class, population binding and mechanics must be equal, otherwise
exit 10 with a closed list of refusals and the diff of what can be stated. A
legacy artifact is refused (its metrics are one unkeyed list from the legacy
accounting). It does not verify unless given `--snapshot`; the summary
says `not-run` otherwise. Scanners are paired by id, or the single scanner of
each side.

### C10. Validate

`validate` parses one document strictly (the contracts' own parser), optionally
binds it to a snapshot and manifest, and runs the accounting verifier for
revision-2 artifacts when the snapshot is given. Reasons are the contracts'
stable codes; no input is echoed (tests probe keys, values, versions, floats,
nulls and file names). Legacy revision 1 documents are readable; a legacy
artifact is exit 11, never reported as verified (ADR 0008, section 1).

### C11. Output handling

The output directory is prepared before the run (symlink, non-directory,
existing results under `refuse`, missing parent and an unwritable directory are
refused, an absent directory is created 0700) and removed again if the command
fails before committing, so an unusable location fails in milliseconds instead of
after a long scan. The writer gained `ArtifactWriter::with_manifest`, which
commits `manifest.json` in the same atomic sequence (first in order; the run
artifact stays the commit marker) so the directory is self-describing for
`replay` and `validate`. Default library behavior is unchanged. Summaries list
files by name, size and digest, never by path.

### C12. Platforms and releases

Execution is supported on Linux and macOS and refused on Windows
(`platform-unsupported`): ADR 0009's tree cleanup and resource sampling are Unix
only. `validate`, `compare` and `replay` use no process API. Release guidance is
documentation only (`cargo build --release --locked`, `--version`, digest
recording); there is no publishing workflow and no claim about reproducible
binaries.

### C13. Stdout, arguments and testing of unreachable paths

Arguments are collected as OS strings inside the panic guard; a non-UTF-8
argument is a usage error (exit 2) with the normal summary. A stdout write error
other than a closed pipe is exit 7. Output failures that no input reaches
(`output-write-failed`, `output-partial`, `output-committed-not-durable`) are
driven end to end through `PII_EVAL_TEST_FAULT`, a writer fault hook compiled
**only with debug assertions** (every `cargo test` build; a release build
compiles it out and the variable does nothing). Not triggerable through the
binary on a supported platform, so covered at unit level only:
`platform-unsupported` (tree cleanup exists on Linux and macOS),
`replay-incomplete-observations` (validation rejects the input first; the
library function is tested directly), `measurement-assembly-failed` and
`artifact-verification-failed` (engine defects that validated inputs cannot
produce; the mappings are unit-tested). CI also runs `cargo check` for
`x86_64-pc-windows-msvc` (installed by `rustup` in the job) to keep the crate
compiling there; execution stays refused.

## Alternatives considered

- A manifest builder in the CLI (a fifth command to author manifests):
  rejected for scope; the CLI consumes the contract documents (the committed
  example manifest is generated by a test from the real adapter plan).
- Exit 0 for a run whose scanner failed, with a flag in the summary: rejected;
  scripts read exit codes first.
- Environment-variable configuration of identities: rejected; only the job
  context path may come from the environment, because the custodian controls the
  environment of a protected job.
- A long-lived process or worker reuse across commands: not applicable; each
  invocation is one run.

## Consequences

- `pii-eval-cli` gains `serde_json` and `serde` as normal dependencies (already
  reviewed) and `signal-hook` 0.4.4 (Unix, exact pin, no default features) with
  its closure `signal-hook-registry`; the dependency guard has a new test for the
  CLI closure and keeps the pure crates and the adapters free of both.
  MSRV 1.85 re-verified.
- New public library names (internal): `args`, `config::{RunConfig, JobContext}`,
  `status::{Exit, Failure, reason}`, `summary::{Report, render}`,
  `scanners::{build_adapter, preflight_pins}`, `signals::install`,
  `replay::{runs_from_observations, needs_original}`, `files::*`,
  `exec::CancelToken::from_flag`, `write::ArtifactWriter::with_manifest`,
  `cmd_{run,replay,validate,compare}`.
- Tests: end-to-end suites for every command (`cli_run`, `cli_replay`,
  `cli_gate`, `cli_commands`, `cli_cancel`, `cli_docs`, `cli_example`), summary snapshots
  under `crates/pii-eval-cli/tests/snapshots/`, the documented quickstart run in
  CI as a named step.

## Gaps and deferrals

- One adapter kind; multi-scanner CLI runs need more kinds.
- Replay without `--original` for scanners that return sanitized output needs the
  verdicts in the observation contract (schema 1.2).
- No signature, owner or isolation check of the job context; the custodian owns
  those.
- A second signal leaves scanner trees running; a killed CLI leaves them too
  (ADR 0009).
- Real-scanner parity and dual runs are P9; performance and the streaming parser
  are P10.
