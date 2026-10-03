# ADR 0015: Worker-job launcher and contract adapters

- Status: accepted; subject to review.
- Date: 2026-10-03
- Related: [ADR 0009](0009-bounded-execution-and-artifact-writing.md),
  [ADR 0010](0010-standalone-cli-workflows.md),
  [ADR 0014](0014-custodian-boundary-and-consumer-contract.md),
  [docs/worker-job.md](../worker-job.md),
  [docs/custodian-contract-status.md](../custodian-contract-status.md),
  [docs/custodian-boundary.md](../custodian-boundary.md).

## Context

The custodian starts an engine as `/stage/engine --job /job/job.json`, reads one
`worker-result/1` from stdout and expects an `aggregates/1` document bound to the
same roster. It has decided the job and result documents, the staged names, the
digest syntax and the sandbox; it has not decided what an entry holds, how the
aggregates reach it, which labels a pii policy allows, how a package tree travels
as one staged file, or where Node, the shim and the package live. The engine had
no launcher (ADR 0014 D4 left it as a proposal).

## Decisions

### D1. A launcher inside the CLI crate, reusing the pipeline

`pii-eval worker-job --job FILE` (alias `pii-eval --job FILE`, exact shape only)
verifies the staged world and then calls `run::run_and_write`, the function
`pii-eval run` uses. Measurement, accounting, statistics and the artifact writer
are not duplicated. Alternative rejected: a second pipeline for worker mode, which
would let the two drift. A test requires the same run artifact digest and the same
numerators and denominators from both.

### D2. Undecided items are adapters with a status; production has none of them

`ContractStatus {Decided, Proposed, TestOnly}`; five slots (stage layout, bundle
format, entry format, aggregates channel, aggregate labels). `Adapters::production()`
holds nothing, so a production build refuses with `contract-not-final: <slot>`
(exit 6) before it touches anything. No flag, environment variable or
configuration field installs an adapter. Test adapters exist only behind the cargo
feature `worker-test-adapters`, carry a marker string, are absent from the CI
engine artifact (a CI step greps for the marker) and are reachable only through the
Rust API. Alternative rejected: a runtime switch for "test mode", which a
production operator could turn on.

### D3. Typed digests with no implicit conversion

Five digest types (custodian syntax, engine syntax, bundle, tree, runtime), no
`From`, `Into`, `Deref` or `AsRef`. The custodian pins a staged FILE; the engine
pins a package TREE; verifying one never stands in for the other. Compile-fail
doctests and runtime tests pin this.

### D4. Engine-owned formats, opaque to the custodian

`pii-eval-worker-config/1`, `pii-eval-bundle/1` and `pii-eval-worker-entry/1`
(docs/worker-job.md). The bundle is a deterministic, canonical, strictly parsed
archive so there is exactly one encoding of a set of files and no tar or zip
dependency; its reader is the only extractor. The entry is the contracts' `Case`
under a schema tag, named by its case identifier. Alternative rejected: tar or zip
(new dependency, a large attack surface, many encodings).

### D5. Result semantics follow the custodian's validator, not the first reading

The status is a function of coverage (`complete` iff `observed == expected`),
because the custodian's `validate_result` rejects a `partial` whose counters say
`observed == expected`. A scanner that did not complete is reported as
`failed = expected` with exit 0 (the custodian maps that to `Partial`). The
consequence that such a result cannot become a receipt is the custodian's to
resolve and is listed in docs/worker-job.md.

### D6. Refuse, never clamp

An aggregates denominator above `observed`, more than 256 cells, a result or
aggregates document over its bound, or an invalid label is a refusal. The unit of
`measurable-share` (the axis assertion) exceeds a roster of entries; the test
labels leave that metric out and publishing all ten is refused. Whether a policy
publishes it is the custodian's (Q3).

### D7. Streaming digest in the contracts crate

`Sha256Digest::of_reader(reader, max)` streams a file in 64 KiB blocks with an
explicit bound. A Node runtime is far larger than the 32 MiB the pin module
reads into memory. It is public API of `pii-eval-contracts`; no schema, fixture or
digest changed, and no dependency was added.

### D8. No exit code added; exit 5 is not used by `worker-job`

The frozen table is reused. Scanner failures are results (exit 0), because the
custodian never parses stdout of a non-zero exit (A6) and documents `Partial` for
the clean-exit form.

## Consequences

- A release binary cannot run a worker job until the custodian decides the slots
  and a `Decided` adapter for each exists. This is intended: nothing is claimed
  that the custodian has not agreed.
- The tests that run a job end to end need the feature and Node; CI has its own
  named step. The default `cargo test --workspace` stays green without it.
- The replica of the custodian's checks in the tests is written from its source at
  commit 142db34 and goes stale if that changes.
- Not verified here: a real `bwrap` run, the real Node runtime under `RLIMIT_AS`,
  the custodian's own code. See docs/worker-job.md.
