# CLI contract

Status: implemented (P8, issue #9). Decisions and alternatives:
[ADR 0010](adr/0010-standalone-cli-workflows.md). This document is the contract
for scripts and for the later GitHub App and custodian integrations; the
binary is `pii-eval` (built from `crates/pii-eval-cli`). The Rust API of that
crate is internal.

The CLI measures. It decides nothing about support status, thresholds,
rankings, publication or protected authorization, and a successful exit says
only that the command did what it was asked (a measurement can be complete and
still show a poor scanner; a scanner that failed is never reported as a clean
result). Everything here is local: no command needs GitHub, a network or the
custodian for public/synthetic data.

## Commands

```text
pii-eval run      --config FILE [--out DIR] [--node PATH] [--job-context FILE]
                  [--projection-roster FILE]
pii-eval replay   --snapshot FILE --manifest FILE --observation FILE [--observation FILE]...
                  --out DIR [--original FILE] [--expect-snapshot-digest SHA256]
                  [--expect-manifest-digest SHA256] [--overwrite refuse|replace]
                  [--job-context FILE] [--projection-roster FILE
                  --projection-mode official|exploratory]
pii-eval validate FILE [--kind KIND] [--snapshot FILE] [--manifest FILE]
                  [--job-context FILE] [--projection-roster FILE]
pii-eval compare  --base FILE --other FILE [--snapshot FILE] [--job-context FILE]
pii-eval worker-job --job FILE       # also: pii-eval --job FILE (see below)
pii-eval --version | --help
```

These five commands are the only ones. Options are long-form with one value
(`--name value` or `--name=value`), and each may appear once except
`--observation`. An unknown option, a missing value, a repeated option or an
extra argument is a usage error (exit 2) that names the option, never the value.

| Command | What it does |
| --- | --- |
| `run` | Validates every identity, launches the pinned scanner(s) under the bounded executor, scores with the kernel, verifies the artifact and writes the documents atomically. |
| `replay` | Re-derives the artifact from fixed observation sets. **No scanner is launched.** Any changed input, setting or identity is rejected; the same observations give the same semantic digests as the original run. |
| `validate` | Strict contract validation of one snapshot, manifest, observation set, run artifact or public artifact, optional bindings, and the accounting verifier for revision-2 artifacts. |
| `compare` | A deterministic, descriptive diff of two artifacts: identities and metric states per scanner and per metric, withheld states included. Not a ranking. |

### `worker-job`

The engine side of the private-custodian worker protocol, started by the
custodian as `/stage/engine --job /job/job.json`. `pii-eval --job FILE` is the
only alias, in exactly that shape. It reads the custodian's job document and the
staged files, runs the same pipeline as `run` and prints exactly one
`private-custodian.worker-result/1` document on stdout (and **nothing** on
stdout when it refuses). It takes no other option and no environment variable.

**In a production build it runs only `Decided` adapters** (issue #30: the stage
layout, the bundle and entry formats, the embedded aggregates and the nine labels are
decided by the custodian's ADR 0135). A `Proposed` or `TestOnly` adapter, which a
production build never contains, would make the command exit 6 with
`contract-not-final`. The job is parsed and validated before any staged artifact is
touched. Everything else (format, layout, order of work,
adapters and their statuses, bounds, reason codes) is in
[worker-job.md](worker-job.md) and [ADR 0015](adr/0015-worker-job-launcher-and-contract-adapters.md).

Exit codes reuse the frozen table below; no code is added. `worker-job` uses 0
(a result was printed, complete or a scanner failure documented as `failed`; the
custodian maps the latter to `Partial`), 3 (invalid job, configuration, entry or
bundle), 4 (an identity, digest, binding, population or run-class mismatch), 6
(`contract-not-final`, refused limits), 7 (the output could not be produced or
delivered), 8 (cancelled) and 1. It never uses 5: a scanner that did not complete
is a result with `failed` counted, not an exit status, because the custodian never
parses the stdout of a non-zero exit. Its reason codes are listed in
[worker-job.md](worker-job.md) and are not part of the list below.

### `run`

`--config` names the run configuration (below). `--out` gives the output
directory and overrides `output.dir`. `--node` gives the absolute path of
`node` and overrides `scanners[].node`; there is no `PATH` lookup, so the
interpreter is always an explicit choice, and the file must be named `node` (the
shim is JavaScript; another interpreter would run its lines in another
language). `--job-context` (or the environment
variable `PII_EVAL_JOB_CONTEXT`, the option wins) names the custodian job
context of a protected run.

`--projection-roster` names a projection roster (below) and overrides
`projection.roster.path`: the public artifact then carries the schema 1.2
product-projection block. Without a roster the output is the schema 1.1 output,
byte for byte.

Order of work: parse the configuration; for a protected run, require and
validate the job context **before any input path is touched**; read the snapshot
and manifest (a protected run only from inside the context's input root); check
every identity pin and binding; read the projection roster, if any, and check it
against the snapshot (every case in exactly one view, every case with one
family); build the pinned adapters and require that each
derived scanner plan equals the manifest's; hash every pinned artifact; prepare
the output directory; check the execution limits; only then start scanners.
Failures before that point launch nothing and leave no output directory behind.
Writer temporaries (`.pii-eval-tmp.*`) that a crashed earlier run left in the
output directory are removed first (the directory is the CLI's own: never point
two concurrent runs at one directory).

Every outcome row passes the snapshot's review gate before accounting: a
variant the snapshot holds for review (`review-required`) has an unmeasured type
axis in the artifact and in the metrics, in `run` and in `replay` alike.

Output files, in the output directory (created with mode 0700, files 0600):

| File | Written when |
| --- | --- |
| `manifest.json` | always: the manifest that was run |
| `observation-<scannerId>.json` | one per scanner |
| `public-synthetic-artifact.json` | public-synthetic runs only |
| `run-artifact.json` | always, last: the commit marker |

The writer validates and verifies every document, writes temporary files, and
renames them into place; a directory without `run-artifact.json` is an
incomplete run. An existing result is never overwritten unless the
configuration says `"overwrite": "replace"` (exploratory runs only). A
scanner that did not complete still produces documents that record the failure,
and the command exits 5.

### `replay`

Inputs: the snapshot, the manifest and one observation set per manifest
scanner, in any order. Each observation set must bind to the manifest and
snapshot (engine, protocol, population digest, scanner, adapter, product,
configuration and activation identities, input digests); a mismatch is exit 4,
a malformed or digest-mismatching document is exit 3.

`--original` names the run artifact the observations came from. It is
**required** when it holds facts an observation set does not: a scanner that did
not complete (its failure code), or a scanner that returned sanitized output
(the `output-verified` verdicts need the sanitized text, which observation sets
never keep). The original must pass the accounting verifier and must bind to
exactly these observation sets by digest, and the replayed artifact must equal it
(`parity: identical`, otherwise exit 4 `replay-diverged` and nothing is written).
`@redact-secret/core` always returns sanitized output, so replaying its
observation sets needs `--original` today; a replay that needs no original is a
contract change deferred in ADR 0010.

**What a replay verifies independently, and what it carries over.** The summary
lists both under `semantic.verification`. *Recomputed on this run from the
observation sets:* matching, accounting, the metrics, the review gate, the
artifact digest (`recomputed`). *Carried over from the original artifact*
(`carriedFromOriginal`): the `output-verdicts` (when a scanner returned sanitized
output) and the `failure-codes` of scanners that did not complete. `parity:
identical` is therefore an independent check of everything except those carried
parts: the original passed the accounting verifier and binds to these
observation sets, but its verdicts and failure codes are not re-derived by the
replay.

`--projection-roster` with `--projection-mode` (both or neither: a replay has no run
configuration to take the mode from) re-attaches the product projection: the replayed
public artifact is byte-identical to a run's under the same roster and mode.

`--expect-snapshot-digest` and `--expect-manifest-digest` pin the semantic
digests. Only revision-2 (canonical) manifests can be replayed; a legacy
revision-1 plan is not re-measured. Diagnostics are never attached, so a
replay's files are byte-identical to the original run's when the original also
had none. Replay of a protected population needs `--job-context` (below); its
inputs and output directory are confined to the context's roots.

### `validate`

`--kind` is one of `corpus-snapshot`, `run-manifest`, `observation-set`,
`run-artifact`, `public-synthetic-artifact`; without it the kind is read from
the document's `schema`. `--snapshot` and `--manifest` add binding checks
(a manifest against a snapshot; an observation set against both; a run artifact
against both, with the accounting verifier needing the snapshot; a public
artifact against the snapshot). An option that does not apply to the kind is a
usage error. A protected document (a snapshot of protected visibility, a
protected-class manifest or artifact) is validated only inside a job context
(`--job-context` or `PII_EVAL_JOB_CONTEXT`; exit 9 otherwise, and the file must
lie inside the input root), and its summary withholds the case and variant counts.
Whether a document is protected is known only after it is parsed, so the file is
read (not reported) before the refusal; an observation set carries no visibility
and is treated as protected only when a protected `--snapshot` or `--manifest`
accompanies it.

For a public artifact under schema 1.2 the typed parse already checks the product
projection's structure and bindings (`semantic.productProjection: "structural"`).
`--projection-roster` (with `--snapshot`) additionally recomputes every row, stratum
and count from the authored population and the roster and compares them with the
block (`"recomputed"`); a block that differs, or an artifact with no block, is exit 3
`verification-failed` with the contract codes of [Product projection](#product-projection-schema-12).

Legacy revision 1 documents are **readable**: they validate structurally and
keep their digests. A legacy run or public artifact is **not verifiable** (its
metrics came from the legacy accounting): the command reports
`valid-legacy-not-verifiable` with exit 11 instead of a verified success.
`semantic.verification` is `verified`, `not-run` (no snapshot given),
`not-verifiable-legacy` or `not-applicable`.

### `compare`

Both inputs are run artifacts of one kind (internal or public), protocol
revision 2. They are comparable only when everything except the **subject** is
equal. The subject is the engine version, the manifest, the scanners'
identities (version, artifact, adapter, product, configuration, activation) and
the measured states. Everything else must be equal: artifact kind, protocol,
run class, population binding (id, version, digest) and accounting mechanics;
otherwise the command exits 10 with the closed list of `semantic.refusals`
(`artifact-kinds-differ`, `legacy-protocol-revision`, `protocol-differs`,
`run-class-differs`, `population-differs`, `mechanics-differs`,
`scanner-sets-not-pairable`). Scanners are paired by id; when each artifact has
exactly one scanner they are paired even if the ids differ (`pairing:
single-scanner`).

Per pair the output lists the changed identity fields (both values), and per
metric both sides' full result (status, counts, effective N, value or withheld
reason), a `relation` (`identical`, `changed`, `withheld-in-both`,
`withheld-in-base`, `withheld-in-other`, `absent-in-base`, `absent-in-other`)
and `identical` (the whole result is equal). A withheld metric is shown as
withheld; the diff never turns it into a number. No field ranks, scores or
prefers either artifact (`interpretation: descriptive-only`).

`compare` does not verify the artifacts unless asked: `semantic.verification`
reports `{base, other}` as `not-run` by default, so a resealed artifact with
fabricated metrics compares as itself. `--snapshot FILE` validates both artifacts
against the snapshot and runs the accounting verifier (`verified`; a failure is
exit 3 `verification-failed`; legacy artifacts are refused anyway). Protected
artifacts need a job context and their metric `counts` and `effectiveN` are
withheld from the output (`identical` is still decided on the full results).

## Run configuration (`pii-eval-run-config/1`)

**Treat a run configuration like a command line.** It names the interpreter that
will be executed, the scanner package that interpreter will load and the
directories that will be written. The pins make a mismatch visible; they do not
make an unreviewed configuration safe to run, because the scanner package is
executable code (SECURITY.md). Do not run a configuration you did not write or
review, and run scanners you do not trust only inside the custodian's isolation.

A versioned JSON file, parsed strictly: duplicate keys, `null`, floats, unknown
fields and wrong types are `config-invalid` naming the field (never the value).
Relative paths resolve against the directory of the configuration file, so a
checked-out example runs from any working directory. JSON was chosen over flags
because the pins are structured (scanner package, artifacts, digests); the
other commands take only file paths and digests and use flags.

```json
{
  "schema": "pii-eval-run-config/1",
  "mode": "official",
  "runClass": "public-synthetic",
  "product": "candidate",
  "engineVersion": "0.0.0",
  "protocol": {"id": "pii-v1", "revision": 2},
  "snapshot": {"path": "snapshot.json", "semanticDigest": "<sha256>"},
  "manifest": {"path": "manifest.json", "semanticDigest": "<sha256>"},
  "scanners": [{
    "adapter": "redact-secret-core",
    "node": "/absolute/path/to/node",
    "shim": {"path": "crates/pii-eval-adapters/shims/node/redact-secret-core.mjs"},
    "package": {"dir": "scanner/core", "entry": "dist/index.js",
                "version": "0.1.0-beta.12", "treeSha256": "<sha256>"},
    "extraArtifacts": [{"path": "scanner/addon.node", "target": "file", "sha256": "<sha256>"}],
    "limits": {"startupTimeoutMs": 30000, "callTimeoutMs": 30000}
  }],
  "host": {"maxWorkers": 4, "resources": "enforce", "diagnostics": false,
           "scratchDir": "/var/tmp/pii-eval", "minSessionMemoryBytes": 134217728},
  "output": {"dir": "out", "overwrite": "refuse"},
  "projection": {"roster": {"path": "projection-roster.json", "rosterDigest": "<sha256>"}}
}
```

| Field | Rule |
| --- | --- |
| `mode` | `exploratory` or `official`. An official run requires `engineVersion`, `protocol`, both `semanticDigest` pins, `host.resources: enforce` and `output.overwrite: refuse`. Exploratory pins are optional and checked when present. |
| `runClass` | `public-synthetic` or `protected`; must equal the manifest's run class. A protected run must be official and needs a job context. |
| `product` | `released` or `candidate`; must equal every scanner identity in the manifest. Independent of `runClass`: a public-synthetic candidate run is still candidate evidence. |
| `engineVersion`, `protocol` | Must equal this binary's engine version and the manifest's protocol (`pii-v1` revision 2: only revision 2 can be run). |
| `snapshot`, `manifest` | File and optional semantic digest pin. The manifest must bind to the snapshot by population digest and run class. |
| `scanners[]` | Only `adapter: redact-secret-core` exists in this release. `shim` is verified against the shipped shim digest and cannot be overridden. `package.treeSha256` is required for a candidate (it is the candidate digest); a released package must be `0.1.0-beta.12` with the released tree digest. `extraArtifacts` pin further files or trees (a native addon). The scanner plan derived by the adapter from the manifest's scanner configuration must equal the manifest's plan, so activation, configuration and adapter identity are bound by the manifest and re-verified by the running scanner. |
| `host` | Execution settings that never enter a digest: `maxWorkers` (1 to 256, a cap on the manifest's `workers`), `resources` (`enforce` or `unenforced`), `diagnostics` (attach non-semantic timing; default false), `scratchDir`, `minSessionMemoryBytes`. |
| `output` | `dir` (or `--out`) and `overwrite` (`refuse` default, `replace`). |
| `projection` | Optional, public-synthetic runs only. `roster.path` names a projection roster; `roster.rosterDigest` pins the roster's digest (required when `mode` is `official`). The run's `mode` becomes the `mode` of every projection row. |

Execution bounds (workers, per-scanner parallelism, pending tasks, batch,
scanner timeout, output bytes, memory, scratch) are fields of the **manifest**,
so they are part of the plan's digest; the host can only lower parallelism,
never raise a bound. Results are identical at one worker and at many
(determinism tests), because the executor indexes by manifest order, never by
completion order.

## Product projection (schema 1.2)

The public artifact can carry one optional block, `semantic.productProjection`,
that restates the **one population** it measured per (scanner, view, family):
the cell's cases, variants and occurrences, method coverage, the ten metrics with
integer counts, effective N and the interval or withheld reason, language strata
(always) and control-class strata (when the roster assigns classes), the run's
`mode` and the scanner, configuration, activation, product and population binding
of the artifact. It is inside `semantic`, so the semantic digest covers it; the
artifact is then sealed under schema 1.2. Design, field shape and rejection rules:
[ADR 0016](adr/0016-product-projection-and-schema-1-2.md). The engine holds no view
policy: the caller's **roster** names the views the run requires, the view of every
authored case, and optionally a control class for some cases.

```json
{
  "schema": "pii-eval-projection-roster/1",
  "requiredViews": ["oracle-plan", "qualification-plan"],
  "views": [
    {"view": "oracle-plan", "cases": ["case-a"]},
    {"view": "qualification-plan", "cases": ["case-b", "case-c"]}
  ],
  "controlClasses": [{"class": "test-value", "cases": ["case-c"]}]
}
```

`requiredViews` are drawn from the closed set `oracle-plan`, `qualification-plan`,
`diagnostic-balanced`, `benign-heavy-stress`; every authored case is in exactly one
view, every listed view is required and has at least one case, and a case's family
is its collision target or the one family all its occurrences share (a case that
spans several families without a target is refused: there is no honest cell for it).
The file is strict JSON with closed fields; a problem is `config-invalid` or
`document-invalid` naming `projection-roster` (never a value), and a pinned
`rosterDigest` that differs is exit 4 `provenance-mismatch` (`projection-roster-digest`).
The `semantic.productProjection` of a `run` or `replay` summary reports the roster
digest, the mode, the required views and the row count.

## Custodian job context (`pii-eval-job-context/1`) and protected runs

A protected run executes only with a valid custodian-controlled job context.
**The context grants no access.** It cannot make an unreadable path readable,
authorizes nothing, and a context that validates is not an authorization
decision: the custodian's isolation and approval are. The CLI only validates the
context and binds the run to it.

```json
{
  "schema": "pii-eval-job-context/1",
  "jobId": "job-0001",
  "custodian": "custodian-id",
  "runClass": "protected",
  "populationDigest": "<the snapshot's semanticDigest>",
  "manifestDigest": "<the manifest's semanticDigest>",
  "candidateDigest": "<sha256, required for a candidate product>",
  "inputRoot": "/absolute/existing/directory",
  "outputRoot": "/absolute/existing/directory"
}
```

The file must be a regular file of at most 1 MiB that group and others cannot
write (mode `& 0o022 == 0`), strict JSON with exactly these fields. The run
refuses (exit 9) when: no context is supplied (`protected-context-required`,
decided before any input path is read); the context is invalid
(`protected-context-invalid`); its digests or candidate digest do not match the
snapshot, manifest and scanner (`protected-context-mismatch`); the snapshot or
manifest lies outside `inputRoot`, or the output directory outside
`outputRoot`, after resolving symlinks and `..`
(`protected-path-outside-context`). A protected run writes the internal
artifact only (no public projection), and its summary carries identities
(digests), statuses and file sizes, not the population's counts. Limits of this check: it does not verify who wrote the context
(no signature, no owner check), it does not isolate the process, and the scanner
is not sandboxed (SECURITY.md).

## Exit codes (frozen)

The numbers and names never change and are never reused. `semantic` and
`error.reason` give the finer state.

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `success` | The command did what was asked and every check passed. |
| 1 | `internal-error` | A defect of this program, or a document it built failed its own verification. Never caused by a scanner. A panic is reported as this, with no panic text. |
| 2 | `usage-error` | The command line is not valid. |
| 3 | `invalid-input` | An input (configuration, document, file) is invalid, unreadable, too large, or unusable for the command. |
| 4 | `provenance-mismatch` | A pinned or bound identity does not match: digest pins, engine, protocol, run class, product, a binding between documents, a scanner plan, a pinned artifact, replay parity. |
| 5 | `scanner-failure` | `run` or `replay` finished and the documents were written, but at least one scanner did not complete: the measurement is incomplete. Never `0`. |
| 6 | `execution-refused` | The run could not be executed: refused limits, unsupported platform, unusable adapter specification. Nothing was launched. |
| 7 | `output-failure` | The output location is unusable, exists, or a write failed, or the commit is not confirmed durable. |
| 8 | `cancelled` | The run was cancelled by SIGINT or SIGTERM; nothing was committed. |
| 9 | `protected-context` | A protected run has no valid job context, or its inputs lie outside it. |
| 10 | `incomparable` | `compare` refused: the artifacts differ in more than the subject. |
| 11 | `not-verifiable` | `validate` read a legacy (revision 1) artifact: valid, readable, not verifiable. |

Reason codes (`error.reason`), by exit: 2 `missing-command`, `unknown-command`,
`unknown-option`, `missing-value`, `duplicate-option`, `missing-required-option`,
`unexpected-argument`, `invalid-option-value`; 3 `input-unreadable`,
`input-too-large`, `config-invalid`, `document-invalid`, `kind-mismatch`,
`protocol-revision-unsupported`, `replay-original-required`,
`replay-incomplete-observations`, `verification-failed`,
`measurement-assembly-failed`; 4 `provenance-mismatch`, `replay-diverged`;
5 `scanner-failure`; 6 `execution-refused`, `platform-unsupported`,
`adapter-invalid`, `signal-handler-unavailable`; 7 `output-unusable`, `output-exists`, `output-write-failed`,
`output-committed-not-durable`, `output-partial`; 8 `cancelled`; 9
`protected-context-required`, `protected-context-invalid`,
`protected-context-mismatch`, `protected-path-outside-context`; 10
`incomparable`; 11 `legacy-not-verifiable`; 1 `internal-error`,
`artifact-verification-failed`.

`output-committed-not-durable` means every file is in place, complete and valid
but the final directory sync failed, so durability across a crash is not
confirmed; nothing is rolled back.

## Standard output and standard error

**Stdout** carries exactly one line of JSON, the summary
(`pii-eval-summary/1`), and nothing else, for every command and every exit
(`--version` and `--help` print their human text instead). Objects have keys in
ascending order; integers only; the same inputs give the same bytes.

```text
{"command":"validate","engine":{"name":"pii-eval","version":"0.0.0"},
 "error":{"codes":["..."],"detail":"...","reason":"..."},
 "exit":{"code":0,"name":"success"},
 "outputs":{"files":[{"bytes":0,"name":"...","sha256":"..."}]},
 "schema":"pii-eval-summary/1","semantic":{...},"state":"valid"}
```

`state` is `valid`, `valid-legacy-not-verifiable`, `compared`, `incomparable`,
`complete`, `incomplete`, `replayed` or `error`; `error` is present whenever the
exit is not success; `semantic` is the deterministic body (digests, statuses,
counts: no timestamps, durations, paths or raw values); `outputs` lists written
files by name, size and SHA-256 (deterministic when diagnostics are off). The
`completeness` field of a run summary is the artifact's outcome-matrix coverage
(a scanner that failed still has explicit not-measured rows); read `state` and
the scanner statuses for whether the measurement is complete.

An argument that is not UTF-8 is a usage error (exit 2, `invalid-option-value`)
with the usual summary, never a panic. A failure to write the summary to stdout
is exit 7 with a line on stderr, except a closed pipe (the reader went away),
which is not a failure of the command.

**Stderr** carries one human diagnostic line on failure
(`pii-eval: <reason> (<exit name>, exit <code>)[: detail][ [codes]]`), plus the
usage text on a usage error. It is built only from this program's fixed
vocabulary: reason codes, field names, document kinds and identity slots. It
never contains input text, a document value, a matched value, a finding, raw
scanner output, a file path or an operating-system message. Nothing is logged
while a command succeeds. This is a human aid, not a contract: scripts read
stdout and the exit status.

## Determinism and reproducibility

A run is reproducible from the recorded identities: engine version, protocol
revision, snapshot digest, manifest digest (which binds scanners, adapters,
configuration, activation, product, mechanics and execution limits), scanner
artifact digests and the corpus digest. The same snapshot, manifest, scanner
and configuration give byte-identical documents and summaries across runs and
across worker counts when diagnostics are off; with `host.diagnostics: true`
the files additionally carry timestamps and timings outside the digested body
(`semanticDigest` is unchanged). Scanner nondeterminism is recorded as
`unstable`, not hidden.

## Quickstart (clean checkout, offline, synthetic)

`examples/quickstart/` holds a synthetic snapshot, a manifest derived from the
inert fake `@redact-secret/core` package under
`crates/pii-eval-adapters/tests/fixtures/fake-core`, and two configurations
(exploratory and official with every pin), plus the same two with the product
projection and its roster (`projection-roster.json`). The fake is not a scanner and not the
real package: it exists so the whole pipeline runs offline in CI. Needs Rust
(the pinned toolchain), Node 22 and `ps`; no network after the build.
The test `cli_example` runs exactly this block.

<!-- quickstart-commands -->
```sh
cargo build --release --locked
NODE="$(command -v node)"
OUT="$(mktemp -d)"
pii-eval validate examples/quickstart/snapshot.json
pii-eval validate examples/quickstart/manifest.json --snapshot examples/quickstart/snapshot.json
pii-eval run --config examples/quickstart/run-config.json --node "$NODE" --out "$OUT/run"
pii-eval validate "$OUT/run/run-artifact.json" --snapshot examples/quickstart/snapshot.json --manifest "$OUT/run/manifest.json"
pii-eval validate "$OUT/run/public-synthetic-artifact.json" --snapshot examples/quickstart/snapshot.json
pii-eval run --config examples/quickstart/run-config.official.json --node "$NODE" --out "$OUT/official"
pii-eval run --config examples/quickstart/run-config.projection.json --node "$NODE" --out "$OUT/projection"
pii-eval validate "$OUT/projection/public-synthetic-artifact.json" --snapshot examples/quickstart/snapshot.json \
  --projection-roster examples/quickstart/projection-roster.json
pii-eval run --config examples/quickstart/run-config.official.projection.json --node "$NODE" --out "$OUT/official-projection"
pii-eval replay --snapshot examples/quickstart/snapshot.json --manifest "$OUT/run/manifest.json" \
  --observation "$OUT/run/observation-redact-secret-core.json" \
  --original "$OUT/run/run-artifact.json" --out "$OUT/replay"
pii-eval compare --base "$OUT/run/run-artifact.json" --other "$OUT/replay/run-artifact.json"
```

(In the block, `pii-eval` is `target/release/pii-eval`; the test substitutes the
built binary and a scratch directory for `$NODE` and `$OUT`, and checks that
every command exits 0.) The `replay` output files are byte-identical to the
`run` output files. The example documents are regenerated, after an intentional
change, with `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test cli_example`.

## Installation and release binary

There is no public release, tag or package. CI publishes the engine as an
**internal workflow artifact** (`pii-eval-engine-<commit>-linux-x86_64`, 30-day
retention, with `build-info.json` and `SHA256SUMS`) that other workflows download
and verify instead of rebuilding; see [docs/ci-artifacts.md](ci-artifacts.md).
To build and verify a binary from a checkout:

```sh
cargo build --release --locked          # target/release/pii-eval
target/release/pii-eval --version       # pii-eval <version> (bootstrap)
cargo test --workspace --locked         # the checks CI runs
shasum -a 256 target/release/pii-eval   # record the digest you deploy
```

`--locked` makes the build use exactly the committed `Cargo.lock`; the
toolchain is pinned by `rust-toolchain.toml` (1.98.1, MSRV 1.85, edition 2024).
A deployment ships the binary, the Node shim
`crates/pii-eval-adapters/shims/node/redact-secret-core.mjs` (its digest is
pinned in the binary and checked before every run), and the pinned scanner
package, installed by a person with `npm install --ignore-scripts` into a
read-only location. Reproducible-build comparison across hosts is not yet
established; compare the semantic digests of runs, not binaries.

Supported platforms for execution: **Linux and macOS** (x86-64 and arm64 where
Rust, Node 22 and `ps` exist; CI exercises Linux, development exercises macOS).
`validate`, `compare` and `replay` use no process API. **Windows is refused for
execution** (`platform-unsupported`, exit 6): scanner process-tree cleanup and
resource sampling are not implemented there. Rust process control is not a
sandbox: a hostile scanner can use the network and read what the user can read;
protected isolation is the custodian's (SECURITY.md).

## Signals

Scanners lead their own process groups, so a terminal Ctrl-C does not reach
them. `run` installs handlers for SIGINT, SIGTERM and SIGHUP (a closed
terminal must not leave a run attached to scanners): the first cancels the
run, the executor kills every scanner process tree and removes its scratch
directories, nothing is committed and the exit status is 8. A second signal
while that happens ends the process at once with status 8 and cleans nothing:
the scanner trees may be left running, scratch directories and writer
temporaries (`.pii-eval-tmp.*`) may remain, an empty output directory may remain,
and files already renamed into place may exist without `run-artifact.json` (an
incomplete run by definition); the custodian must contain the run. If the CLI is
killed (`SIGKILL`) the same applies. If a handler cannot be registered the run is
not started (exit 6 `signal-handler-unavailable`). Other commands keep the default signal behavior.

## Known limits

- One adapter kind (`redact-secret-core`); runs with several scanners need more
  adapter kinds (follow-up).
- The CLI does not create manifests: a manifest is a contract document
  (`schemas/run-manifest.v1.schema.json`), authored or generated by the caller; the
  committed example manifest shows the shape and is regenerated by a test.
- Replay without `--original` is impossible for scanners that return sanitized
  output (ADR 0010).
- Output failures that no ordinary input reaches (`output-write-failed`,
  `output-partial`, `output-committed-not-durable`) are exercised through a
  debug-build-only fault hook (ADR 0010 C13); `platform-unsupported`,
  `replay-incomplete-observations`, `measurement-assembly-failed` and
  `artifact-verification-failed` cannot be triggered through the binary on a
  supported platform and have unit-level tests only.
- `run` with a configuration that claims `public-synthetic` over a snapshot that
  turns out to be protected reads the file before refusing (visibility is only
  known from the content); nothing is reported or written.
- Documents up to 32 MiB are parsed; a document at the cap can need about 1 GiB
  of memory to parse (ADR 0008, section 6).
