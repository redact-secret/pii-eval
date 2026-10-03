# ADR 0006: Scanner adapter boundary, shim protocol and pinned process execution

- Status: accepted for P6 (issue #7); subject to review.
- Date: 2026-10-02
- Related: [ADR 0001](0001-rust-first-and-oracle-pin.md),
  [ADR 0002](0002-freeze-pii-contracts-v1.md),
  [ADR 0004](0004-order-invariant-pii-matching.md),
  [ownership map](../migration/ownership-map.md),
  [SECURITY.md](../../SECURITY.md), epic #1.

## Context

P2 froze what an observation records (scanner, adapter, product, configuration
and activation identities, capabilities, normalized findings, output digest).
P3 froze how a runtime offset becomes a UTF-8 byte range (`translate_range`).
P6 has to produce those records from real scanners without letting a scanner,
its shim or the corpus influence what is executed, and without letting a
failure look like a clean scan. Scanners are untrusted executable code
(SECURITY.md threat model).

## Decisions

### D1. Adapters observe; they never score

`pii-eval-adapters` has no access to expected labels, ranges, sensitivity or
case identity. The only data that reaches a scanner process is run
configuration (once) and input text (per call). This is enforced by shape, not
by convention: `ScanSession::scan(&mut self, text: &str)` has no other
parameter, the wire encoders take none, and a test has the fake shim report the
key set of every message it received.

### D2. One trait pair, one concrete process adapter

`ScannerAdapter` turns a `ScannerConfiguration` into a bound `ScannerPlan` and
starts a `ScanSession` from a plan. `ScanSession` answers `scan(text)` with a
`ScanOutput` or a distinct `AdapterError`. `ProcessAdapter` is the only
implementation: a pinned shim process driven over stdin/stdout. A library
scanner that is linked in-process would implement the same traits; none is
planned. The adapter has no dependency on product-internal detector policy and
works outside the benchmarks (it needs a Node executable, a shim and the
scanner package, nothing else).

### D3. Shim protocol `pii-eval-adapter/1`

JSON lines, UTF-8, LF terminated, one object per line. Specified in
`crates/pii-eval-adapters/src/wire.rs`.

Rust to shim (configuration and text only):

```text
{"type":"init","protocol":"pii-eval-adapter/1","activation":["pii:global"],
 "parameters":{"findingSource":"pii-domain-only"},"returnOutput":true,
 "limits":{"maxInputBytes":1048576,"maxFindings":10000}}
{"type":"scan","seq":1,"text":"..."}
{"type":"shutdown"}
```

Shim to Rust:

```text
{"type":"ready","protocol":"pii-eval-adapter/1","scanner":{"id":"..","version":".."},
 "runtime":{"name":"node","version":"v22.16.0"},"activation":"<scanner identity string>",
 "offsetUnit":"utf16-code-units"}
{"type":"result","seq":1,"findings":[{"start":0,"end":3,"type":"..","detector":"..","action":".."}],"output":".."}
{"type":"error","stage":"init"|"scan","seq":1,"code":"<fixed code>"}
```

- The shim forwards native values untouched. It maps nothing and decides
  nothing. Meaning is assigned in Rust (D6).
- Parsing is strict (`parse_strict` of the contracts): duplicate keys, `null`,
  floats, `-0`, integers above 2^53 - 1, unknown fields, wrong types and
  nesting deeper than 8 are all malformed output. `output` must be present
  exactly when it was requested.
- Error messages are never accepted, only the fixed codes
  `unsupported-selector`, `invalid-selector`, `initialization-failed`,
  `scanner-error`, `input-limit`, `finding-limit`, `protocol-error`. An unknown
  code is malformed output, so scanner text cannot travel through the error
  path.
- The protocol identifier is a version of this protocol, separate from the
  engine, contract schema, protocol (`pii-v1`), adapter and normalization
  versions. A breaking change to the lines above bumps it.

### D4. Process execution is fixed, scrubbed and bounded

- Executable: an absolute path, canonicalized at construction, never resolved
  through `PATH`, never through a shell. Arguments are exactly
  `[shim path, scanner entry path]`. Configuration never reaches argv or the
  environment; it travels as JSON data in `init`.
- Environment: cleared, then `PII_EVAL_ADAPTER_PROTOCOL` plus names from the
  fixed allowlist `INHERITABLE_ENV` (`LANG`, `LC_ALL`, `TMPDIR`, `TMP`, `TEMP`,
  `SystemRoot`) that the spec asks for. `PATH`, `HOME`, `NODE_OPTIONS`,
  `NODE_PATH`, `LD_*`, `DYLD_*` and every other variable are not passed, and a
  spec naming one is rejected.
- Working directory: the shim's directory.
- Closed configuration: a configuration must equal the adapter's fixed
  parameter list exactly, and activation selectors must satisfy the scanner's
  selector grammar, before any process exists. Free text from a plan is
  therefore never executed and never interpreted, only compared.
- Limits (`AdapterLimits`, each with a validated floor and ceiling): startup
  timeout, per-call timeout (default 30 s each, at most one hour), output line
  bytes (default 8 MiB, ceiling 16 MiB; a longer line is a limit failure, never
  truncated), stderr bytes counted (default 64 KiB), findings per input
  (10,000, the contract bound), text bytes (1 MiB, the contract bound). The
  8 MiB default is the worst legitimate result: 10,000 findings (about
  1.5 MiB) plus sanitized output of a 1 MiB text whose control characters JSON
  escapes six-fold. Memory per call is bounded by the line (at most
  `max_line_bytes`), a parse tree of the same order, and the kernel's range
  tables (at most 8 MiB); the number of findings is checked on the raw line
  (`wire::count_finding_keys`, one `"start":` key per finding) before the parse
  tree is built, so a line of many tiny findings cannot inflate it.
- Writes are bounded as well as reads: a line is queued to the writer thread
  with the call's deadline (`try_send` and a short wait). A shim that never
  reads stdin backs the writer up; the next send then times out as
  `timeout: scan` (or `startup`), the child is killed and reaped, and the
  caller is never blocked.
- Threads: a writer thread owns stdin so a shim that never reads cannot block
  the caller; a reader thread splits stdout into bounded lines; a stderr thread
  drains and counts and stores nothing. Stderr is never captured, so it cannot
  be surfaced. On timeout, limit violation, protocol violation or drop, the
  child is killed and reaped. After any failure the session is closed: later
  calls return `SessionClosed`, never a clean result.

What this does not do (P7 must add it, see D12): kill descendants (a child that
inherited the pipes can outlive its parent), bound the number of concurrent
processes, limit memory, CPU or temporary storage, isolate network or
filesystem access, or detect a scanner that changes its own files.

### D5. Pins are verified before use, in a fixed order

`ScannerAdapter::start` checks, each before the next:

1. The plan's `ScannerIdentity` and its two digests equal what the adapter
   derives again from the plan's own configuration. A wrong configuration
   digest, activation digest, adapter or normalization version, scanner
   version, artifact digest or product identity stops here
   (`pin-mismatch: plan-identity`).
2. The shim file and the scanner artifact (and any extra artifacts) match their
   pinned SHA-256 digests. Symlinks are rejected for a pinned file and anywhere
   inside a pinned tree; reads are bounded (32 MiB per file, 4096 files and
   256 MiB per tree, depth 16). Tests use a script that creates a marker file
   when spawned to show that nothing ran after a failed pin.
3. The process is spawned, and its `ready` message must repeat the pinned
   scanner id and version, runtime name (and version prefix when pinned), offset
   unit and activation selectors. Only then is any input sent.

Tree digest: SHA-256 of the listing `<file sha256>  <relative path>\n` sorted
bytewise by path (reproducible with `find . -type f | sed 's|^\./||' | LC_ALL=C
sort | xargs shasum -a 256 | shasum -a 256`). It is the scanner's
`artifactDigest`. For a candidate, `ProductIdentity::Candidate.candidateDigest`
must equal that digest, so a candidate is identified by the bytes that run.

The pins are checked again when startup completes (after the scanner has
loaded its code, so a swap between the first check and the load is detected
before any input is sent) and when the session ends: `SessionStats.pin_check`
is `Some(PinMismatch)` when anything changed, and the observations of that
session must not be trusted. Precisely what this does and does not cover:

- Covered: the bytes of the shim file, of every file in the pinned scanner
  tree (names and contents), and of each extra artifact, at three points in
  time (before spawn, after `ready`, at the end).
- Not covered: content swapped and restored between two checks; code already
  loaded into the process memory; anything outside the pinned paths, notably
  `node_modules` above the package (for `@redact-secret/core` its
  `@redact-secret/wasm` and `@redact-secret/node-<platform>` packages are
  separate pins the caller must list in `extra_artifacts`, and a platform
  addon that is not listed is not verified); the identity of the `node`
  binary (it is canonicalized and must be a regular file, but its bytes are not
  hashed, and the runtime version in `ready` is reported by the shim itself,
  so it is a consistency check and not evidence); the shell environment of
  whoever launches the executor; intermediate directory symlinks above a
  pinned path (only the pinned path itself and everything inside a tree are
  checked for symlinks).
- Therefore the runner must still make installs read-only for the duration of
  a run and pin the interpreter by digest (P7). This ADR does not claim that
  the loaded code is proven to be the verified code.

Tree names: file names inside a pinned tree must be printable ASCII without a
backslash, otherwise the pin fails with `pin-mismatch: artifact-bad-name`. A
name holding a newline could forge a second listing line (a tree of the files
`a` and `b` and a tree of one file `a\n<hash of b>  b` would otherwise share a
digest), and non-NFC or look-alike Unicode spellings cannot be told apart by a
reviewer. The digest format itself is unchanged; the rule only refuses trees
whose listing could be ambiguous. A test builds the collision example.

### D6. Normalization: one translation, closed vocabulary, nothing dropped

`normalize_findings` converts each PII finding with the kernel's
`RangeTranslator` exactly once, against the exact text that was sent, in the
unit the shim declared and the adapter pinned. `RangeTranslator` indexes a text
once (O(text), at most 8 MiB of tables for a 1 MiB text) and converts each
range in O(log n) with the same semantics, check order and errors as
`translate_range`, which is now a thin wrapper over it (equivalence is tested
for every offset pair in all three units on Korean, emoji, CRLF and combining
text, and on fixed-seed generated text). Before this, every finding cost
O(text): 10,000 findings over 1 MiB took about 21 s of CPU outside any timeout;
the probe test `tests/normalize_cost.rs` now measures the same input at about
30 ms in a debug build and asserts a 5 s ceiling. Total work is bounded by
`text + max_findings * log(text)`, and `max_findings` is checked before any
conversion.

A range that does not convert (empty, inverted, past the end, inside a
character or surrogate pair) makes the whole scan
`malformed-output: invalid-range`; it is never clamped, rounded or dropped. The
contract has no finer failure code for a bad range, so all range errors share
it, except an oversize text (`InputTooLarge`, a caller error that cannot occur
in a session because oversize text is refused before it is sent). Each
reported family and jurisdiction is checked against what the running scanner
declared for its activation: a finding outside it is
`malformed-output: undeclared`, not a pass-through (an unmapped type with no
family makes no such claim and is kept). Findings are sorted into the
contract's canonical order; duplicates are kept.

Per-scanner mapping lives in a `ScannerVocabulary`: selector grammar, selector
jurisdiction, base capabilities, activation parsing and finding mapping. An
action word outside the scanner's closed vocabulary is malformed output, never
guessed.

### D7. Failure states are distinct and map to the contract

| `AdapterError` | Contract failure code | Scanner status |
| --- | --- | --- |
| `MissingCapability` (selector unsupported, configuration rejected) | `unsupported` | `unsupported` |
| `PinMismatch`, `StartupFailure` (spawn, exited before ready, initialization) | `unavailable` | `unavailable` |
| `Timeout` | `timeout` | `error` |
| `Crashed`, `ScannerError` | `execution-error` | `error` |
| `OutputLimit` (line, findings) | `output-limit-exceeded` | `error` |
| `MalformedOutput` (including `invalid-range`, `undeclared`) | `malformed-output` | `error` |
| `InvalidSpec`, `InputTooLarge`, `SessionClosed` | none (caller errors) | none |

A clean scan is only `Ok(ScanOutput)`. `replay-disagreement`, `unstable` and
`cancelled` need a replay scheduler and a cancel signal, which are P7's.
Errors hold fixed enums only: no output line, input fragment, OS message, path
or offset. A test formats every failure with `Display` and `Debug` and asserts
that a planted sentinel never appears; `ScanOutput`, `ScanResult`,
`RawFinding` and `SanitizedOutput` print no text.

### D8. Capability mapping

Capabilities come from the running scanner, not from a static claim:

- `ranges`, `family-classification`, `sensitivity-classification` and
  `jurisdiction-reporting` come from the vocabulary's base declaration.
- `action` is `sanitized-output` when output was requested and returned, else
  `reported-action`. Never inferred from a finding flag.
- `families` are the families in the scanner's own activation identity;
  `jurisdictions` are those families' scopes. Anything not listed is
  `undeclared` (the contract's `family_state` rule), never `supported`.
- A rejected selector is `unsupported`/`unsupported` with the jurisdiction
  recorded `unsupported` only when exactly one requested selector names one,
  since the scanner does not say which it rejected. Otherwise nothing is
  declared.

### D9. Reported action and sanitized output are separate observations

`Finding.action` is the action word the scanner reported, mapped to the neutral
kinds. `InputObservation.sanitizedOutputDigest` is the SHA-256 of the output the
scanner returned. The sanitized text itself is held in memory in
`ScanOutput.sanitized_output` (a type that hides its text from `Debug`) so the
executor can verify removal in P7; this crate never serializes it. Whether the
reported action matches the output is not decided here.

### D10. `@redact-secret/core` 0.1.0-beta.12 adapter

The only PII scoring path in the oracle (`scanners/candidate.mjs`,
`scripts/observe-pii-populations.mjs`). Ported as behavior:

- activation via `initialize({ pii: [...] })`; selectors `pii:global` and
  `pii:<cc>`;
- only `pii-domain` findings are PII observations; other detectors are counted
  in `skipped_findings`;
- `piiFindingIdentity`: `pii_global_<name>` to `pii:global:<name>`;
  `pii_jurisdiction_<cc>_<name>` to `pii:<cc>:<name>` with jurisdiction `<CC>`;
  an unmapped type keeps its range with no family;
- a PII finding is reported `sensitive: true`, which is the oracle's mapping
  (the product's redaction decision) recorded as adapter policy.

Actions: `redact` to `redact`, `warn` and `allow` to `preserve`, `block` to
`other` (it replaces text like `redact` but is a different decision).

Identity records: scanner id `redact-secret-core`, adapter id
`redact-secret-core-node`, adapter version `1.0.0`, normalization version `1`.
Pinned version `0.1.0-beta.12`; npm integrity
`sha512-fDVwt2U7…` (from the oracle lockfile, checked by npm at install);
package tree digest `7264216361…` (computed from that tarball installed with
`--ignore-scripts`; full values are constants in
`crates/pii-eval-adapters/src/redact_secret.rs`). The platform addon
(`@redact-secret/node-<platform>`) and the WebAssembly fallback are separate
packages; the caller pins them through `extra_artifacts`, because their digests
are platform specific. The activation the scanner reports must show
`credentials=full` (the recorded `detectorProfile`), and its `selectors` must
equal the requested ones.

Configuration identity: the parameters are closed and fixed
(`detectorProfile=full`, `findingSource=pii-domain-only`,
`offsetUnit=utf16-code-units`, `sanitizedOutput=true`). The scanner has no PII
threshold, so there is no threshold parameter; the configuration digest records
exactly these values. The activation digest covers the requested selectors.
The scanner's own activation identity string and its SHA-256 are recorded in the
`RuntimeRecord` next to the runtime name and version, the shim digest and the
artifact digest.

Jurisdictions: an unsupported selector (the package rejects `pii:kr` with
`PII_SELECTOR_UNSUPPORTED` at this version) is a missing capability, not an
empty scan. The package allows one activation per process, so an executor must
start a fresh process per activation.

### D11. Other legacy scanners

`crates/pii-eval-adapters/src/inventory.rs` records every entry of the
ownership map with its disposition, and a test checks it against the map.

- `flare-redact` 1.6.1 and `@openredaction/core` 1.1.5: no PII-observation
  adapter. In the oracle they are timed through `redact(text)` for throughput
  (`supportClaims: false`) and their findings are never mapped to PII families,
  ranges or sensitivity. An adapter would have to invent a mapping the oracle
  does not have. The framework supports adding one later with a reviewed
  mapping and its own conformance vectors.
- `gitleaks` 8.30.1, `trufflehog` 3.97.4: credential scanners with no PII
  adapter in the oracle.

### D12. What P7 must add

- A bounded worker pool, per-scanner parallelism and pending-task limits from
  the manifest's `ExecutionLimits`, and a fresh process per
  scanner/configuration/activation realm (the core package rejects a second,
  different activation in one process).
- Process-group (Unix) or job-object (Windows) cleanup of descendants,
  cancellation, memory/CPU/temporary-storage limits, network and filesystem
  isolation, and read-only scanner installs for the run duration.
- Replay scheduling (`replay-disagreement`, `unstable`), timing diagnostics,
  assembling `ObservationSet` bodies (engine, protocol, population digest,
  status, replay record), and artifact writing.
- Output verification (`removed`, `residual-present`, `collateral-change`) from
  `ScanOutput.sanitized_output`.
- Where the scanner installation comes from (reviewed, `--ignore-scripts`,
  integrity-verified), and pinning of the platform addon digests.

## Alternatives considered

- Passing configuration in argv or environment variables: rejected; it would
  put plan text on a command line the shim can be tricked by.
- Letting the shim compute family, action and sensitivity: rejected; it would
  move decisions out of Rust and make the shim a second place that must be
  parity-tested.
- Hashing only the scanner entry file: rejected; it leaves most of the package
  unverified. The tree digest covers it.
- A Node or Python process pool in this phase: deferred to P7 by the issue
  split; a minimal single-process interface is enough to define the boundary.
- Adding PII adapters for the throughput-only peers by guessing a mapping:
  rejected (D11).
- A third-party process or async crate: rejected; `std` is enough and the
  dependency guard now covers this crate.

## Consequences

- `pii-eval-adapters` gains `pii-eval-kernel` and `serde_json` (both already
  reviewed and used by the pure crates); no new third-party crate. The
  dependency guard checks the adapters' closure against the same allowlist.
- CI gains Node 22 (`actions/setup-node` pinned by SHA) and sets
  `PII_EVAL_REQUIRE_NODE=1` so adapter tests fail instead of skipping there. No
  scanner is installed in CI and no npm command runs. Locally the tests skip
  with a printed reason when Node is absent.
- The real `@redact-secret/core` test is opt-in
  (`PII_EVAL_REDACT_SECRET_CORE_DIR`), skipped with a reason otherwise.
- No contract changed; schemas, fixtures and digests are untouched.
- Behavior that is planned and not implemented is listed in D4 and D12.
