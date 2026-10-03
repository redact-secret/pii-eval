# Agent instructions

@\~/.codex/RTK.md

Read `README.md` and `ARCHITECTURE.md` before changing this repository. They
define the repository boundary and take precedence over inherited conventions
or assumptions from predecessor repositories.

## Repository boundary

`pii-eval` measures scanner behavior on PII. It consumes versioned corpus
snapshots (one identified population per run), runs scanners through adapters
or validated observation replay, normalizes findings to half-open UTF-8 byte
ranges, applies the measurement protocol (seven methods, ten metrics), and
emits reproducible artifacts. The TypeScript engine in
`redact-secret-benchmarks` is the migration oracle, not a dependency.

This repository does not own canonical truth or corpus custody, Redact Secret
support status, thresholds, release approval, public-site content, scanner
rankings, or permission to publish protected results. Protected runs execute
only inside a `private-custodian` environment; an engine invocation is not an
authorization decision. Never change an expected result merely to match a
scanner's output; scanner agreement is not ground truth.

Do not depend on credential family semantics or on `credential-eval`
internals. Reuse a shared crate only after its neutral contract and both
consumers are proven, and pin it.

## Working rules

- Preserve scanner neutrality. Product-specific behavior belongs in an adapter
  or downstream qualification policy, not the measurement kernel.
- Treat the outcome lattice (`pass`, `fail`, `review-required`,
  `not-measured`), range states, matching/selection rules, and accounting as
  protocol semantics. Refactors must preserve them; intentional changes
  require an explicit, reviewed protocol revision with a difference report.
  Do not fix a legacy semantic bug merely to achieve or abandon parity.
- Keep type identity and sensitivity context as independent outcome axes.
  Detection, a reported `redact` action, and verified sanitized output are
  separate observations; never infer removal from a finding flag.
- Coordinates are half-open UTF-8 bytes into the original input. Convert
  runtime indices once, in adapters; never normalize input silently.
- Keep execution bounded: concurrency, subprocess output, timeouts, buffers,
  and generated variants must all have explicit limits.
- Keep results deterministic. Parallel scheduling may not alter semantic
  output ordering or aggregate results.
- Record all identities needed for reproduction: engine, protocol,
  accounting, method, and adapter versions, corpus snapshot and digest,
  scanner, configuration, and seeds. Keep population visibility
  (`public-synthetic` or `protected`) separate from product identity
  (`released` or `candidate`).
- Use only synthetic or documented public-test material. Never use real
  personal data or real credentials. Never log input text or matched values,
  or copy raw scanner output, into public artifacts or errors.
- Replays are stability checks, not extra samples; record authored counts,
  variant counts, and effective N separately.
- Keep the kernel free of process spawning, network, publication, and product
  policy. Adapters never score expected outcomes.
- First-party crates forbid `unsafe` unless an ADR shows a measured need.
- Keep compatibility code in `pii-eval-compat`, isolated and removable. Do
  not shape the canonical model around legacy JSON.

## Work discipline

- Before proposing any command that takes more than five minutes, read and
  validate its inputs first. If validation costs two orders of magnitude less
  than the run, always validate first.
- In test and verification work, separate what is being measured from what
  inputs it needs. Inputs must be the smallest size that still satisfies the
  measurement.
- Do not assume that choosing among existing assets (issues, branches, files)
  is the only option. If creating something new is cheaper, propose that
  first.
- When challenged, answer the objection actually raised, not an easier one.
- Before benchmark or parity measurements, check that every scanner binary
  and adapter version matches the plan's pin (a self-update can change
  results). If it differs, do not report the numbers; put the pinned binary
  first on `PATH` and rerun. State the population visibility and the
  released/candidate mode alongside any reported number.
- Agents may run public synthetic tests within authorized scope. They cannot
  authorize protected runs, expand budgets, alter expected answers from
  scanner output, publish artifacts, or change support policy.

## Before finishing

The repository is a design baseline; the workspace may not exist yet. Run the
documented format, Clippy, locked workspace tests, schema drift, independent
conformance, compatibility parity, and relevant integration checks that exist
at the time of the change. If the implementation is not present yet, say which
checks could not run instead of inventing commands or CLI flags. For changes
to scoring, normalization, accounting, ranges, or serialization, add focused
tests and verify deterministic output across repeated runs and worker counts.

## Local skills

Repository-specific workflows live in `.agents/skills/`.

- Measurement correctness: `corpus-snapshot-validate`,
  `range-conformance-check`, `metric-accounting-check`, `determinism-check`,
  `oracle-parity-check`, `release-regression-check`.
- Evaluator security (they inspect this evaluator's own attack surface and do
  not assess whether any scanner is good or bad): `owasp-review`,
  `sast-sweep`, `vulnerability-test`, `dependency-audit`,
  `scan-secrets-in-history`, `scorecard-check`.
- Handoff: `promote-finding`.

<!-- graft:start -->
## Graft — repo context graph

This repo is indexed in `graft/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `graft map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `graft ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `graft grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `graft skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `graft callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `graft/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `graft ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `graft build` (deterministic,
no API key, $0).
<!-- graft:end -->
