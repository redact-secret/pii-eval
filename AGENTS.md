# Agent instructions

@\~/.codex/RTK.md

Read `README.md` and `ARCHITECTURE.md` before changing this repository. They
define the repository boundary and take precedence over inherited conventions
or assumptions from predecessor repositories.

## Repository boundary

`credential-eval` measures scanner behavior. It consumes versioned corpus
snapshots (public `credential-evidence` releases or separately identified
product-owned corpora, one population per run), runs scanners through
adapters, normalizes file/range findings, applies the measurement protocol,
and emits reproducible artifacts. See `docs/multi-corpus-qualification.md`.

This repository does not own credential truth, Redact Secret support status,
release policy, public-site content, or scanner rankings. Never change an
expected result merely to match a scanner's output.

## Working rules

- Preserve scanner neutrality. Product-specific behavior belongs in an adapter
  or downstream qualification policy, not the measurement kernel.
- Treat the outcome lattice and accounting rules as protocol semantics.
  Refactors must preserve them; intentional changes require an explicit,
  reviewed protocol revision.
- Keep execution bounded: concurrency, subprocess output, timeouts, buffers,
  and generated variants must all have explicit limits.
- Keep results deterministic. Parallel scheduling may not alter semantic
  output ordering or aggregate results.
- Record all identities needed for reproduction: engine, protocol, evidence
  snapshot, scanner, adapter, configuration, and corpus digest.
- Use only synthetic or documented public-test credential material. Never log
  matched values or copy raw scanner output into public artifacts.
- Keep compatibility code isolated and removable. Do not shape the canonical
  model around a legacy benchmark schema.

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
- Before benchmark measurements check that `trufflehog --version` matches the pin(3.97.4). A self-update that bumps only the patch version changes the stable count. If it differs, do not report the numbers; put the pinned binary first on `PATH` and rerun.
  Always state the mode (published or candidate) alongside a stable count.

## Before finishing

Run the repository's documented format, lint, test, schema, and parity checks
that exist at the time of the change. If the implementation is not present yet,
say which checks could not run instead of inventing commands. For changes to
scoring, normalization, accounting, or serialization, add focused tests and
verify deterministic output across repeated runs where practical.

## Local skills

Repository-specific workflows live in `.agents/skills/`. Security-review
skills inspect this evaluator's own attack surface; they do not assess whether
any scanner is good or bad.

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
