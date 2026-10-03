---
name: owasp-review
description: Review pii-eval's corpus ingestion, observation replay, scanner adapters/shims, orchestration, and artifact publication against applicable OWASP guidance. Use for an OWASP or secure-design review. Read-only.
---

# OWASP review

Review this evaluator's attack surface, not scanner detection quality. Begin
with `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `CONVENTIONS.md`, and the
scoped code. Use the threat model in `SECURITY.md`: inputs, generated
variants, scanner output, adapter packages, and run configuration are all
untrusted, and a scanner shim is executable code.

Cover applicable controls for:

- untrusted input validation of `CorpusSnapshot`, `RunPlan`, and
  `ObservationSet` (schema, counts, version support, size limits);
- offset and range validation: half-open UTF-8 byte ranges, byte-boundary
  versus length-bound checks, runtime-index translation in adapters;
- path containment, symlink and archive escape, temporary files and scratch
  permissions;
- command/argument construction, fixed executable paths, environment
  inheritance, and Node/Python worker isolation and reset;
- resource limits: workers, per-scanner parallelism, pending tasks, memory,
  timeouts, stdout/stderr buffers, variant generation, temp storage, and
  process-tree cleanup;
- error handling: scanner errors kept distinct from clean scans, stable
  reason codes, no input snippets or private paths in public errors;
- log and artifact redaction: no input text, matched values, raw scanner
  output, seeds, or case identifiers where the output class forbids them;
- artifact integrity: replay rejecting changed inputs or settings, identity
  binding (engine, protocol, snapshot, scanner, adapter, configuration),
  canonical digest determinism;
- public/protected separation and publication guards: visibility
  (`public-synthetic`/`protected`) and identity (`released`/`candidate`) kept
  independent, and projection allowlisted;
- dependency provenance and CI permissions.

For each applicable control report `pass`, `fail`, or `not assessable`, with a
file/line reference and concrete evidence. Documented design intent is not
implementation evidence; if no code exists for a control, report
`not assessable`. A `network=off` manifest field is not enforcement evidence.
Treat intentionally offline synthetic evaluation as reducing exposure, not
eliminating the need for containment and bounds.

Do not modify code or reinterpret measurement outcomes.
