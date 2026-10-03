---
name: promote-finding
description: Turn a reproducible pii-eval observation into a well-scoped handoff to its owning repository without converting measurement into product policy. Use when asked to promote or escalate an evaluator finding.
---

# Promote a finding

A finding starts as a reproducible evaluator observation. Determine its owner
before changing anything (see the ecosystem table in `README.md`):

- wrong, ambiguous, or unreviewed expectation, provenance, or generation rule
  -> the corpus author;
- scoring, range assessment, accounting, normalization, adapter,
  orchestration, or artifact defect -> `pii-eval`;
- a legacy-engine semantic bug found while checking parity -> the
  TypeScript oracle in `redact-secret-benchmarks`, recorded as a versioned
  protocol decision rather than a silent fix;
- protected-execution authorization, budget, custody, or release of an
  aggregate -> `private-custodian`;
- Redact Secret qualification policy or public presentation ->
  `redact-secret-benchmarks`;
- credential-family semantics or credential measurement -> `credential-eval`;
- scanner implementation or product policy -> that product's repository.

Capture the engine, protocol, accounting, method, and adapter versions; the
corpus snapshot and population identity (visibility and released/candidate);
scanner and configuration identity; case/method IDs; the outcome axis
(type identity, sensitivity context, range state, or action observation) with
expected and observed values; and a sanitized minimal reproduction. Confirm
the run completed and reproduce once from pinned inputs, including a replay
of the same observations when the finding is a scoring question.

Create or update only the local tracking artifact explicitly requested by the
user. The handoff must state what was measured, what remains interpretation,
and acceptance criteria for a rerun. Never include input text, matched
values, raw scanner output, seeds, or case IDs from a protected population.
Never change an expected result to fit the observation: scanner agreement is
not ground truth. Never label a product stable, supported, or release-blocking
from this workflow alone.
