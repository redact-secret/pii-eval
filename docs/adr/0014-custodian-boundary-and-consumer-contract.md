# ADR 0014: Custodian boundary, consumer contract and handoff

- Status: accepted for P12 (issue #13); subject to review.
- Date: 2026-10-03
- Related: [ADR 0002](0002-freeze-pii-contracts-v1.md),
  [ADR 0008](0008-protocol-revision-2-and-schema-1-1.md),
  [ADR 0010](0010-standalone-cli-workflows.md),
  [ADR 0011](0011-internal-github-app.md),
  [ADR 0012](0012-oracle-parity-and-migration-evidence.md),
  [docs/custodian-boundary.md](../custodian-boundary.md),
  [docs/migration/consumer-handoff-665-666.md](../migration/consumer-handoff-665-666.md), epic #1.

## Context

Issue #13 asks for the custodian job and artifact boundary, a consumer example,
and the handoff for benchmarks #665 and #666. On reading private-custodian
(read-only, 2026-10-03) its issues 3, 4, 7 and 12 are closed and its
contracts, worker protocol, disclosure and benchmarks bridge are implemented as
synthetic-tested libraries. Its worker protocol (`worker-job/1`,
`worker-result/1`) and aggregate input (`aggregates/1`) name pii-eval deliverables
that do not exist. So the premise "define the contract jointly" is half true:
the custodian side is specified, ours is a gap, and several points are
unspecified for PII.

## Decisions

### D1. Engines measure; the custodian authorizes and discloses; nothing crosses that line in code

No engine document carries a budget, approval, expiry, revocation, signature or
ledger field, and the engine has no publication path for a protected population.
The job context keeps granting nothing. The responsibilities table and the
binding table are in the boundary document and are the contract.
Alternative rejected: adding `notAfter` or a revocation field to the job context
now. The custodian owns freshness; a field the engine cannot verify against any
authority would be decoration, and it would change `pii-eval-job-context/1`
without a consumer asking for it (kept as open question Q8).

### D2. `pii-eval-job-context/1` is unchanged

The existing context carries run class, population digest, manifest digest,
candidate digest and the two roots, which is what the engine can check. A domain
field is not added: the engine serves one domain, protocol `pii-v1` is the domain
identity in every document, and the custodian checks the domain on its own
`worker-job/1` and `worker-result/1`. A mismatching domain therefore fails
before the engine (the custodian refuses to start a job for another domain) and at
verification (the artifact's protocol). Alternative rejected: a `/2` context with
`domain` and `notAfter` for symmetry; no consumer, and it would force a
coordinated change before the real integration shape (D4) is settled.

### D3. Terminology: scanner activation is not policy activation

The engine's `activationDigest` identifies enabled detector selectors. The
custodian's policy activation is its disclosure and approval state. Both are
bound in the round trip, under their own names; the engine attests only the first.

### D4. The worker protocol and the aggregates artifact are a proposal, not built

The engine does not speak `worker-job/1` and does not emit `worker-result/1` or
`aggregates/1`. The shape that fits (an engine-owned `pii-eval worker --job`
launcher; roster, stratum and delivery mapping) is written down as a proposal with
nine open questions (boundary document, section 6). It is not implemented here
because three of the questions (roster unit, aggregates delivery, strata labels)
are the custodian's to settle and a guess would be an invented custodian
behavior that would later have to be un-built; the delivery question (Q2) shows
that, as its code reads today, one stdout document cannot satisfy both of the
custodian's checks (and its receipt assembly is not written yet). What is implemented is the test stub that builds both documents from the
internal artifact and checks them against the custodian's documented bounds, so the
mapping is shown feasible and every denominator fits. Alternative rejected:
implementing `pii-eval worker` now with guessed roster and strata semantics.

### D5. The round trip uses a stub custodian written in tests

`tests/custodian_round_trip.rs` contains `SyntheticCustodian`, a stub that
re-implements from the custodian's documents only the checks this boundary needs.
It imports no custodian code and runs no custodian test. It is labelled as a stub in
the file, the boundary document and the handoff, and its results are never
described as the custodian's. Real runs of private-custodian over pii-eval need
the engine launcher (D4) and an isolation self-check that includes Node (Q7).
Alternative rejected: depending on a custodian crate (circular repository
dependency, forbidden by ARCHITECTURE.md).

### D6. The consumer is a dependency-free Node program with exact pins

`examples/consumer/consume.mjs`, standard library only, imports nothing of this
repository. It reads the published JSON format (digest construction of ADR 0003,
documented schemas) and the caller's pins. It is Node rather than Rust because the
consumer it mirrors, benchmarks, is TypeScript, and because a Rust consumer inside
this workspace could not demonstrate the absence of kernel imports. The pins file
is the consumer's own format (`pii-eval-consumer-pins/1`); it is not an engine
contract. Rules: an artifact is accepted only when its digest recomputes, equals
the pinned digest and every pinned binding matches exactly; retired digests are
reported as `superseded`, not as unknown; the internal artifact and legacy schema
1.0 are never consumable; populations are composed side by side and never pooled
(`pooling: none` is part of the report, and no report field exists that could hold
a pooled value); the report contains no verdict (`decision: none`). Exit 0 means
every supplied artifact was accepted and every pin satisfied; incomplete or
partial composition is never a success.

### D7. Fixtures come from the real engine

The consumer's positive and negative artifacts are produced by the built binary
(`consumer_fixtures.rs`), compared byte for byte in CI, and regenerated with
`PII_EVAL_UPDATE_FIXTURES=1`. The consumer's digest implementation is exercised
against the engine's digests on every run, so a divergence of the two
independent implementations fails the build. Mutated negatives are re-sealed with
the consumer's own digest function; that is valid only because the positive
fixtures prove the function reproduces the engine's.

### D8. Public-release hygiene is a tripwire, not a scan

`public_release_hygiene.rs` checks the working tree: no committed JSON document
outside the negative fixtures is protected or carries a custody-ledger field name,
no key material or custodian internal tag appears, and the public artifact schema
cannot represent a protected population or raw data. It is cheap and structural. It
does not scan history; the `scan-secrets-in-history` skill and a person remain
required before publication (SECURITY.md).

### D9. Compatibility retirement is gated downstream

The engine states what the compatibility crate contains and what must stay until
retirement; it does not decide retirement. The gate is benchmarks' recorded oracle
exit, rollback rehearsal and caller inventory (handoff, section 5). This ADR adds no
deletion.

## Consequences

- A protected run of this engine cannot be dispatched by the custodian's worker
  protocol until the launcher exists. This is the principal gap and it is stated
  in the boundary document, the handoff and the PR.
- The engine's refusal after the custodian recorded exposure is a consumed attempt
  on the custodian's side; the custodian should verify a context locally before
  dispatch (boundary document, section 5).
- The consumer example is a reference, not benchmarks' client; benchmarks keeps
  its own verification of custodian signatures, feed freshness and revocation.
- No contract, schema, protocol or dependency changed: schemas, fixtures,
  `Cargo.lock`, toolchain and MSRV are untouched, so the identity table of the 664
  handoff stays valid.

## Verification

`cargo test -p pii-eval-cli --locked --test consumer_fixtures --test custodian_round_trip --test public_release_hygiene`,
`node --test examples/consumer/test/consume.test.mjs`; CI runs both in named steps.
