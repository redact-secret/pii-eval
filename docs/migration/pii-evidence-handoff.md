# Handoff: the first pii-evidence snapshot measured by pii-eval

Audience: the owners of `pii-evidence` (evidence), downstream benchmark qualification (`redact-secret-benchmarks`) and
whoever extends the loop. Public synthetic material only: no protected corpus, private custodian, private ledger, EC2
host or production key is used or needed. Design: [ADR 0019](../adr/0019-pii-evidence-snapshot-consumer.md). Reference:
[docs/evidence-consumer.md](../evidence-consumer.md). Source issue:
[redact-secret/pii-evidence#9](https://github.com/redact-secret/pii-evidence/issues/9).

## What the loop is

```text
pii-evidence snapshot (immutable, public)  ->  pii-eval-evidence verify / import  ->  corpus snapshot (schema 1.4)
  ->  pii-eval run (one real scanner, official, released)  ->  pii-eval replay  ->  public-synthetic artifact
```

Pinned input: `public-pii-phi/2026-10-07/9d4e8e036bbb` (content digest
`9d4e8e036bbb180fb3a09569a2993e51ad10fbc183765882325f2bc10b321ba2`, manifest SHA-256
`a9e24b6dc73bc876f9fce341c7305421b054ae399df83d198513bede03555ca9`, tag
`snapshot-public-pii-phi-2026-10-07-9d4e8e036bbb`, commit `c436ae013011b9c8b1126f589d1b14d99a84baf5`). Output: the files
under [`docs/measurements/pii-evidence-public-pii-phi-2026-10-07-9d4e8e036bbb/`](../measurements/pii-evidence-public-pii-phi-2026-10-07-9d4e8e036bbb/)
with the identities in `provenance.json`.

## What belongs to whom

| | Evidence (`pii-evidence`) | Measurement (`pii-eval`) | Downstream benchmark qualification |
| --- | --- | --- | --- |
| Owns | What a value is: authored cases, fixture bytes, spans, identity and sensitivity expectations, sources, provenance, the immutable snapshot and its digests | How a scanner behaves on an identified population under a protocol: verification, mapping, execution, replay, accounting, the artifact and its digests | What a result means for Redact Secret: scorer, denominators, thresholds, support states, rankings, release approval, publication |
| Never does | Carry a detector, support state, threshold, score or scanner behavior | Edit an expectation to fit a scanner, rank, decide support, publish, or authorize a protected run | Treat a public measurement as protected evaluation, or a pin as proof the evidence is right |
| Hands over | A snapshot and a pin | A public-synthetic artifact, its manifest, observation set and the binding of every mapping decision | The qualification decision, in its own repository |

Two denominators stay separate: this population's, and any other population's (a protected one, the NER evidence
`externalRefs` would join). The artifact is one population; nothing here pools.

## Reproduce

```sh
cargo build --release --locked -p pii-eval-cli
node tools/pii-evidence/reproduce.mjs          # verify, import, plan, EXECUTE, REPLAY, compare with provenance.json
cargo test -p pii-eval-cli --locked --test evidence_consumer --test evidence_measurement   # no scanner, no network
node tools/pii-evidence/fetch-snapshot.mjs --pin fixtures/pii-evidence/pin.json --out <new-dir>   # optional fetch
pii-eval-evidence verify --snapshot-dir <dir> --pin fixtures/pii-evidence/pin.json
```

`reproduce.mjs` needs Node 22, `npm` with registry access and the release binaries (not `gh`; only the optional fetch
needs it). Replay without a scanner:

```sh
pii-eval-evidence import --snapshot-dir fixtures/pii-evidence/snapshots/public-pii-phi/2026-10-07/9d4e8e036bbb \
  --pin fixtures/pii-evidence/pin.json --out <dir>
pii-eval replay --snapshot <dir>/snapshot.json --manifest docs/measurements/<id>/manifest.json \
  --observation docs/measurements/<id>/observation-redact-secret-core.json \
  --original docs/measurements/<id>/run-artifact.json --out <out> \
  --expect-snapshot-digest 612a8cf629c24c8e92be474a8129a592c7f1f75cbe4e2e2afcc60383cc6347d8 \
  --expect-manifest-digest a2ee0b5bcc81f945e60bde49ad8a018c82276ab0f04b9dbc162710b565e75c5f
```

## Pins a consumer of this measurement should check

Population digest `612a8cf629c24c8e92be474a8129a592c7f1f75cbe4e2e2afcc60383cc6347d8`, manifest digest
`a2ee0b5bcc81f945e60bde49ad8a018c82276ab0f04b9dbc162710b565e75c5f`, public artifact digest
`d54f96f9b71f89c4960d7d3e086de6d1a19f24d9012fa63d08015f9a605faa6d`, scanner `redact-secret-core` 0.1.0-beta.12
`released` (package tree `726421636189573bc76024ecf23ec6bd1d71fef6d8272e5da1b3967dee036d03`), engine `pii-eval` 0.0.0,
protocol `pii-v1` revision 2, schema 1.4, run class `public-synthetic`. The example consumer
(`examples/consumer/consume.mjs`) accepts schema 1.1 and 1.2 public artifacts only, so it does not read this schema 1.4
artifact yet; a consumer must read schema 1.4 (it carries the `unresolved` range state of ADR 0018).

## Known mapping losses

Quantified per variant in the binding (digest `f481baee5aa3d812f7858902c5024618e09e0a2868993d31dc10525c53ddf9fb`),
decided in [the mapping table](../evidence-consumer.md#mapping-rule-pii-evidence-to-corpus-revision-1):

- 41 of 139 occurrences are range-less (the 16 `derivedFromRule` fixtures and 25 variants of cases the evidence leaves
  unlocated). They are observed `unresolved` on identity, sensitivity and range and `not-measured` on action. 17 had an
  authored `invalid` identity and 19 an authored `sensitive` or `non-sensitive` value that pii-eval can hold only as
  `not-established` without a span.
- 11 located occurrences have sensitivity `context-dependent`, flattened to `not-established`.
- 37 variants name contexts and 37 are in the `phi` domain; neither has a corpus field.
- Two structural `us-ssn` cases have no fixture and eight (case, rule) pairs were skipped by the producer; none is
  measured.
- No `payment-card`, `iban` or `national-id` case exists in this snapshot (excluded by the producer's provenance gate).
- Language is `und`; context frame is `neutral`, obligation `none`, action `not-specified`: the evidence states none.

## Result, read carefully

139 variants, complete. All 98 located occurrences were observed with range `miss`: the pinned scanner reported no
finding on any of them (type-miss 20/20 cases, sensitive-miss 18/18, wrong-family 0/20, wrong-jurisdiction 0/8; the
benign rates are withheld below the minimum denominator of 4; measurable-share 39 of 110). The corpus is reserved
example values, mostly without labels, authored by one project without independent review, so this is a description
of one build on this corpus, not accuracy evidence and not a product verdict.

## What the run does not authorize

- Redact Secret product qualification, a support state, a threshold, a ranking, a release or a publication decision.
- A protected evaluation or any use of protected data, custody, budgets or a custodian job context.
- Treating `unresolved` or `not-measured` as pass or fail, pooling this population with another, or reading the
  scanner's silence as ground truth (scanner agreement is not ground truth).

## Follow-ups

Protocol or contract changes this work deliberately did not make (full list in ADR 0019): a variant-level negative
expectation, a `context-dependent` sensitivity value, context and domain axes in the corpus, binding the platform addon
into the manifest's scanner identity. For the evidence owners: stating a span for the invalid and non-sensitive
negative cases would let their authored claim survive the mapping exactly; adding labeled and unreserved-looking
synthetic variants would make a measurement discriminate (that is evidence authoring, not scanner tuning). For the
benchmarks: a reader of schema 1.4, the scorer and denominators for `unresolved`, and a pin of the artifact digest above.
