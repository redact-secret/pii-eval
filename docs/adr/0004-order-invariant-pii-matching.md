# ADR 0004: Byte-range rules and order-invariant PII matching

- Status: accepted for P3 (issue #4); subject to review.
- Date: 2026-10-02
- Related: [ADR 0001](0001-rust-first-and-oracle-pin.md),
  [ADR 0002](0002-freeze-pii-contracts-v1.md),
  [ownership map](../migration/ownership-map.md), epic #1. Implementation:
  `crates/pii-eval-kernel/src/range.rs`, `crates/pii-eval-kernel/src/matching.rs`,
  `crates/pii-eval-compat/src/legacy.rs`.

## Context

ARCHITECTURE.md required these decisions before canonical semantics are frozen:
ordering, duplicate handling, multiple overlaps, label mappings and outcome
precedence. The oracle (`contract-model.ts`, `interpretPiiOutcome` and
`rangeOutcome`, oracle commit `4b846967346505baca11e0b98cab1475fbce6773`)
decides every axis of a variant from the **first finding, in scanner emission
order, that overlaps the candidate range**. Its result therefore depends on
order, it validates no range, and it ignores declared capability.

This ADR does three things: it fixes the range and offset rules, it keeps the
legacy rule as a named compatibility mode, and it specifies a separately
versioned order-invariant rule with a classified list of differences.

## 1. Coordinates and offset units

- Coordinates are half-open `[start, end)` UTF-8 byte ranges into the original
  input. Input is never normalized: NFC and NFD spellings are different bytes
  and are measured as given.
- A range is valid when, in this order, `start < end` (empty and inverted are
  distinct errors), `end <= 2^53 - 1`, `end <= byte length`, and both ends are
  on Unicode scalar boundaries. Structure, bound and boundary are separate
  errors (`RangeError`), mapped to the contracts' reason codes. A boundary is a
  scalar boundary, not a grapheme boundary: a range may separate a base
  character from a combining mark.
- Adapters translate scanner indices exactly once with `translate_range` (or
  `translate_offset`). Declared units: `utf8-bytes`, `utf16-code-units`,
  `unicode-code-points` (`OffsetUnit`). The contracts declare no offset unit
  today, so the unit set belongs to the kernel; an unknown unit name is refused
  (`OffsetUnit::from_wire`), never defaulted. An offset inside a UTF-8 sequence
  or between UTF-16 surrogate halves is rejected, never rounded. Work is linear
  in the text and the text is capped at `MAX_TEXT_BYTES`.

## 2. Compatibility mode `legacy-first-overlap` (protocol revision 1)

Reproduced unchanged in `pii-eval-compat::legacy`, not in the kernel, because
CONVENTIONS.md keeps legacy behavior in the removable compat crate and the
canonical model must not be shaped around it. It is a port of the oracle code,
quirks included, and tests pin it with hand-calculated vectors. Behavior:

1. Candidates are the findings whose range satisfies
   `finding.start < candidate.end && candidate.start < finding.end`, applied to
   whatever numbers arrive (an empty finding strictly inside the candidate, or an
   inverted one, overlaps and is `partial`; nothing is validated).
2. The **first** candidate in the order given decides type, sensitivity and range.
3. Range: exact if equal; overbroad if the finding contains the candidate;
   otherwise partial; miss if there is no candidate.
4. Type: an invalid expectation is `invalid-accepted` if there is any candidate,
   else `invalid-correct`. A valid expectation: no candidate is `miss`; no
   family is `not-measured`; a different family is `wrong-jurisdiction` when the
   case has a jurisdiction and the finding reports a different one, else
   `wrong-family`; the same family with a case jurisdiction and none reported is
   `not-measured`, with a different one `wrong-jurisdiction`; else `correct`.
5. Sensitivity: `not-established` is `unresolved`; otherwise "flagged" is
   `first.sensitive == true` (absence reads as not flagged) and the state is
   correct/miss or correct/false-positive.
6. `observed` counts all candidates (duplicates included) and lists their
   families and jurisdictions ascending and unique.
7. A scanner that did not complete measures nothing.

## 3. Canonical rule `pii-v1-canonical` (proposed protocol revision 2)

Identifier `MATCHING_RULE_ID = "pii-v1-canonical"`, revision
`MATCHING_PROTOCOL_REVISION = 2`.

### 3.1 Input and ordering

The result is a function of the **set** of findings and the **set** of
expectations. Findings are sorted by the contracts' total order (`Finding: Ord`:
range, family, jurisdiction, sensitivity, action; absent before present, enums
by wire string) and expectations by occurrence id before any decision, so no
permutation of the input can change the output. Every expectation range is validated
against the text first. Finding ranges are validated next, **unless the
scanner measured nothing** (status other than `complete`, or ranges
unsupported): then findings are not read or validated and all axes are
unmeasured. An invalid range is an error (the first in canonical order is
reported), never skipped or repaired. Limits:
at most `MAX_FINDINGS_PER_INPUT` findings, `MAX_EXPECTATIONS_PER_VARIANT`
expectations, `MAX_TEXT_BYTES` text; occurrence ids must be unique.

### 3.2 Candidates and selection of the primary finding

For each expected occurrence the **candidates** are the findings that overlap
its range (half-open, so adjacent ranges do not overlap). One candidate is the
**primary**, chosen by the smallest key, compared in this order:

1. closeness `(rank, tightness)`: exact `(0,0)`; overbroad `(1, finding length -
   expected length)`; partial `(2, expected length - overlap length)`;
2. identity evidence: 0 reports the expected family (and, when the case has a
   jurisdiction, the same jurisdiction), 1 reports another family or a
   mismatching or missing jurisdiction, 2 reports no family;
3. evidence completeness: 3 minus the number of optional fields the finding
   reports among jurisdiction, sensitivity and action (more reported fields is
   better), so a finding that reports sensitivity and action is never shadowed
   by an otherwise equal one that reports none, however they sort;
4. position in canonical finding order (a total tie-break by finding value).

Geometry decides before identity: a closer wrong-family finding beats a looser
right-family one. Identity only breaks ties between equally close findings, so
that two exact findings on one range do not produce a result that depends on
how family names happen to sort. Residual ties (equal closeness, identity evidence and completeness) fall to canonical finding order; this is arbitrary but deterministic
and scanner-neutral. A finding may be primary for several occurrences: matching
is per occurrence, with no one-to-one assignment.

### 3.3 Axes, all judged on the primary

- **Range** (`exact`/`overbroad`/`partial`/`miss`/`not-applicable`): the
  relation of the primary to the occurrence; `miss` with no candidate;
  `not-applicable` when the scanner measured nothing.
- **Type**, with this precedence: (1) an unsupported family classification, an
  unsupported expected family, or an unsupported case jurisdiction gives
  `not-measured` for valid and invalid expectations alike; (2) invalid
  expectation: `invalid-accepted` if there is any candidate, else
  `invalid-correct`; (3) valid: no primary is `miss`; primary without a family
  `not-measured`; different family `wrong-jurisdiction` when the case has a
  jurisdiction and the primary reports a different one, else `wrong-family`;
  same family with a case jurisdiction and none reported `not-measured`, a
  different one `wrong-jurisdiction`; else `correct`.
- **Sensitivity**: unsupported capability is `not-measured`; `not-established`
  is `unresolved` (review-required); otherwise the primary's `sensitive` value
  decides (correct/miss, correct/false-positive). A primary that reports no
  value is `not-measured`. With no primary, absence is negative evidence only
  when the capability is `supported`; `undeclared` gives `not-measured`.
- **Action**: unavailable capability is `not-measured`; otherwise the primary's
  reported action (`reported`, with its kind) or `no-action-reported`. The
  matcher never produces `output-verified` (it needs sanitized output, P7) and a
  sensitivity flag never implies an action. The authored action expectation is
  not compared here.
- Type identity, family/jurisdiction, sensitivity context and action are
  separate fields; none is computed from another. Status is derived from state
  (`TypeState::status`, `SensitivityState::status`). Every produced row satisfies
  the contracts' `validate_outcome_lattice` (a test enumerates the capability
  combinations).
- A scanner that did not complete, or cannot report ranges, measured nothing:
  every axis is unmeasured, findings are not read, and no span rows are produced.

### 3.4 Duplicates and multiple spans

Findings are never merged. Identical findings count in
`observed.finding_count` and each is its own `ReportedSpan` row, so no
denominator row is hidden; they do not change the primary. For every finding the
kernel also reports its best-matching occurrence (closeness, then lowest
occurrence id), its relation and how many occurrences it overlaps, or `None`
for a finding that overlaps none. This is the fact base for range-collateral
accounting; counting rules belong to P4. Deduplication, if ever wanted, would be
an authored, versioned rule, not part of matching.

### 3.5 Label mappings

The matcher compares `FamilyId`s. Mapping a scanner's native label to a family
is adapter work (P6). A native label with no mapping becomes a finding with no
family, which yields `not-measured` for type, not `wrong-family`; the matcher
never guesses a family.

## 4. Classified differences, legacy to canonical

Executable evidence: `crates/pii-eval-compat/tests/differences.rs` (ids match).

| Id | Difference | Class |
| --- | --- | --- |
| D1 | Selection is by closeness and identity, not by first position. With two or more candidates the outcome can differ. | Intentional semantic change (order dependence removed) |
| D2 | A contract document stores findings in canonical order, not scanner emission order, so legacy over a stored `ObservationSet` can pick a different "first" than the oracle did. | Parity caveat for P9: replay must carry emission order, or compare against canonical |
| D3 | A selected finding with no `sensitive` value is `not-measured` (legacy: not flagged, so `miss` or `correct`). | Intentional (absence is not a negative answer) |
| D4 | No finding under an `undeclared` sensitivity capability is `not-measured` (legacy: `miss`/`correct`). With `supported` it is unchanged. | Intentional (capability-aware) |
| D5 | (see also D11) Declared capability is honored: unsupported family/jurisdiction/sensitivity or unavailable action gives `not-measured`; legacy ignored capabilities (for example an invalid expectation was classified by overlap alone). | Intentional (contract lattice) |
| D11 | A scanner whose `ranges` capability is unsupported measured nothing: every axis is `not-measured` / `not-applicable` and findings are not read. Legacy has no capability input and measures from the findings given. | Intentional (contract lattice); test `d11_...` |
| D6 | Empty, inverted, out-of-bounds and mid-character ranges are errors. Legacy matched them. | Intentional (validation) |
| D7 | Action axis added. | Addition |
| D8 | Reported-span rows (best occurrence, relation, overlap count) added. | Addition |
| D9 | One variant may have several expected occurrences, each assessed independently. Legacy had one candidate per variant. | Addition (contract shape) |
| D10 | Legacy filtered findings by file path. Findings are per input in the contracts. | Contract shape, no semantic change |
| U1 | Unchanged: range geometry, `observed` count/families/jurisdictions over all candidates (duplicates counted), type and sensitivity rules when there is at most one candidate and every field is reported with full capability, completed-scanner gating, `unresolved` for `not-established`. | Equal (property test over generated vectors) |

## 5. Contract impact

None in this change. The contracts bind `pii-v1` revision 1 (the legacy
semantics) and `ObservationSetBody` rejects any other `protocol` value
(`protocol-binding-mismatch`). The canonical rule is revision 2 and is **not yet
representable in a document**: an artifact produced with it cannot yet state so.
Before any phase emits canonical-rule artifacts, a contract change per ADR 0002
(a protocol revision, not a schema major, because no field is removed or
retyped) must bump `PROTOCOL_VERSION` or accept a declared set of revisions,
regenerate the schemas, registry, fixtures and digests, and carry a migration
note. That change is deliberately left out to avoid altering frozen meaning
inside P3; P4 or P7 owns it. Until then the kernel and compat functions are
library functions that do not write documents.

No schema field, reason code, canonical-serialization rule or digest preimage
changes here. `FamilyId`, `Finding`, `Expectation`, `ObservedSummary`,
`OutcomeRow` and the lattice are reused, not duplicated.

## 6. Consequences

- Tie-breaking by evidence completeness (3.2, rank 3) is a classified consequence:
  between two findings of equal closeness and identity, the one reporting more
  optional fields is primary, which can change sensitivity or action outcomes
  relative to sorting by value alone. Legacy would have taken whichever came
  first (D1).
- Phases P4 to P7 build on `assess_variant`; the offset translation in
  `translate_range` is the only place adapters convert indices.
- Per-occurrence selection can leave one finding primary for several
  occurrences and a competing finding visible only in counts and span rows.
  A stricter assignment (one finding per occurrence) would be a later revision.
- Identity tie-breaking favors a scanner only between equally close findings.
- Legacy parity runs (P9) must choose explicitly between `legacy-first-overlap`
  (with emission order) and the canonical rule and attribute every difference to
  an id above.

## Tests

Hand-calculated vectors from byte layouts: `crates/pii-eval-kernel/tests/conformance.rs`,
unit tests in `range.rs`, and the legacy pins in
`crates/pii-eval-compat/tests/legacy_first_overlap.rs`. Properties with a
fixed-seed generator (`tests/properties.rs`, `tests/differences.rs`):
permutation and repetition invariance of the canonical rule, offset round-trip
through every unit, validation never panicking on arbitrary bytes and offsets,
legacy "first overlapping finding alone decides", and legacy/canonical agreement
where U1 says they agree.

## Known limitations

- `RangeError::InvalidUtf8` maps to the contracts' `range-not-on-char-boundary`
  reason code, which is loose: there is no dedicated reason code and the
  contracts are frozen (ADR 0002), so none is added. Callers that need to tell
  the two apart use the `RangeError` variant, not the reason code.
- Legacy vectors are checked against hand evaluation of the oracle source
  (`crates/pii-eval-compat/tests/oracle_vectors.rs`), not by running the
  TypeScript oracle; same-observation replay parity is P9.
