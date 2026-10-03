# ADR 0003: Canonical serialization and semantic digest

- Status: accepted for P2 (issue #3); subject to review.
- Date: 2026-10-02
- Related: [ADR 0002](0002-freeze-pii-contracts-v1.md); implementation in
  `crates/pii-eval-contracts/src/canonical.rs`.

This is the normative specification. The digest construction identifier is
`pii-eval-semantic-digest/1` (`DIGEST_CONSTRUCTION`). Changing any rule here is
a breaking change (new construction identifier and schema major).

## Strict input

A document is one JSON text in UTF-8 and is rejected with a stable code if it:
exceeds 128 MiB (`document-too-large`), nests deeper than 32 levels
(`nesting-too-deep`), repeats an object key (`duplicate-key`), contains `null`
(`null-not-allowed`), contains a number that is not an integer
(`float-not-allowed`; this includes `1.0`, `1e2`, `-0`, `-0.0`, and integers
that do not fit 64 bits), or contains an integer outside +/-(2^53 - 1)
(`integer-out-of-range`). A byte-order mark or trailing data is `malformed-json`.

## Value rules

- **Absent versus null.** Optional fields are omitted when unset. `null` is never
  valid; there is no canonical form for it. "Unknown" is an explicit enum value
  (`undeclared`, `not-measured`), not a missing or null field.
- **Numbers.** Plain decimal integers: no sign for non-negative values, no
  leading zeros, no exponent, no fraction. There are no floats in any contract,
  hence no `NaN`, no infinity and no negative zero. A rate or interval is a
  `ScaledDecimal {mantissa, scale}` in normalized form (no trailing decimal
  zero unless scale is 0).
- **Large integers.** Every integer is at most 2^53 - 1 in magnitude so that all
  JSON consumers read it exactly. A value that may exceed this must be modeled
  as a decimal string by a later schema revision; none exists in 1.0.
- **Strings.** Compared and ordered as UTF-8 bytes. No Unicode normalization is
  applied to any value, including case text.

## Canonical form

Of a JSON value: compact (no whitespace); object members in ascending order of
the UTF-8 bytes of the key (the sort is explicit and does not depend on the JSON
library's map type; this differs from RFC 8785, which orders by UTF-16 code
unit); arrays in their stated order; strings quoted with `"` and `\` escaped as
`\"` and `\\`, every code point below U+0020 as `\u00xx` (lowercase hex), and
every other code point written as raw UTF-8 (including U+007F, U+2028, `/`).

Array order is semantic. Collections that are sets (cases, variants, scanners,
metrics, outcomes, findings, capability entries, and so on) must already be in
ascending key order with unique keys; a document with another order is rejected
(`non-canonical-order`, `duplicate-identity`) rather than normalized, so
scheduler order can never be a hidden input. Sort keys are the wire strings of
the identity (method and metric ids sort by their wire string, not by enum
declaration order). Findings are sorted by `(range, family, jurisdiction,
sensitive, action)` with absent before present; duplicates are kept.

## Semantic digest

```
digest = lowercase_hex( SHA-256(
    "pii-eval-semantic-digest/1" "\n" domain "\n" canonical(semantic) ) )
domain = schemaId "/" schemaMajor      e.g. "pii-eval.corpus-snapshot/1"
```

`semantic` is the document's digested body. `diagnostics` (start and end
times, durations, phase timing) is a separate field with separate types that are
not reachable from the body, so timing cannot enter the digest; the digest is
also independent of host, worker count, scheduling, repeated runs and the order
or whitespace of the JSON text. Scanner configuration and activation have their
own domains (`pii-eval.scanner-parameters/1`, `pii-eval.scanner-activation/1`).
Raw input bytes (variant text, sanitized output) are identified by plain SHA-256
of the bytes, not by a domain-separated digest.

A document's `semanticDigest` is verified on parse (`semantic-digest-mismatch`).
The corpus snapshot digest is the population digest that manifests,
observations and artifacts bind to.

## Verification

- Hand-checkable vectors in the unit tests of `canonical.rs`, including key
  order, escapes, `-0`, large integers, depth and size.
- The digest of the committed fixtures was reproduced by an independent Python
  implementation of this text during P2; the snapshot digest is pinned in
  `crates/pii-eval-contracts/tests/digest.rs`.
- Tests shuffle object member order and whitespace of every fixture and require
  identical digests; repeated builds are byte-identical.
