---
name: range-conformance-check
description: Verify pii-eval's half-open UTF-8 byte-range handling and the five range states (exact, overbroad, partial, miss, not-applicable) with independent hand-checkable vectors. Use when range validation, adapter index translation, or range assessment changes. Test-adding only.
---

# Range conformance check

Read `ARCHITECTURE.md` (PII semantics) and `CONVENTIONS.md` (Identity and
data). Coordinates are half-open UTF-8 byte ranges into the original input.
Adapters translate runtime indices exactly once; the kernel never sees
UTF-16 or code-point indices. If the kernel or adapters do not exist yet,
say which checks could not run.

## Vectors

Write expected values by hand from the byte layout, never by running the
code under test and copying its output. Each vector records input bytes,
the expected range, the reported range, and the expected state. Cover:

- each state: identical range, reported range containing the expected one,
  reported range inside it, disjoint, and a case where no range applies;
- boundaries: zero-length ranges, start == end, range at 0 and at input
  length, adjacent but non-overlapping ranges;
- invalid input: start > end, end > length, offsets inside a multi-byte
  character, negative or overflowing values. Byte-boundary validation is
  distinct from length bounds and each must have its own rejecting case;
- text shapes: Korean (3-byte), combining marks, emoji and surrogate pairs,
  CRLF, and non-ASCII prefixes that shift every later offset;
- adapter translation for each runtime (UTF-16 code units for Node,
  code points for Python): the same finding must land on the same bytes;
- no silent normalization: input that changes under NFC/NFD must be
  rejected as ambiguous or measured as given, never quietly rewritten.

Multiple overlaps, duplicates, and ordering are not decided by this skill.
Those belong to the selection-rule decision in `ARCHITECTURE.md`; if a
vector depends on it, mark it as blocked on that protocol decision rather
than choosing a rule.

Add property tests where practical (offset round-trip through adapters,
validation never panics on arbitrary bytes). Do not change an expected
result to match the implementation.
