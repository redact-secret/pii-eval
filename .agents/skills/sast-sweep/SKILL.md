---
name: sast-sweep
description: Run static analysis over pii-eval's Rust workspace and Node/Python scanner shims, focused on unsafe process execution, path handling, byte-range conversion, parser boundaries, resource exhaustion, and personal-data leakage. Report-only unless fixes are requested.
---

# SAST sweep

Read the architecture, conventions, and security policy, then inspect the
current manifests to select analyzers; do not assume a language or directory
that is not present. If there is no code yet, report that and stop. Use
maintained rules for the detected languages (for example Clippy with
security-relevant lints, Semgrep, `cargo geiger`/`cargo deny` for Rust;
equivalent linters for shims) and record analyzer versions.

Prioritize:

- shell invocation, argument injection, environment inheritance, and
  executable resolution in adapters and Node/Python shims;
- path traversal, symlink escape, unsafe temporary files, and archive
  extraction;
- UTF-8 byte-range handling: runtime-specific indices (UTF-16 code units,
  code points, grapheme clusters) converted to byte offsets, slicing that can
  panic off a char boundary, off-by-one on half-open ranges, silent input
  normalization;
- unchecked parsing, integer overflow or lossy casts in counters and
  offsets, `unwrap`/`expect`/indexing panics reachable from untrusted corpus,
  observation, or scanner output, and any `unsafe` in first-party crates
  (forbidden by `CONVENTIONS.md`);
- non-deterministic digest inputs: hashing map iteration order, locale-aware
  sorting, non-finite floats, negative zero, absent-versus-null handling, or
  timestamps inside semantic output;
- missing bounds on concurrency, pending tasks, file sizes, subprocess
  stdout/stderr, generated variants, and worker lifetime;
- input text, matched values, raw scanner output, seeds, case IDs, value
  hashes, or private paths reaching logs, errors, or public artifacts;
- digest or identity checks performed after use rather than before it;
- kernel purity: process spawning, network, or publication code inside
  `pii-eval-kernel` or `pii-eval-contracts`.

Triage every tool hit in context. Report severity, rule, file/line, data flow,
existing guard, and a recommended regression test (include Korean, combining
marks, emoji, CRLF, and non-ASCII-prefix cases for range logic). Do not report
a scanner's failure to detect a fixture as a SAST issue.
