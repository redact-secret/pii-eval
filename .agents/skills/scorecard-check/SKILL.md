---
name: scorecard-check
description: Run OpenSSF Scorecard for redact-secret/pii-eval and translate low scores into repository-specific supply-chain actions. Use for supply-chain posture reviews. Report-only.
---

# Scorecard check

Run Scorecard against `github.com/redact-secret/pii-eval` with the required
authentication. Record Scorecard version, date, repository revision, and
whether the repository is public enough for each check to be meaningful. The
repository starts private and has no release yet, so many checks may be
`not applicable` rather than failing; say which.

For every below-target result, inspect the actual repository evidence. Focus on
pinned CI actions, least-privilege workflow permissions, branch protection,
review requirements, dependency update practice (Cargo plus Node/Python shim
locks), SAST, fuzzing for the parsers and UTF-8 range logic, release
provenance, signed artifacts, and maintained status. Also check the
pre-publication items in `SECURITY.md`: private vulnerability reporting
configured, `LICENSE` chosen, and history/assets/logs scanned.

Distinguish controls that are not yet applicable because the repository has no
release or workflow from actual failures. Route dependency findings to
`dependency-audit`, code-analysis gaps to `sast-sweep`, history/leak concerns
to `scan-secrets-in-history`, and executable security hypotheses to
`vulnerability-test`.

Do not change settings or fabricate scores when the tool or access is missing.
