---
name: scan-secrets-in-history
description: Scan pii-eval's Git history for accidentally committed credentials, real personal data, protected corpus material, or unsanitized scanner output. Use before publication or when leakage is suspected. Report-only and never prints matched plaintext.
---

# Scan secrets and personal data in history

`SECURITY.md` requires a history scan before public release. Use a reputable
history-aware secret scanner with redaction enabled and record its version and
exact scope. Scan all history reachable from `HEAD` unless the user requests a
narrower range. Secret scanners do not find personal data well, so also search
paths and content shapes the policy forbids:

- protected population inputs, holdout/private plans, seeds, or case lists;
- custodian ledgers, budgets, signing keys, or storage credentials;
- raw scanner stdout/stderr, input snippets, or observation dumps containing
  input text;
- generated corpus or result artifacts that belong in ignored locations
  (see `.gitignore`);
- identifiers that look like real people, accounts, or national/government
  numbers outside documented synthetic or public-test material, including
  Korean-language fixtures.

Triage by path and commit. Synthetic fixtures or documented public test values
may be expected, but evaluator logs, result artifacts, adapter snapshots, CI
files, and documentation are not safe locations for matched material. Do not
infer safety from a patterned-looking value or a valid checksum; use
repository provenance. A fixture without recorded synthetic provenance is
`unclear`.

Report commit, path, rule ID, and disposition only: `verified synthetic/public
test`, `unclear`, `needs private rotation and history remediation`, or
`possible real personal data: escalate to a maintainer privately`.
Never print the match, even partially. Do not rewrite history, revoke a
credential, force-push, or open a public issue.
