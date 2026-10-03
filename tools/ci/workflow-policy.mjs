#!/usr/bin/env node
// Line-based policy check for GitHub Actions workflows (docs/ci-artifacts.md).
// Standard library only. It is a tripwire for the mistakes that matter here, not
// a YAML parser: every rule is a conservative text rule.
//
//   node tools/ci/workflow-policy.mjs .github/workflows/*.yml
//
// Rules:
//   1. every `uses:` is a local reusable workflow (`./.github/workflows/...`) or
//      `owner/repo[/path]@<40 hex>` (pinned by full commit SHA);
//   2. a top-level `permissions:` key exists (least privilege is explicit);
//   3. no `pull_request_target` trigger and no `secrets: inherit`;
//   4. no untrusted or step-derived expression inside a `run:` script: values
//      such as inputs, event fields, refs, actors, step and job outputs reach a
//      script only through `env:`.
import { readFileSync } from 'node:fs';

const FORBIDDEN_IN_RUN =
  /\$\{\{\s*(inputs\.|github\.event|github\.head_ref|github\.base_ref|github\.ref|github\.actor|github\.triggering_actor|steps\.|needs\.|matrix\.|vars\.|secrets\.)/;

export function checkWorkflow(name, text) {
  const problems = [];
  const lines = text.split('\n');
  if (!/^permissions:/m.test(text)) problems.push(`${name}: no top-level permissions`);
  if (/pull_request_target/.test(text)) problems.push(`${name}: pull_request_target is not allowed`);
  if (/secrets:\s*inherit/.test(text)) problems.push(`${name}: secrets: inherit is not allowed`);
  let runIndent = -1;
  lines.forEach((raw, i) => {
    const n = i + 1;
    const line = raw.replace(/\s+#.*$/, '');
    const uses = /^\s*(?:-\s*)?uses:\s*(\S+)/.exec(line);
    if (uses) {
      const ref = uses[1];
      const local = ref.startsWith('./.github/workflows/');
      const pinned = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._\/-]+@[0-9a-f]{40}$/.test(ref);
      if (!local && !pinned) problems.push(`${name}:${n}: uses ${ref} is not pinned by full commit SHA`);
    }
    const indent = raw.length - raw.trimStart().length;
    const run = /^(\s*)(?:-\s*)?run:\s*(.*)$/.exec(raw);
    if (run) {
      const inline = run[2].replace(/\s+#.*$/, '');
      const keyIndent = run[1].length + (/^\s*-\s*run:/.test(raw) ? 2 : 0);
      if (/^[|>][-+]?\s*$/.test(inline)) {
        runIndent = keyIndent;
      } else {
        runIndent = -1;
        if (FORBIDDEN_IN_RUN.test(inline)) problems.push(`${name}:${n}: untrusted expression in run`);
      }
      return;
    }
    if (runIndent >= 0) {
      if (raw.trim() === '') return;
      if (indent > runIndent) {
        if (FORBIDDEN_IN_RUN.test(raw)) problems.push(`${name}:${n}: untrusted expression in run`);
        return;
      }
      runIndent = -1;
    }
  });
  return problems;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const files = process.argv.slice(2);
  if (files.length === 0) {
    process.stderr.write('usage: workflow-policy.mjs FILE...\n');
    process.exit(2);
  }
  const problems = files.flatMap((f) => checkWorkflow(f, readFileSync(f, 'utf8')));
  for (const p of problems) process.stderr.write(`${p}\n`);
  process.stdout.write(`${JSON.stringify({ ok: problems.length === 0, files: files.length, problems: problems.length })}\n`);
  process.exit(problems.length === 0 ? 0 : 1);
}
