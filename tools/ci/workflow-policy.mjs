#!/usr/bin/env node
// Line-based policy check for GitHub Actions workflows (docs/ci-artifacts.md).
// Standard library only. It is a tripwire for the mistakes that matter here, not
// a YAML parser: every rule is a conservative text rule, and a workflow it cannot
// read with these rules should be rewritten, not exempted.
//
//   node tools/ci/workflow-policy.mjs .github/workflows/*.yml
//
// Rules:
//   1. every `uses:` is a local reusable workflow (`./.github/workflows/...`) or
//      `owner/repo[/path]@<40 hex>` (pinned by full commit SHA); flow-style
//      `{ uses: ... }` and `actions/github-script` are not allowed;
//   2. a top-level `permissions:` key exists, and no `permissions` block anywhere
//      grants `write` or `write-all` (read-only workflows: a job that needs more
//      is a reviewed change to this rule);
//   3. no `pull_request_target` trigger and no `secrets: inherit`;
//   4. inside a `run:` script no `${{ ... }}` expression mentions untrusted or
//      step-derived data (inputs, event fields, refs, actors, step and job
//      outputs, matrix, vars, secrets, toJSON), whatever function wraps it, and no
//      expression spans lines; such values reach a script only through `env:`;
//   5. a `run:` script does not write GITHUB_ENV or GITHUB_PATH.
import { readFileSync } from 'node:fs';
import { isMain } from './main-guard.mjs';

const FORBIDDEN_TOKEN =
  /\binputs\b|github\.event|github\.head_ref|github\.base_ref|github\.ref|github\.actor|github\.triggering_actor|\bsteps\b|\bneeds\b|\bmatrix\b|\bvars\b|\bsecrets\b|toJSON\s*\(/i;

function expressionProblems(line) {
  const out = [];
  let from = 0;
  for (;;) {
    const open = line.indexOf('${{', from);
    if (open < 0) break;
    const close = line.indexOf('}}', open);
    if (close < 0) {
      out.push('expression spans lines');
      break;
    }
    if (FORBIDDEN_TOKEN.test(line.slice(open + 3, close))) out.push('untrusted expression in run');
    from = close + 2;
  }
  return out;
}

export function checkWorkflow(name, text) {
  const problems = [];
  const lines = text.split('\n');
  if (!/^permissions:/m.test(text)) problems.push(`${name}: no top-level permissions`);
  if (/pull_request_target/.test(text)) problems.push(`${name}: pull_request_target is not allowed`);
  if (/secrets:\s*inherit/.test(text)) problems.push(`${name}: secrets: inherit is not allowed`);
  let scriptIndent = -1;
  let permIndent = -1;
  lines.forEach((raw, i) => {
    const n = i + 1;
    const line = raw.replace(/\s+#.*$/, '');
    const indent = raw.length - raw.trimStart().length;

    // permissions blocks, at any level
    if (permIndent >= 0) {
      if (raw.trim() === '') return;
      if (indent > permIndent) {
        if (/:\s*write\b/.test(line)) problems.push(`${name}:${n}: write permission`);
        return;
      }
      permIndent = -1;
    }
    const perm = /^(\s*)permissions:\s*(.*)$/.exec(line);
    if (perm) {
      const inline = perm[2].trim();
      if (/\bwrite(-all)?\b/.test(inline)) problems.push(`${name}:${n}: write permission`);
      if (inline === '') permIndent = perm[1].length;
      return;
    }

    // uses
    if (/\{\s*uses:/.test(line)) problems.push(`${name}:${n}: flow-style uses is not allowed`);
    const uses = /^\s*(?:-\s*)?uses:\s*(\S+)/.exec(line);
    if (uses) {
      const ref = uses[1];
      const local = ref.startsWith('./.github/workflows/');
      const pinned = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._\/-]+@[0-9a-f]{40}$/.test(ref);
      if (!local && !pinned) problems.push(`${name}:${n}: uses ${ref} is not pinned by full commit SHA`);
      if (/^actions\/github-script@/.test(ref)) problems.push(`${name}:${n}: actions/github-script is not allowed`);
    }

    // run / script blocks
    const key = /^(\s*)(?:-\s*)?(run|script):\s*(.*)$/.exec(raw);
    if (key) {
      const inline = key[3].replace(/\s+#.*$/, '');
      const keyIndent = key[1].length + (/^\s*-\s*(run|script):/.test(raw) ? 2 : 0);
      if (/^[|>][-+]?\s*$/.test(inline)) {
        scriptIndent = keyIndent;
      } else {
        scriptIndent = -1;
        for (const p of expressionProblems(inline)) problems.push(`${name}:${n}: ${p}`);
        if (/GITHUB_(ENV|PATH)\b/.test(inline)) problems.push(`${name}:${n}: script writes GITHUB_ENV or GITHUB_PATH`);
      }
      return;
    }
    if (scriptIndent >= 0) {
      if (raw.trim() === '') return;
      if (indent > scriptIndent) {
        for (const p of expressionProblems(raw)) problems.push(`${name}:${n}: ${p}`);
        if (/GITHUB_(ENV|PATH)\b/.test(raw)) problems.push(`${name}:${n}: script writes GITHUB_ENV or GITHUB_PATH`);
        return;
      }
      scriptIndent = -1;
    }
  });
  return problems;
}

if (isMain(import.meta.url)) {
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
