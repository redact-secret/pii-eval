// node --test tools/ci/test/workflow-policy.test.mjs
// The committed workflows satisfy the policy, and the policy can fail.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkWorkflow } from '../workflow-policy.mjs';

const DIR = fileURLToPath(new URL('../../../.github/workflows/', import.meta.url));
const SHA = 'a'.repeat(40);
const ok = `name: t
on: workflow_dispatch
permissions:
  contents: read
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA} # v7
      - run: echo hi
`;

describe('committed workflows', () => {
  const files = readdirSync(DIR).filter((f) => f.endsWith('.yml'));
  it('exist (the policy is not vacuous)', () => {
    for (const expected of ['ci.yml', 'build-engine.yml', 'evaluate.yml']) assert.ok(files.includes(expected), expected);
  });
  for (const f of files) {
    it(`${f} satisfies the policy`, () => {
      assert.deepEqual(checkWorkflow(f, readFileSync(join(DIR, f), 'utf8')), []);
    });
  }
  it('evaluate.yml receives its inputs only through env', () => {
    const text = readFileSync(join(DIR, 'evaluate.yml'), 'utf8');
    assert.match(text, /env:\n\s+ENGINE_RUN_ID: \$\{\{ inputs\.engine-run-id \}\}/);
    assert.deepEqual(checkWorkflow('evaluate.yml', text), []);
  });
});

describe('the policy can fail', () => {
  it('accepts a clean workflow', () => {
    assert.deepEqual(checkWorkflow('t', ok), []);
  });
  it('accepts a local reusable workflow call', () => {
    assert.deepEqual(checkWorkflow('t', `${ok}  k:\n    uses: ./.github/workflows/build-engine.yml\n`), []);
  });
  it('flags an action pinned by tag or branch, or short sha', () => {
    for (const ref of ['actions/checkout@v4', 'actions/checkout@main', `actions/checkout@${'a'.repeat(39)}`, 'actions/checkout']) {
      const p = checkWorkflow('t', ok.replace(`actions/checkout@${SHA}`, ref));
      assert.equal(p.length, 1, ref);
      assert.match(p[0], /not pinned/);
    }
  });
  it('flags a missing top-level permissions key', () => {
    const p = checkWorkflow('t', ok.replace('permissions:\n  contents: read\n', ''));
    assert.match(p.join('\n'), /no top-level permissions/);
  });
  it('flags a job-level permissions key as not enough', () => {
    const p = checkWorkflow('t', ok.replace('permissions:\n  contents: read\n', '').replace('    runs-on', '    permissions: {}\n    runs-on'));
    assert.match(p.join('\n'), /no top-level permissions/);
  });
  it('flags pull_request_target and secrets: inherit', () => {
    assert.match(checkWorkflow('t', ok.replace('workflow_dispatch', 'pull_request_target')).join('\n'), /pull_request_target/);
    assert.match(checkWorkflow('t', `${ok}  k:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n`).join('\n'), /secrets: inherit/);
  });
  it('flags untrusted expressions inline in run', () => {
    for (const expr of ['inputs.x', 'github.event.pull_request.title', 'github.head_ref', 'github.ref_name', 'github.actor', 'steps.a.outputs.b', 'needs.j.outputs.o', 'matrix.v', 'secrets.S', 'vars.V']) {
      const p = checkWorkflow('t', ok.replace('echo hi', `echo \${{ ${expr} }}`));
      assert.match(p.join('\n'), /untrusted expression in run/, expr);
    }
  });
  it('flags untrusted expressions inside a run block', () => {
    const wf = ok.replace('      - run: echo hi\n', '      - name: x\n        run: |\n          echo start\n          echo "${{ github.event.pull_request.title }}"\n          echo end\n');
    assert.match(checkWorkflow('t', wf).join('\n'), /untrusted expression in run/);
    const wf2 = ok.replace('      - run: echo hi\n', '      - run: |\n          echo "${{ inputs.value }}"\n');
    assert.match(checkWorkflow('t', wf2).join('\n'), /untrusted expression in run/);
  });
  it('allows safe expressions in a run block and any expression outside run', () => {
    const wf = ok.replace(
      '      - run: echo hi\n',
      '      - run: |\n          echo "${{ runner.temp }} ${{ github.sha }}"\n      - uses: actions/upload-artifact@' + SHA + '\n        with:\n          name: x-${{ github.run_id }}\n          path: ${{ steps.a.outputs.p }}\n',
    );
    assert.deepEqual(checkWorkflow('t', wf), []);
  });
  it('stops treating lines as script once the run block ends', () => {
    const wf = ok.replace(
      '      - run: echo hi\n',
      '      - name: a\n        run: |\n          echo one\n        env:\n          X: ${{ inputs.x }}\n',
    );
    assert.deepEqual(checkWorkflow('t', wf), []);
  });
});

describe('stricter rules', () => {
  const body = (inner) => ok.replace('      - run: echo hi\n', inner);
  it('flags untrusted data wrapped in a function or an operator inside run', () => {
    for (const expr of ["format('{0}', inputs.x)", 'toJSON(inputs)', '!inputs.x', "contains(github.event.pull_request.title, 'x')", "fromJSON(steps.a.outputs.j).k", 'github.event.comment.body || github.sha']) {
      const p = checkWorkflow('t', body(`      - run: echo \${{ ${expr} }}\n`));
      assert.match(p.join('\n'), /untrusted expression in run/, expr);
    }
  });
  it('flags an expression that spans lines inside a run block', () => {
    const wf = body('      - run: |\n          echo "${{ format(\n            inputs.x) }}"\n');
    assert.match(checkWorkflow('t', wf).join('\n'), /expression spans lines/);
  });
  it('flags write permissions at any level, in block and inline form', () => {
    assert.match(checkWorkflow('t', ok.replace('contents: read', 'contents: write')).join('\n'), /write permission/);
    assert.match(checkWorkflow('t', ok.replace('permissions:\n  contents: read', 'permissions: write-all')).join('\n'), /write permission/);
    const job = ok.replace('    runs-on: ubuntu-latest', '    permissions:\n      checks: write\n    runs-on: ubuntu-latest');
    assert.match(checkWorkflow('t', job).join('\n'), /write permission/);
    const inline = ok.replace('    runs-on: ubuntu-latest', '    permissions: { contents: write }\n    runs-on: ubuntu-latest');
    assert.match(checkWorkflow('t', inline).join('\n'), /write permission/);
  });
  it('allows read permissions at job level', () => {
    const job = ok.replace('    runs-on: ubuntu-latest', '    permissions:\n      actions: read\n      contents: read\n    runs-on: ubuntu-latest');
    assert.deepEqual(checkWorkflow('t', job), []);
  });
  it('flags github-script and flow-style uses', () => {
    assert.match(checkWorkflow('t', body(`      - uses: actions/github-script@${SHA}\n`)).join('\n'), /github-script/);
    assert.match(checkWorkflow('t', body('      - { uses: actions/checkout@v4 }\n')).join('\n'), /flow-style uses|not pinned/);
  });
  it('flags a script that writes GITHUB_ENV or GITHUB_PATH', () => {
    assert.match(checkWorkflow('t', body('      - run: echo "X=1" >> "$GITHUB_ENV"\n')).join('\n'), /GITHUB_ENV/);
    assert.match(checkWorkflow('t', body('      - run: |\n          echo /x >> "$GITHUB_PATH"\n')).join('\n'), /GITHUB_ENV or GITHUB_PATH/);
  });
  it('flags tee and bare-variable writes too, but not a mere mention', () => {
    assert.match(checkWorkflow('t', body('      - run: echo X=1 | tee -a "$GITHUB_ENV"\n')).join('\n'), /GITHUB_ENV or GITHUB_PATH/);
    assert.match(checkWorkflow('t', body('      - run: echo X=1 >> $GITHUB_ENV\n')).join('\n'), /GITHUB_ENV or GITHUB_PATH/);
    assert.match(checkWorkflow('t', body('      - run: echo X=1 >> ${GITHUB_PATH}\n')).join('\n'), /GITHUB_ENV or GITHUB_PATH/);
    assert.deepEqual(checkWorkflow('t', body('      - run: |\n          # GITHUB_ENV is unset for the child\n          env -u GITHUB_ENV -u GITHUB_PATH true\n')), []);
  });
  it('still allows GITHUB_OUTPUT and GITHUB_STEP_SUMMARY', () => {
    assert.deepEqual(checkWorkflow('t', body('      - run: |\n          echo "a=b" >> "$GITHUB_OUTPUT"\n          echo x >> "$GITHUB_STEP_SUMMARY"\n')), []);
  });
});
