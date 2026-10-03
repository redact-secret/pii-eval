// node --test tools/isolation/test/worker-e2e.test.mjs
// The pure parts of tools/isolation/worker-e2e.mjs: the expectation table, the report shape,
// the identity check and the parsing of the engine's fixed-vocabulary output. No sandbox here.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildArgv } from '../bwrap-argv.mjs';
import {
  SCENARIOS,
  SUCCESS_FROM_MIB,
  aggregatesOf,
  checkExpectation,
  engineReasonOf,
  expectationFor,
  identityMismatches,
  makeWorkerRunner,
  quotasFor,
  reportRow,
  runPlan,
  summaryMarkdown,
  sweepPlan,
  terminationArg,
} from '../worker-e2e.mjs';

const success = { ran: true, outcome: 'Success', reason: 'completed', roster: { expected: 3, observed: 3, failed: 0 }, aggregatesOk: true, stdoutBytes: 190, exitCode: 0, engineReason: null };

describe('the expectation table', () => {
  it('covers every scenario of the example and every run plan entry', () => {
    for (const s of SCENARIOS) assert.doesNotThrow(() => expectationFor(s, 1024), s);
    assert.throws(() => expectationFor('nope', 1024));
    assert.deepEqual([...new Set(runPlan().map((p) => p.scenario))].sort(), [...SCENARIOS].sort());
    assert.equal(new Set(runPlan().map((p) => `${p.scenario}@${p.memMiB}`)).size, runPlan().length);
  });

  it('expects Success from the measured boundary and never below it', () => {
    assert.deepEqual(expectationFor('normal', SUCCESS_FROM_MIB).outcomes, ['Success']);
    assert.deepEqual(expectationFor('normal', 1536).outcomes, ['Success']);
    const low = expectationFor('normal', 512);
    assert.equal(low.notSuccess, true);
    assert.ok(!low.outcomes.includes('Success'));
    // The 512 MiB run is part of the plan: the Q7 conflict is reproduced end to end, never papered over.
    assert.ok(runPlan().some((p) => p.scenario === 'normal' && p.memMiB === 512));
  });

  it('maps each refusal to the custodian outcome and the engine reason', () => {
    for (const [s, reason] of [
      ['population-mismatch', 'population-binding-mismatch'],
      ['run-class-mismatch', 'run-class-mismatch'],
      ['wrong-bundle-digest', 'candidate-bundle-digest-mismatch'],
      ['wrong-tree-digest', 'package-tree-digest-mismatch'],
      ['wrong-runtime-digest', 'runtime-digest-mismatch'],
      ['stale-job', 'entries-listing-mismatch'],
    ]) {
      const e = expectationFor(s, 1024);
      assert.deepEqual([e.outcomes, e.reasons, e.engineReason, e.stdoutEmpty, e.nonZeroExit], [['Failed'], ['non_zero_exit'], reason, true, true], s);
    }
    assert.deepEqual(expectationFor('scanner-crash', 1024).outcomes, ['Partial']);
    assert.deepEqual(expectationFor('scanner-hang', 1024).reasons, ['timeout']);
    assert.deepEqual([expectationFor('staged-file-tampered', 1024).ran, expectationFor('staged-file-tampered', 1024).outcomes], [false, ['Rejected']]);
  });

  it('never loosens a quota: only the hang scenario shortens the wall clock', () => {
    for (const s of SCENARIOS) {
      const q = quotasFor(s);
      assert.ok(Object.keys(q).every((k) => k === 'wallMs'), s);
      if (q.wallMs !== undefined) assert.ok(q.wallMs < 20000, s);
    }
  });

  it('plans the population sweep at two sizes of memory', () => {
    const p = sweepPlan();
    assert.deepEqual([...new Set(p.map((x) => x.entries))], [20, 100, 400]);
    assert.deepEqual([...new Set(p.map((x) => x.memMiB))], [1024, 1536]);
  });
});

describe('checkExpectation', () => {
  it('accepts the expected success and reports each way it can be violated', () => {
    const e = expectationFor('normal', 1024);
    assert.deepEqual(checkExpectation(e, success), []);
    assert.ok(checkExpectation(e, { ...success, outcome: 'Partial', reason: 'engine_partial' }).length >= 2);
    assert.ok(checkExpectation(e, { ...success, aggregatesOk: false }).some((v) => v.includes('aggregatesOk')));
    assert.ok(checkExpectation(e, { ...success, roster: { expected: 3, observed: 3, failed: 1 } }).some((v) => v.includes('roster')));
    assert.ok(checkExpectation(e, { ...success, ran: false }).some((v) => v.includes('ran')));
  });

  it('a success below the boundary is a violation, a failure is not', () => {
    const e = expectationFor('normal', 512);
    assert.ok(checkExpectation(e, success).some((v) => v.includes('succeeded below')));
    const failed = { ran: true, outcome: 'Partial', reason: 'engine_partial', roster: { expected: 3, observed: 3, failed: 3 }, aggregatesOk: false, stdoutBytes: 190, exitCode: 0 };
    assert.deepEqual(checkExpectation(e, failed), []);
    assert.deepEqual(checkExpectation(e, { ...failed, outcome: 'Failed', reason: 'signaled', roster: null }), []);
  });

  it('a refusal must print nothing, exit non-zero and name the engine reason', () => {
    const e = expectationFor('wrong-tree-digest', 1024);
    const ok = { ran: true, outcome: 'Failed', reason: 'non_zero_exit', roster: null, aggregatesOk: false, stdoutBytes: 0, exitCode: 4, engineReason: 'package-tree-digest-mismatch' };
    assert.deepEqual(checkExpectation(e, ok), []);
    assert.ok(checkExpectation(e, { ...ok, stdoutBytes: 10 }).length > 0);
    assert.ok(checkExpectation(e, { ...ok, exitCode: 0 }).length > 0);
    assert.ok(checkExpectation(e, { ...ok, engineReason: 'population-binding-mismatch' }).length > 0);
  });
});

describe('termination, identity and output parsing', () => {
  it('maps how the worker ended to the validator argument', () => {
    assert.equal(terminationArg({ exitCode: 0 }), '0');
    assert.equal(terminationArg({ exitCode: 4 }), '4');
    assert.equal(terminationArg({ signal: 'SIGKILL', exitCode: null }), 'signal:SIGKILL');
    assert.equal(terminationArg({ timedOut: true, signal: 'SIGKILL' }), 'timeout');
    assert.equal(terminationArg({ outputLimit: true, exitCode: 0 }), 'output-limit');
    assert.equal(terminationArg({ signal: 'bad value', exitCode: null }), 'signal:UNKNOWN');
  });

  it('finds exactly the staged files that no longer hash to their pin', () => {
    const pins = { engine: 'sha256:a', config: 'sha256:b', 'scanner-0': 'sha256:c' };
    const files = { engine: 'sha256:a', config: 'sha256:b', 'scanner-0': 'sha256:c' };
    assert.deepEqual(identityMismatches(pins, (n) => files[n]), []);
    assert.deepEqual(identityMismatches(pins, (n) => (n === 'config' ? 'sha256:x' : files[n])), ['config']);
    assert.deepEqual(identityMismatches(pins, (n) => (n === 'engine' ? null : files[n])), ['engine']);
  });

  it('reads the engine reason and the aggregates line, and nothing else', () => {
    assert.equal(engineReasonOf('pii-eval: population-binding-mismatch (provenance-mismatch, exit 4): snapshot\n'), 'population-binding-mismatch');
    assert.equal(engineReasonOf('garbage'), null);
    assert.equal(aggregatesOf('pii-eval-worker-e2e-aggregates {"a":1}\n'), '{"a":1}');
    assert.equal(aggregatesOf('pii-eval-worker-e2e-aggregates {}\npii-eval-worker-e2e-aggregates {}\n'), null);
    assert.equal(aggregatesOf(''), null);
  });
});

describe('the sandbox runner and the report', () => {
  it('builds the dispatcher vector: three read-only mounts, four variables, the memory under test', () => {
    const roots = [{ bind: '/usr' }];
    const argv = buildArgv(
      {
        program: '/stage/engine',
        args: ['--job', '/job/job.json'],
        roMounts: [
          { host: '/w/stage', inner: '/stage' },
          { host: '/w/input', inner: '/input' },
          { host: '/w/job', inner: '/job' },
        ],
        env: [['PATH', '/usr/bin:/bin'], ['HOME', '/scratch'], ['TMPDIR', '/scratch'], ['LANG', 'C']],
        quotas: { cpuSeconds: 30, wallMs: 20000, storageBytes: 64 << 20, maxProcesses: 32, stdoutBytes: 65536, stderrBytes: 1 << 20, memoryBytes: 1024 << 20 },
      },
      roots,
    );
    const text = argv.join(' ');
    for (const m of ['/w/stage /stage', '/w/input /input', '/w/job /job']) assert.ok(text.includes(`--ro-bind ${m}`), m);
    assert.ok(text.endsWith('-- /stage/engine --job /job/job.json'));
    assert.ok(text.includes(`--as=${1024 << 20}`));
    assert.equal(argv.filter((x) => x === '--setenv').length, 4);
    assert.equal(typeof makeWorkerRunner, 'function');
  });

  it('has a stable report row and summary with no free text', () => {
    const exp = expectationFor('normal', 1024);
    const row = reportRow({ scenario: 'normal', memMiB: 1024, entries: 3, quotas: { wallMs: 20000 }, observed: success, expectation: exp, violations: [] });
    assert.deepEqual(Object.keys(row).sort(), ['custodian', 'elapsedMs', 'engineReason', 'entries', 'expected', 'memMiB', 'quotas', 'ran', 'scenario', 'stdoutBytes', 'termination', 'violations']);
    assert.deepEqual(Object.keys(row.custodian).sort(), ['aggregatesOk', 'outcome', 'reason', 'roster']);
    const sweep = reportRow({ scenario: 'normal', memMiB: 1024, entries: 20, quotas: {}, observed: success, expectation: null, violations: [], sweep: true });
    assert.equal(sweep.sweep, true);
    assert.ok(!('violations' in sweep));
    const md = summaryMarkdown({
      replicaOf: { commit: '142db34dd4bc02903f47cba951a054351bb55fde' },
      host: { kernel: 'Linux 6', bwrap: 'bubblewrap 0.9', node: { version: 'v22' } },
      controls: { pass: true },
      violations: [],
      runs: [row],
      sweep: [sweep],
    });
    assert.ok(md.includes('| normal | 1024 MiB | 3 | Success (completed)'));
    assert.ok(md.includes('Population sweep'));
  });
});
