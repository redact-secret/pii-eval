// node --test tools/isolation/test/lib.test.mjs
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ENV_ALLOWLIST } from '../bwrap-argv.mjs';
import { envNamesOutsideAllowlist, floorOf, parseAddressSpaceLimit, parseCapEff, parseVmLines, sanitize } from '../lib.mjs';
import { summaryMarkdown } from '../matrix.mjs';

describe('sanitize', () => {
  it('keeps printable ASCII, flattens whitespace, replaces everything else, caps', () => {
    assert.equal(sanitize('a\nb\tc\r\nd'), 'a b c d');
    assert.equal(sanitize('x\u001b[31mred\u0000é'), 'x?[31mred??');
    assert.equal(sanitize('y'.repeat(400), 10), 'yyyyyyyyyy...');
    assert.equal(sanitize(null), '');
  });
  it('cannot start a workflow command or contain a newline', () => {
    const s = sanitize('::error::injected\n::set-output name=x::y');
    assert.ok(!s.includes('\n'));
  });
});

describe('/proc parsers', () => {
  const limits = [
    'Limit                     Soft Limit           Hard Limit           Units',
    'Max cpu time              30                   30                   seconds',
    'Max address space         536870912            536870912            bytes',
    'Max processes             32                   32                   processes',
  ].join('\n');
  it('reads the address-space limit', () => {
    assert.deepEqual(parseAddressSpaceLimit(limits), { soft: 536870912, hard: 536870912 });
    assert.deepEqual(parseAddressSpaceLimit('Max address space unlimited unlimited bytes'), { soft: null, hard: null });
    assert.equal(parseAddressSpaceLimit('nothing here'), null);
    assert.equal(parseAddressSpaceLimit('Max address space  abc  def  bytes'), null);
  });
  it('reads the effective capability mask', () => {
    assert.equal(parseCapEff('Name:\tx\nCapEff:\t0000000000000000\nCapBnd:\t1\n'), '0000000000000000');
    assert.equal(parseCapEff('CapEff:\t000001ffffffffff'), '000001ffffffffff');
    assert.equal(parseCapEff('no caps'), null);
  });
  it('reads Vm lines', () => {
    assert.deepEqual(parseVmLines('VmPeak:\t 4096 kB\nVmSize: 100 kB\nVmRSS:\t7 kB\nVmHWM: 9 kB\nOther: 1 kB'), { VmPeak: 4096, VmSize: 100, VmRSS: 7, VmHWM: 9 });
  });
});

describe('floorOf', () => {
  const m = (pairs) => new Map(pairs);
  it('is the smallest size from which every larger size passes', () => {
    assert.deepEqual(floorOf([128, 256, 512, 1024], m([[128, false], [256, false], [512, true], [1024, true]])), { floor: 512, monotone: true });
  });
  it('does not count a lucky pass below a failure and reports the non-monotone series', () => {
    assert.deepEqual(floorOf([128, 256, 512, 1024], m([[128, false], [256, true], [512, false], [1024, true]])), { floor: 1024, monotone: false });
  });
  it('is null when nothing passes and the smallest size when everything does', () => {
    assert.deepEqual(floorOf([128, 256], m([[128, false], [256, false]])), { floor: null, monotone: true });
    assert.deepEqual(floorOf([128, 256], m([[128, true], [256, true]])), { floor: 128, monotone: true });
  });
  it('treats a missing result as failing', () => {
    assert.deepEqual(floorOf([128, 256], m([[256, true]])), { floor: 256, monotone: true });
  });
});

describe('environment check', () => {
  it('flags names outside the allowlist, ignoring shell artefacts', () => {
    assert.deepEqual(envNamesOutsideAllowlist('PATH=/usr/bin\nHOME=/scratch\nSHLVL=1\n_=/usr/bin/env\nLD_PRELOAD=x\nGITHUB_TOKEN=y', ENV_ALLOWLIST), ['LD_PRELOAD', 'GITHUB_TOKEN']);
    assert.deepEqual(envNamesOutsideAllowlist('PATH=/usr/bin\nPWD=/scratch', ENV_ALLOWLIST), []);
  });
});

describe('summary', () => {
  const b = (ok) => ({ ok, exitCode: ok ? 0 : 1, signal: null, timedOut: false });
  it('renders a table and the floors', () => {
    const md = summaryMarkdown({
      host: { kernel: 'Linux 6.8', bwrap: 'bubblewrap 0.9.0', node: { version: 'v22.0.0' } },
      replicaOf: { commit: '142db34dd4bc02903f47cba951a054351bb55fde' },
      controls: { pass: true },
      matrix: [{ memMiB: 256, limitApplied: true, nodeStart: b(false), nodeJitless: b(false), engineVersion: b(true), engineQuickstartRun: b(false), engineQuickstartRunNodeJitless: b(false) }, { memMiB: 1024, limitApplied: true, nodeStart: b(true), nodeJitless: b(true), engineVersion: b(true), engineQuickstartRun: b(true), engineQuickstartRunNodeJitless: b(true) }],
      floors: { nodeStartMiB: { floor: 1024 }, nodeJitlessMiB: { floor: 320 }, engineQuickstartRunMiB: { floor: 1024 }, engineQuickstartRunNodeJitlessMiB: { floor: 512 } },
      custodianNormalMemory: { memMiB: 512, nodeStarts: false, engineQuickstartRuns: false },
    });
    assert.match(md, /\| 256 MiB \| yes \| \*\*fail\*\* \(exit 1\) \|/);
    assert.match(md, /\| 1024 MiB \| yes \| ok \| ok \| ok \| ok \| ok \|/);
    assert.match(md, /node --jitless 512 MiB/);
    assert.match(md, /Floors .*node 1024 MiB/);
    assert.match(md, /142db34d/);
  });
});
