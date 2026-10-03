// Tests of the performance tooling's pure parts (P10, ADR 0013): `node --test tools/perf/test/`.
// No process is measured here and no timing is asserted; this is a CI-safe check that the generator is
// deterministic and that the report parsers and statistics do what the documentation says.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { median, parseTimeOutput, summarize, timedArgv } from '../lib.mjs';
import { buildInput, normalize, render } from '../make-workload.mjs';

const BSD = `        4.85 real         3.29 user         1.14 sys
           221151232  maximum resident set size
                   0  average shared memory size
               15833  page reclaims
               63398  involuntary context switches
         28314316946  instructions retired
         10626829764  cycles elapsed
           197901648  peak memory footprint
`;
const GNU = `\tCommand being timed: "x"
\tUser time (seconds): 3.29
\tSystem time (seconds): 1.14
\tElapsed (wall clock) time (h:mm:ss or m:ss): 1:04.85
\tMaximum resident set size (kbytes): 215968
\tMinor (reclaiming a frame) page faults: 15833
\tInvoluntary context switches: 63398
`;

test('the BSD report is parsed in bytes', () => {
  const u = parseTimeOutput(`child stderr line\n${BSD}`);
  assert.equal(u.format, 'bsd-l');
  assert.equal(u.wallS, 4.85);
  assert.equal(u.userS, 3.29);
  assert.equal(u.sysS, 1.14);
  assert.equal(u.maxRssBytes, 221151232);
  assert.equal(u.peakFootprintBytes, 197901648);
  assert.equal(u.instructions, 28314316946);
});

test('the GNU report is parsed and converted to bytes and seconds', () => {
  const u = parseTimeOutput(GNU);
  assert.equal(u.format, 'gnu-v');
  assert.equal(u.wallS, 64.85);
  assert.equal(u.maxRssBytes, 215968 * 1024);
  assert.equal(u.peakFootprintBytes, null);
});

test('an unrecognised report is null, never a guess', () => {
  assert.equal(parseTimeOutput('nothing here'), null);
  assert.deepEqual(timedArgv(['x'], 'darwin').slice(0, 2), ['/usr/bin/time', '-l']);
  assert.deepEqual(timedArgv(['x'], 'linux').slice(0, 2), ['/usr/bin/time', '-v']);
});

test('median and MAD', () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 2, 3]), 2.5);
  assert.deepEqual(summarize([1, 2, 3, 4, 100]), { n: 5, median: 3, mad: 1, min: 1, max: 100 });
  assert.deepEqual(summarize([]), { n: 0 });
  assert.deepEqual(summarize([null, undefined, NaN]), { n: 0 });
});

test('a workload is determined by its parameters alone', () => {
  const params = { id: 'det', cases: 25, koShare: 40, scanners: 3, findings: 4, padBytes: 16 };
  const a = render(params);
  const b = render({ ...params });
  assert.equal(a.text, b.text);
  assert.equal(a.digest, b.digest);
  assert.notEqual(render({ ...params, findings: 5 }).digest, a.digest);
  const input = buildInput(params);
  assert.equal(input.cases.length, 25);
  assert.equal(input.scanners.length, 3);
  // Korean and English both occur at koShare 40, and the two fixed context groups come first.
  assert.ok(input.cases.some((c) => c.language === 'ko') && input.cases.some((c) => c.language === 'en'));
  assert.deepEqual(input.cases.slice(0, 2).map((c) => c.id), ['en-email-core', 'ko-email-core']);
  // The recipe holds `findings` findings per behaviour (the behaviour's own plus noise) for the non-miss behaviours.
  assert.ok(input.scanners[0].recipe.all.cycle.some((list) => list.length === 4));
  // Only ASCII is written (non-ASCII is escaped), so the digest does not depend on a file encoding.
  assert.ok(/^[\x00-\x7f]*$/.test(a.text));
});

test('parameters are validated before anything is generated', () => {
  assert.throws(() => normalize({ id: 'x', cases: 0 }), /out of range/);
  assert.throws(() => normalize({ id: 'x', cases: 1.5 }), /out of range/);
  assert.throws(() => normalize({ id: 'x', bogus: 1 }), /unknown parameter/);
  assert.throws(() => normalize({ id: 'bad id' }), /id must be/);
  assert.throws(() => normalize({ id: 'x', cases: 10 ** 9 }), /out of range/);
});
