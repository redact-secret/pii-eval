// node --test tools/ci/test/ci-tools.test.mjs
// Build information and engine-artifact verification (docs/ci-artifacts.md).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build, stable } from '../build-info.mjs';
import { verify } from '../verify-engine.mjs';

const TOOLS = fileURLToPath(new URL('..', import.meta.url));
const COMMIT = 'a'.repeat(40);
const made = [];
const tmp = (prefix) => {
  const d = mkdtempSync(join(tmpdir(), `pii-eval-ci-${prefix}-`));
  made.push(d);
  return d;
};
after(() => made.forEach((d) => rmSync(d, { recursive: true, force: true })));

const sha = (b) => createHash('sha256').update(b).digest('hex');
const fakeBinary = (version) => `#!/bin/sh\necho "${version}"\n`;

function inputs(dir, extra = {}) {
  return {
    dir,
    target: 'linux-x86_64',
    repository: 'redact-secret/pii-eval',
    commit: COMMIT,
    ref: 'refs/heads/main',
    'run-id': '123456789',
    'run-attempt': '1',
    'rustc-version': 'rustc 1.98.1 (test)',
    ...extra,
  };
}

function makeDist(version = 'pii-eval 0.0.0 (bootstrap)') {
  const root = tmp('root');
  writeFileSync(join(root, 'Cargo.lock'), '# lock\n');
  writeFileSync(join(root, 'rust-toolchain.toml'), '[toolchain]\nchannel = "1.98.1"\n');
  const dir = tmp('dist');
  writeFileSync(join(dir, 'pii-eval'), fakeBinary(version));
  chmodSync(join(dir, 'pii-eval'), 0o755);
  const info = build({ ...inputs(dir), root });
  return { root, dir, info };
}

function resum(dir) {
  const rows = ['build-info.json', 'pii-eval']
    .map((n) => `${sha(readFileSync(join(dir, n)))}  ${n}\n`)
    .join('');
  writeFileSync(join(dir, 'SHA256SUMS'), rows);
}

const reason = (fn) => {
  try {
    fn();
  } catch (e) {
    return e.code ?? e.message;
  }
  return 'no-failure';
};

describe('build-info', () => {
  it('writes build-info.json and SHA256SUMS that verify, with and without execution', () => {
    const { dir, info } = makeDist();
    assert.equal(info.binary.sha256, sha(readFileSync(join(dir, 'pii-eval'))));
    assert.equal(verify({ dir, commit: COMMIT, repository: 'redact-secret/pii-eval', target: 'linux-x86_64' }).commit, COMMIT);
    assert.equal(verify({ dir, 'make-executable': true }).binary.version, 'pii-eval 0.0.0 (bootstrap)');
  });

  it('is a pure function of its inputs (no timestamps)', () => {
    const a = makeDist();
    const b = makeDist();
    assert.equal(readFileSync(join(a.dir, 'build-info.json'), 'utf8'), readFileSync(join(b.dir, 'build-info.json'), 'utf8'));
    assert.equal(readFileSync(join(a.dir, 'SHA256SUMS'), 'utf8'), readFileSync(join(b.dir, 'SHA256SUMS'), 'utf8'));
  });

  it('writes sorted two-space sums that sha256sum-style tools accept', () => {
    const { dir } = makeDist();
    const lines = readFileSync(join(dir, 'SHA256SUMS'), 'utf8').trimEnd().split('\n');
    assert.equal(lines.length, 2);
    assert.match(lines[0], /^[0-9a-f]{64} {2}build-info\.json$/);
    assert.match(lines[1], /^[0-9a-f]{64} {2}pii-eval$/);
  });

  it('serializes with sorted keys', () => {
    assert.equal(stable({ b: 1, a: { d: 1, c: 2 } }), '{\n  "a": {\n    "c": 2,\n    "d": 1\n  },\n  "b": 1\n}\n');
  });

  it('rejects malformed inputs', () => {
    const { dir, root } = makeDist();
    for (const bad of [
      { commit: 'abc' },
      { commit: 'A'.repeat(40) },
      { target: 'windows-x86_64' },
      { repository: 'no-slash' },
      { repository: 'a/b/c' },
      { ref: 'has space' },
      { 'run-id': 'x1' },
      { 'run-attempt': '12345' },
    ]) {
      assert.throws(() => build({ ...inputs(dir, bad), root }), undefined, JSON.stringify(bad));
    }
  });
});

describe('verify-engine', () => {
  it('rejects a changed binary', () => {
    const { dir } = makeDist();
    writeFileSync(join(dir, 'pii-eval'), fakeBinary('pii-eval 9.9.9'));
    assert.equal(reason(() => verify({ dir })), 'sums-mismatch');
  });

  it('rejects a changed build-info.json whose sums were not updated', () => {
    const { dir } = makeDist();
    const p = join(dir, 'build-info.json');
    writeFileSync(p, readFileSync(p, 'utf8').replace(COMMIT, 'b'.repeat(40)));
    assert.equal(reason(() => verify({ dir })), 'sums-mismatch');
  });

  it('rejects consistent sums over a build-info that disagrees with the binary', () => {
    const { dir } = makeDist();
    const p = join(dir, 'build-info.json');
    const info = JSON.parse(readFileSync(p, 'utf8'));
    info.binary.sha256 = '0'.repeat(64);
    writeFileSync(p, stable(info));
    resum(dir);
    assert.equal(reason(() => verify({ dir })), 'binary-mismatch');
    info.binary.sha256 = sha(readFileSync(join(dir, 'pii-eval')));
    info.binary.bytes += 1;
    writeFileSync(p, stable(info));
    resum(dir);
    assert.equal(reason(() => verify({ dir })), 'binary-mismatch');
  });

  it('rejects unexpected, missing and non-regular files', () => {
    const a = makeDist();
    writeFileSync(join(a.dir, 'extra.txt'), 'x');
    assert.equal(reason(() => verify({ dir: a.dir })), 'unexpected-file');
    const b = makeDist();
    unlinkSync(join(b.dir, 'SHA256SUMS'));
    assert.equal(reason(() => verify({ dir: b.dir })), 'missing-file');
    const c = makeDist();
    const target = join(tmp('elsewhere'), 'real');
    writeFileSync(target, fakeBinary('pii-eval 0.0.0 (bootstrap)'));
    unlinkSync(join(c.dir, 'pii-eval'));
    symlinkSync(target, join(c.dir, 'pii-eval'));
    assert.equal(reason(() => verify({ dir: c.dir })), 'not-regular-file');
    assert.equal(reason(() => verify({ dir: join(c.dir, 'nope') })), 'dir-unreadable');
  });

  it('enforces the expectations it is given', () => {
    const { dir } = makeDist();
    assert.equal(reason(() => verify({ dir, commit: 'c'.repeat(40) })), 'commit-mismatch');
    assert.equal(reason(() => verify({ dir, repository: 'other/repo' })), 'repository-mismatch');
    assert.equal(reason(() => verify({ dir, target: 'macos-arm64' })), 'target-mismatch');
  });

  it('rejects malformed SHA256SUMS in every shape', () => {
    const { dir } = makeDist();
    const good = readFileSync(join(dir, 'SHA256SUMS'), 'utf8');
    const [info, bin] = good.trimEnd().split('\n');
    for (const bad of [
      good.trimEnd(), // no trailing newline
      `${bin}\n${info}\n`, // not sorted
      `${info}\n${info}\n`, // duplicate
      `${info}\n`, // missing entry
      `${info}\n${bin.replace('  pii-eval', '  ../pii-eval')}\n`, // path traversal
      `${info}\n${bin.replace('  pii-eval', ' pii-eval')}\n`, // one space
      `${info.toUpperCase()}\n${bin}\n`, // uppercase hex
      `${info}\n${bin}\nextra\n`,
    ]) {
      writeFileSync(join(dir, 'SHA256SUMS'), bad);
      assert.equal(reason(() => verify({ dir })), 'sums-malformed', JSON.stringify(bad.slice(0, 40)));
    }
  });

  it('enforces the closed build-info schema', () => {
    const { dir } = makeDist();
    const p = join(dir, 'build-info.json');
    const good = JSON.parse(readFileSync(p, 'utf8'));
    const cases = {
      'unknown key': { ...good, note: 'x' },
      'wrong schema': { ...good, schema: 'pii-eval-build-info/2' },
      'bad commit': { ...good, commit: 'zz' },
      'bad target': { ...good, target: 'plan9' },
      'bad toolchain key': { ...good, toolchain: { ...good.toolchain, extra: 1 } },
      'bad binary name': { ...good, binary: { ...good.binary, name: 'other' } },
      'zero bytes': { ...good, binary: { ...good.binary, bytes: 0 } },
      'array': [good],
    };
    for (const [label, doc] of Object.entries(cases)) {
      writeFileSync(p, stable(doc));
      resum(dir);
      assert.equal(reason(() => verify({ dir })), 'build-info-invalid', label);
    }
    writeFileSync(p, '{ not json');
    resum(dir);
    assert.equal(reason(() => verify({ dir })), 'build-info-invalid');
  });

  it('checks the executed version against build-info', () => {
    const { dir } = makeDist();
    const p = join(dir, 'build-info.json');
    const info = JSON.parse(readFileSync(p, 'utf8'));
    info.binary.version = 'pii-eval 1.2.3';
    writeFileSync(p, stable(info));
    resum(dir);
    assert.equal(reason(() => verify({ dir })), 'no-failure'); // not executed without the flag
    assert.equal(reason(() => verify({ dir, 'make-executable': true })), 'version-mismatch');
  });

  it('restores the executable bit that artifact download drops', () => {
    const { dir } = makeDist();
    chmodSync(join(dir, 'pii-eval'), 0o644);
    assert.equal(verify({ dir, 'make-executable': true }).binary.name, 'pii-eval');
  });
});

describe('command line', () => {
  it('prints exactly one JSON line and exits 0 on success', () => {
    const { dir } = makeDist();
    const out = execFileSync('node', [join(TOOLS, 'verify-engine.mjs'), '--dir', dir, '--commit', COMMIT, '--make-executable'], { encoding: 'utf8' });
    assert.equal(out.trimEnd().split('\n').length, 1);
    const j = JSON.parse(out);
    assert.equal(j.ok, true);
    assert.equal(j.schema, 'pii-eval-engine-verify/1');
    assert.equal(j.commit, COMMIT);
  });

  it('prints the reason and exits 1 on failure, 2 on misuse', () => {
    const { dir } = makeDist();
    writeFileSync(join(dir, 'pii-eval'), 'tampered');
    const bad = spawnSync('node', [join(TOOLS, 'verify-engine.mjs'), '--dir', dir], { encoding: 'utf8' });
    assert.equal(bad.status, 1);
    assert.deepEqual(JSON.parse(bad.stdout), { schema: 'pii-eval-engine-verify/1', ok: false, reason: 'sums-mismatch' });
    const usage = spawnSync('node', [join(TOOLS, 'verify-engine.mjs')], { encoding: 'utf8' });
    assert.equal(usage.status, 2);
    assert.equal(JSON.parse(usage.stdout).reason, 'usage');
  });

  it('build-info exits 2 on bad input and writes nothing', () => {
    const dir = tmp('empty');
    const r = spawnSync('node', [join(TOOLS, 'build-info.mjs'), '--dir', dir, '--target', 'linux-x86_64'], { encoding: 'utf8' });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /missing --repository/);
  });
});
