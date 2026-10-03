// node --test tools/isolation/test/argv.test.mjs
// Fidelity of the replica of the custodian's sandbox launcher. Each test ports an
// assertion of private-custodian@142db34 crates/custodian-worker/tests/argv.rs (named
// in the test title) and the golden vector below was derived by hand from
// `BubblewrapSandbox::build_argv`, not from this code.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ENV_ALLOWLIST, REPLICA_OF, SpecError, buildArgv, detectSystemRoots, envNameAllowed } from '../bwrap-argv.mjs';

const ROOTS = [{ bind: '/usr' }, { symlink: { path: '/lib', target: 'usr/lib' } }];
const spec = () => ({
  program: '/stage/engine',
  args: ['--job', '/job/job.json; rm -rf /'],
  roMounts: [{ host: '/tmp/run-1/stage', inner: '/stage' }],
  env: [['PATH', '/usr/bin:/bin']],
  quotas: { cpuSeconds: 7, wallMs: 9000, memoryBytes: 123456789, storageBytes: 8388608, maxProcesses: 11, stdoutBytes: 100, stderrBytes: 100 },
});
const argv = (s = spec()) => buildArgv(s, ROOTS);
const hasSeq = (a, seq) => a.some((_, i) => seq.every((x, j) => a[i + j] === x));
const reason = (fn) => {
  try {
    fn();
  } catch (e) {
    return e instanceof SpecError ? e.code : `other:${e.message}`;
  }
  return 'no-failure';
};

describe('pinned to the custodian commit', () => {
  it('names the commit and the files it was written from', () => {
    assert.equal(REPLICA_OF.commit, '142db34dd4bc02903f47cba951a054351bb55fde');
    assert.deepEqual(REPLICA_OF.files, ['crates/custodian-worker/src/bwrap.rs', 'crates/custodian-worker/src/sandbox.rs']);
  });
  it('produces the exact vector build_argv produces for the custodian test spec (golden, derived by hand)', () => {
    assert.deepEqual(argv(), [
      '--die-with-parent', '--new-session', '--unshare-user', '--unshare-ipc', '--unshare-pid', '--unshare-net', '--unshare-uts',
      '--unshare-cgroup-try', '--cap-drop', 'ALL', '--clearenv',
      '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib',
      '--proc', '/proc', '--dev', '/dev', '--size', '8388608', '--tmpfs', '/scratch',
      '--ro-bind', '/tmp/run-1/stage', '/stage',
      '--remount-ro', '/', '--chdir', '/scratch',
      '--setenv', 'PATH', '/usr/bin:/bin',
      '--', '/usr/bin/prlimit', '--cpu=7', '--as=123456789', '--nproc=11', '--fsize=8388608', '--core=0', '--nofile=256',
      '--', '/stage/engine', '--job', '/job/job.json; rm -rf /',
    ]);
  });
});

describe('ports of tests/argv.rs', () => {
  it('isolation_flags_are_all_present', () => {
    const a = argv();
    for (const f of ['--die-with-parent', '--new-session', '--unshare-user', '--unshare-ipc', '--unshare-pid', '--unshare-net', '--unshare-uts', '--clearenv']) {
      assert.ok(a.includes(f), `missing ${f}`);
    }
    assert.ok(hasSeq(a, ['--cap-drop', 'ALL']));
    assert.ok(hasSeq(a, ['--remount-ro', '/']));
    assert.ok(!a.includes('--share-net') && !a.includes('--unshare-all'));
    assert.ok(hasSeq(a, ['--size', '8388608', '--tmpfs', '/scratch']));
    assert.ok(!a.includes('--bind') && !a.includes('--bind-try') && !a.includes('--dev-bind'));
  });
  it('mounts_are_read_only_and_system_roots_are_explicit', () => {
    const a = argv();
    assert.ok(hasSeq(a, ['--ro-bind', '/usr', '/usr']));
    assert.ok(hasSeq(a, ['--symlink', 'usr/lib', '/lib']));
    assert.ok(hasSeq(a, ['--ro-bind', '/tmp/run-1/stage', '/stage']));
    for (const p of ['/home', '/etc', '/var', '/root', '/run']) assert.ok(!a.includes(p), `${p} must not be mounted`);
  });
  it('rlimits_wrap_the_payload_inside_the_sandbox', () => {
    const a = argv();
    const i = a.indexOf('/usr/bin/prlimit');
    assert.equal(a[i - 1], '--');
    for (const want of ['--cpu=7', '--as=123456789', '--nproc=11', '--fsize=8388608', '--core=0']) assert.ok(a.slice(i).includes(want), want);
    // one argv element per argument, never parsed by a shell
    assert.deepEqual(a.slice(-3), ['/stage/engine', '--job', '/job/job.json; rm -rf /']);
  });
  it('environment_is_cleared_then_allowlisted', () => {
    const a = argv();
    assert.ok(a.indexOf('--clearenv') < a.indexOf('--setenv'));
    assert.ok(hasSeq(a, ['--setenv', 'PATH', '/usr/bin:/bin']));
    const bad = spec();
    bad.env.push(['GITHUB_TOKEN', 'x']);
    assert.equal(reason(() => argv(bad)), 'path-rejected');
  });
  it('malformed_specs_are_refused', () => {
    let s = spec();
    s.program = 'relative/engine';
    assert.equal(reason(() => argv(s)), 'path-rejected');
    s = spec();
    s.roMounts[0].inner = '/stage/../etc';
    assert.equal(reason(() => argv(s)), 'path-rejected');
    s = spec();
    s.quotas.maxProcesses = 0;
    assert.equal(reason(() => argv(s)), 'plan-inconsistent');
  });
});

describe('environment allowlist (sandbox.rs)', () => {
  it('allows exactly the listed names and refuses credential-looking ones', () => {
    for (const n of ENV_ALLOWLIST) assert.ok(envNameAllowed(n), n);
    for (const n of ['GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'NODE_OPTIONS', 'LD_PRELOAD', 'path', 'CUSTODIAN_LEDGER_TOKEN', '']) assert.ok(!envNameAllowed(n), n);
  });
});

describe('system roots detection', () => {
  const st = (kind) => ({ isSymbolicLink: () => kind === 'link', isDirectory: () => kind === 'dir' });
  it('binds directories, mirrors symlinks, skips absent roots, requires /usr', () => {
    const roots = detectSystemRoots(
      (p) => {
        if (p === '/usr' || p === '/etc-not-a-root') return st('dir');
        if (p === '/lib' || p === '/bin') return st('link');
        throw new Error('absent');
      },
      (p) => (p === '/lib' ? 'usr/lib' : 'usr/bin'),
    );
    assert.deepEqual(roots, [{ bind: '/usr' }, { symlink: { path: '/lib', target: 'usr/lib' } }, { symlink: { path: '/bin', target: 'usr/bin' } }]);
    assert.equal(reason(() => detectSystemRoots(() => { throw new Error('absent'); })), 'isolation-unavailable');
  });
});
