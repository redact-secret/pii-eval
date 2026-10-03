// A replica of the private-custodian worker sandbox launcher: the bubblewrap +
// prlimit argument vector, the environment allowlist and the quota validation.
//
// REPLICA, NOT THE CUSTODIAN'S CODE. It is written from
//   redact-secret/private-custodian @ 142db34dd4bc02903f47cba951a054351bb55fde
//   crates/custodian-worker/src/bwrap.rs   (`BubblewrapSandbox::build_argv`)
//   crates/custodian-worker/src/sandbox.rs (`ENV_ALLOWLIST`, `DENY_FRAGMENTS`,
//                                           `SandboxSpec::validate`)
// and pinned to that commit by tools/isolation/test/argv.test.mjs, which ports the
// assertions of the custodian's own tests/argv.rs. It exists so pii-eval can measure
// how its engine and a Node runtime behave under the SAME limits (docs/custodian-isolation-node.md)
// without access to the private repository. It is evidence about those limits only; the
// custodian's startup self-check on the production host stays the evidence of isolation.
//
// Standard library only. No shell is ever involved: the vector is passed to execve.
import { lstatSync, readlinkSync } from 'node:fs';

export const REPLICA_OF = Object.freeze({
  repository: 'redact-secret/private-custodian',
  commit: '142db34dd4bc02903f47cba951a054351bb55fde',
  files: ['crates/custodian-worker/src/bwrap.rs', 'crates/custodian-worker/src/sandbox.rs'],
});

// The fixed in-sandbox location of prlimit (custodian: PRLIMIT_INNER).
export const PRLIMIT_INNER = '/usr/bin/prlimit';
// Directories that provide the dynamic loader and libraries (custodian: SYSTEM_ROOTS).
export const SYSTEM_ROOTS = ['/usr', '/lib', '/lib64', '/bin', '/sbin'];

export const ENV_ALLOWLIST = [
  'PATH',
  'HOME',
  'PWD',
  'TMPDIR',
  'LANG',
  'CUSTODIAN_STAGE_ROOT',
  'CUSTODIAN_INPUT_ROOT',
  'CUSTODIAN_JOB_ROOT',
  'CUSTODIAN_SCRATCH',
];

const DENY_FRAGMENTS = ['TOKEN', 'SECRET', 'KEY', 'PASS', 'CRED', 'LEDGER', 'SIGN', 'DATABASE', 'DB_', 'APP_', 'AWS', 'GITHUB', 'SSH'];

export function envNameAllowed(name) {
  return ENV_ALLOWLIST.includes(name) && !DENY_FRAGMENTS.some((d) => name.toUpperCase().includes(d));
}

export class SpecError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/** Find the system roots on this host (custodian: `BubblewrapSandbox::detect`). */
export function detectSystemRoots(lstat = lstatSync, readlink = readlinkSync) {
  const roots = [];
  for (const r of SYSTEM_ROOTS) {
    let st;
    try {
      st = lstat(r);
    } catch {
      continue;
    }
    if (st.isSymbolicLink()) roots.push({ symlink: { path: r, target: readlink(r) } });
    else if (st.isDirectory()) roots.push({ bind: r });
  }
  if (!roots.some((x) => x.bind === '/usr')) throw new SpecError('isolation-unavailable');
  return roots;
}

/** `SandboxSpec::validate`. */
export function validateSpec(spec) {
  if (typeof spec.program !== 'string' || !spec.program.startsWith('/') || spec.program.includes('\0')) throw new SpecError('path-rejected');
  for (const m of spec.roMounts) {
    if (!m.inner.startsWith('/') || m.inner.includes('..') || m.inner.includes('\0')) throw new SpecError('path-rejected');
    if (!m.host.startsWith('/')) throw new SpecError('path-rejected');
  }
  for (const [k, v] of spec.env) {
    if (!envNameAllowed(k) || v.includes('\0')) throw new SpecError('path-rejected');
  }
  const q = spec.quotas;
  if (!(q.cpuSeconds > 0 && q.wallMs > 0 && q.memoryBytes > 0 && q.storageBytes > 0 && q.maxProcesses > 0 && q.stdoutBytes > 0 && q.stderrBytes > 0)) {
    throw new SpecError('plan-inconsistent');
  }
}

/** The complete launcher argument vector, without the launcher itself. Pure. */
export function buildArgv(spec, roots) {
  validateSpec(spec);
  const q = spec.quotas;
  const a = [
    '--die-with-parent',
    '--new-session',
    '--unshare-user',
    '--unshare-ipc',
    '--unshare-pid',
    '--unshare-net',
    '--unshare-uts',
    '--unshare-cgroup-try',
    '--cap-drop',
    'ALL',
    '--clearenv',
  ];
  for (const r of roots) {
    if (r.bind !== undefined) a.push('--ro-bind', r.bind, r.bind);
    else a.push('--symlink', r.symlink.target, r.symlink.path);
  }
  a.push('--proc', '/proc', '--dev', '/dev', '--size', String(q.storageBytes), '--tmpfs', '/scratch');
  for (const m of spec.roMounts) a.push('--ro-bind', m.host, m.inner);
  a.push('--remount-ro', '/', '--chdir', '/scratch');
  for (const [k, v] of spec.env) a.push('--setenv', k, v);
  a.push(
    '--',
    PRLIMIT_INNER,
    `--cpu=${q.cpuSeconds}`,
    `--as=${q.memoryBytes}`,
    `--nproc=${q.maxProcesses}`,
    `--fsize=${q.storageBytes}`,
    '--core=0',
    '--nofile=256',
    '--',
    spec.program,
    ...spec.args,
  );
  return a;
}
