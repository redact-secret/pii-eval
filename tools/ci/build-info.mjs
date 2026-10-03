#!/usr/bin/env node
// Writes build-info.json and SHA256SUMS next to a built `pii-eval` binary
// (docs/ci-artifacts.md). Standard library only; no network; no timestamps, so
// the output is a pure function of the inputs.
//
//   node tools/ci/build-info.mjs --dir DIR --target linux-x86_64 \
//     --repository OWNER/REPO --commit SHA40 --head-sha SHA40 --event NAME --ref REF \
//     --run-id ID --run-attempt N [--root REPO_ROOT] [--rustc-version TEXT]
//
// `--commit` is GITHUB_SHA (for a pull_request event the merge commit, which
// disappears after the merge); `--head-sha` is the commit the event is about (the
// pull request head, or the same commit for a push); `--event` is the event name.
//
// DIR must already hold the binary `pii-eval`. `--root` (default: the working
// directory) is where Cargo.lock and rust-toolchain.toml are read from.
// `--rustc-version` replaces running `rustc --version` (tests).
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { isMain } from './main-guard.mjs';

export const SCHEMA = 'pii-eval-build-info/1';
export const TARGETS = ['linux-x86_64'];
export const BINARY = 'pii-eval';
export const INFO = 'build-info.json';
export const SUMS = 'SHA256SUMS';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

// Stable serialization: sorted keys, two-space indent, trailing newline.
export function stable(value) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object') {
      return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sort(v[k])]));
    }
    return v;
  };
  return `${JSON.stringify(sort(value), null, 2)}\n`;
}

class UsageError extends Error {}

export function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    if (!flag.startsWith('--') || i + 1 >= argv.length) throw new UsageError(`bad argument ${flag}`);
    out[flag.slice(2)] = argv[i + 1];
  }
  return out;
}

export function validateInputs(a) {
  const need = ['dir', 'target', 'repository', 'commit', 'head-sha', 'event', 'ref', 'run-id', 'run-attempt'];
  for (const k of need) if (typeof a[k] !== 'string' || a[k] === '') throw new UsageError(`missing --${k}`);
  if (!TARGETS.includes(a.target)) throw new UsageError('unsupported target');
  if (!/^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/.test(a.repository)) throw new UsageError('bad repository');
  if (!/^[0-9a-f]{40}$/.test(a.commit)) throw new UsageError('bad commit');
  if (!/^[0-9a-f]{40}$/.test(a['head-sha'])) throw new UsageError('bad head sha');
  if (!/^[a-z_]{1,50}$/.test(a.event)) throw new UsageError('bad event');
  if (!/^[\x21-\x7e]{1,200}$/.test(a.ref)) throw new UsageError('bad ref');
  if (!/^[0-9]{1,20}$/.test(a['run-id'])) throw new UsageError('bad run id');
  if (!/^[0-9]{1,4}$/.test(a['run-attempt'])) throw new UsageError('bad run attempt');
}

export function build(a) {
  validateInputs(a);
  const dir = resolve(a.dir);
  const root = resolve(a.root ?? '.');
  const binPath = join(dir, BINARY);
  const st = lstatSync(binPath);
  if (!st.isFile()) throw new UsageError('the binary is not a regular file');
  const bytes = readFileSync(binPath);
  const version = execFileSync(binPath, ['--version'], { encoding: 'utf8', timeout: 20000 }).trim();
  if (!/^[\x20-\x7e]{1,200}$/.test(version)) throw new UsageError('unexpected --version output');
  const rustc = (a['rustc-version'] ?? execFileSync('rustc', ['--version'], { encoding: 'utf8' })).trim();
  if (!/^[\x20-\x7e]{1,200}$/.test(rustc)) throw new UsageError('unexpected rustc version text');
  const info = {
    schema: SCHEMA,
    repository: a.repository,
    commit: a.commit,
    event: a.event,
    headSha: a['head-sha'],
    ref: a.ref,
    runId: a['run-id'],
    runAttempt: a['run-attempt'],
    target: a.target,
    toolchain: {
      rustc,
      cargoLockSha256: sha256(readFileSync(join(root, 'Cargo.lock'))),
      rustToolchainFileSha256: sha256(readFileSync(join(root, 'rust-toolchain.toml'))),
    },
    binary: { name: BINARY, sha256: sha256(bytes), bytes: bytes.length, version },
  };
  const infoText = stable(info);
  writeFileSync(join(dir, INFO), infoText, { mode: 0o644 });
  // Sorted by file name, two spaces, as `sha256sum -c` expects.
  const sums = [[INFO, sha256(Buffer.from(infoText))], [BINARY, info.binary.sha256]]
    .sort((x, y) => (x[0] < y[0] ? -1 : 1))
    .map(([name, h]) => `${h}  ${name}\n`)
    .join('');
  writeFileSync(join(dir, SUMS), sums, { mode: 0o644 });
  return info;
}

if (isMain(import.meta.url)) {
  try {
    const info = build(parseArgs(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify({ ok: true, commit: info.commit, binarySha256: info.binary.sha256 })}\n`);
  } catch (e) {
    process.stderr.write(`build-info: ${e instanceof UsageError ? e.message : 'failed'}\n`);
    process.exit(e instanceof UsageError ? 2 : 1);
  }
}
