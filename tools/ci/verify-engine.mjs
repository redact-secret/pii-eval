#!/usr/bin/env node
// Verifies a downloaded or about-to-be-uploaded engine artifact directory
// (docs/ci-artifacts.md). Standard library only. Prints exactly one JSON line;
// exit 0 only when every check passes. Reason codes are a closed list.
//
//   node tools/ci/verify-engine.mjs --dir DIR [--commit SHA40] [--repository OWNER/REPO]
//     [--target linux-x86_64] [--make-executable]
//
// What it proves: the directory holds exactly pii-eval, build-info.json and
// SHA256SUMS; the sums are well formed and match the bytes; build-info.json has
// the closed schema and agrees with the binary (digest, size); optional
// expectations (commit, repository, target) hold; with --make-executable the
// binary (artifact download drops the executable bit) is made executable and
// its `--version` equals build-info. What it does not prove: that the commit is
// trustworthy or that the build is reproducible (no signature or attestation).
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmodSync, lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { BINARY, INFO, SCHEMA, SUMS, TARGETS } from './build-info.mjs';
import { isMain } from './main-guard.mjs';

export const SUMMARY_SCHEMA = 'pii-eval-engine-verify/1';

class Fail extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const HEX64 = /^[0-9a-f]{64}$/;
const PRINTABLE = /^[\x20-\x7e]{1,200}$/;

function regularFile(path, missing) {
  let st;
  try {
    st = lstatSync(path);
  } catch {
    throw new Fail(missing);
  }
  if (!st.isFile()) throw new Fail('not-regular-file');
  return st;
}

function parseSums(text) {
  if (!text.endsWith('\n')) throw new Fail('sums-malformed');
  const lines = text.slice(0, -1).split('\n');
  const entries = new Map();
  let previous = '';
  for (const line of lines) {
    const m = /^([0-9a-f]{64}) {2}(build-info\.json|pii-eval)$/.exec(line);
    if (!m) throw new Fail('sums-malformed');
    if (entries.has(m[2]) || m[2] <= previous) throw new Fail('sums-malformed');
    entries.set(m[2], m[1]);
    previous = m[2];
  }
  if (entries.size !== 2) throw new Fail('sums-malformed');
  return entries;
}

const KEYS = {
  top: ['binary', 'commit', 'event', 'headSha', 'ref', 'repository', 'runAttempt', 'runId', 'schema', 'target', 'toolchain'],
  toolchain: ['cargoLockSha256', 'rustToolchainFileSha256', 'rustc'],
  binary: ['bytes', 'name', 'sha256', 'version'],
};

function exactKeys(obj, expected) {
  const keys = Object.keys(obj).sort();
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) throw new Fail('build-info-invalid');
}

function checkInfo(info) {
  if (!info || typeof info !== 'object' || Array.isArray(info)) throw new Fail('build-info-invalid');
  exactKeys(info, KEYS.top);
  if (info.schema !== SCHEMA) throw new Fail('build-info-invalid');
  if (!/^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/.test(info.repository)) throw new Fail('build-info-invalid');
  if (!/^[0-9a-f]{40}$/.test(info.commit) || !/^[0-9a-f]{40}$/.test(info.headSha)) throw new Fail('build-info-invalid');
  if (!/^[a-z_]{1,50}$/.test(info.event)) throw new Fail('build-info-invalid');
  if (!/^[\x21-\x7e]{1,200}$/.test(info.ref)) throw new Fail('build-info-invalid');
  if (!/^[0-9]{1,20}$/.test(info.runId) || !/^[0-9]{1,4}$/.test(info.runAttempt)) throw new Fail('build-info-invalid');
  if (!TARGETS.includes(info.target)) throw new Fail('build-info-invalid');
  const t = info.toolchain;
  if (!t || typeof t !== 'object') throw new Fail('build-info-invalid');
  exactKeys(t, KEYS.toolchain);
  if (!HEX64.test(t.cargoLockSha256) || !HEX64.test(t.rustToolchainFileSha256) || !PRINTABLE.test(t.rustc)) {
    throw new Fail('build-info-invalid');
  }
  const b = info.binary;
  if (!b || typeof b !== 'object') throw new Fail('build-info-invalid');
  exactKeys(b, KEYS.binary);
  if (b.name !== BINARY || !HEX64.test(b.sha256) || !Number.isSafeInteger(b.bytes) || b.bytes < 1) {
    throw new Fail('build-info-invalid');
  }
  if (!PRINTABLE.test(b.version)) throw new Fail('build-info-invalid');
}

export function verify(opts) {
  const dir = resolve(opts.dir);
  let names;
  try {
    names = readdirSync(dir).sort();
  } catch {
    throw new Fail('dir-unreadable');
  }
  const want = [BINARY, INFO, SUMS].sort();
  for (const n of names) if (!want.includes(n)) throw new Fail('unexpected-file');
  for (const n of want) if (!names.includes(n)) throw new Fail('missing-file');
  const binPath = join(dir, BINARY);
  const binStat = regularFile(binPath, 'missing-file');
  const infoBytes = (regularFile(join(dir, INFO), 'missing-file'), readFileSync(join(dir, INFO)));
  const sums = parseSums((regularFile(join(dir, SUMS), 'missing-file'), readFileSync(join(dir, SUMS), 'utf8')));
  const binBytes = readFileSync(binPath);
  if (sums.get(BINARY) !== sha256(binBytes) || sums.get(INFO) !== sha256(infoBytes)) throw new Fail('sums-mismatch');
  let info;
  try {
    info = JSON.parse(infoBytes.toString('utf8'));
  } catch {
    throw new Fail('build-info-invalid');
  }
  checkInfo(info);
  if (info.binary.sha256 !== sums.get(BINARY) || info.binary.bytes !== binStat.size) throw new Fail('binary-mismatch');
  if (opts.commit !== undefined && info.commit !== opts.commit) throw new Fail('commit-mismatch');
  if (opts.repository !== undefined && info.repository !== opts.repository) throw new Fail('repository-mismatch');
  if (opts.target !== undefined && info.target !== opts.target) throw new Fail('target-mismatch');
  if (opts['make-executable'] !== undefined) {
    chmodSync(binPath, 0o755);
    let out;
    try {
      out = execFileSync(binPath, ['--version'], { encoding: 'utf8', timeout: 20000 }).trim();
    } catch {
      throw new Fail('exec-failed');
    }
    if (out !== info.binary.version) throw new Fail('version-mismatch');
  }
  return info;
}

function parse(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 1) {
    const f = argv[i];
    if (f === '--make-executable') {
      o['make-executable'] = true;
    } else if (f.startsWith('--') && i + 1 < argv.length) {
      o[f.slice(2)] = argv[(i += 1)];
    } else {
      throw new Fail('usage');
    }
  }
  if (typeof o.dir !== 'string') throw new Fail('usage');
  return o;
}

if (isMain(import.meta.url)) {
  try {
    const info = verify(parse(process.argv.slice(2)));
    process.stdout.write(
      `${JSON.stringify({ schema: SUMMARY_SCHEMA, ok: true, repository: info.repository, commit: info.commit, headSha: info.headSha, event: info.event, runId: info.runId, target: info.target, binarySha256: info.binary.sha256, version: info.binary.version })}\n`,
    );
  } catch (e) {
    const code = e instanceof Fail ? e.code : 'internal';
    process.stdout.write(`${JSON.stringify({ schema: SUMMARY_SCHEMA, ok: false, reason: code })}\n`);
    process.exit(code === 'usage' ? 2 : 1);
  }
}
