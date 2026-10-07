#!/usr/bin/env node
// Fetch and unpack a pinned pii-evidence snapshot release, OUTSIDE the engine.
//
// The engine (kernel, CLI, loader) never touches the network. This tool does the one network
// step the consumer contract needs, with `gh` (public repository, no token needed beyond the
// usual rate limits), and refuses anything that is not exactly what the pin says:
//
//   1. the git tag resolves (through an annotated tag object if there is one) to the pinned commit;
//   2. the downloaded `.tar.gz` has the pinned SHA-256;
//   3. its gunzipped tar has the pinned SHA-256 (the deterministic tar of the producer);
//   4. every tar entry is a regular file below the one top directory named after the snapshot id,
//      with a safe relative path, inside the size limits; nothing else is extracted.
//
// It writes the snapshot files to <out>/ (a NEW, empty directory) and prints one JSON line. It
// does NOT judge the snapshot: `pii-eval-evidence verify` does, with the same pin, before anything
// is mapped or executed. A pin proves which release was fetched, not that its expectations are right.
//
// Usage: node tools/pii-evidence/fetch-snapshot.mjs --pin fixtures/pii-evidence/pin.json --out <new-dir>
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

export const PIN_SCHEMA = 'pii-eval-evidence-pin/1';
export const MAX_FILES = 64;
export const MAX_FILE_BYTES = 32 * 1024 * 1024;
export const MAX_TOTAL_BYTES = 64 * 1024 * 1024;

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export class FetchRefusal extends Error {
  constructor(code, at) {
    super(`${code}: ${at}`);
    this.code = code;
    this.at = at;
  }
}

const HEX64 = /^[0-9a-f]{64}$/;

/** Parse a pin file strictly (closed fields, the contract this loader knows). */
export function parsePin(text) {
  let pin;
  try {
    pin = JSON.parse(text);
  } catch {
    throw new FetchRefusal('pin-invalid', 'pin');
  }
  const closed = (o, keys, at) => {
    if (!o || typeof o !== 'object' || Array.isArray(o) || Object.keys(o).sort().join() !== [...keys].sort().join()) {
      throw new FetchRefusal('pin-invalid', at);
    }
  };
  closed(pin, ['contract', 'release', 'schema', 'snapshot'], 'pin');
  if (pin.schema !== PIN_SCHEMA) throw new FetchRefusal('pin-invalid', 'schema');
  closed(pin.contract, ['digestSpec', 'name', 'version'], 'contract');
  if (pin.contract.name !== 'pii-evidence-consumer-contract' || pin.contract.version !== '1' || pin.contract.digestSpec !== 'files-v1') {
    throw new FetchRefusal('pin-invalid', 'contract');
  }
  closed(pin.snapshot, ['contentDigest', 'id', 'manifestSha256', 'sourceManifestDigest'], 'snapshot');
  closed(pin.release, ['archive', 'commit', 'repository', 'tag'], 'release');
  closed(pin.release.archive, ['name', 'tarGzSha256', 'tarSha256'], 'release.archive');
  for (const [v, at] of [
    [pin.snapshot.contentDigest, 'snapshot.contentDigest'],
    [pin.snapshot.manifestSha256, 'snapshot.manifestSha256'],
    [pin.snapshot.sourceManifestDigest, 'snapshot.sourceManifestDigest'],
    [pin.release.archive.tarGzSha256, 'release.archive.tarGzSha256'],
    [pin.release.archive.tarSha256, 'release.archive.tarSha256'],
  ]) {
    if (typeof v !== 'string' || !HEX64.test(v)) throw new FetchRefusal('pin-invalid', at);
  }
  if (!/^[0-9a-f]{40}$/.test(pin.release.commit)) throw new FetchRefusal('pin-invalid', 'release.commit');
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(pin.release.repository)) throw new FetchRefusal('pin-invalid', 'release.repository');
  if (!/^[A-Za-z0-9_.-]+$/.test(pin.release.tag) || !/^[A-Za-z0-9_.-]+$/.test(pin.release.archive.name)) {
    throw new FetchRefusal('pin-invalid', 'release.tag');
  }
  return pin;
}

/** The snapshot id with `/` replaced by `-`: the producer's top directory name. */
export const flatId = (id) => id.replaceAll('/', '-');

/**
 * Read a ustar archive. Accepts only regular files (typeflag `0` or NUL) whose names start with
 * `<top>/`, are relative, contain no `.`, `..`, empty or backslash segment, and stay inside the
 * limits. Anything else (directory entries, links, devices, pax headers, odd names) is refused,
 * not skipped: the producer writes none of them.
 */
export function readTar(tar, top) {
  const files = new Map();
  let total = 0;
  let off = 0;
  const field = (h, from, len) => {
    const raw = h.subarray(from, from + len);
    const end = raw.indexOf(0);
    return raw.subarray(0, end < 0 ? len : end).toString('latin1');
  };
  while (off + 512 <= tar.length) {
    const h = tar.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const name = field(h, 0, 100);
    const prefix = field(h, 345, 155);
    const type = String.fromCharCode(h[156] || 48);
    const size = parseInt(field(h, 124, 12).trim() || '0', 8);
    if (prefix !== '' || type !== '0' || !Number.isSafeInteger(size) || size < 0) throw new FetchRefusal('archive-entry-refused', name);
    let sum = 0;
    for (let i = 0; i < 512; i += 1) sum += i >= 148 && i < 156 ? 32 : h[i];
    if (sum !== parseInt(field(h, 148, 8).trim(), 8)) throw new FetchRefusal('archive-checksum', name);
    if (!name.startsWith(`${top}/`)) throw new FetchRefusal('archive-entry-refused', name);
    const rel = name.slice(top.length + 1);
    if (rel === '' || rel.startsWith('/') || rel.includes('\\') || rel.split('/').some((s) => s === '' || s === '.' || s === '..')) {
      throw new FetchRefusal('archive-entry-refused', name);
    }
    if (files.has(rel) || files.size >= MAX_FILES || size > MAX_FILE_BYTES) throw new FetchRefusal('archive-entry-refused', rel);
    total += size;
    if (total > MAX_TOTAL_BYTES) throw new FetchRefusal('archive-too-large', rel);
    const start = off + 512;
    if (start + size > tar.length) throw new FetchRefusal('archive-truncated', rel);
    files.set(rel, Buffer.from(tar.subarray(start, start + size)));
    off = start + Math.ceil(size / 512) * 512;
  }
  if (files.size === 0) throw new FetchRefusal('archive-empty', top);
  return files;
}

/** Write the files below `out`, which must not exist or must be an empty directory. */
export function writeFiles(files, out) {
  if (existsSync(out) && readdirSync(out).length > 0) throw new FetchRefusal('output-not-empty', 'out');
  for (const [rel, bytes] of files) {
    const path = join(out, rel);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, bytes, { mode: 0o644 });
  }
}

/** Verify the archive bytes against the pin and return the files. Pure: no network, no disk. */
export function unpack(gz, pin) {
  if (sha256(gz) !== pin.release.archive.tarGzSha256) throw new FetchRefusal('archive-digest-mismatch', 'tarGzSha256');
  const tar = gunzipSync(gz, { maxOutputLength: MAX_TOTAL_BYTES + 1024 * 1024 });
  if (sha256(tar) !== pin.release.archive.tarSha256) throw new FetchRefusal('archive-digest-mismatch', 'tarSha256');
  return readTar(tar, flatId(pin.snapshot.id));
}

const gh = (args) => execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000 });

/** Resolve a tag to the commit it points at, through an annotated tag object when there is one. */
export function resolveTagCommit(repository, tag) {
  const ref = JSON.parse(gh(['api', `repos/${repository}/git/ref/tags/${tag}`, '--jq', '.object']));
  let object = ref;
  for (let hops = 0; object.type === 'tag' && hops < 3; hops += 1) {
    object = JSON.parse(gh(['api', `repos/${repository}/git/tags/${object.sha}`, '--jq', '.object']));
  }
  if (object.type !== 'commit') throw new FetchRefusal('tag-not-a-commit', tag);
  return object.sha;
}

export function main(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!['--pin', '--out'].includes(argv[i]) || argv[i + 1] === undefined || argv[i] in opts) throw new FetchRefusal('usage', 'arguments');
    opts[argv[i]] = argv[i + 1];
  }
  if (!opts['--pin'] || !opts['--out']) throw new FetchRefusal('usage', 'arguments');
  const pin = parsePin(readFileSync(opts['--pin'], 'utf8'));
  const commit = resolveTagCommit(pin.release.repository, pin.release.tag);
  if (commit !== pin.release.commit) throw new FetchRefusal('tag-commit-mismatch', pin.release.tag);
  const scratch = mkdtempSync(join(tmpdir(), 'pii-evidence-fetch-'));
  try {
    gh(['release', 'download', pin.release.tag, '--repo', pin.release.repository, '--pattern', pin.release.archive.name, '--dir', scratch]);
    const files = unpack(readFileSync(join(scratch, pin.release.archive.name)), pin);
    writeFiles(files, opts['--out']);
    return { schema: 'pii-eval-evidence-fetch/1', snapshotId: pin.snapshot.id, tag: pin.release.tag, commit, files: files.size, state: 'fetched-unverified' };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(main(process.argv.slice(2)))}\n`);
  } catch (e) {
    const refusal = e instanceof FetchRefusal ? e : new FetchRefusal('fetch-failed', 'gh');
    process.stderr.write(`pii-evidence fetch: ${refusal.code}: ${refusal.at}\n`);
    process.exit(refusal.code === 'usage' ? 2 : 4);
  }
}
