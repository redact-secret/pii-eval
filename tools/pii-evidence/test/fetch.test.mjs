// Offline tests of the fetch tool's pure parts. Nothing here uses the network or `gh`.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

import { FetchRefusal, flatId, parsePin, readTar, sha256, unpack, writeFiles } from '../fetch-snapshot.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const pinText = readFileSync(join(root, 'fixtures/pii-evidence/pin.json'), 'utf8');
const pin = parsePin(pinText);
const snapshotDir = join(root, 'fixtures/pii-evidence/snapshots', pin.snapshot.id);

// The producer's deterministic tar (pii-evidence scripts/lib/snapshot.mjs `tarOf`), reimplemented
// from the consumer contract: sorted names, mode 0644, uid/gid 0, mtime 0, top directory = flat id.
function header(name, size, type = '0') {
  const h = Buffer.alloc(512, 0);
  const put = (off, s) => h.write(s, off, 'ascii');
  put(0, name);
  put(100, '0000644\0');
  put(108, '0000000\0');
  put(116, '0000000\0');
  put(124, `${size.toString(8).padStart(11, '0')}\0`);
  put(136, '00000000000\0');
  put(148, '        ');
  put(156, type);
  put(257, 'ustar\0');
  put(263, '00');
  let sum = 0;
  for (const b of h) sum += b;
  put(148, `${sum.toString(8).padStart(6, '0')}\0 `);
  return h;
}
function tarOf(top, files) {
  const parts = [];
  for (const path of [...files.keys()].sort()) {
    const body = files.get(path);
    parts.push(header(`${top}/${path}`, body.length), body, Buffer.alloc((512 - (body.length % 512)) % 512, 0));
  }
  parts.push(Buffer.alloc(1024, 0));
  return Buffer.concat(parts);
}
function walk(dir, base = dir, out = new Map()) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, base, out);
    else out.set(relative(base, p).split('\\').join('/'), readFileSync(p));
  }
  return out;
}
const pinFor = (gz, tar) => ({
  ...pin,
  release: { ...pin.release, archive: { ...pin.release.archive, tarGzSha256: sha256(gz), tarSha256: sha256(tar) } },
});

test('the vendored snapshot is byte-identical to the released archive (deterministic tar digest)', () => {
  const files = walk(snapshotDir);
  assert.equal(files.size, 10);
  const tar = tarOf(flatId(pin.snapshot.id), files);
  assert.equal(sha256(tar), pin.release.archive.tarSha256);
  assert.equal(sha256(files.get('manifest.json')), pin.snapshot.manifestSha256);
});

test('unpack accepts exactly the pinned archive and returns the files', () => {
  const files = walk(snapshotDir);
  const tar = tarOf(flatId(pin.snapshot.id), files);
  const gz = gzipSync(tar, { level: 9 });
  const out = unpack(gz, pinFor(gz, tar));
  assert.deepEqual([...out.keys()].sort(), [...files.keys()].sort());
  for (const [k, v] of files) assert.ok(out.get(k).equals(v));
});

test('unpack refuses a wrong archive digest and a wrong tar digest', () => {
  const tar = tarOf(flatId(pin.snapshot.id), walk(snapshotDir));
  const gz = gzipSync(tar);
  assert.throws(() => unpack(gz, pin), (e) => e.code === 'archive-digest-mismatch' && e.at === 'tarGzSha256');
  const p = pinFor(gz, tar);
  p.release.archive.tarSha256 = '0'.repeat(64);
  assert.throws(() => unpack(gz, p), (e) => e.code === 'archive-digest-mismatch' && e.at === 'tarSha256');
});

test('readTar refuses traversal, absolute and foreign top-directory entries', () => {
  const top = 'snap';
  for (const name of ['snap/../evil', '/abs', 'other/file', 'snap//x', 'snap/./x', 'snap/a\\b']) {
    const tar = Buffer.concat([header(name, 1), Buffer.alloc(512, 0), Buffer.alloc(1024, 0)]);
    assert.throws(() => readTar(tar, top), (e) => e instanceof FetchRefusal && e.code === 'archive-entry-refused', name);
  }
});

test('readTar refuses links, directories and devices', () => {
  for (const type of ['1', '2', '3', '4', '5', 'x', 'g']) {
    const tar = Buffer.concat([header('snap/f', 0, type), Buffer.alloc(1024, 0)]);
    assert.throws(() => readTar(tar, 'snap'), (e) => e.code === 'archive-entry-refused', type);
  }
});

test('readTar refuses a corrupt header checksum, a truncated body and an empty archive', () => {
  const bad = header('snap/f', 1);
  bad[0] ^= 1;
  assert.throws(() => readTar(Buffer.concat([bad, Buffer.alloc(512), Buffer.alloc(1024)]), 'snap'), (e) => e.code === 'archive-checksum');
  assert.throws(() => readTar(header('snap/f', 100), 'snap'), (e) => e.code === 'archive-truncated');
  assert.throws(() => readTar(Buffer.alloc(1024), 'snap'), (e) => e.code === 'archive-empty');
});

test('writeFiles needs a new or empty directory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'fetch-test-'));
  try {
    writeFiles(new Map([['a/b.txt', Buffer.from('x')]]), dir);
    assert.throws(() => writeFiles(new Map([['c.txt', Buffer.from('y')]]), dir), (e) => e.code === 'output-not-empty');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('parsePin is closed and refuses a floating or malformed pin', () => {
  assert.equal(pin.snapshot.id, 'public-pii-phi/2026-10-07/9d4e8e036bbb');
  for (const mutate of [
    (p) => { p.extra = 1; },
    (p) => { p.contract.version = '2'; },
    (p) => { p.snapshot.contentDigest = 'latest'; },
    (p) => { p.release.commit = 'main'; },
    (p) => { p.schema = 'pii-eval-evidence-pin/2'; },
    (p) => { delete p.release.archive; },
  ]) {
    const p = JSON.parse(pinText);
    mutate(p);
    assert.throws(() => parsePin(JSON.stringify(p)), (e) => e instanceof FetchRefusal && e.code === 'pin-invalid');
  }
  assert.throws(() => parsePin('{'), (e) => e.code === 'pin-invalid');
});

test('the content digest of the vendored files matches the pin (files-v1)', () => {
  const files = walk(snapshotDir);
  const lines = [...files.keys()]
    .filter((p) => p !== 'manifest.json')
    .sort()
    .map((p) => `${sha256(files.get(p))} ${p}\n`)
    .join('');
  assert.equal(createHash('sha256').update(lines).digest('hex'), pin.snapshot.contentDigest);
});
