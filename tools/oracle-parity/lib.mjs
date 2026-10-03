// Shared helpers of the oracle-parity tooling. Plain Node >= 22.6, no packages.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');

/** The git blob id of a file's bytes (what the pinned commit's tree lists). */
export const gitBlobSha1 = (data) => createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex');

/**
 * Tree digest of a set of files: sha256 over the lines `path NUL blob-sha1 LF`, sorted by path.
 * `blobOf(path)` returns the blob id of each file.
 */
export function treeDigest(paths, blobOf) {
  return sha256([...paths].sort().map((p) => `${p}\0${blobOf(p)}\n`).join(''));
}

/** Tree digest of the oracle files found under `root` (a directory fetched by fetch-oracle.mjs). */
export function onDiskTreeDigest(root, spec) {
  return treeDigest(spec.files, (p) => gitBlobSha1(readFileSync(join(root, p))));
}

/** Deterministic JSON: keys sorted at every level, one-space indent, trailing newline. Integers and strings only are expected. */
export function stableJson(value) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sort(v[k])]));
    return v;
  };
  return `${JSON.stringify(sort(value), null, 1)}\n`;
}
