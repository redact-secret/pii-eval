#!/usr/bin/env node
// Reproduce the pii-evidence public-synthetic measurement (docs/evidence-consumer.md).
//
// MANUAL tooling: CI never runs it (it needs the public npm registry for the scanner package). CI
// instead replays the committed observation set, which needs no scanner and no network.
//
// What it does, in order, each step stopping the run on failure:
//   1. verify the snapshot directory (the vendored copy by default, or one `fetch-snapshot.mjs` wrote)
//      against `fixtures/pii-evidence/pin.json`;
//   2. import it: the mapped corpus snapshot and the binding document;
//   3. install `@redact-secret/core` 0.1.0-beta.12 hermetically (`npm ci --ignore-scripts` from the
//      committed lockfile, which npm checks against the sha512 integrity it records) and hash the
//      package, the platform addon and the WebAssembly package (the three directories the scanner can load);
//   4. write the run plan (manifest) and the official run configuration;
//   5. EXECUTE: `pii-eval run` launches the scanner (the one step that is execution, not replay);
//   6. REPLAY: `pii-eval replay` re-derives the artifacts from the observation set alone, with no
//      scanner launched, and must reproduce the semantic digests exactly;
//   7. compare every digest with the committed record (`provenance.json`) and print one JSON report.
//
// Needs: Node >= 22 on PATH (the adapter pins the major), npm with registry access, and the release
// binaries (`cargo build --release --locked -p pii-eval-cli`). The platform addon is platform
// specific: digests of the scanner side differ on another platform, and the report says so rather
// than failing the semantic comparison silently.
//
// Usage: node tools/pii-evidence/reproduce.mjs [--scratch DIR] [--snapshot-dir DIR] [--node PATH]
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

/** The tree digest of `crates/pii-eval-adapters/src/pin.rs`: sha256 of sorted `<sha256>  <path>\n` lines. */
export function treeSha256(dir) {
  const files = [];
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else files.push(relative(dir, p).split('\\').join('/'));
    }
  };
  walk(dir);
  const bytes = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
  const listing = files.sort(bytes).map((f) => `${sha256(readFileSync(join(dir, f)))}  ${f}\n`).join('');
  return sha256(listing);
}

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!['--scratch', '--snapshot-dir', '--node'].includes(argv[i]) || argv[i + 1] === undefined) {
      throw new Error('usage: reproduce.mjs [--scratch DIR] [--snapshot-dir DIR] [--node PATH]');
    }
    o[argv[i]] = argv[i + 1];
  }
  return o;
}

const run = (bin, args, { allowFailure = false } = {}) => {
  try {
    return JSON.parse(execFileSync(bin, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  } catch (e) {
    if (allowFailure && e.stdout) return JSON.parse(e.stdout);
    throw new Error(`${bin} ${args[0]} failed: ${(e.stderr ?? '').toString().trim()}`);
  }
};

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const scratch = resolve(opts['--scratch'] ?? join(root, 'target/pii-evidence'));
  const node = resolve(opts['--node'] ?? process.execPath);
  const snapshotDir = resolve(opts['--snapshot-dir'] ?? join(root, 'fixtures/pii-evidence/snapshots/public-pii-phi/2026-10-07/9d4e8e036bbb'));
  const evidenceBin = join(root, 'target/release/pii-eval-evidence');
  const engineBin = join(root, 'target/release/pii-eval');
  for (const b of [evidenceBin, engineBin]) if (!existsSync(b)) throw new Error(`build first: cargo build --release --locked -p pii-eval-cli (${b})`);
  const pin = join(root, 'fixtures/pii-evidence/pin.json');
  const measurement = join(root, 'docs/measurements/pii-evidence-public-pii-phi-2026-10-07-9d4e8e036bbb');
  const record = JSON.parse(readFileSync(join(measurement, 'provenance.json'), 'utf8'));
  rmSync(scratch, { recursive: true, force: true });
  mkdirSync(scratch, { recursive: true });

  // 1-2. Verify, then import.
  const verified = run(evidenceBin, ['verify', '--snapshot-dir', snapshotDir, '--pin', pin]);
  const imported = run(evidenceBin, ['import', '--snapshot-dir', snapshotDir, '--pin', pin, '--out', join(scratch, 'import')]);

  // 3. The scanner, hermetically.
  const scanner = join(scratch, 'scanner');
  mkdirSync(scanner);
  for (const f of ['package.json', 'package-lock.json']) copyFileSync(join(root, 'tools/pii-evidence/scanner', f), join(scanner, f));
  execFileSync('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: scanner, stdio: 'ignore' });
  const modules = join(scanner, 'node_modules/@redact-secret');
  const platform = `${process.platform}-${process.arch}`;
  const addonName = `node-${platform}`;
  const trees = {
    core: treeSha256(join(modules, 'core')),
    addon: existsSync(join(modules, addonName)) ? treeSha256(join(modules, addonName)) : null,
    wasm: treeSha256(join(modules, 'wasm')),
  };
  const pinned = record.scanner.artifacts;
  if (trees.core !== pinned.packageTreeSha256) throw new Error('scanner package tree differs from the released digest');

  // 4. Plan and official configuration. Paths are relative to <scratch>.
  const shim = relative(scratch, join(root, 'crates/pii-eval-adapters/shims/node/redact-secret-core.mjs'));
  const extra = [
    trees.addon && { path: `scanner/node_modules/@redact-secret/${addonName}`, target: 'tree', sha256: trees.addon },
    { path: 'scanner/node_modules/@redact-secret/wasm', target: 'tree', sha256: trees.wasm },
  ].filter(Boolean);
  const config = (mode, manifestDigest) => ({
    schema: 'pii-eval-run-config/1',
    mode,
    runClass: 'public-synthetic',
    product: 'released',
    ...(mode === 'official' ? { engineVersion: record.engine.version, protocol: { id: 'pii-v1', revision: 2 } } : {}),
    snapshot: { path: 'import/snapshot.json', ...(mode === 'official' ? { semanticDigest: imported.semantic.population.semanticDigest } : {}) },
    manifest: { path: 'manifest.json', ...(manifestDigest ? { semanticDigest: manifestDigest } : {}) },
    scanners: [{
      adapter: 'redact-secret-core',
      shim: { path: shim },
      package: { dir: 'scanner/node_modules/@redact-secret/core', entry: 'dist/index.js', version: '0.1.0-beta.12', treeSha256: trees.core },
      extraArtifacts: extra,
    }],
    host: { maxWorkers: 2, resources: 'enforce' },
    ...(mode === 'official' ? { output: { dir: 'run', overwrite: 'refuse' } } : {}),
  });
  writeFileSync(join(scratch, 'run-config.plan.json'), `${JSON.stringify(config('exploratory'), null, 2)}\n`);
  const planned = run(evidenceBin, ['plan', '--config', join(scratch, 'run-config.plan.json'), '--node', node]);
  writeFileSync(join(scratch, 'run-config.json'), `${JSON.stringify(config('official', planned.semantic.manifestSemanticDigest), null, 2)}\n`);

  // 5. Execute (launches the scanner).
  const executed = run(engineBin, ['run', '--config', join(scratch, 'run-config.json'), '--node', node]);

  // 6. Replay (no scanner).
  const out = join(scratch, 'run');
  const replayed = run(engineBin, [
    'replay', '--snapshot', join(scratch, 'import/snapshot.json'), '--manifest', join(out, 'manifest.json'),
    '--observation', join(out, 'observation-redact-secret-core.json'), '--original', join(out, 'run-artifact.json'),
    '--out', join(scratch, 'replay'), '--expect-snapshot-digest', imported.semantic.population.semanticDigest,
    '--expect-manifest-digest', planned.semantic.manifestSemanticDigest,
  ]);

  // 7. Compare with the committed record.
  const got = {
    populationDigest: imported.semantic.population.semanticDigest,
    bindingDigest: imported.semantic.binding.semanticDigest,
    manifestDigest: executed.semantic.manifestDigest,
    observationDigest: executed.semantic.scanners[0].observationDigest,
    runArtifactDigest: executed.semantic.runArtifactDigest,
    publicArtifactDigest: executed.semantic.publicArtifactDigest,
  };
  const want = record.digests;
  const differences = Object.keys(want).filter((k) => got[k] !== want[k]);
  const report = {
    schema: 'pii-eval-evidence-reproduction/1',
    verified: verified.state,
    executed: { completeness: executed.semantic.completeness, replaysAgreed: executed.semantic.scanners[0].replays.agreed },
    replay: { state: replayed.state, parity: replayed.semantic?.parity ?? null, runArtifactDigest: replayed.semantic?.runArtifactDigest, publicArtifactDigest: replayed.semantic?.publicArtifactDigest },
    platform: { id: platform, addonPinned: trees.addon !== null, matchesRecordedAddon: trees.addon === pinned.addonTrees?.[platform] },
    observed: got,
    differences,
    reproduced: differences.length === 0 && replayed.semantic?.publicArtifactDigest === got.publicArtifactDigest,
  };
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exitCode = report.reproduced ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    process.stderr.write(`pii-evidence reproduce: ${e.message}\n`);
    process.exitCode = 2;
  }
}
