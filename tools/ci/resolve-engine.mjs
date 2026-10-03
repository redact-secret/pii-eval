#!/usr/bin/env node
// Chooses which engine artifact of which workflow run evaluate.yml may use
// (docs/ci-artifacts.md). Standard library plus the preinstalled `gh` CLI.
//
//   GH_TOKEN=... node tools/ci/resolve-engine.mjs --run-id ID --current-run-id ID \
//     --repository OWNER/REPO [--allow-unverified-ref true|false] [--github-output FILE]
//
// Why this exists: `engine-run-id` is untrusted text and any run id of the
// repository is a valid-looking value, including a pull request's run, a failed
// run and a run on another branch. Whatever ends up in `build-info.json` and
// `SHA256SUMS` can be rewritten by whoever can write the artifact, so those files
// are not what decides trust. This script decides from GitHub's own record of the
// run instead:
//   - the run of THIS workflow run (the engine was built a moment ago): accepted;
//   - any other run: it must be completed and successful, a `push` or
//     `workflow_dispatch` on `main` of this repository, of one of this
//     repository's own build workflows, and its artifact must be named after the
//     run's head commit; anything else (a pull request run, another branch)
//     needs the explicit `--allow-unverified-ref true`;
//   - exactly one unexpired artifact named pii-eval-engine-<40 hex>-linux-x86_64.
// Output is validated before it is written anywhere (the output file is a
// workflow command channel).
import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { isMain } from './main-guard.mjs';

export const SUMMARY_SCHEMA = 'pii-eval-engine-resolve/1';
const NAME = /^pii-eval-engine-([0-9a-f]{40})-linux-x86_64$/;
const WORKFLOWS = ['ci.yml', 'build-engine.yml', 'evaluate.yml'];
const EVENTS = ['push', 'workflow_dispatch'];

export class Refusal extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export function decide({ run, artifacts, runId, currentRunId, repository, allowUnverified }) {
  if (!/^[0-9]{1,20}$/.test(runId) || !/^[0-9]{1,20}$/.test(currentRunId)) throw new Refusal('run-id-invalid');
  const same = runId === currentRunId;
  const trusted = { event: null, branch: null };
  if (!same) {
    if (!run || run.status !== 'completed') throw new Refusal('run-not-completed');
    if (run.conclusion !== 'success') throw new Refusal('run-not-successful');
    if (!allowUnverified) {
      if (!EVENTS.includes(run.event)) throw new Refusal('run-event-not-allowed');
      if (run.head_branch !== 'main') throw new Refusal('run-not-on-main');
      const repo = run.repository && run.repository.full_name;
      const headRepo = run.head_repository && run.head_repository.full_name;
      if (repo !== repository || headRepo !== repository) throw new Refusal('run-from-another-repository');
      // GitHub reports `.github/workflows/ci.yml` (verified against real runs); a
      // `@<ref>` suffix is accepted only for main.
      const m = /^\.github\/workflows\/([A-Za-z0-9._-]+)(?:@(.+))?$/.exec(typeof run.path === 'string' ? run.path : '');
      if (!m || !WORKFLOWS.includes(m[1]) || (m[2] !== undefined && m[2] !== 'refs/heads/main')) {
        throw new Refusal('run-from-another-workflow');
      }
    }
    trusted.event = run.event;
    trusted.branch = run.head_branch;
  }
  const list = Array.isArray(artifacts && artifacts.artifacts) ? artifacts.artifacts : [];
  const matches = list.filter((a) => a && typeof a.name === 'string' && NAME.test(a.name) && a.expired !== true);
  if (matches.length === 0) throw new Refusal('no-engine-artifact');
  if (matches.length > 1) throw new Refusal('several-engine-artifacts');
  const name = matches[0].name;
  const commit = NAME.exec(name)[1];
  if (!same && EVENTS.includes(run.event) && run.head_sha !== commit) throw new Refusal('artifact-commit-differs-from-run');
  return { artifactName: name, commit, runId, event: trusted.event, branch: trusted.branch, sameRun: same };
}

function gh(path) {
  const out = execFileSync('gh', ['api', '-H', 'Accept: application/vnd.github+json', path], {
    encoding: 'utf8',
    timeout: 60000,
    maxBuffer: 8 * 1024 * 1024,
  });
  return JSON.parse(out);
}

function parse(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith('--') || i + 1 >= argv.length) throw new Refusal('usage');
    o[argv[i].slice(2)] = argv[i + 1];
  }
  for (const k of ['run-id', 'current-run-id', 'repository']) if (typeof o[k] !== 'string') throw new Refusal('usage');
  if (!/^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/.test(o.repository)) throw new Refusal('usage');
  if (o['allow-unverified-ref'] !== undefined && !['true', 'false'].includes(o['allow-unverified-ref'])) throw new Refusal('usage');
  return o;
}

if (isMain(import.meta.url)) {
  try {
    const o = parse(process.argv.slice(2));
    if (!/^[0-9]{1,20}$/.test(o['run-id'])) throw new Refusal('run-id-invalid');
    const same = o['run-id'] === o['current-run-id'];
    const base = `repos/${o.repository}/actions/runs/${o['run-id']}`;
    const run = same ? null : gh(base);
    const artifacts = gh(`${base}/artifacts?per_page=100`);
    const d = decide({
      run,
      artifacts,
      runId: o['run-id'],
      currentRunId: o['current-run-id'],
      repository: o.repository,
      allowUnverified: o['allow-unverified-ref'] === 'true',
    });
    if (o['github-output']) appendFileSync(o['github-output'], `artifact-name=${d.artifactName}\ncommit=${d.commit}\n`);
    process.stdout.write(`${JSON.stringify({ schema: SUMMARY_SCHEMA, ok: true, ...d })}\n`);
  } catch (e) {
    const code = e instanceof Refusal ? e.code : 'internal';
    process.stdout.write(`${JSON.stringify({ schema: SUMMARY_SCHEMA, ok: false, reason: code })}\n`);
    process.exit(code === 'usage' ? 2 : 1);
  }
}
