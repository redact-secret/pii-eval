# Oracle parity tooling

Manual tooling that produces the committed oracle export used by the parity
suite (`crates/pii-eval-cli/tests/oracle_parity.rs`). Method, classification and
limits: [ADR 0012](../../docs/adr/0012-oracle-parity-and-migration-evidence.md);
results: [the generated report](../../docs/migration/oracle-parity-report.md).

**CI never runs these scripts.** CI has no access to the private oracle
repository or to the npm registry; it compares the Rust engine against the
COMMITTED exports and checks that the export manifest and the oracle pin are
unchanged. Regenerating the export is a documented manual step. The only thing CI
does with this directory is syntax-check the scripts.

## Needs

- `gh`, authenticated, with read access to `redact-secret/redact-secret-benchmarks`
  (read-only; nothing is ever written to that repository);
- Node >= 22.6 (the export records the Node and ICU versions it ran on; a different
  Node patch version can change `provenance.runtime` and so the file bytes);
- for the real-scanner step only: `npm` and network access to the public registry.

## Files

| File | Role |
| --- | --- |
| `oracle-files.json` | The oracle commit pin and the exact list of oracle files that are fetched, with their tree digest |
| `fetch-oracle.mjs` | Fetch those files at the pin and verify the commit, every git blob id and the tree digest |
| `hooks.mjs`, `register.mjs`, `stubs/` | Node module hooks that let the unmodified oracle TypeScript run under Node 22 type stripping: an `ajv` stub, JSON imports and a stub for the evidence loader |
| `make-input.mjs` | Authors the frozen synthetic input `fixtures/oracle-parity/input.json` |
| `export-oracle.mjs` | Runs the oracle's own code on the input and writes the export (integers and strings only, sorted keys) |
| `lib.mjs` | Digests and deterministic JSON |
| `regenerate.sh` | Fetch, rebuild the input, export twice (byte-identical), compare with or replace the committed files |
| `real-scanner/` | Opt-in same-pinned-scanner run: hermetic install of `@redact-secret/core` 0.1.0-beta.12 from the oracle's lockfile entries, the oracle's own adapter over the frozen input, the committed real-scanner export |

## Verify the committed export (does not change the repository)

```sh
tools/oracle-parity/regenerate.sh "$(mktemp -d)"
```

This fetches the pinned oracle files into the scratch directory, checks them,
rebuilds `input.json`, runs the oracle twice and fails unless both exports are
byte-identical to each other and to `fixtures/oracle-parity/oracle-export.json`.

## Refresh after a reviewed change

```sh
tools/oracle-parity/regenerate.sh "$SCRATCH" --update
PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test oracle_parity   # report.json and the Markdown report
cargo test -p pii-eval-cli --locked --test oracle_parity --test real_scanner
```

Change `make-input.mjs` only to add cases or scanner behaviors; never to make an
engine agree. A change to the oracle file list or the pin also changes the tree
digest, which is recorded in `oracle-files.json` and in a constant of
`oracle_parity.rs` on purpose.

## Real scanner (opt-in)

```sh
tools/oracle-parity/real-scanner/run.sh "$SCRATCH"            # verify the committed real-core-export.json
tools/oracle-parity/real-scanner/run.sh "$SCRATCH" --update   # replace it
```

The script prints the command that runs the Rust adapter and engine over the same
installed package (`PII_EVAL_REDACT_SECRET_CORE_DIR=... cargo test -p pii-eval-cli
--test real_scanner`). The install is `npm ci --ignore-scripts` against a lockfile
that holds only the `@redact-secret/*` entries of the oracle's verified lockfile,
so npm refuses any tarball whose integrity differs; nothing else is installed and
no install script runs. Install into a scratch directory, never into this
repository.

## What is not here

No protected corpus, no live credential and no scanner output beyond the
synthetic observations in the committed exports. No oracle source is copied into
this repository. Do not post anything to the benchmarks repository from here; the
consumer handoff is a document
([benchmarks-handoff-664.md](../../docs/migration/benchmarks-handoff-664.md)).
