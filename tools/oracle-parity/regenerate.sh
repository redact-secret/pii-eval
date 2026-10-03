#!/bin/bash
# Regenerate (or verify) the committed oracle export. A MANUAL step: it needs `gh` with read
# access to redact-secret/redact-secret-benchmarks and Node >= 22.6. CI never runs it.
#
# Usage: tools/oracle-parity/regenerate.sh <scratch-dir> [--update]
#
#   1. fetches the pinned oracle files into <scratch-dir>/oracle and verifies them (commit SHA,
#      git blob SHAs against the pinned tree, tree digest);
#   2. rebuilds the frozen input from make-input.mjs and compares it with the committed input;
#   3. runs the oracle's own code on the input TWICE and requires the two exports to be
#      byte-identical (reproducibility);
#   4. compares the export with the committed one. Without --update a difference is an error
#      (the committed export is stale, or the oracle, Node or a script changed). With --update the
#      committed input and export are replaced; review the diff and rerun the parity suite with
#      PII_EVAL_UPDATE_FIXTURES=1 to refresh the report (docs/migration/oracle-parity-report.md).
#
# Nothing is written outside <scratch-dir> and, with --update, fixtures/oracle-parity/.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SCRATCH="${1:?usage: regenerate.sh <scratch-dir> [--update]}"
UPDATE="${2:-}"
FIX="$ROOT/fixtures/oracle-parity"
mkdir -p "$SCRATCH/out"

node -e 'const [a,b]=process.versions.node.split(".").map(Number); if (a<22||(a===22&&b<6)) { console.error("Node >= 22.6 is required"); process.exit(1); }'
node "$HERE/fetch-oracle.mjs" "$SCRATCH"
node "$HERE/make-input.mjs" "$SCRATCH/out/input.json"

run_export() {
  node --experimental-strip-types --no-warnings --import "$HERE/register.mjs" \
    "$HERE/export-oracle.mjs" "$SCRATCH/oracle" "$SCRATCH/out/input.json" "$1"
}
run_export "$SCRATCH/out/export-1.json"
run_export "$SCRATCH/out/export-2.json"
cmp "$SCRATCH/out/export-1.json" "$SCRATCH/out/export-2.json"
echo "reproducible: two runs are byte-identical"

if [ "$UPDATE" = "--update" ]; then
  mkdir -p "$FIX"
  cp "$SCRATCH/out/input.json" "$FIX/input.json"
  cp "$SCRATCH/out/export-1.json" "$FIX/oracle-export.json"
  echo "updated $FIX/input.json and $FIX/oracle-export.json"
else
  cmp "$SCRATCH/out/input.json" "$FIX/input.json"
  cmp "$SCRATCH/out/export-1.json" "$FIX/oracle-export.json"
  echo "verified: the committed input and export equal a fresh regeneration"
fi
