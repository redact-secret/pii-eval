#!/bin/bash
# Opt-in, MANUAL: same-pinned-scanner parity. Installs the real `@redact-secret/core` 0.1.0-beta.12
# hermetically, runs the ORACLE's own adapter and pipeline over the frozen parity input with it, and
# writes (or verifies) the committed synthetic observation export. Not part of CI. Needs `gh` (read access
# to the oracle repository), `npm` with network access to the public registry, and Node >= 22.6.
#
# Usage: tools/oracle-parity/real-scanner/run.sh <scratch-dir> [--update]
#
# What it does, in order:
#   1. fetches and verifies the pinned oracle files (../fetch-oracle.mjs), including its package-lock.json;
#   2. builds a package.json and a package-lock.json from the oracle lockfile's @redact-secret entries only
#      (make-lock.mjs: version, resolved URL and sha512 integrity copied verbatim);
#   3. `npm ci --ignore-scripts --no-audit --no-fund`: npm refuses any tarball whose integrity differs from
#      the lockfile; no install script runs and no other package is installed;
#   4. runs the oracle's `loadCandidate` (scanners/candidate.mjs) over the parity input, twice, and requires
#      the two exports to be byte-identical;
#   5. verifies the export against `fixtures/oracle-parity/real-core-export.json`, or replaces it (--update).
# It then prints the command that runs the Rust engine over the same package (the live end-to-end check).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$TOOLS/../.." && pwd)"
SCRATCH="${1:?usage: run.sh <scratch-dir> [--update]}"
UPDATE="${2:-}"
FIX="$ROOT/fixtures/oracle-parity"
mkdir -p "$SCRATCH/out"

node "$TOOLS/fetch-oracle.mjs" "$SCRATCH"
node "$HERE/make-lock.mjs" "$SCRATCH/oracle" "$SCRATCH/real-core" > "$SCRATCH/out/real-lock.json"
(cd "$SCRATCH/real-core" && npm ci --ignore-scripts --no-audit --no-fund)

run_export() {
  node --experimental-strip-types --no-warnings --import "$TOOLS/register.mjs" \
    "$TOOLS/export-oracle.mjs" "$SCRATCH/oracle" "$FIX/input.json" "$1" "$SCRATCH/real-core"
}
run_export "$SCRATCH/out/real-1.json"
run_export "$SCRATCH/out/real-2.json"
cmp "$SCRATCH/out/real-1.json" "$SCRATCH/out/real-2.json"
echo "reproducible: two runs are byte-identical"

if [ "$UPDATE" = "--update" ]; then
  cp "$SCRATCH/out/real-1.json" "$FIX/real-core-export.json"
  echo "updated $FIX/real-core-export.json"
else
  cmp "$SCRATCH/out/real-1.json" "$FIX/real-core-export.json"
  echo "verified: the committed real-scanner export equals a fresh run"
fi
echo
echo "Live Rust end-to-end check (Rust adapter and shim over the same package):"
echo "  PII_EVAL_REDACT_SECRET_CORE_DIR=$SCRATCH/real-core/node_modules/@redact-secret/core \\"
echo "  cargo test -p pii-eval-cli --test real_scanner --locked -- --nocapture"
