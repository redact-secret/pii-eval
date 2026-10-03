#!/bin/bash
# Regenerate tests/vectors/oracle_methods.rs from the pinned oracle. Not run in CI.
# Needs: gh (authenticated, read access to redact-secret/redact-secret-benchmarks) and Node >= 22.6.
# Usage: regenerate_oracle_vectors.sh <scratch-dir>
set -euo pipefail
PIN=4b846967346505baca11e0b98cab1475fbce6773   # oracle commit (ADR 0001)
HERE="$(cd "$(dirname "$0")" && pwd)"
T="${1:?scratch dir}/otree"
B=benchmarks/evaluation/domains/pii
raw() { gh api "repos/redact-secret/redact-secret-benchmarks/contents/$1?ref=$PIN" -H "Accept: application/vnd.github.raw"; }
for f in \
  $B/methods/benign.ts $B/methods/common.ts $B/methods/context-discrimination.ts $B/methods/jurisdiction-collision.ts \
  $B/methods/mutation.ts $B/methods/reference-differential.ts $B/methods/schema-only.ts $B/methods/type-validation.ts \
  $B/operators.ts $B/validators.ts $B/contract-model.ts $B/jurisdictions.ts $B/types.ts $B/benign-collision-classes.ts \
  benchmarks/evaluation/substrate/hash.ts benchmarks/evaluation/substrate/variant-lifecycle.ts \
  benchmarks/evaluation/substrate/registry.ts benchmarks/evaluation/substrate/runtime.ts; do
  mkdir -p "$T/$(dirname "$f")"
  raw "$f" > "$T/$f"
done
raw $B/context-evidence-v1.json > "$1/context-evidence-v1.json"
# The two oracle modules that load evidence corpora through Ajv are replaced by stubs.
cp "$HERE/oracle_stubs/"*.ts "$T/$B/"
node --experimental-strip-types "$HERE/oracle_methods_driver.mjs" "$T" "$1/context-evidence-v1.json" "$HERE/oracle_methods.rs"
