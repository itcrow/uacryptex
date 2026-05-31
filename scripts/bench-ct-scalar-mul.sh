#!/usr/bin/env bash
# Compare DSTU 4145 M257 verify/sign latency with and without ct-scalar-mul.
# Exit criteria (7.3b): CT path should not regress more than ~20% vs legacy on verify.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BENCH_FILTER="${1:-dstu4145}"

run_bench() {
  local label="$1"
  shift
  echo "=== ${label} ==="
  cargo bench -p uacryptex-core --bench crypto "$@" -- "${BENCH_FILTER}" --noplot 2>&1 \
    | grep -E 'time:|Benchmarking' || true
  echo
}

run_bench "legacy (default)"
run_bench "ct-scalar-mul" --features ct-scalar-mul

echo "See docs/PHASE7_BACKLOG.md §7.3 for acceptance criteria."
