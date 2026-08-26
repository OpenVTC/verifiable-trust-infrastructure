#!/usr/bin/env bash
# Report how much of the VTA's Trust Task response surface the test suite
# actually exercises.
#
# The conformance layer in `vta-service/src/test_support/response_conformance.rs`
# validates every response a test provokes. It can only validate what it sees,
# so "zero violations" is meaningful only against the number this script
# prints — the first time it ran, the suite touched 29 of 79 checkable tasks,
# and a clean report over a third of the surface reads far stronger than it is.
#
# Coverage is a property of a run, not of a process, and every binary under
# `tests/` is its own process. So the layer appends each task it observes to a
# shared file and this script aggregates, rather than trying to hold the set in
# memory somewhere.
set -euo pipefail

cd "$(dirname "$0")/.."

OBSERVED="${TRUST_TASK_OBSERVED_FILE:-$PWD/target/trust-task-observed.txt}"
mkdir -p "$(dirname "$OBSERVED")"
: > "$OBSERVED"          # a stale file would overstate coverage
export TRUST_TASK_OBSERVED_FILE="$OBSERVED"

echo "==> running the vta-service suite (observations -> $OBSERVED)"
# `--no-fail-fast` so a failing binary still contributes what it exercised:
# coverage of a partial run is a floor, and a floor beats no number.
cargo test -p vta-service --no-fail-fast "$@" || true

echo "==> coverage"
cargo test -p vta-service --lib -- --ignored --nocapture report_task_coverage
