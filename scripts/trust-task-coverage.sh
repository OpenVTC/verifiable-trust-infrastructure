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
# `tests/` is its own process. So each process writes the tasks it observed to
# its own file under a shared directory and this script aggregates them.
#
# One file per process, not one shared file: the shared-append version lost
# whole binaries' observations intermittently, reporting 31 tasks on one run and
# 33 on the next off identical code.
set -euo pipefail

cd "$(dirname "$0")/.."

OBSERVED="${TRUST_TASK_OBSERVED_DIR:-$PWD/target/trust-task-observed}"
rm -rf "$OBSERVED"       # stale files would overstate coverage
mkdir -p "$OBSERVED"
export TRUST_TASK_OBSERVED_DIR="$OBSERVED"

echo "==> running the vta-service suite (observations -> $OBSERVED/<pid>.tasks)"
# `--no-fail-fast` so a failing binary still contributes what it exercised:
# coverage of a partial run is a floor, and a floor beats no number.
cargo test -p vta-service --no-fail-fast "$@" || true

echo "==> coverage"
cargo test -p vta-service --lib -- --ignored --nocapture report_task_coverage
