#!/bin/zsh
# Runs Metal Miner's tests.
#
#   ./test.sh          unit tests: offline and quick, no GPU (Stratum handling, settings, the engine's choices,
#                      quiet mode, formatting, CLI flags)
#   ./test.sh NAME     only the unit tests whose name contains NAME, e.g. ./test.sh Quiet
#   ./test.sh --gpu    the unit tests, then on the GPU: every algorithm's official vectors and GPU/CPU cross-check,
#                      the Stratum layer, and every pool connection against a local test pool (a few minutes)
set -euo pipefail
ROOT="${0:A:h}"
GPU=0
ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "--gpu" ]]; then GPU=1; else ARGS+=("$arg"); fi
done
"$ROOT/build.sh" --tests
"$ROOT/.build/all/metalminer-tests" "${ARGS[@]}"
if (( GPU )); then
  "$ROOT/.build/all/metalminer" stratumtest
  "$ROOT/.build/all/metalminer" test all
  "$ROOT/.build/all/metalminer" pooltest
fi
