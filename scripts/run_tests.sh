#!/usr/bin/env bash
# Usage: run_tests.sh [--list | package...]  (no arguments: all packages)
set -euo pipefail

# We want the code to panic if there is an integer overflow
export RUSTFLAGS="-C overflow-checks=on"

# CI sets NIGHTLY from .github/workflows/build.yml
NIGHTLY="${NIGHTLY:-nightly-2025-09-04}"

TESTS=(
  "jf-utils"
  "jf-plonk --lib --bins"
  "jf-merkle-tree --features gadgets"
  "jf-pcs --features test-srs"
  "jf-rescue --features gadgets"
  "jf-signature --features bls,schnorr,gadgets"
  "jf-aead"
  "jf-elgamal --features gadgets"
  "jf-vrf"
  "jf-prf"
  "jf-crhf"
  "jf-commitment"
)

if [ "${1:-}" = "--list" ]; then
  for t in "${TESTS[@]}"; do echo "${t%% *}"; done
  exit
fi

ran=0
for t in "${TESTS[@]}"; do
  pkg="${t%% *}"
  if [ $# -gt 0 ] && [[ " $* " != *" $pkg "* ]]; then continue; fi
  # shellcheck disable=SC2086
  cargo +"$NIGHTLY" test --release -p $t -- -Zunstable-options --report-time
  ran=$((ran + 1))
done
[ $# -eq 0 ] || [ "$ran" -eq $# ] || { echo "unknown package in: $*" >&2; exit 1; }
