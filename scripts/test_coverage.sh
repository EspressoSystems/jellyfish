#!/usr/bin/env bash
set -e
set -o xtrace
IGNORED_FILES="--ignore **/errors.rs\
               --ignore **/src/bin/*\
               --ignore transactions/src/parameters.rs\
               --ignore transactions/src/bench_utils/*\
              "
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=3 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests"
export RUSTDOCFLAGS=""
rm -vf ./target/**/*.gcda
cargo +nightly-2024-06-25 build --features "test-srs, gadgets, bls, schnorr"
cargo +nightly-2024-06-25 test --lib --features "test-srs, gadgets, bls, schnorr"
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing  $IGNORED_FILES -o ./target/debug/coverage/
echo "Coverage report available at target/debug/coverage/index.html."
