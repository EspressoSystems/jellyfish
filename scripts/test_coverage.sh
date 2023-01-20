#!/usr/bin/env nix-shell
#!nix-shell ../nix/nightly.nix -i bash
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
cargo build
cargo test --lib
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing  $IGNORED_FILES -o ./target/debug/coverage/
echo "Coverage report available at target/debug/coverage/index.html."
