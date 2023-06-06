#!/usr/bin/env bash
set -e

# We want the code to panic if there is an integer overflow
export RUSTFLAGS="-C overflow-checks=on"

cargo +nightly test --release -p jf-utils -- -Zunstable-options --report-time
cargo +nightly test --release -p jf-plonk --lib --bins -- -Zunstable-options --report-time
cargo +nightly test --release -p jf-primitives -- -Zunstable-options --report-time
cargo +nightly test --release -p jf-relation -- -Zunstable-options --report-time
