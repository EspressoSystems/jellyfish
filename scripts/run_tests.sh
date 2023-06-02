#!/usr/bin/env bash
set -e

# We want the code to panic if there is an integer overflow
export RUSTFLAGS="-C overflow-checks=on"

cargo test --release -p jf-utils -- --report-time
cargo test --release -p jf-plonk --lib --bins -- --report-time
cargo test --release -p jf-primitives -- --report-time
cargo test --release -p jf-relation -- --report-time
