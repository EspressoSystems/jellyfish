#!/usr/bin/env bash

# We want the code to panic if there is an integer overflow
export RUSTFLAGS="-C overflow-checks=on"

cargo test --release -p jf-utils -- -Zunstable-options --report-time
cargo test --release -p jf-plonk -- -Zunstable-options --report-time
cargo test --release -p jf-primitives -- -Zunstable-options --report-time
cargo test --release -p jf-rescue -- -Zunstable-options --report-time
cargo test --release -p jf-utils -- -Zunstable-options --report-time
cargo test --release -p jf-utils-derive -- -Zunstable-options --report-time

