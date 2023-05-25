#!/usr/bin/env bash
set -e

RUSTFLAGS="-C target-cpu=generic" cargo build --target wasm32-unknown-unknown --no-default-features