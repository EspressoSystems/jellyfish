#!/usr/bin/env bash
set -e

RUSTFLAGS='-C target-cpu=generic --cfg curve25519_dalek_backend="u32"' cargo build --target wasm32-unknown-unknown --no-default-features --features "test-srs, gadgets, bls, schnorr"