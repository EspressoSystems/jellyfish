#!/usr/bin/env bash
set -e
set -x

cargo-nono check --no-default-features --package jf-utils
cargo-nono check --no-default-features --package jf-relation
cargo-nono check --no-default-features --package jf-primitives --features "test-srs, gadgets"
cargo-nono check --no-default-features --package jf-primitives-core
cargo-nono check --no-default-features --package jf-merkle-tree --features "gadgets"
cargo-nono check --no-default-features --package jf-pcs --features "test-srs"
cargo-nono check --no-default-features --package jf-rescue --features "gadgets"
cargo-nono check --no-default-features --package jf-signature --features "bls, schnorr, gadgets"
cargo-nono check --no-default-features --package jf-vdf
cargo-nono check --no-default-features --package jf-vid --features "test-srs"
