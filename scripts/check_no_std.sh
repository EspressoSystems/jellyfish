#!/usr/bin/env bash
set -e
set -x

cargo-nono check --no-default-features --package jf-utils
cargo-nono check --no-default-features --package jf-relation
cargo-nono check --no-default-features --package jf-primitives
cargo-nono check --no-default-features --package jf-primitives-core
cargo-nono check --no-default-features --package jf-merkle-tree
cargo-nono check --no-default-features --package jf-pcs
cargo-nono check --no-default-features --package jf-rescue
cargo-nono check --no-default-features --package jf-signature --features "bls, schnorr, gadgets"
cargo-nono check --no-default-features --package jf-vdf
cargo-nono check --no-default-features --package jf-vid
