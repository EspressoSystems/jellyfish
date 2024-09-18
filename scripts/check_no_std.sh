#!/usr/bin/env bash
set -e
set -x

# WARN: cargo-nono is reporting false positives.
cargo-nono check --no-default-features --package jf-utils
cargo-nono check --no-default-features --package jf-relation
cargo-nono check --no-default-features --package jf-merkle-tree --features "gadgets"
cargo-nono check --no-default-features --package jf-pcs --features "test-srs"
cargo-nono check --no-default-features --package jf-rescue --features "gadgets"
cargo-nono check --no-default-features --package jf-signature --features "bls, schnorr, gadgets"
cargo-nono check --no-default-features --package jf-vid --features "test-srs"
cargo-nono check --no-default-features --package jf-aead
cargo-nono check --no-default-features --package jf-elgamal --features "gadgets"
cargo-nono check --no-default-features --package jf-vrf
cargo-nono check --no-default-features --package jf-prf
cargo-nono check --no-default-features --package jf-crhf
cargo-nono check --no-default-features --package jf-commitment
