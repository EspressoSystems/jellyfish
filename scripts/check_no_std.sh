#!/usr/bin/env bash

set -x

cargo-nono check --no-default-features --package jf-utils
cargo-nono check --no-default-features --package jf-rescue
cargo-nono check --no-default-features --package jf-primitives
cargo-nono check --no-default-features --package jf-plonk
