#!/usr/bin/env bash
set -e

# We want the code to panic if there is an integer overflow
export RUSTFLAGS="-C overflow-checks=on"

cargo +nightly-2025-09-04 test --release -p jf-utils -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-plonk --lib --bins -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-merkle-tree --features gadgets -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-pcs --features test-srs -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-rescue --features gadgets -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-signature --features "bls, schnorr, gadgets" -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-vid --features test-srs -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-aead -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-elgamal --features gadgets -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-vrf -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-prf -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-crhf -- -Zunstable-options --report-time
cargo +nightly-2025-09-04 test --release -p jf-commitment -- -Zunstable-options --report-time
