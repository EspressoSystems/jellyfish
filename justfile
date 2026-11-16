features := "test-srs test-apis bls schnorr gadgets"
nightly := env("NIGHTLY", "nightly")
no_std_rustflags := '-C target-cpu=generic --cfg curve25519_dalek_backend="u32"'

default:
    @just --list

fmt-check:
    cargo +{{nightly}} fmt -- --check

clippy:
    cargo clippy --workspace --features '{{features}}' -- -D warnings

check-bench:
    cargo bench --features 'test-srs bls bls12-381 schnorr gadgets' --no-run

check-tests:
    cargo check --workspace --tests --lib --bins

check-features:
    cargo check --workspace --features 'std parallel {{features}}'

no-std:
    RUSTFLAGS='{{no_std_rustflags}}' cargo check --no-default-features --features 'bls schnorr gadgets'

wasm:
    RUSTFLAGS='{{no_std_rustflags}}' cargo build --target wasm32-unknown-unknown --no-default-features --features 'bls schnorr gadgets'

[positional-arguments]
test *args:
    cargo nextest run --no-fail-fast --workspace --features '{{features}}' "$@"

doctest:
    cargo test --doc --no-fail-fast --workspace --features '{{features}}'

example:
    cargo run --release --example proof-of-exp --features test-srs

docs:
    cargo doc --no-deps --lib --release
