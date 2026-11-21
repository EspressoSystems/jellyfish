features := "test-srs test-apis bls schnorr gadgets"
# keep in sync with NIGHTLY in .github/workflows/build.yml and flake.nix
nightly := env("NIGHTLY", "nightly-2026-11-16")
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

# icicle* features need a CUDA toolchain, so they are excluded from cargo-hack runs
hack_exclude := "icicle,icicle-core,icicle-bn254,icicle-cuda-runtime"

# check every feature flag of every crate in isolation
check-each-feature:
    cargo hack check --workspace --each-feature --no-dev-deps --exclude-features '{{hack_exclude}}'

# check all pairs of feature flags (slow, run periodically)
check-feature-powerset:
    cargo hack check --workspace --feature-powerset --depth 2 --no-dev-deps --exclude-features '{{hack_exclude}}'

no-std:
    RUSTFLAGS='{{no_std_rustflags}}' cargo check --no-default-features --features 'bls schnorr gadgets'

[positional-arguments]
test *args:
    cargo nextest run --no-fail-fast --workspace --features '{{features}}' "$@"

doctest:
    cargo test --doc --no-fail-fast --workspace --features '{{features}}'

example:
    cargo run --release --example proof-of-exp --features test-srs

docs:
    cargo doc --no-deps --lib --release
