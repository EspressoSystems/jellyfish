# Jellyfish cryptographic library

![example workflow](https://github.com/EspressoSystems/jellyfish/actions/workflows/build.yml/badge.svg)
![Crates.io (version)](https://img.shields.io/crates/dv/jf-plonk/0.1.0)
![GitHub](https://img.shields.io/github/license/EspressoSystems/jellyfish)

## Disclaimer

**DISCLAIMER:** This software is provided "as is" and its security has not been externally audited. Use at your own risk.

## Chatroom

For general discussions on Jellyfish PLONK, please join our [Discord channel](https://discord.gg/GJa4gznGfU).

## Development environment setup

We recommend the following tools:

- [`nix`](https://nixos.org/download.html)
- [`direnv`](https://direnv.net/docs/installation.html)

Run `direnv allow` at the repo root. You should see dependencies (including Rust) being installed.
Alternatively, enter the nix-shell manually via `nix develop`.

You can check you are in the correct development environment by running `which cargo`, which should print
something like `/nix/store/2gb31jhahrm59n3lhpv1lw0wfax9cf9v-rust-minimal-1.69.0/bin/cargo`;
and running `echo $CARGO_HOME` should print `~/.cargo-nix`.

## Build, run tests and examples

Build:

```
cargo build
```

Run an example:

```
cargo run --release --example proof-of-exp --features test-srs
```

This is a simple example to prove and verify knowledge of exponent.
It shows how one may compose a circuit, and then build a proof for the circuit.

### WASM target

Jellyfish is `no_std` compliant and compilable to WASM target environment, just run:

```
./scripts/build_wasm.sh
```

### Backends

To choose different backends for arithemtics of `curve25519-dalek`, which is currently
used by `jf-primitives/aead`, set the environment variable:

```
RUSTFLAGS='--cfg curve25519_dalek_backend="BACKEND"'
```

See the full list of backend options [here](https://github.com/dalek-cryptography/curve25519-dalek#backends).

You could further configure the word size for the backend by setting (see [here](https://github.com/dalek-cryptography/curve25519-dalek#word-size-for-serial-backends)):

```
RUSTFLAGS='--cfg curve25519_dalek_bits="SIZE"'
```

### Tests

```
cargo test --release
```

Note that by default the _release_ mode does not check integers overflow.
In order to enforce this check run:

```
./scripts/run_tests.sh
```

#### Test coverage

We use [grcov](https://github.com/mozilla/grcov) for test coverage

```
./scripts/test_coverage.sh
```

### Generate and read the documentation

#### Standard

```
cargo doc --open
```

### Code formatting

To format your code run

```
cargo fmt
```

### Updating non-cargo dependencies

Run `nix flake update` if you would like to pin other version edit `flake.nix`
beforehand. Commit the lock file when happy.

To update only a single input specify it as argument, for example

    nix flake update github:oxalica/rust-overlay

### Benchmarks

#### Primitives

Currently, a benchmark for verifying Merkle paths is implemented.
The additional flags allow using assembly implementation of `square_in_place` and `mul_assign` within arkworks:

```bash
RUSTFLAGS='-Ctarget-cpu=native -Ctarget-feature=+bmi2,+adx' cargo bench --bench=merkle_path
```

#### PLONK proof generation/verification

For benchmark, run:

```
RAYON_NUM_THREADS=N cargo bench
```

where N is the number of threads you want to use (N = 1 for single-thread).

A sample benchmark result is available under [`bench.md`](./bench.md).

### Profiling

You could use `cargo flamegraph` (already installed in the nix-shell) as follows (more [documentations here](https://github.com/flamegraph-rs/flamegraph#examples)):

``` bash
# --root is necessary for Mac users
cargo flamegraph --root --bench=plonk-benches --features test-srs

# output to a specific file, targeting wasm
cargo flamegraph --root -o path/to/wasm-flamegraph.svg --bench=plonk-benches --no-default-features --features test-srs

# profile a specific test
cargo flamegraph --root --unit-test -p jf-primitives -- pcs::univariate_kzg::tests::end_to_end_test
```

You can also perform _causal profiling_ using [coz](https://github.com/plasma-umass/coz) only on Linux systems.

``` bash
# build the bench or example or binary that you want to profile
cargo build --bench reed-solomon-coz --features profiling --release

# you can find the binary inside ./target/<mode>/deps/<name>-<hash>
coz run --- ./target/release/deps/reed_solomon_coz-db5107103a0e378c

# plot your result
coz plot

# alternatively, view your profile.coz on https://plasma-umass.org/coz/
```

As an example, you can view `./primitives/src/reed_solomon_code/mod.rs::read_solomon_erasure_decode()` for some sample usages of `coz` annotation for latency profiling; view `./primitives/benches/reed_solomon_coz.rs` for the benchmark code.
You could also conduct throughput profiling, read more [here](https://github.com/plasma-umass/coz/tree/master/rust).
