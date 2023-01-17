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

## Build, run tests and examples

Build:

```
cargo build
```

Run an example:

```
cargo run --release --example proof_of_exp
```

This is a simple example to prove and verify knowledge of exponent.
It shows how one may compose a circuit, and then build a proof for the circuit.

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

## Git Hooks

The pre-commit hooks are installed via the nix shell. To run them on all files use

```
pre-commit run --all-files
```
