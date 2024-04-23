# Jellyfish cryptographic library

![example workflow](https://github.com/EspressoSystems/jellyfish/actions/workflows/build.yml/badge.svg)
![Crates.io (version)](https://img.shields.io/crates/dv/jf-plonk/0.1.0)
![GitHub](https://img.shields.io/github/license/EspressoSystems/jellyfish)

## Disclaimer

**DISCLAIMER:** This software is provided "as is" and its security has not been externally audited. Use at your own risk.

## Chatroom

For general discussions on Jellyfish PLONK, please join our [Discord channel](https://discord.gg/GJa4gznGfU).

## Crates

### Helper
- ['utilities'](jf_utils): utilities and helper functions.

### Primitives
- ['traits'](jf_traits): trait definitions for PRF, CRHF and commitment scheme.
- ['rescue'](jf_rescue): Rescue hash function, and its subsequent PRF, CRHF, commitment scheme implementations.
- ['elgamal'](jf_elgamal): a Rescue-based ElGamal encryption scheme implementation.
- ['signature'](jf_signature): signature scheme trait definition, and BLS/Schnorr signature scheme implementations.
- ['vrf'](jf_vrf): verifiable random function trait definition and BLS-based implementation.
- ['aead'](jf_aead): authenticated encryption with associated data (AEAD) implementation.
- ['merkle_tree'](jf_merkle_tree): various (vanilla, sparse, namespaced) Merkle tree trait definitions and implementations.
- ['pcs'](jf_pcs): polynomial commitment scheme (PCS) trait definitions and univariate/multilinear KZG-PCS implementations.
- ['vdf'](jf_vdf): verifiable delay function (VDF) trait definitions and (non-verifiable) MinRoot implementation.
- ['vid'](jf_vid): verifiable information dispersal (VID) trait definition and implementation.

### Plonk
- ['relation'](jf_relation): Jellyfish constraint system for PLONK.
- ['plonk'](jf_plonk): KZG-PCS based TurboPlonk and UltraPlonk implementations.

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

To choose different backends for arithmetics of `curve25519-dalek`, which is currently
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

## Git Hooks

The pre-commit hooks are installed via the nix shell. To run them on all files use

```
pre-commit run --all-files
```
