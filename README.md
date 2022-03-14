# Jellyfish cryptographic library
![example workflow](https://github.com/EspressoSystems/jellyfish/actions/workflows/build.yml/badge.svg)
![Crates.io (version)](https://img.shields.io/crates/dv/jf-plonk/0.1.0)
![GitHub](https://img.shields.io/github/license/EspressoSystems/jellyfish)

## Disclaimer

**DISCLAIMER:** This software is provided "as is" and its security has not been externally audited. Use at your own risk.

## Chatroom
 
For general discussions on Jellyfish PLONK, please join our [Discord channel](https://discord.gg/GJa4gznGfU).

## Development environment setup

### Install RUST

We recommend to use nix for installing the correct version of rust and
additional libraries:

```bash
> curl -L https://nixos.org/nix/install | sh
> . ~/.nix-profile/etc/profile.d/nix.sh
```

### Compiling the project for the first time

```bash
> nix-shell
> cargo build
```

### Direnv

To avoid manually activating the nix shell each time the
[direnv](https://direnv.net/) shell extension can be used to activate the
environment when entering the local directory with the checkout of this repo.
Note that direnv needs to be [installed](https://direnv.net/docs/installation.html) first, and to be [hooked](https://direnv.net/docs/hook.html) into
the shell to function.

To allow `direnv` for this repo run

    direnv allow

from within the local checkout of this repo.

### Git Hooks

The pre-commit hooks are installed via the nix shell. To run them on all files use

```
> pre-commit run --all-files
```

### Get start

```
> cargo run --release --example proof_of_exp
```

This is a simple example to prove and verify knowledge of exponent.
It shows how one may compose a circuit, and then build a proof for the circuit.

### Tests

```
> cargo test --release
```

Note that by default the _release_ mode does not check integers overflow.
In order to enforce this check run:

```
> ./scripts/run_tests.sh
```

#### Test coverage

We use [grcov](https://github.com/mozilla/grcov) for test coverage

```
> ./scripts/test_coverage.sh
```

### Generate and read the documentation

#### Standard

```
> cargo doc --open
```

### Code formatting

To format your code run

```
> cargo fmt
```

### Updating non-cargo dependencies

- To update the [nix packages](https://github.com/NixOS/nixpkgs) run `./nix/update-nix`.
- To update the [rust overlay](https://github.com/oxalica/rust-overlay) run
  `./nix/update-rust-overlay`.

To use the updates enter a new `nix-shell`.

### Testing the nix-shell dev environment on other platforms

Refer to the [nix/vagrant](./nix/vagrant/) directory.

### Benchmarks

#### Primitives

Currently, a benchmark for verifying Merkle paths is implemented.
The additional flags allow using assembly implementation of `square_in_place` and `mul_assign` within arkworks:

```bash
> RUSTFLAGS='-Ctarget-cpu=native -Ctarget-feature=+bmi2,+adx' cargo bench --bench=merkle_path
```

#### PLONK proof generation/verification

For benchmark, run:

```
RAYON_NUM_THREADS=N cargo bench --features bench
```

where N is the number of threads you want to use (N = 1 for single-thread).

A sample benchmark result is available under [`bench.md`](./bench.md).
