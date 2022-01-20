# Jellyfish cryptographic library

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

### Git Hooks

We use [`cargo-husky`](https://github.com/rhysd/cargo-husky) to automatically load any scripts under `.cargo-husky/hooks` into `.git/hooks`.

Changes made to any `.cargo-husky/hooks` will be automatically synced to `.git/` every time you run `cargo test` -- no special extra command to run.

### Tests

```
> cargo test --release
```

Note that by default the *release* mode does not check integers overflow.
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


#### Plonk proof generation/verification
For benchmark, run:
```
RAYON_NUM_THREADS=N cargo bench
```
where N is the number of threads you want to use (N = 1 for single-thread).

##### Environment
- MacBoo Pro (16-inch, 2019)
- Processor: 2.3 GHz 8-Core Intel Core i9
- Memory: 6 GB 2667 MHz DDR4

##### TurboPlonk
- BLS12-381: Proving time: 59317 ns/constraint; Verifying time: 3.207 ms; Batch verifying time for 1000 proofs: 17.683 ms
- BN-254: Proving time: 44857 ns/constraint; Verifying time: 2.364 ms; Batch verifying time for 1000 proofs: 14.803 ms
- BW6-761: Proving time: 271828 ns/constraint; Verifying time: 12.504 ms; Batch verifying time for 1000 proofs: 37.909 ms

##### UltraPlonk
- BLS12-381: Proving time: 89593 ns/constraint; Verifying time: 3.549 ms; Batch verifying time for 1000 proofs: 20.784 ms
- BN-254: Proving time: 70383 ns/constraint; Verifying time: 2.390 ms; Batch verifying time for 1000 proofs: 17.173 ms
- BW6-761: Proving time: 373141 ns/constraint; Verifying time: 13.656 ms; Batch verifying time for 1000 proofs: 44.023 ms



