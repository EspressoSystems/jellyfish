# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0

- [#PR](https://github.com/EspressoSystems/jellyfish/pull/PR) Upgrade arkworks dependencies to v0.6.0.
- [#PR](https://github.com/EspressoSystems/jellyfish/pull/PR) Move to `spongefish` 0.7. `Poseidon2Permutation` is now stateless and drops its rate parameter, the CRHFs take a sponge type such as `Poseidon2SpongeBnN3R1` instead of a permutation, and the `Poseidon2Permutation*R*` aliases are removed. Hash outputs are unchanged.

## 0.2.0

- [#827](https://github.com/EspressoSystems/jellyfish/pull/827) Upgrade arkworks dependencies to v0.5.0.
- [#829](https://github.com/EspressoSystems/jellyfish/pull/829) Migrated from `nimue` to `spongefish` library for sponge functionality

## 0.1.0

- Initial release with Poseidon2 and its derived primitives (w/ BLS12-381, BN254 instances)
  - [#708](https://github.com/EspressoSystems/jellyfish/pull/708): P2 permutation and reference parameters
  - [#713](https://github.com/EspressoSystems/jellyfish/pull/713): P2 sponge function
  - [#716](https://github.com/EspressoSystems/jellyfish/pull/716): P2-based CRHF and `DigestAlgorithm` implementation
