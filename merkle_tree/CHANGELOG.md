# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0

### Breaking Changes

- [#840](https://github.com/EspressoSystems/jellyfish/pull/840): `jf-rescue` moved away from `spongefish` migration.

## 0.3.0

- [#827](https://github.com/EspressoSystems/jellyfish/pull/827) Upgrade arkworks dependencies to v0.5.0.
- [#829](https://github.com/EspressoSystems/jellyfish/pull/829) Updated to work with new Poseidon2 implementation using `spongefish`

## 0.2.2 (2025-04-25)

- [#774](https://github.com/EspressoSystems/jellyfish/pull/774) Add domain separator for Merkle Tree digest functions.
- [#775](https://github.com/EspressoSystems/jellyfish/pull/775) Fix incorrect domain separator for hashers.

## 0.2.1 (2025-01-13)
- [#716](https://github.com/EspressoSystems/jellyfish/pull/716) Poseidon2-based Merkle Tree available.

## 0.2.0 (2024-10-21)

- [#692](https://github.com/EspressoSystems/jellyfish/pull/692) Major refactor for ergonomics reason
    - `MerkleProof` now doesn't contain leaf information. Proofs should be verified along with claimed 
      index and element information.
    - Merkle proof verification proof APIs now takes `MerkleCommitment` instead of simply a root digest 
      value. It can now be called without instantiating an actual Merkle tree struct.
    - Deprecate namespace Merkle tree for now because it's no longer in use.
- [#685](https://github.com/EspressoSystems/jellyfish/pull/685) Include a keccak256 Merkle trees in prelude

## 0.1.0

- Initial release. 
- Various (including namespace) Merkle tree trait definitions and implementations.
- Turn on `gadgets` for circuit implementations.
