# CHANGELOG

We take inspiration from [keep changelog](https://keepachangelog.com/en/1.0.0/) and [arkworks](https://github.com/arkworks-rs/algebra/blob/master/CHANGELOG.md),
and follow [semantic versioning](https://semver.org/) for our releases.

**Breaking Changes** and **Fixed** contain backward incompatible changes, bug fixes, and security patches;
**Added, Changed, Removed, Deprecated** contain backward compatible improvements or new features.

## [Unreleased](https://github.com/EspressoSystems/jellyfish/compare/0.3.0...main)

### Breaking Changes

### Fixed

### Added

### Changed

### Removed

### Deprecated

## [v0.3.0](https://github.com/EspressoSystems/jellyfish/compare/0.2.0...0.3.0) - 2023-03-22

### Breaking Changes
- [#207](https://github.com/EspressoSystems/jellyfish/pull/207) Update arkworks dependency to v0.4.0

## [v0.2.0](https://github.com/EspressoSystems/jellyfish/compare/0.1.2...0.2.0) - 2023-01-20

### Breaking Changes

- [#80](https://github.com/EspressoSystems/jellyfish/pull/80),[#87](https://github.com/EspressoSystems/jellyfish/pull/87) (`jf-plonk`) Refactored `UniversalSNARK` trait
- [#89](https://github.com/EspressoSystems/jellyfish/pull/89) (`jf-primitives`) Use [blst](https://github.com/supranational/blst) library for BLS signature/VRF
- [#91](https://github.com/EspressoSystems/jellyfish/pull/91) (`jf-plonk`) Introduce `struct BoolVar` whenever necessary and possible
- [#96](https://github.com/EspressoSystems/jellyfish/pull/96) (`jf-plonk`) Introduce comparison gates
- [#107](https://github.com/EspressoSystems/jellyfish/pull/107) (`jf-primitives`) Updated `crypto_box` from `0.7.1` to `0.8.1`
- [#110](https://github.com/EspressoSystems/jellyfish/pull/110) (workspace) Reorganized codebase structure
    - Remove `jf-rescue` crate, rescue hash function now resides in `jf-primitives/rescue`.
    - Plonk constraint system definition and concrete constructions now live in a standalone crate `jf-relation`.
        - Basic and customized circuit gates are defined in `jf-relation`.
        - Customized/advanced circuit implementations are located in their own crates.
            - Plonk verifier related gadgets, `transcript` and `plonk-verifier` are now in `jf-plonk/circuit`.
            - Primitive gadgets, including `commitment`, `el gamal` etc. remains in `jf-primitives/circuit`.
            - Circuit for rescue hash function is now in `jf-primitives/circuit/rescue`.
    - `par-utils` is moved to `jf-utils`.
- [#126](https://github.com/EspressoSystems/jellyfish/pull/126) (nix) Used nix flake
- [#135](https://github.com/EspressoSystems/jellyfish/pull/135) Major Merkle Tree refactoring, Unification of different variants:
    - Introduce new traits which define the functionalities.
        - `MerkleTreeScheme` is the abstraction of a static array accumulator,
        - `AppendableMerkleTreeScheme` is the abstraction of an appendable vector accumulator.
        - `UniversalMerkleTreeScheme` is the abstraction of a key-value map accumulator, which also supports non-membership query/proof.
        - `ForgetableMerkleTreeScheme` allows you to forget/remember some leafs from the memory.
    - Implementation of new generic merkle tree: `MerkleTree` and `UniversalMerkleTree`
        - A default rate-3 rescue merkle tree implementation is provided in `prelude` module.
        - Other example instantiation can be found in `example` module.
- [#137](https://github.com/EspressoSystems/jellyfish/pull/137) (`jf-primitives`) Refactored VRF APIs and traits
- [#144](https://github.com/EspressoSystems/jellyfish/pull/144) (`jf-primitives`) Updated append-only merkle tree gadget with the latest MT API
- [#119](https://github.com/EspressoSystems/jellyfish/pull/119) (all) Updated dependencies
  - Upgraded `criterion` from `0.3.1` to `0.4.0`
- [#146](https://github.com/EspressoSystems/jellyfish/pull/146) (`jf-primitives`) Refactored Rescue sponge API:
    - Remove all `.*sponge.*` methods from `Permutation`.
    - Introduce `RescueCRHF` which takes over `sponge_with_padding` and `sponge_no_padding` from `Permutation`.
    - Introduce `RescuePRF` which takes over `full_state_keyed_sponge_with_padding` and `full_state_keyed_sponge_no_padding` from `Permutation`.
- [#148](https://github.com/EspressoSystems/jellyfish/pull/148), [#156](https://github.com/EspressoSystems/jellyfish/pull/156) (`jf-primitives`) Refactored BLS Signature implementation
  - #148 Added trait bounds on associated types of `trait SignatureScheme`
  - #156 Improved BLS correctness and API compliance with IRTF standard with better doc
- [#150](https://github.com/EspressoSystems/jellyfish/pull/150) (`jf-primitives`) Refactor `RescueGadget`
    - Introduce `SpongeStateVar` to abstract over `RescueStateVar` and `RescueNonNativeStateVar` structs.
    - Unify `RescueGadget` and `RescueNonNativeGadget` traits into `RescueGadget`.
- [#158](https://github.com/EspressoSystems/jellyfish/pull/158) (`jf-primitives`) Refactored `MerkleTreeGadget` API:
    - Generic only over `MerkleTreeScheme`.
    - New methods for allocating variables: `create_leaf_variable`, `create_membership_proof_variable`, `create_root_variable`.
    - New methods for enforcing constraints: `is_member` and `enforce_merkle_proof`.
    - Move the remaining methods to the internals of circuit implementation for `RescueMerkleTree`.
    - Implement `MerkleTreeGadget` for `RescueMerkleTree`.
- [#169](https://github.com/EspressoSystems/jellyfish/pull/169) (`jf-primitives`) Stabilize API effort
    - Introduced `trait CRHF` and moved current implementations under `struct FixedLengthRescueCRHF, VariableLengthRescueCRHF`.
    - Introduced `trait CommitmentScheme` and moved current implementations under `struct FixedLengthRescueCommitment`.
- [#194](https://github.com/EspressoSystems/jellyfish/pull/194) (all) Set MSVR of all crates to 1.64.
- (`jf-primitives`) `zeroize` from `1.3` to `^1.5`

### Fixed

- [#76](https://github.com/EspressoSystems/jellyfish/pull/76) (`jf-plonk`) Splitting polynomials are masked to ensure zero-knowledge of Plonk
    - Now `PlonkKzgSnark` use our own KZG10 implementation.
- [#115](https://github.com/EspressoSystems/jellyfish/pull/115) (`jf-relation`) Fix a bug in `logic_or` gate

### Added

- [#85](https://github.com/EspressoSystems/jellyfish/pull/85), [#87](https://github.com/EspressoSystems/jellyfish/pull/87) (all) Added `no_std` compliance
- [#116](https://github.com/EspressoSystems/jellyfish/pull/116) (`jf-primitives`) Introduced new `PolynomialCommitmentScheme` trait
- [#117](https://github.com/EspressoSystems/jellyfish/pull/117) (`jf-relation`) Added gadgets for comparison with constant values
- [#176](https://github.com/EspressoSystems/jellyfish/pull/176) (`jf-primitives`) Added implementation for light weight merkle tree -- an append-only merkle tree who only keeps its frontier.
- [#167](https://github.com/EspressoSystems/jellyfish/pull/167) (`jf-primitives`) Add `DigestGadget` associated type to `MerkleTreeGadget`.

### Changed

- [#105](https://github.com/EspressoSystems/jellyfish/pull/105) (all) Trait bound relaxation
- [#108](https://github.com/EspressoSystems/jellyfish/pull/108) (`jf-utils`) Allowed more general input to `deserialize_canonical_bytes!()`
- [#113](https://github.com/EspressoSystems/jellyfish/pull/113) (`jf-plonk`) Corrected error type for `PlonkVerifier` gadgets
- [#162](https://github.com/EspressoSystems/jellyfish/pull/162) (`jf-utils`) Renamed `#serde(with="field_elem")` to `#serde(with="canonical")`
- [#177](https://github.com/EspressoSystems/jellyfish/pull/177) (`jf-primitives`) Refactor multilinear PCS opening.
- [#197](https://github.com/EspressoSystems/jellyfish/pull/197) (`jf-relation`) Added `no_std` attribute.

### Removed

- [#143](https://github.com/EspressoSystems/jellyfish/pull/143) (`jf-utils`) Removed `tagged_blob`, use `tagged_base64::tagged` instead

### Deprecated

## [v0.1.2-patch.1](https://github.com/EspressoSystems/jellyfish/compare/0.1.2...0.1.2-patch.1) - 2022-11-30

### Breaking Changes

- [#107](https://github.com/EspressoSystems/jellyfish/pull/110) (`jf-primitives`) Updated `crypto_box` from `0.7.1` to `0.8.1`
- [#149](https://github.com/EspressoSystems/jellyfish/pull/149) (`jf-primitives`, nix) 
    - Updated dependencies
        - `crypto_box` from `0.7.1` to `0.8.1`
        - `zeroize` from `1.3` to `^1.5`
    - Used nix flake instead, bumped rust version to `1.65`

## [v0.1.2](https://github.com/EspressoSystems/jellyfish/compare/0.1.1...0.1.2) - 2022-06-22

### Changed

- [#72](https://github.com/EspressoSystems/jellyfish/pull/72) (`jf-utils`) Improved `#[tagged_blob(...)]` macro to support `const` variables in addition to string literals

## [v0.1.1](https://github.com/EspressoSystems/jellyfish/compare/0.1.0...0.1.1) - 2022-05-17

### Breaking Changes

- [#53](https://github.com/EspressoSystems/jellyfish/pull/53) (`jf-primitives`) Defined and using our own signature scheme trait
- [#57](https://github.com/EspressoSystems/jellyfish/pull/57) (`jf-plonk`) Updated `is_xxx` to `check_xxx` gadget APIs
- [#65](https://github.com/EspressoSystems/jellyfish/pull/65) (`jf-plonk`) Added HashToGroup implementation to TE Curves

### Fixed

- [#65](https://github.com/EspressoSystems/jellyfish/pull/64) (`jf-plonk`) Fixed a missing decomposing check in range gate

### Added

- [#51](https://github.com/EspressoSystems/jellyfish/pull/51) (`jf-plonk`) Introduced lookup table domain separation
- [#55](https://github.com/EspressoSystems/jellyfish/pull/55) (`jf-primitives`) Added naive implementations of BLS signature and VRF
- [#65](https://github.com/EspressoSystems/jellyfish/pull/65) (`jf-primitives`) Added `HashToGroup` support for both SW and TE curves

### Changed

- [#66](https://github.com/EspressoSystems/jellyfish/pull/66) (dep) Updated `tagged-base64` reference url to reflect the Espresso Systems name change

## [v0.1.0](https://github.com/EspressoSystems/jellyfish/tree/0.1.0) - 2022-04-05
