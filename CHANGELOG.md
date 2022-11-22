# CHANGELOG

## Pending

- Splitting polynomials are masked to ensure zero-knowledge of Plonk (#76)
- Refactored `UniversalSNARK` trait (#80, #87)
- Restore `no_std` compliance (#85, #87)
- Use [blst](https://github.com/supranational/blst) library for BLS signature/VRF (#89)
- Introduce `struct BoolVar` whenever necessary and possible (#91)
- Introduce comparison gates (#81)
- More general input to `deserialize_canonical_bytes!()` (#108)
- Codebase refactor (#110)
    - Remove `jf-rescue` crate, rescue hash function now resides in `jf-primitives/rescue`.
    - Plonk constraint system definition and concrete constructions now live in a standalone crate `jf-relation`.
        - Basic and customized circuit gates are defined in `jf-relation`.
        - Customized/advanced circuit implementations are located in their own crates.
            - Plonk verifier related gadgets, `transcript` and `plonk-verifier` are now in `jf-plonk/circuit`.
            - Primitive gadgets, including `commitment`, `el gamal` etc. remains in `jf-primitives/circuit`.
            - Circuit for rescue hash function is now in `jf-primitives/circuit/rescue`.
    - `par-utils` is moved to `jf-utils`.
- Introduct new `PolynomialCommitmentScheme` trait and basic implementations.
    - Now `PlonkKzgSnark` use our own KZG10 implementation.
- Merkle tree is refactored (#135)
    - Introduce new traits which define the functionalities.
        - `MerkleTreeScheme` is the abstraction of a static array accumulator,
        - `AppendableMerkleTreeScheme` is the abstraction of an appendable vector accumulator.
        - `UniversalMerkleTreeScheme` is the abstraction of a key-value map accumulator, which also supports non-membership query/proof.
        - `ForgetableMerkleTreeScheme` allows you to forget/remember some leafs from the memory.
    - Implementation of new generic merkle tree: `MerkleTree` and `UniversalMerkleTree`
        - A default rate-3 rescue merkle tree implementation is provided in `prelude` module.
        - Other example instantiation can be found in `example` module.

## v0.1.2

### Improvements

- `#[tagged_blob(...)]` macro now supports `const` variables in addition to string literals

## v0.1.1

### Features

- Introducing an example for proving knowledge of exponent
- Add api to get SRS size.

### Improvements

- Derive `Debug`, `Snafu` on `enum TaggedBlobError`
- Updated `tagged-base64` reference url to reflect the Espresso Systems name change
- Add `HashToGroup` support for both SW and TE curves

## v0.1.0 (Initial release of Jellyfish plonk prove system)
