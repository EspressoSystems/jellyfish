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
    - Circuit definition now has a standalone crate `jf-relation`.
        - Basic and customized circuit gates are defined in `jf-relation`.
        - Customized/advanced circuit implementations are located in their own crates.
            - Plonk related circuits, `transcript` and `plonk-verifier` are now in `jf-plonk/circuit`.
            - Primitive circuits, including `commitment`, `el gamal` etc. remains in `jf-primitives/circuit`.
            - Circuit for rescue hash function is now in `jf-primitives/circuit/rescue`.
    - `par-utils` is moved to `jf-utils`.

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
