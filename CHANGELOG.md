# CHANGELOG

## Pending

- Splitting polynomials are masked to ensure zero-knowledge of Plonk (#76)
- Refactored `UniversalSNARK` trait (#80, #87)
- Restore `no_std` compliance (#85, #87)

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
