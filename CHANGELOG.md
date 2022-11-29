# CHANGELOG

## Pending

## v0.1.3

- Update dependencies
  - `crypto_box` from `0.7.1` to `0.8.1`
  - `zeroize` from `1.3` to `^1.5`
- Use nix flake instead, bump rust version to the latest

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
