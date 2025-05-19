# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- [#773](https://github.com/EspressoSystems/jellyfish/pull/773): Add subgroup and on curve check to BLS signatures and public keys
- [#786](https://github.com/EspressoSystems/jellyfish/pull/786): Debug public key types as TaggedBase64

## [0.2.0]((https://github.com/EspressoSystems/jellyfish/compare/jf-signatures-v0.1.1...jf-signatures-v0.2.0)) (2024-10-29)

### Changed

- [#696](https://github.com/EspressoSystems/jellyfish/pull/696): removed derived `Debug` and `Serialize` for private keys.
  - Manually implemented `Debug` for private signing keys to not print the actual value.
  - Remove derived (de)serialization. Implemented `to/from_bytes()` and the conversions to/from `TaggedBase64`.

## [0.1.1]((https://github.com/EspressoSystems/jellyfish/compare/0.4.5...jf-signatures-v0.1.1)) (2024-07-25)

### Changed

- [#586](https://github.com/EspressoSystems/jellyfish/pull/586) Omit private keys from logging and debug output.

## 0.1.0

- Initial release. Carved out from `jf-primitives`.
- Signature scheme trait definitions and implementations.
- Turn on `bls` feature to use BLS signature scheme on `Bn254` and `Bls12_381`.
- Turn on `schnorr` feature to use Schnorr signature scheme.
- Turn on `gadgets` feature for circuit implementation of Schnorr signature scheme.
