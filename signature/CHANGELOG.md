# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0

- Initial release. Carved out from `jf-primitives`.
- Signature scheme trait definitions and implementations.
- Turn on `bls` feature to use BLS signature scheme on `Bn254` and `Bls12_381`.
- Turn on `schnorr` feature to use Schnorr signature scheme.
- Turn on `gadgets` feature for circuit implementation of Schnorr signature scheme.
