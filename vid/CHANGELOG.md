# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# Unreleased

## Breaking changes

## Added

## Deprecated

## Removed

## Fixed

## Performance

## Security

# 0.2.0 (2024-09-11)

## Breaking changes

- [#670](https://github.com/EspressoSystems/jellyfish/pull/670) ADVZ multiplicity depend on payload size
  - Largely a performance improvement, but technically a breaking change because ADVZ no longer guarantees to use the exact `multiplicity` specified by the caller. Instead, this arg is now `max_multiplicity`; dispersal might use a smaller multiplicity for small payloads.
- [#674](https://github.com/EspressoSystems/jellyfish/pull/674) ADVZ delete field Share::evals, extract data from eval_proofs instead
  - Change serialization of ADVZ shares.
- [#678](https://github.com/EspressoSystems/jellyfish/pull/678) ADVZ eliminate unnecessary merkle proofs in ADVZ shares
  - Change serialization of ADVZ shares.

## Fixed

- [#653](https://github.com/EspressoSystems/jellyfish/pull/653) ADVZ check consistency of multiplicity in verify_share

## Performance

- [#650](https://github.com/EspressoSystems/jellyfish/pull/650) ADVZ verify_share use parallelism over multiplicity
- [#670](https://github.com/EspressoSystems/jellyfish/pull/670) ADVZ multiplicity depend on payload size
  - Also a breaking change.

## Security

- [#657](https://github.com/EspressoSystems/jellyfish/pull/657) ADVZ check eval_proof for all evaluations
  - This patch was later obsoleted by [#678](https://github.com/EspressoSystems/jellyfish/pull/678).
- [#674](https://github.com/EspressoSystems/jellyfish/pull/674) ADVZ delete field Share::evals, extract data from eval_proofs instead
  - Also a breaking change.

# 0.1.0 (2024-04-24)

- Initial release. Verifiable information dispersal trait definition and implementations. This package spun out of `jf-primitives` in [#556](https://github.com/EspressoSystems/jellyfish/pull/556).
