# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# 0.2.5

## Breaking changes

- Moved from `jellyfish-compat` into the `jellyfish` repo.
- Removed the `seq-fk-23` and `kzg-print-trace` features. They had no effect: neither was forwarded to `jf-pcs`. Enable `jf-pcs/seq-fk-23` or `jf-pcs/kzg-print-trace` directly instead.

## Changes

- Bump `jf-merkle-tree-compat` to 0.3.2.

## Security

- [jellyfish-compat#56](https://github.com/EspressoSystems/jellyfish-compat/pull/56): `payload_verify` now requires the exact prefix and suffix lengths for `SmallRangeProof` and `LargeRangeProof`. Before, an honest proof for one byte range could also verify the same bytes claimed at another range of the same length, and a malformed `SmallRangeProof` could panic instead of returning an error.

# 0.2.4 (2026-02-05)

- Bump `jf-merkle-tree-compat` to 0.3.1 (Merkle tree lookups return owned values).

# 0.2.3 (2026-01-28)

- Bump `jf-merkle-tree-compat` to 0.3.0.

# 0.2.2 (2025-10-01)

- Bump `jf-merkle-tree-compat` to 0.2.0 (`jf-rescue` 0.3.0).

# 0.2.1 (2025-09-15)

## Breaking changes

- **Breaking**: moved to `jellyfish-compat` crate.
- **Breaking**: renamed to `jf-advz`.
- [#9](https://github.com/EspressoSystems/jellyfish-compat/pull/9): add `evals` back to ADVZShare for backward compatibility in espresso-network.

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
