# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Breaking Changes

### Non-breaking Changes

## 0.5.1 (2024-09-04)

### Breaking Changes

- [#648](https://github.com/EspressoSystems/jellyfish/pull/648) Refactored `trait Transcript`; Updated `SolidityTranscript` to use `state`-based logic correctly

### Non-breaking Changes

- [#647](https://github.com/EspressoSystems/jellyfish/pull/647) Append G2 points from SRS to `Transcript`


## 0.5.0 (2024-07-02)

### Breaking Changes

- [#619](https://github.com/EspressoSystems/jellyfish/pull/619) `SolidityTranscript` removed `state`, making challenge `tau` only for lookup-enabled proofs

### Fixed

- [#611](https://github.com/EspressoSystems/jellyfish/pull/611) Lagrange coefficient computation for domain elements

## 0.4.4

- See `CHANGELOG_OLD.md` for all previous changes.
