# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- [#288](https://github.com/EspressoSystems/jellyfish/issues/288) (breaking) Remove unused serde helpers `CanonicalBytes`, `deserialize_canonical_bytes!` and `test_serde_default!`. Use `#[serde(with = "canonical")]` instead.

## 0.5.0

- Upgrade arkworks dependencies to v0.5.0.

## 0.4.4

- See `CHANGELOG_OLD.md` for all previous changes.
- `reed_solomon_code` is moved from `jf-primitives` to here.