# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.2

- Moved from `jellyfish-compat` into the `jellyfish` repo. Dependencies are unchanged: `jf-relation`, `jf-rescue` and `jf-utils` stay pinned to their released tags.

## 0.3.1 (2026-02-05)

- **Breaking**: Merkle tree lookups return owned values instead of references.

## 0.3.0 (2026-01-28)

- **Breaking**: [jellyfish-compat#49](https://github.com/EspressoSystems/jellyfish-compat/pull/49): make internal Merkle tree structs public.

## 0.2.0 (2025-10-01)

- **Breaking**: bump `jf-rescue` to 0.3.0.

## 0.1.0

- Initial release.
- Various (including namespace) Merkle tree trait definitions and implementations.
- Turn on `gadgets` for circuit implementations.
