# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Untracked

### Changes

- [#843](https://github.com/EspressoSystems/jellyfish/pull/843): replace unmaintained `derivative` with `derive_where`.
- [#894](https://github.com/EspressoSystems/jellyfish/pull/893): Circuit bug: range-check the limb decomposition of `FpElemVar`. Adds `FpElemVar::new_checked` and uses it for the outputs of `mod_add`, `mod_add_constant`, `mod_add_vec` and `mod_negate`, whose limbs were previously underconstrained.

## 0.5.0

- [#827](https://github.com/EspressoSystems/jellyfish/pull/827) Upgrade arkworks dependencies to v0.5.0.
- [#823](https://github.com/EspressoSystems/jellyfish/pull/823) Circuit bug: enforcing canonical field representation during unpack

## 0.4.4

- See `CHANGELOG_OLD.md` for all previous changes.
