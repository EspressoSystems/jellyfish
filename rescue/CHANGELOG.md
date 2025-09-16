# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0

- [#827](https://github.com/EspressoSystems/jellyfish/pull/827) Upgrade arkworks dependencies to v0.5.0.
- [#829](https://github.com/EspressoSystems/jellyfish/pull/829) Migrated CRHF and PRF implementations to use `spongefish` library, drop `ark-sponge` implementations: breaking changes from state XOR mode to overwrite mode


## 0.1.0

- Initial release. Carved out from `jf-primitives`.
- Rescue hash function and its subsequent PRF, CRHF, Commitment scheme implementation.
- Turn on `gadgets` feature for circuit implementations.
