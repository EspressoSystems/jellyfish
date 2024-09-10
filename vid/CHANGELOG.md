# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0

- Initial release. Verifiable information dispersal trait definition and implementations.

## 0.2.0

- [#650](https://github.com/EspressoSystems/jellyfish/pull/650) perf: VID ADVZ verify_share use parallelism over multiplicity
- [#653](https://github.com/EspressoSystems/jellyfish/pull/653) fix: VID ADVZ check consistency of multiplicity in verify_share
- [#657](https://github.com/EspressoSystems/jellyfish/pull/657) fix: check eval_proof for all evaluations
- [#670](https://github.com/EspressoSystems/jellyfish/pull/670) feat: multiplicity depend on payload size
- [#674](https://github.com/EspressoSystems/jellyfish/pull/674) fix: Delete field Share::evals, extract data from eval_proofs instead
- [#678](https://github.com/EspressoSystems/jellyfish/pull/678) fix!: eliminate unnecessary merkle proofs in ADVZ shares
