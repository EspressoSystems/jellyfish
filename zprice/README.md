# ZPrice: [Plonk-DIZK GPU Acceleration](https://www.zprize.io/prizes/plonk-dizk-gpu-acceleration)

Please read the [detailed price spec](https://assets.website-files.com/625a083eef681031e135cc99/628fe2fac35719417bf82def_Plonk-DIZK%20GPU%20Acceleration.pdf) first.

## What should you submit?

You should submit your open-sourced code (under permissible licenses) with sufficient documentation and running scripts or instructions.

Your code/library is required to provide **one public API for proof generation** which we would invoke during benchmarking.

```rust
use jf_plonk::prelude::*;
use ark_std::rand::{CryptoRng, RngCore};

fn prove<C, R>(
    rng: &mut R,
    circuit: &C,
    prove_key: &ProvingKey<Bls12_381>,
) -> Result<Proof<Bls12_381>, PlonkError>
where
    C: Arithmetization<Fr>,
    R: CryptoRng + RngCore,
```

Apparently, you could start with reading our current non-GPU-accelerated version of the prover implementation at `PlonkKzgSnark::prove()` in file `jellyfish/plonk/src/proof_system/snark.rs`,
then optimizing it and building a Spark-like library in Rust to distribute and parallelize computation across multiple GPUs.

## How do we, the judges, benchmark your submission?

## How do you local test?
