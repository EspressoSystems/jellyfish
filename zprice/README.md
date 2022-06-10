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

Note that due to the resource limitation, and also to prevent accidental DoS, the benchmark will be terminate once a TIME_LIMIT is hit. This limit is tentatively set to 12 hours, and subject to change.

Apparently, you could start with reading our current non-GPU-accelerated version of the prover implementation at `PlonkKzgSnark::prove()` in file `jellyfish/plonk/src/proof_system/snark.rs`,
then optimizing it and building a Spark-like library in Rust to distribute and parallelize computation across multiple GPUs.

### Regarding the proving key and verification key

We will provide three `.bin` files (one for the universal SRS, one for the proving key, and one for the verification key) at the beginning of the competition to you, which you shall place under `zprice/data/` folder,
then run the benchmark as the next section instructed.

## How do we, the judges, benchmark your submission?

We will replace a single line of code in our `zprice/benches/zprice_benchmark.rs`:

```rust
fn prove<C, R>(
    rng: &mut R,
    circuit: &C,
    prove_key: &ProvingKey<Bls12_381>,
) -> Result<Proof<Bls12_381>, PlonkError>
where
    C: Arithmetization<Fr>,
    R: CryptoRng + RngCore,
{
    // NOTE: this is our non-GPU-accelerated version of the prover,
    // comment the following line with during actual benchmark
    // `your_crate::prove(rng, circuit, &prove_key)`

    PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(rng, circuit, &prove_key)

}
```

then run: `cargo bench -p jf-zprice` which uses [Criterion](https://bheisler.github.io/criterion.rs/book/criterion_rs.html) under the hood.

It's possible that your submission requires some special hardware instructions, or specific compilation flags, please indicate them clearly in your README if so.

## How do you test your improved prover iteratively?

As you will make changes to the prover implementation, you may want to frequently test its correctness.
Luckily, `jf-plonk` crate already comes with many test vectors, all you need is to change the internal of the aforementioned prover function: `PlonkKzgSnark::prove()` to invoke your `prove()` API in your crate,
then you can run `cargo test -p jf-plonk` locally to make sure changes you introduced doesn't break correctness or soundness of the Plonk protocol.
