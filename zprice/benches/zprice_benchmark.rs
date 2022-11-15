use ark_bls12_381::{Bls12_381, Fr};
use ark_std::rand::{CryptoRng, RngCore};
use criterion::{criterion_group, criterion_main, Criterion};
use jf_plonk::prelude::*;

fn prove<C, R>(
    rng: &mut R,
    circuit: &C,
    prove_key: &ProvingKey<Bls12_381>,
) -> Result<Proof<Bls12_381>, PlonkError>
where
    C: Arithmetization<Fr>,
    R: CryptoRng + RngCore,
{
    // TODO: USE THIS DURING ACTUAL BENCHMARK
    prover_single_gpu::Prover::prove(rng, circuit, &prove_key)
    // PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(rng, circuit, &prove_key)
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    // Build a circuit with randomly sampled satisfying assignments
    let circuit = jf_zprice::generate_circuit(&mut rng).unwrap();

    // load pre-generated proving key and verification key from files
    let pk = jf_zprice::load_proving_key(None);
    let vk = jf_zprice::load_verification_key(None);

    // verify the proof against the public inputs.
    let proof = prove(&mut rng, &circuit, &pk).unwrap();
    let public_inputs = circuit.public_input().unwrap();
    assert!(
        PlonkKzgSnark::<Bls12_381>::verify::<StandardTranscript>(&vk, &public_inputs, &proof,)
            .is_ok()
    );

    c.bench_function("TurboPlonk Prover", |b| {
        b.iter(|| prove(&mut rng, &circuit, &pk).unwrap())
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark
);
criterion_main!(benches);
