use ark_bls12_381::{Bls12_381, Fr};
use ark_std::rand::{CryptoRng, RngCore};
use criterion::{criterion_group, criterion_main, Criterion};
use jf_plonk::prelude::*;
use jf_zprice::generate_circuit;

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
    // your_crate::prove(rng, circuit, &prove_key)

    PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(rng, circuit, &prove_key)
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    // Build a circuit with randomly sampled satisfying assignments
    let circuit = generate_circuit(&mut rng).unwrap();

    // FIXME: change these to load from files instead
    let srs_size = circuit.srs_size().unwrap();
    let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(srs_size, &mut rng).unwrap();

    // Then, we generate the proving key and verification key from the SRS and
    // circuit.
    let (pk, vk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &circuit).unwrap();

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
