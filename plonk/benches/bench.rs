// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench
// where N is the number of threads you want to use (N = 1 for single-thread).

use ark_bls12_377::{Bls12_377, Fr as Fr377};
use ark_bls12_381::{Bls12_381, Fr as Fr381};
use ark_bn254::{Bn254, Fr as Fr254};
use ark_bw6_761::{Fr as Fr761, BW6_761};
use ark_ff::PrimeField;
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit},
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, Snark},
    transcript::StandardTranscript,
};

const NUM_REPETITIONS: usize = 10;
const NUM_GATES_LARGE: usize = 32768;
const NUM_GATES_SMALL: usize = 8192;

fn gen_circuit_for_bench<F: PrimeField>(num_gates: usize) -> Result<PlonkCircuit<F>, PlonkError> {
    let mut cs: PlonkCircuit<F> = PlonkCircuit::new();
    let mut a = cs.zero();
    for _ in 0..num_gates - 10 {
        a = cs.add(a, cs.one())?;
    }
    // Finalize the circuit.
    cs.finalize_for_arithmetization()?;

    Ok(cs)
}

macro_rules! plonk_prove_bench {
    ($bench_curve:ty, $bench_field:ty, $num_gates:expr) => {
        let rng = &mut ark_std::test_rng();
        let cs = gen_circuit_for_bench::<$bench_field>($num_gates).unwrap();

        let max_degree = $num_gates + 2;
        let srs = PlonkKzgSnark::<$bench_curve>::universal_setup(max_degree, rng).unwrap();

        let (pk, _) = PlonkKzgSnark::<$bench_curve>::preprocess(&srs, &cs).unwrap();

        let start = ark_std::time::Instant::now();

        for _ in 0..NUM_REPETITIONS {
            let _ = PlonkKzgSnark::<$bench_curve>::prove::<_, _, StandardTranscript>(rng, &cs, &pk)
                .unwrap();
        }

        println!(
            "proving time for {}, {}: {} ns/gate",
            stringify!($bench_curve),
            stringify!($bench_plonk_type),
            start.elapsed().as_nanos() / NUM_REPETITIONS as u128 / $num_gates as u128
        );
    };
}

fn bench_prove() {
    plonk_prove_bench!(Bls12_381, Fr381, NUM_GATES_LARGE);
    plonk_prove_bench!(Bls12_377, Fr377, NUM_GATES_LARGE);
    plonk_prove_bench!(Bn254, Fr254, NUM_GATES_LARGE);
    plonk_prove_bench!(BW6_761, Fr761, NUM_GATES_SMALL);
}

macro_rules! plonk_verify_bench {
    ($bench_curve:ty, $bench_field:ty, $num_gates:expr) => {
        let rng = &mut ark_std::test_rng();
        let cs = gen_circuit_for_bench::<$bench_field>($num_gates).unwrap();

        let max_degree = $num_gates + 2;
        let srs = PlonkKzgSnark::<$bench_curve>::universal_setup(max_degree, rng).unwrap();

        let (pk, vk) = PlonkKzgSnark::<$bench_curve>::preprocess(&srs, &cs).unwrap();

        let proof = PlonkKzgSnark::<$bench_curve>::prove::<_, _, StandardTranscript>(rng, &cs, &pk)
            .unwrap();

        let start = ark_std::time::Instant::now();

        for _ in 0..NUM_REPETITIONS {
            let _ = PlonkKzgSnark::<$bench_curve>::verify::<StandardTranscript>(&vk, &[], &proof)
                .unwrap();
        }

        println!(
            "verifying time for {}, {}: {} ns",
            stringify!($bench_curve),
            stringify!($bench_plonk_type),
            start.elapsed().as_nanos() / NUM_REPETITIONS as u128
        );
    };
}

fn bench_verify() {
    plonk_verify_bench!(Bls12_381, Fr381, NUM_GATES_LARGE);
    plonk_verify_bench!(Bls12_377, Fr377, NUM_GATES_LARGE);
    plonk_verify_bench!(Bn254, Fr254, NUM_GATES_LARGE);
    plonk_verify_bench!(BW6_761, Fr761, NUM_GATES_SMALL);
}

macro_rules! plonk_batch_verify_bench {
    ($bench_curve:ty, $bench_field:ty, $num_proofs:expr) => {
        let rng = &mut ark_std::test_rng();
        let cs = gen_circuit_for_bench::<$bench_field>(1024).unwrap();

        let max_degree = 1026;
        let srs = PlonkKzgSnark::<$bench_curve>::universal_setup(max_degree, rng).unwrap();

        let (pk, vk) = PlonkKzgSnark::<$bench_curve>::preprocess(&srs, &cs).unwrap();

        let proof = PlonkKzgSnark::<$bench_curve>::prove::<_, _, StandardTranscript>(rng, &cs, &pk)
            .unwrap();

        let vks = vec![&vk; $num_proofs];
        let pub_input = vec![];
        let public_inputs_ref = vec![&pub_input[..]; $num_proofs];
        let proofs_ref = vec![&proof; $num_proofs];

        let start = ark_std::time::Instant::now();

        for _ in 0..NUM_REPETITIONS {
            let _ = PlonkKzgSnark::<$bench_curve>::batch_verify::<StandardTranscript>(
                &vks,
                &public_inputs_ref[..],
                &proofs_ref,
            )
            .unwrap();
        }

        println!(
            "batch verifying time for {}, {}, {} proofs: {} ns/proof",
            stringify!($bench_curve),
            stringify!($bench_plonk_type),
            stringify!($num_proofs),
            start.elapsed().as_nanos() / NUM_REPETITIONS as u128 / $num_proofs as u128
        );
    };
}

fn bench_batch_verify() {
    plonk_batch_verify_bench!(Bls12_381, Fr381, 1000);
    plonk_batch_verify_bench!(Bls12_377, Fr377, 1000);
    plonk_batch_verify_bench!(Bn254, Fr254, 1000);
    plonk_batch_verify_bench!(BW6_761, Fr761, 1000);
}

fn main() {
    bench_prove();
    bench_verify();
    bench_batch_verify();
}
