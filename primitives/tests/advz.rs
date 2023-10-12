#![cfg(feature = "test-srs")]
use ark_bls12_381::Bls12_381;
use ark_ff::{Field, PrimeField};
use jf_primitives::{
    pcs::{checked_fft_size, prelude::UnivariateKzgPCS, PolynomialCommitmentScheme},
    vid::advz::Advz,
};
use sha2::Sha256;

mod vid;

#[test]
fn round_trip() {
    // play with these items
    let vid_sizes = [(2, 3), (8, 11)];
    let byte_lens = [0, 1, 2, 16, 32, 47, 48, 49, 64, 100, 400];

    // more items as a function of the above
    let supported_degree = vid_sizes.iter().max_by_key(|v| v.0).unwrap().0 - 1;
    let mut rng = jf_utils::test_rng();
    let srs = UnivariateKzgPCS::<Bls12_381>::gen_srs_for_testing(
        &mut rng,
        checked_fft_size(supported_degree).unwrap(),
    )
    .unwrap();

    println!(
            "modulus byte len: {}",
            (<<UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme>::Evaluation as Field>::BasePrimeField
                ::MODULUS_BIT_SIZE - 7)/8 + 1
        );

    vid::round_trip(
        |payload_chunk_size, num_storage_nodes| {
            Advz::<Bls12_381, Sha256>::new(payload_chunk_size, num_storage_nodes, &srs).unwrap()
        },
        &vid_sizes,
        &byte_lens,
        &mut rng,
    );
}
