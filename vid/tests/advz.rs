#![cfg(feature = "test-srs")]
use ark_bn254::Bn254;
use ark_ff::{Field, PrimeField};
use ark_std::rand::seq::SliceRandom;
use jf_pcs::{checked_fft_size, prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
use jf_vid::advz;
use sha2::Sha256;

mod vid;

#[cfg(not(feature = "gpu-vid"))]
/// Internal Jellyfish VID scheme
type Advz<E, H> = advz::Advz<E, H>;
#[cfg(feature = "gpu-vid")]
/// Internal Jellyfish VID scheme
type Advz<E, H> = advz::AdvzGPU<'static, E, H>;

#[test]
fn round_trip() {
    // play with these items
    let vid_sizes = [(2, 3), (8, 11)];
    let payload_byte_lens = [0, 1, 2, 16, 32, 47, 48, 49, 64, 100, 400];
    let mut multiplicities = [1, 2, 4, 8, 16];

    // more items as a function of the above
    let supported_degree = vid_sizes.iter().max_by_key(|v| v.0).unwrap().0 - 1;
    let mut rng = jf_utils::test_rng();
    multiplicities.shuffle(&mut rng);
    let srs = UnivariateKzgPCS::<Bn254>::gen_srs_for_testing(
        &mut rng,
        checked_fft_size(supported_degree as usize).unwrap()
            * *multiplicities.iter().max().unwrap() as usize,
    )
    .unwrap();

    println!(
            "modulus byte len: {}",
            (<<UnivariateKzgPCS<Bn254> as PolynomialCommitmentScheme>::Evaluation as Field>::BasePrimeField
                ::MODULUS_BIT_SIZE - 7)/8 + 1
        );

    vid::round_trip(
        |recovery_threshold, num_storage_nodes, multiplicity| {
            Advz::<Bn254, Sha256>::with_multiplicity(
                num_storage_nodes,
                recovery_threshold,
                multiplicity,
                &srs,
            )
            .unwrap()
        },
        &vid_sizes,
        &multiplicities,
        &payload_byte_lens,
        &mut rng,
    );
}
