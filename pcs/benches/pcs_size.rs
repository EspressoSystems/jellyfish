use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use jf_pcs::{
    prelude::{MultilinearKzgPCS, PolynomialCommitmentScheme, MLE},
    StructuredReferenceString,
};
use jf_utils::test_rng;

const MIN_NUM_VARS: usize = 10;
const MAX_NUM_VARS: usize = 20;

/// Report the size of a commitment
pub fn commitment_size<E: Pairing>(num_vars: usize) -> usize {
    let rng = &mut test_rng();
    let pp = MultilinearKzgPCS::<E>::gen_srs_for_testing(rng, num_vars).unwrap();

    let (ml_ck, _ml_vk) = pp.0.trim(num_vars).unwrap();
    let (uni_ck, _uni_vk) = pp.1.trim(num_vars).unwrap();
    let ck = (ml_ck, uni_ck);

    let poly = MLE::from(DenseMultilinearExtension::rand(num_vars, rng));

    let commitment = MultilinearKzgPCS::commit(&ck, &poly).unwrap();
    commitment.serialized_size(ark_serialize::Compress::No)
}

/// Report the size of a proof
pub fn proof_size<E: Pairing>(num_vars: usize) -> usize {
    let rng = &mut test_rng();
    let pp = MultilinearKzgPCS::<E>::gen_srs_for_testing(rng, num_vars).unwrap();

    let (ml_ck, _ml_vk) = pp.0.trim(num_vars).unwrap();
    let (uni_ck, _uni_vk) = pp.1.trim(num_vars).unwrap();
    let ck = (ml_ck, uni_ck);

    let poly = MLE::from(DenseMultilinearExtension::rand(num_vars, rng));
    let point: Vec<_> = (0..num_vars).map(|_| E::ScalarField::rand(rng)).collect();

    let (proof, _) = MultilinearKzgPCS::open(&ck, &poly, &point).unwrap();

    proof.serialized_size(ark_serialize::Compress::No)
}

fn main() {
    println!("\nKZG on BN-254: Commitment size");
    for num_vars in (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2) {
        println!(
            "\tnum_vars: {}, size: {} B",
            num_vars,
            commitment_size::<Bn254>(num_vars)
        );
    }

    println!("\nKZG on BN-254: Proof size");
    for num_vars in (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2) {
        println!(
            "\tnum_vars: {}, size: {} B",
            num_vars,
            proof_size::<Bn254>(num_vars)
        );
    }

    println!("\nKZG on BLS-381: Commitment size");
    for num_vars in (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2) {
        println!(
            "\tnum_vars: {}, size: {} B",
            num_vars,
            commitment_size::<Bls12_381>(num_vars)
        );
    }

    println!("\nKZG on BLS-381: Proof size");
    for num_vars in (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2) {
        println!(
            "\tnum_vars: {}, size: {} B",
            num_vars,
            proof_size::<Bls12_381>(num_vars)
        );
    }
}
