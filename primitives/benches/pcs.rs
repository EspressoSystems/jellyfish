// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use std::time::{Duration, Instant};

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use jf_primitives::pcs::{
    prelude::{MultilinearKzgPCS, PolynomialCommitmentScheme, MLE},
    StructuredReferenceString,
};
use jf_utils::test_rng;

const MIN_NUM_VARS: usize = 10;
const MAX_NUM_VARS: usize = 20;

/// Measure the time cost of {commit/open/verify} across a range of num_vars
pub fn bench_pcs_method<E: Pairing>(
    c: &mut Criterion,
    range: impl Iterator<Item = usize>,
    msg: &str,
    method: impl Fn(&<MultilinearKzgPCS<E> as PolynomialCommitmentScheme>::SRS, usize) -> Duration,
) {
    let mut group = c.benchmark_group(msg);

    let mut rng = &mut test_rng();

    for num_vars in range {
        let pp = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, num_vars).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_vars),
            &num_vars,
            |b, num_vars| {
                b.iter(|| method(&pp, *num_vars));
            },
        );
    }

    group.finish();
}

/// Report the time cost of a commitment
pub fn commit<E: Pairing>(
    pp: &<MultilinearKzgPCS<E> as PolynomialCommitmentScheme>::SRS,
    num_vars: usize,
) -> Duration {
    let rng = &mut test_rng();

    let (ml_ck, _ml_vk) = pp.0.trim(num_vars).unwrap();
    let (uni_ck, _uni_vk) = pp.1.trim(num_vars).unwrap();
    let ck = (ml_ck, uni_ck);

    let poly = MLE::from(DenseMultilinearExtension::rand(num_vars, rng));

    let start = Instant::now();
    let _ = MultilinearKzgPCS::commit(&ck, &poly).unwrap();
    start.elapsed()
}

/// Report the time cost of an opening
pub fn open<E: Pairing>(
    pp: &<MultilinearKzgPCS<E> as PolynomialCommitmentScheme>::SRS,
    num_vars: usize,
) -> Duration {
    let rng = &mut test_rng();

    let (ml_ck, _ml_vk) = pp.0.trim(num_vars).unwrap();
    let (uni_ck, _uni_vk) = pp.1.trim(num_vars).unwrap();
    let ck = (ml_ck, uni_ck);

    let poly = MLE::from(DenseMultilinearExtension::rand(num_vars, rng));
    let point: Vec<_> = (0..num_vars).map(|_| E::ScalarField::rand(rng)).collect();

    let start = Instant::now();
    let _ = MultilinearKzgPCS::open(&ck, &poly, &point).unwrap();
    start.elapsed()
}

/// Report the time cost of a verification
pub fn verify<E: Pairing>(
    pp: &<MultilinearKzgPCS<E> as PolynomialCommitmentScheme>::SRS,
    num_vars: usize,
) -> Duration {
    let rng = &mut test_rng();

    let (ml_ck, ml_vk) = pp.0.trim(num_vars).unwrap();
    let (uni_ck, uni_vk) = pp.1.trim(num_vars).unwrap();
    let ck = (ml_ck, uni_ck);
    let vk = (ml_vk, uni_vk);

    let poly = MLE::from(DenseMultilinearExtension::rand(num_vars, rng));
    let point: Vec<_> = (0..num_vars).map(|_| E::ScalarField::rand(rng)).collect();

    let commitment = MultilinearKzgPCS::commit(&ck, &poly).unwrap();

    let (proof, value) = MultilinearKzgPCS::open(&ck, &poly, &point).unwrap();

    let start = Instant::now();
    assert!(MultilinearKzgPCS::verify(&vk, &commitment, &point, &value, &proof).unwrap());
    start.elapsed()
}

fn kzg_254(c: &mut Criterion) {
    bench_pcs_method::<Bn254>(
        c,
        (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2),
        "commit_kzg_range_BN_254",
        commit::<Bn254>,
    );
    bench_pcs_method::<Bn254>(
        c,
        (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2),
        "open_kzg_range_BN_254",
        open::<Bn254>,
    );
    bench_pcs_method::<Bn254>(
        c,
        (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2),
        "verify_kzg_range_BN_254",
        verify::<Bn254>,
    );
}

fn kzg_381(c: &mut Criterion) {
    bench_pcs_method::<Bls12_381>(
        c,
        (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2),
        "commit_kzg_range_BLS_381",
        commit::<Bls12_381>,
    );
    bench_pcs_method::<Bls12_381>(
        c,
        (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2),
        "open_kzg_range_BLS_381",
        open::<Bls12_381>,
    );
    bench_pcs_method::<Bls12_381>(
        c,
        (MIN_NUM_VARS..MAX_NUM_VARS).step_by(2),
        "verify_kzg_range_BLS_381",
        verify::<Bls12_381>,
    );
}

criterion_group! {
    name = pcs_benches;
    config = Criterion::default();
    targets =
        kzg_254,
        kzg_381
}

criterion_main!(pcs_benches);
