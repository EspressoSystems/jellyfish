//! This benchmark meant for MSM speed comparison between arkworks and
//! GPU-accelerated code We use `UnivariateKzgPCS::commit()` as a proxy for MSM
//!
//! Run `cargo bench --bench kzg-gpu --features "test-srs icicle"`
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
#[cfg(feature = "icicle")]
use jf_primitives::icicle_deps::*;
use jf_primitives::pcs::{
    prelude::{PolynomialCommitmentScheme, UnivariateKzgPCS},
    StructuredReferenceString,
};
use jf_utils::test_rng;

const MIN_LOG_DEGREE: usize = 19;
const MAX_LOG_DEGREE: usize = 23;

/// running MSM using arkworks backend
pub fn kzg_ark<E: Pairing>(c: &mut Criterion) {
    let mut group = c.benchmark_group("MSM with arkworks");
    let mut rng = test_rng();

    let supported_degree = 2usize.pow(MAX_LOG_DEGREE as u32);
    let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(&mut rng, supported_degree).unwrap();

    // setup for commit first
    for log_degree in MIN_LOG_DEGREE..MAX_LOG_DEGREE {
        let degree = 2usize.pow(log_degree as u32);
        let (ck, _vk) = pp.trim(degree).unwrap();
        let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
            degree, &mut rng,
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(log_degree),
            &log_degree,
            |b, _log_degree| b.iter(|| UnivariateKzgPCS::<E>::commit(&ck, &p).unwrap()),
        );
    }
    group.finish();
}

/// running MSM using ICICLE backends
#[cfg(feature = "icicle")]
pub fn kzg_icicle<E>(c: &mut Criterion)
where
    E: Pairing,
    UnivariateKzgPCS<E>: GPUCommittable<E>,
{
    let mut group = c.benchmark_group("MSM with ICICLE");
    let mut rng = test_rng();
    let stream = warmup_new_stream().unwrap();

    let supported_degree = 2usize.pow(MAX_LOG_DEGREE as u32);
    let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(&mut rng, supported_degree).unwrap();
    let (full_ck, _vk) = pp.trim(supported_degree).unwrap();
    let mut srs_on_gpu = <UnivariateKzgPCS<E> as GPUCommittable<E>>::load_prover_param_to_gpu(
        full_ck,
        supported_degree,
    )
    .unwrap();

    // setup for commit first
    for log_degree in MIN_LOG_DEGREE..MAX_LOG_DEGREE {
        let degree = 2usize.pow(log_degree as u32);
        let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
            degree, &mut rng,
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(log_degree),
            &log_degree,
            |b, _log_degree| {
                b.iter(|| {
                    <UnivariateKzgPCS<E> as GPUCommittable<E>>::gpu_commit_with_loaded_prover_param(
                        &mut srs_on_gpu,
                        &p,
                        &stream,
                    )
                    .unwrap()
                })
            },
        );
    }
    group.finish();
}

fn kzg_gpu_bn254(c: &mut Criterion) {
    kzg_ark::<Bn254>(c);
    #[cfg(feature = "icicle")]
    kzg_icicle::<Bn254>(c);
}

criterion_group! {
    name = kzg_gpu_benches;
    config = Criterion::default().sample_size(10);
    targets =
        kzg_gpu_bn254,
}

criterion_main!(kzg_gpu_benches);
