//! This benchmark meant for MSM speed comparison between arkworks and
//! GPU-accelerated code We use `UnivariateKzgPCS::commit()` as a proxy for MSM
//!
//! Run `cargo bench --bench kzg-gpu --features "test-srs icicle"`
use ark_bn254::Bn254;
#[cfg(feature = "icicle")]
use ark_ec::models::{short_weierstrass::Affine, CurveConfig};
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
pub fn kzg_icicle<E, C>(c: &mut Criterion)
where
    C: IcicleCurve + MSM<C>,
    C::ScalarField: ArkConvertible<ArkEquivalent = E::ScalarField>,
    C::BaseField: ArkConvertible<ArkEquivalent = <C::ArkSWConfig as CurveConfig>::BaseField>,
    E: Pairing<G1Affine = Affine<<C as IcicleCurve>::ArkSWConfig>>,
{
    let mut group = c.benchmark_group("MSM with ICICLE");
    let mut rng = test_rng();

    let supported_degree = 2usize.pow(MAX_LOG_DEGREE as u32);
    let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(&mut rng, supported_degree).unwrap();
    // TODO: (alex) figure out load longer SRS first, and only use part of it later
    // currently it will error if the `scalars.len() % points.len() != 0`
    // while we can tap into a slice behind the reference via
    // `HostOrDeviceSlice[..]` which gives `&[T]` however msm() doesn't accept
    // &[T], only `&HostOrDeviceSlice`

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
            |b, _log_degree| {
                b.iter(|| UnivariateKzgPCS::<E>::commit_with_gpu::<C>(&ck, &p).unwrap())
            },
        );
    }
    group.finish();
}

fn kzg_gpu_bn254(c: &mut Criterion) {
    kzg_ark::<Bn254>(c);
    #[cfg(feature = "icicle")]
    kzg_icicle::<Bn254, icicle_bn254::curve::CurveCfg>(c);
}

criterion_group! {
    name = kzg_gpu_benches;
    config = Criterion::default().sample_size(10);
    targets =
        kzg_gpu_bn254,
}

criterion_main!(kzg_gpu_benches);
