// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![cfg(feature = "test-srs")]

use ark_bn254::{Bn254, Fr};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};
use jf_primitives::pcs::prelude::{MultilinearKzgPCS, PolynomialCommitmentScheme, MLE};
use jf_primitives::pcs::StructuredReferenceString;
use jf_utils::test_rng;

const SAMPLES: usize = 100;

fn commit(c: &mut Criterion) {
    let max_num_vars = 18;
    let nv = 17;

    let mut rng = &mut test_rng();
    let uni_params =
        MultilinearKzgPCS::<Bn254>::gen_srs_for_testing(&mut rng, max_num_vars).unwrap();

    let (ml_ck, _ml_vk) = uni_params.0.trim(nv).unwrap();
    let (uni_ck, _uni_vk) = uni_params.1.trim(nv).unwrap();
    let ck = (ml_ck, uni_ck);

    let polys = (0..SAMPLES)
        .map(|_| MLE::from(DenseMultilinearExtension::rand(nv, &mut rng)))
        .collect::<Vec<_>>();

    // this is a little ugly, but ideally we want to avoid cloning inside the benchmark. Therefore we keep `labeled_polys` in scope, and just commit to references to it.

    c.bench_function("Multilinear KZG Commit", |b| {
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % SAMPLES;
            let _commit = MultilinearKzgPCS::commit(&ck, &polys[i]).unwrap();
        })
    });
}

fn open(c: &mut Criterion) {
    let max_num_vars = 18;
    let nv = 17;

    let mut rng = &mut test_rng();
    let uni_params =
        MultilinearKzgPCS::<Bn254>::gen_srs_for_testing(&mut rng, max_num_vars).unwrap();

    let (ml_ck, _ml_vk) = uni_params.0.trim(nv).unwrap();
    let (uni_ck, _uni_vk) = uni_params.1.trim(nv).unwrap();
    let ck = (ml_ck, uni_ck);

    let polys = (0..SAMPLES)
        .map(|_| MLE::from(DenseMultilinearExtension::rand(nv, &mut rng)))
        .collect::<Vec<_>>();

    let points: Vec<_> = (0..SAMPLES)
        .map(|_| (0..nv).map(|_| Fr::rand(&mut rng)).collect())
        .collect();

    c.bench_function("Multilinear KZG Open", |b| {
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % SAMPLES;
            let _open = MultilinearKzgPCS::open(&ck, &polys[i], &points[i]).unwrap();
        })
    });
}

fn verify(c: &mut Criterion) {
    let max_num_vars = 18;
    let nv = 17;

    let mut rng = &mut test_rng();
    let uni_params =
        MultilinearKzgPCS::<Bn254>::gen_srs_for_testing(&mut rng, max_num_vars).unwrap();

    let (ml_ck, ml_vk) = uni_params.0.trim(nv).unwrap();
    let (uni_ck, uni_vk) = uni_params.1.trim(nv).unwrap();
    let ck = (ml_ck, uni_ck);
    let vk = (ml_vk, uni_vk);

    let polys = (0..SAMPLES)
        .map(|_| MLE::from(DenseMultilinearExtension::rand(nv, &mut rng)))
        .collect::<Vec<_>>();

    let commitments: Vec<_> = (0..SAMPLES)
        .map(|i| MultilinearKzgPCS::commit(&ck, &polys[i]).unwrap())
        .collect();

    let points: Vec<_> = (0..SAMPLES)
        .map(|_| (0..nv).map(|_| Fr::rand(&mut rng)).collect())
        .collect();

    let (proofs, values): (Vec<_>, Vec<_>) = (0..SAMPLES)
        .map(|i| MultilinearKzgPCS::open(&ck, &polys[i], &points[i]).unwrap())
        .unzip();

    c.bench_function("Multilinear KZG Verify", |b| {
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % SAMPLES;
            let _verify =
                MultilinearKzgPCS::verify(&vk, &commitments[i], &points[i], &values[i], &proofs[i])
                    .unwrap();
        })
    });
}

criterion_group! {
    name = pcs_benches;
    config = Criterion::default();
    targets =
        commit,
        open,
        verify,
}

criterion_main!(pcs_benches);
