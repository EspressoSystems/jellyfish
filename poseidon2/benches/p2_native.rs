//! Benchmark for native speed of Poseidon2
//! `cargo bench --bench p2_native`
#[macro_use]
extern crate criterion;
use std::time::Duration;

use ark_std::{test_rng, UniformRand};
use criterion::Criterion;
use jf_poseidon2::{
    constants::{
        bls12_381::{Poseidon2ParamsBls2, Poseidon2ParamsBls3},
        bn254::Poseidon2ParamsBn3,
    },
    Poseidon2,
};

// BLS12-381 scalar field, state size = 2
fn bls2(c: &mut Criterion) {
    let mut group = c.benchmark_group("Poseidon2 over (Bls12_381::Fr, t=2)");
    group.sample_size(10).measurement_time(Duration::new(20, 0));
    type Fr = ark_bls12_381::Fr;
    let rng = &mut test_rng();

    group.bench_function("1k iter", |b| {
        b.iter(|| {
            let mut input = [Fr::rand(rng), Fr::rand(rng)];
            for _ in 0..1000 {
                Poseidon2::permute_mut::<Poseidon2ParamsBls2, 2>(&mut input);
            }
        })
    });
    group.bench_function("100k iter", |b| {
        b.iter(|| {
            let mut input = [Fr::rand(rng), Fr::rand(rng)];
            for _ in 0..100_000 {
                Poseidon2::permute_mut::<Poseidon2ParamsBls2, 2>(&mut input);
            }
        })
    });
    group.finish();
}

// BLS12-381 scalar field, state size = 3
fn bls3(c: &mut Criterion) {
    let mut group = c.benchmark_group("Poseidon2 over (Bls12_381::Fr, t=3)");
    group.sample_size(10).measurement_time(Duration::new(20, 0));
    type Fr = ark_bls12_381::Fr;
    let rng = &mut test_rng();

    group.bench_function("1k iter", |b| {
        b.iter(|| {
            let mut input = [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
            for _ in 0..1000 {
                Poseidon2::permute_mut::<Poseidon2ParamsBls3, 3>(&mut input);
            }
        })
    });
    group.bench_function("100k iter", |b| {
        b.iter(|| {
            let mut input = [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
            for _ in 0..100_000 {
                Poseidon2::permute_mut::<Poseidon2ParamsBls3, 3>(&mut input);
            }
        })
    });
    group.finish();
}

// BN254 scalar field, state size = 3
fn bn3(c: &mut Criterion) {
    let mut group = c.benchmark_group("Poseidon2 over (Bn254::Fr, t=3)");
    group.sample_size(10).measurement_time(Duration::new(20, 0));
    type Fr = ark_bn254::Fr;
    let rng = &mut test_rng();

    group.bench_function("1k iter", |b| {
        b.iter(|| {
            let mut input = [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
            for _ in 0..1000 {
                Poseidon2::permute_mut::<Poseidon2ParamsBn3, 3>(&mut input);
            }
        })
    });
    group.bench_function("100k iter", |b| {
        b.iter(|| {
            let mut input = [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
            for _ in 0..100_000 {
                Poseidon2::permute_mut::<Poseidon2ParamsBn3, 3>(&mut input);
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bls2, bls3, bn3);

criterion_main!(benches);
