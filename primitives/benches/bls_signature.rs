// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#[macro_use]
extern crate criterion;
use criterion::{Criterion, Throughput};
use jf_primitives::signatures::{
    bls_over_bn254::BLSOverBN254CurveSignatureScheme, BLSSignatureScheme, SignatureScheme,
};
use jf_utils::test_rng;

fn bench_bls12381(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group("BLS Over BLS12-381");
    benchmark_group.sample_size(500);
    benchmark_group.throughput(Throughput::Elements(1u64));
    let rng = &mut test_rng();
    let pp = BLSSignatureScheme::param_gen(Some(rng)).unwrap();
    let (sk, vk) = BLSSignatureScheme::key_gen(&pp, rng).unwrap();
    let msg = String::from_utf8(vec![b'X'; 1024]).unwrap();
    let sig = BLSSignatureScheme::sign(&pp, &sk, &msg, rng).unwrap();

    benchmark_group.bench_function("Sign", |b| {
        b.iter(|| BLSSignatureScheme::sign(&pp, &sk, &msg, rng).unwrap())
    });
    benchmark_group.bench_function("Verification", |b| {
        b.iter(|| BLSSignatureScheme::verify(&pp, &vk, &msg, &sig).unwrap())
    });

    benchmark_group.finish();
}

fn bench_bn254(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group("BLS Over Bn254");
    benchmark_group.sample_size(500);
    benchmark_group.throughput(Throughput::Elements(1u64));
    let rng = &mut test_rng();
    let pp = BLSOverBN254CurveSignatureScheme::param_gen(Some(rng)).unwrap();
    let (sk, vk) = BLSOverBN254CurveSignatureScheme::key_gen(&pp, rng).unwrap();
    let msg = String::from_utf8(vec![b'X'; 1024]).unwrap();
    let sig = BLSOverBN254CurveSignatureScheme::sign(&pp, &sk, &msg, rng).unwrap();

    benchmark_group.bench_function("Sign", |b| {
        b.iter(|| BLSOverBN254CurveSignatureScheme::sign(&pp, &sk, &msg, rng).unwrap())
    });
    benchmark_group.bench_function("Verification", |b| {
        b.iter(|| BLSOverBN254CurveSignatureScheme::verify(&pp, &vk, &msg, &sig).unwrap())
    });

    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    bench_bls12381(c);
    bench_bn254(c);
}

criterion_group!(benches, bench);
criterion_main!(benches);
