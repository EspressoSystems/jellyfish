// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#[macro_use]
extern crate criterion;
use ark_std::rand::rngs::StdRng;
use criterion::{BenchmarkGroup, Criterion, Throughput};
use jf_signature::{
    bls_over_bls12381::BLSSignatureScheme, bls_over_bn254::BLSOverBN254CurveSignatureScheme,
    AggregateableSignatureSchemes, SignatureScheme,
};
use jf_utils::test_rng;

fn bench_aggregate<S: AggregateableSignatureSchemes, T: criterion::measurement::Measurement>(
    benchmark_group: &mut BenchmarkGroup<T>,
    msgs: &[&[S::MessageUnit]],
    rng: &mut StdRng,
) {
    let pp = S::param_gen(Some(rng)).unwrap();
    let mut vks = vec![];
    let mut sigs = vec![];
    let mut partial_sigs = vec![];
    let msg_for_msig = &msgs[0];
    for msg in msgs.iter() {
        let (sk, vk) = S::key_gen(&pp, rng).unwrap();
        let sig = S::sign(&pp, &sk, msg, rng).unwrap();
        let partial_sig = S::sign(&pp, &sk, msg_for_msig, rng).unwrap();
        vks.push(vk);
        sigs.push(sig);
        partial_sigs.push(partial_sig);
    }

    let agg_sig = S::aggregate(&pp, &vks, &sigs).unwrap();
    let multi_sig = S::aggregate(&pp, &vks, &partial_sigs).unwrap();

    benchmark_group.bench_function(format!("aggregation_{}", msgs.len()), |b| {
        b.iter(|| S::aggregate(&pp, &vks, &sigs).unwrap())
    });
    benchmark_group.bench_function(format!("aggregate_verification_{}", msgs.len()), |b| {
        b.iter(|| S::aggregate_verify(&pp, &vks, msgs, &agg_sig).unwrap())
    });
    benchmark_group.bench_function(
        format!("multi_signature_verification_{}", msgs.len()),
        |b| b.iter(|| S::multi_sig_verify(&pp, &vks, msgs[0], &multi_sig).unwrap()),
    );
}

fn bench_bls12381(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group("BLS Over BLS12-381");
    benchmark_group.sample_size(500);
    benchmark_group.throughput(Throughput::Elements(1u64));
    let rng = &mut test_rng();
    let (sk, vk) = BLSSignatureScheme::key_gen(&(), rng).unwrap();
    let msg = String::from_utf8(vec![b'X'; 1024]).unwrap();
    let sig = BLSSignatureScheme::sign(&(), &sk, &msg, rng).unwrap();

    benchmark_group.bench_function("Sign", |b| {
        b.iter(|| BLSSignatureScheme::sign(&(), &sk, &msg, rng).unwrap())
    });
    benchmark_group.bench_function("Verification", |b| {
        b.iter(|| BLSSignatureScheme::verify(&(), &vk, &msg, &sig).unwrap())
    });

    // TODO: aggregate signature benchmark not implemented

    benchmark_group.finish();
}

fn bench_bn254(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group("BLS Over Bn254");
    benchmark_group.sample_size(100);
    benchmark_group.throughput(Throughput::Elements(1u64));
    let rng = &mut test_rng();
    let (sk, vk) = BLSOverBN254CurveSignatureScheme::key_gen(&(), rng).unwrap();
    let msg = vec![12u8; 1000];
    let msgs = vec![msg.as_slice(); 1000];
    let sig = BLSOverBN254CurveSignatureScheme::sign(&(), &sk, msgs[0], rng).unwrap();

    benchmark_group.bench_function("Sign", |b| {
        b.iter(|| BLSOverBN254CurveSignatureScheme::sign(&(), &sk, msgs[0], rng).unwrap())
    });
    benchmark_group.bench_function("Verification", |b| {
        b.iter(|| BLSOverBN254CurveSignatureScheme::verify(&(), &vk, msgs[0], &sig).unwrap())
    });

    bench_aggregate::<BLSOverBN254CurveSignatureScheme, _>(
        &mut benchmark_group,
        &msgs.as_slice()[0..10],
        rng,
    );
    bench_aggregate::<BLSOverBN254CurveSignatureScheme, _>(
        &mut benchmark_group,
        &msgs.as_slice()[0..100],
        rng,
    );
    bench_aggregate::<BLSOverBN254CurveSignatureScheme, _>(
        &mut benchmark_group,
        msgs.as_slice(),
        rng,
    );

    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    bench_bls12381(c);
    bench_bn254(c);
}

criterion_group!(benches, bench);
criterion_main!(benches);
