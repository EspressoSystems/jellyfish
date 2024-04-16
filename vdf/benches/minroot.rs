// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#[macro_use]
extern crate criterion;
use ark_bls12_381::Fr as Fr381;
use ark_bn254::Fr as Fr254;
use ark_pallas::Fr as PastaFr;
use ark_std::rand::rngs::StdRng;
use criterion::{Criterion, Throughput};
use jf_vdf::{
    minroot::{MinRoot, MinRootElement},
    VDF,
};

fn minroot_bench(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group("MinRoot");
    benchmark_group.sample_size(10);
    let iterations = 1u64 << 16;

    benchmark_group.throughput(Throughput::Elements(iterations));
    let pp = MinRoot::<Fr254>::setup::<StdRng>(iterations, None).unwrap();
    let input = MinRootElement::<Fr254>::default();
    benchmark_group.bench_function("MinRoot_BN254", |b| {
        b.iter(|| MinRoot::<Fr254>::eval(&pp, &input).unwrap())
    });

    let input = MinRootElement::<Fr381>::default();
    benchmark_group.bench_function("MinRoot_BLS381", |b| {
        b.iter(|| MinRoot::<Fr381>::eval(&pp, &input).unwrap())
    });

    let input = MinRootElement::<PastaFr>::default();
    benchmark_group.bench_function("MinRoot_Pallas", |b| {
        b.iter(|| MinRoot::<PastaFr>::eval(&pp, &input).unwrap())
    });

    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    minroot_bench(c);
}

criterion_group!(benches, bench);

criterion_main!(benches);
