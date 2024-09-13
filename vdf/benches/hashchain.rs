// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#[macro_use]
extern crate criterion;
use ark_std::rand::rngs::StdRng;
use criterion::{Criterion, Throughput};
use jf_vdf::{hashchain::HashChain, VDF};

fn minroot_bench(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group("HashChain");
    benchmark_group.sample_size(10);
    let iterations = 1u64 << 22;

    benchmark_group.throughput(Throughput::Elements(iterations));
    let pp = HashChain::setup::<StdRng>(iterations, None).unwrap();
    let input = [0u8; 32];
    benchmark_group.bench_function("HashChain_sha3_keccak", |b| {
        b.iter(|| HashChain::eval(&pp, &input).unwrap())
    });

    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    minroot_bench(c);
}

criterion_group!(benches, bench);

criterion_main!(benches);
