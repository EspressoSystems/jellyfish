// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![deny(warnings)]
#[macro_use]
extern crate criterion;
use ark_ed_on_bls12_381::Fq as Fq381;
use ark_std::rand::Rng;
use criterion::Criterion;
use jf_primitives::merkle_tree::{prelude::RescueMerkleTree, MerkleTreeScheme};
use std::time::Duration;

const BENCH_NAME: &str = "merkle_path_height_20";

fn twenty_hashes(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group(BENCH_NAME);
    benchmark_group.sample_size(10);
    benchmark_group.measurement_time(Duration::new(10, 0));

    let mut rng = jf_utils::test_rng();

    let leaf: Fq381 = rng.gen();

    let mt = RescueMerkleTree::<Fq381>::from_elems(20, &[leaf, leaf]).unwrap();
    let (_, proof) = mt.lookup(0).expect_ok().unwrap();

    let num_inputs = 0;
    benchmark_group.bench_with_input(BENCH_NAME, &num_inputs, move |b, &_num_inputs| {
        b.iter(|| mt.verify(0, &proof).unwrap())
    });
    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    twenty_hashes(c);
}

criterion_group!(benches, bench);

criterion_main!(benches);
