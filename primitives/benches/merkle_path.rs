// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![deny(warnings)]
#[macro_use]
extern crate criterion;
use ark_ed_on_bls12_381::Fq as Fq381;
use ark_std::rand::{prelude::SliceRandom, Rng};
use criterion::Criterion;
use jf_primitives::merkle_tree::{
    MerkleLeafProof, MerklePath, MerklePathNode, MerkleTree, NodePos, NodeValue,
};
use std::time::Duration;

const BENCH_NAME: &str = "merkle_path_height_20";

fn twenty_hashes(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group(BENCH_NAME);
    benchmark_group.sample_size(10);
    benchmark_group.measurement_time(Duration::new(10, 0));

    let mut rng = ark_std::test_rng();

    let leaf: Fq381 = rng.gen();
    let base: NodeValue<Fq381> = rng.gen();
    let mut sibs = vec![];
    for _ in 0..20 {
        let pos = *[NodePos::Left, NodePos::Middle, NodePos::Right]
            .choose(&mut rng)
            .unwrap();
        let sibling1: NodeValue<_> = rng.gen();
        let sibling2: NodeValue<_> = rng.gen();
        sibs.push(MerklePathNode {
            sibling1,
            sibling2,
            pos,
        });
    }

    let sibs = MerklePath { nodes: sibs };

    let num_inputs = 0;
    benchmark_group.bench_with_input(BENCH_NAME, &num_inputs, move |b, &_num_inputs| {
        b.iter(|| MerkleTree::check_proof(base, 0, &MerkleLeafProof::new(leaf, sibs.clone())))
    });

    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    twenty_hashes(c);
}

criterion_group!(benches, bench);

criterion_main!(benches);
