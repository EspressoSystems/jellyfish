// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_serialize::Write;
use ark_std::rand::RngCore;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use digest::{crypto_common::generic_array::ArrayLength, Digest, DynDigest, OutputSizeUser};
use jf_pcs::{checked_fft_size, prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
use jf_vid::{advz::Advz, VidScheme};
use sha2::Sha256;

const KB: usize = 1 << 10;
const MB: usize = KB << 10;

fn advz<E, H>(c: &mut Criterion, pairing_name: &str)
where
    E: Pairing,
    // TODO(Gus) clean up nasty trait bounds upstream
    H: Digest + DynDigest + Default + Clone + Write + Send + Sync,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    // play with these items
    //
    // CODE_RATE is merely a convenient way to automatically choose polynomial
    // degree as a function of storage node count.
    // If desired, you could set polynomial degrees independent of storage node
    // count.
    const CODE_RATE: u32 = 4; // ratio of num_storage_nodes : polynomial_degree
    let storage_node_counts = [512, 1024];
    let payload_byte_lens = [1 * MB];

    // more items as a function of the above
    let poly_degrees_iter = storage_node_counts.iter().map(|c| c / CODE_RATE);
    let supported_degree = poly_degrees_iter.clone().max().unwrap();
    let vid_sizes_iter = poly_degrees_iter.zip(storage_node_counts);
    let mut rng = jf_utils::test_rng();
    let srs = UnivariateKzgPCS::<E>::gen_srs_for_testing(
        &mut rng,
        checked_fft_size(supported_degree as usize).unwrap(),
    )
    .unwrap();

    // run all benches for each payload_byte_lens
    for len in payload_byte_lens {
        // random payload data
        let payload_bytes = {
            let mut payload_bytes = vec![0u8; len];
            rng.fill_bytes(&mut payload_bytes);
            payload_bytes
        };

        let benchmark_group_name =
            |op_name| format!("advz_{}_{}_{}KB", pairing_name, op_name, len / KB);

        // commit
        let mut grp = c.benchmark_group(benchmark_group_name("commit"));
        grp.throughput(Throughput::Bytes(len as u64));
        for (poly_degree, num_storage_nodes) in vid_sizes_iter.clone() {
            let mut advz = Advz::<E, H>::new(num_storage_nodes, poly_degree, &srs).unwrap();
            grp.bench_with_input(
                BenchmarkId::from_parameter(num_storage_nodes),
                &num_storage_nodes,
                |b, _| {
                    b.iter(|| advz.commit_only(&payload_bytes).unwrap());
                },
            );
        }
        grp.finish();

        // disperse
        let mut grp = c.benchmark_group(benchmark_group_name("disperse"));
        grp.throughput(Throughput::Bytes(len as u64));
        for (poly_degree, num_storage_nodes) in vid_sizes_iter.clone() {
            let mut advz = Advz::<E, H>::new(num_storage_nodes, poly_degree, &srs).unwrap();
            grp.bench_with_input(
                BenchmarkId::from_parameter(num_storage_nodes),
                &num_storage_nodes,
                |b, _| {
                    b.iter(|| advz.disperse(&payload_bytes).unwrap());
                },
            );
        }
        grp.finish();

        // verify
        let mut grp = c.benchmark_group(benchmark_group_name("verify"));
        grp.throughput(Throughput::Bytes(len as u64));
        for (poly_degree, num_storage_nodes) in vid_sizes_iter.clone() {
            let mut advz = Advz::<E, H>::new(num_storage_nodes, poly_degree, &srs).unwrap();
            let disperse = advz.disperse(&payload_bytes).unwrap();
            let (shares, common, commit) = (disperse.shares, disperse.common, disperse.commit);
            grp.bench_with_input(
                BenchmarkId::from_parameter(num_storage_nodes),
                &num_storage_nodes,
                |b, _| {
                    // verify only the 0th share
                    b.iter(|| {
                        advz.verify_share(&shares[0], &common, &commit)
                            .unwrap()
                            .unwrap()
                    });
                },
            );
        }
        grp.finish();

        // recover
        let mut grp = c.benchmark_group(benchmark_group_name("recover"));
        grp.throughput(Throughput::Bytes(len as u64));
        for (poly_degree, num_storage_nodes) in vid_sizes_iter.clone() {
            let mut advz = Advz::<E, H>::new(num_storage_nodes, poly_degree, &srs).unwrap();
            let disperse = advz.disperse(&payload_bytes).unwrap();
            let (shares, common) = (disperse.shares, disperse.common);
            grp.bench_with_input(
                BenchmarkId::from_parameter(num_storage_nodes),
                &num_storage_nodes,
                |b, _| {
                    // recover from only the first poly_degree shares
                    b.iter(|| {
                        advz.recover_payload(&shares[..poly_degree as usize], &common)
                            .unwrap()
                    });
                },
            );
        }
        grp.finish();
    }
}

fn advz_main(c: &mut Criterion) {
    advz::<Bls12_381, Sha256>(c, "Bls381");
    advz::<Bn254, Sha256>(c, "Bn254");
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = advz_main);

criterion_main!(benches);
