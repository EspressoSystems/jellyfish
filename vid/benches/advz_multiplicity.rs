// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Benchmarks demonstrating performance improvement in [`Advz::verify_share`]
//! from use of parallelism over `multiplicity`.
//!
//! Run
//! ```
//! cargo bench --bench=advz_multiplicity --features="test-srs"
//! ```
//!
//! By
//! [default](https://github.com/rayon-rs/rayon/blob/main/FAQ.md#how-many-threads-will-rayon-spawn)
//! the number of threads = number of available CPU cores. You can override this
//! choice by prevising the above command with `RAYON_NUM_THREADS=N `. Example:
//! set `N=1` to eliminate parallelism.

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_serialize::Write;
use ark_std::rand::RngCore;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use digest::{crypto_common::generic_array::ArrayLength, Digest, DynDigest, OutputSizeUser};
use jf_pcs::{checked_fft_size, prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
use jf_utils::field_byte_len;
use jf_vid::{advz::Advz, VidScheme};
use sha2::Sha256;

const KB: usize = 1 << 10;
// const MB: usize = KB << 10;

fn advz<E, H>(c: &mut Criterion)
where
    E: Pairing,
    // TODO(Gus) clean up nasty trait bounds upstream
    H: Digest + DynDigest + Default + Clone + Write + Send + Sync,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    // play with these items
    //
    // INVERSE_CODE_RATE is merely a convenient way to automatically choose
    // recovery threshold as a function of storage node count. If desired, you
    // could set recovery thresholds independent of storage node counts.
    let multiplicities = [1, 256];
    let num_storage_nodes = 128;
    const INVERSE_CODE_RATE: usize = 4; // ratio of num_storage_nodes : recovery_threshold

    // more items as a function of the above
    let recovery_threshold = num_storage_nodes / INVERSE_CODE_RATE;
    let max_multiplicity = multiplicities.iter().max().unwrap();
    let max_degree = recovery_threshold * max_multiplicity;
    let coeff_byte_len = field_byte_len::<E::ScalarField>();
    let payload_byte_len = {
        // ensure payload is large enough to fill at least 1 polynomial at
        // maximum multiplicity.
        max_degree * coeff_byte_len
    };
    let mut rng = jf_utils::test_rng();
    let payload_bytes = {
        // random payload data
        let mut payload_bytes = vec![0u8; payload_byte_len];
        rng.fill_bytes(&mut payload_bytes);
        payload_bytes
    };
    let srs =
        UnivariateKzgPCS::<E>::gen_srs_for_testing(&mut rng, checked_fft_size(max_degree).unwrap())
            .unwrap();

    let benchmark_group_name = format!(
        "advz_verify_payload_{}KB_multiplicity",
        payload_byte_len / KB
    );
    let mut grp = c.benchmark_group(benchmark_group_name);
    for multiplicity in multiplicities {
        let mut advz = Advz::<E, H>::with_multiplicity(
            num_storage_nodes.try_into().unwrap(),
            recovery_threshold.try_into().unwrap(),
            multiplicity.try_into().unwrap(),
            &srs,
        )
        .unwrap();
        let disperse = advz.disperse(&payload_bytes).unwrap();
        let (shares, common, commit) = (disperse.shares, disperse.common, disperse.commit);
        grp.bench_function(BenchmarkId::from_parameter(multiplicity), |b| {
            // verify only the 0th share
            b.iter(|| {
                advz.verify_share(&shares[0], &common, &commit)
                    .unwrap()
                    .unwrap()
            });
        });
    }
    grp.finish();
}

fn advz_main(c: &mut Criterion) {
    advz::<Bn254, Sha256>(c);
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = advz_main);

criterion_main!(benches);
