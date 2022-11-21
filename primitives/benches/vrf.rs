// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

// #![deny(warnings)]
#[macro_use]
extern crate criterion;
use ark_std::rand::Rng;
use criterion::Criterion;
use jf_primitives::vrf::{
    blsvrf::{BLSVRFCipherSuite, BLSVRFScheme},
    blsvrf_generic::BLSVRFSchemeGen,
    Vrf,
};
use sha2::{Sha256, Sha512};

const SAMPLES: usize = 1000;
type BLSVRFSchemeGen512 = BLSVRFSchemeGen<Sha512>;

fn blsvrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("blsvrf");
    group.sample_size(10000);

    let mut rng = &mut ark_std::test_rng();

    let mut vrf = BLSVRFScheme::new(BLSVRFCipherSuite::VRF_BLS_12_381_SHA512);
    let mut vrf_gen = BLSVRFSchemeGen512::new();

    // parameters are the same
    let parameters = vrf.param_gen(Some(&mut rng)).unwrap();

    let (sk, pk) = vrf.key_gen(&parameters, &mut rng).unwrap();

    let mut proofs = Vec::new();
    let mut messages = Vec::new();

    group.bench_function("prove dyn", |b| {
        b.iter(|| {
            let message: [u8; 32] = rng.gen();
            messages.push(message);
            let proof = vrf.prove(&parameters, &sk, &message.to_vec(), rng).unwrap();
            proofs.push(proof);
        })
    });
    group.bench_function("prove generic", |b| {
        b.iter(|| {
            let message: [u8; 32] = rng.gen();
            messages.push(message);
            let proof = vrf_gen
                .prove(&parameters, &sk, &message.to_vec(), rng)
                .unwrap();
            proofs.push(proof);
        })
    });

    group.bench_function("hash dyn", |b| {
        let mut i = 0;
        b.iter(|| {
            let _vrf_output = vrf
                .proof_to_hash(&parameters, &proofs[i % SAMPLES])
                .unwrap();
            i += 1;
        })
    });

    group.bench_function("hash_gen", |b| {
        let mut i = 0;
        b.iter(|| {
            let _vrf_output = vrf_gen
                .proof_to_hash(&parameters, &proofs[i % SAMPLES])
                .unwrap();
            i += 1;
        })
    });

    group.bench_function("verify dyn", |b| {
        let mut i = 0;
        b.iter(|| {
            vrf.verify(
                &parameters,
                &proofs[i % SAMPLES],
                &pk,
                &messages[i % SAMPLES].to_vec(),
            )
            .unwrap();
            i += 1;
        })
    });
    group.bench_function("verify gen", |b| {
        let mut i = 0;
        b.iter(|| {
            vrf_gen
                .verify(
                    &parameters,
                    &proofs[i % SAMPLES],
                    &pk,
                    &messages[i % SAMPLES].to_vec(),
                )
                .unwrap();
            i += 1;
        })
    });
}

fn bench(c: &mut Criterion) {
    blsvrf(c);
}

criterion_group!(benches, bench);

criterion_main!(benches);
