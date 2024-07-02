// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![deny(warnings)]
#[macro_use]
extern crate criterion;
use ark_bn254::Fr as Fr254;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use criterion::Criterion;
use jf_utils::reed_solomon_code::reed_solomon_erasure_decode;
use std::time::Duration;

const BENCH_ENCODE: &str = "reed_solomon_encode_4096";
const BENCH_DECODE: &str = "reed_solomon_decode_4096";
const N: usize = 2048;
const N_HALF: usize = 1024;

fn reed_solomon(c: &mut Criterion) {
    let domain = GeneralEvaluationDomain::<Fr254>::new(N).unwrap();

    let mut bench = c.benchmark_group("reed_solomon");
    bench.sample_size(10);
    bench.measurement_time(Duration::new(5, 0));
    let input = vec![Fr254::from(1u64); N_HALF];
    bench.bench_function(BENCH_ENCODE, |b| b.iter(|| domain.fft(&input)));

    let code = domain.fft(&input);
    let eval_points = domain.elements().collect::<Vec<_>>();

    bench.bench_function(BENCH_DECODE, |b| {
        b.iter(|| {
            reed_solomon_erasure_decode::<Fr254, _, _, _>(
                eval_points.iter().zip(&code).take(N_HALF),
                N_HALF,
            )
            .unwrap()
        })
    });
    bench.finish();
}

fn bench(c: &mut Criterion) {
    reed_solomon(c);
}

criterion_group!(benches, bench);

criterion_main!(benches);
