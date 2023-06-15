//! Benchmark code for reed_solomon implementation for coz profiler.
use ark_bn254::Fr as Fr254;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use jf_primitives::reed_solomon_code::reed_solomon_erasure_decode;

const N: usize = 2048;
const N_HALF: usize = 1024;
// run it many times so coz will be triggered enough times
// see: <https://github.com/plasma-umass/coz/issues/158#issuecomment-708507510>
const ITERATIONS: usize = 2_000_000_000;

fn main() {
    coz::thread_init();

    let domain = GeneralEvaluationDomain::<Fr254>::new(N).unwrap();
    let input = vec![Fr254::from(1u64); N_HALF];

    // encode and evaluate
    let code = domain.fft(&input);
    let eval_points = domain.elements().collect::<Vec<_>>();

    // decode
    for _ in 0..ITERATIONS {
        reed_solomon_erasure_decode::<Fr254, _, _, _>(
            eval_points.iter().zip(&code).take(N_HALF),
            N_HALF,
        )
        .unwrap();
    }
}
