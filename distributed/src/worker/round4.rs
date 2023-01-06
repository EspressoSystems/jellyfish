use std::cmp::max;

use ark_bls12_381::Fr;
use ark_ff::{Field, Zero};
use fn_timer::fn_timer;
use rayon::{
    prelude::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};

use super::PlonkImplInner;

fn evaluate(v: &[Fr], point: &Fr) -> Fr {
    if v.is_empty() {
        return Fr::zero();
    } else if point.is_zero() {
        return v[0];
    }
    // Horners method - parallel method
    // compute the number of threads we will be using.
    let num_elem_per_thread = max(v.len() / rayon::current_num_threads(), 16);

    // run Horners method on each thread as follows:
    // 1) Split up the coefficients across each thread evenly.
    // 2) Do polynomial evaluation via horner's method for the thread's coefficeints
    // 3) Scale the result point^{thread coefficient start index}
    // Then obtain the final polynomial evaluation by summing each threads result.
    v.par_chunks(num_elem_per_thread)
        .enumerate()
        .map(|(i, chunk)| {
            let mut thread_result =
                chunk.iter().rfold(Fr::zero(), move |result, coeff| result * point + coeff);
            thread_result *= point.pow(&[(i * num_elem_per_thread) as u64]);
            thread_result
        })
        .sum()
}

impl PlonkImplInner {
    #[fn_timer]
    pub fn evaluate_w(&self, zeta: &Fr) -> Fr {
        evaluate(&self.w.load().unwrap(), zeta)
    }

    #[fn_timer]
    pub fn evaluate_sigma(&self, zeta: &Fr) -> Fr {
        evaluate(&self.sigma.load().unwrap(), zeta)
    }

    #[fn_timer]
    pub fn evaluate_z(&self, zeta: &Fr) -> Fr {
        evaluate(&self.z, &(self.domain1.generator() * zeta))
    }
}
