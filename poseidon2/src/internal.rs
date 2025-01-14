//! Generic implementation for internal layers

use ark_ff::PrimeField;

use crate::s_box;

/// Matrix multiplication in the internal layers
/// Given a vector v compute the matrix vector product (1 + diag(v))*state
/// with 1 denoting the constant matrix of ones.
// @credit: `matmul_internal()` in zkhash and in plonky3
#[inline(always)]
fn matmul_internal<F: PrimeField, const T: usize>(
    state: &mut [F; T],
    mat_diag_minus_1: &'static [F; T],
) {
    match T {
        // for 2 and 3, since we know the constants, we hardcode it
        2 => {
            // [2, 1]
            // [1, 3]
            let mut sum = state[0];
            sum += state[1];
            state[0] += sum;
            state[1].double_in_place();
            state[1] += sum;
        },
        3 => {
            // [2, 1, 1]
            // [1, 2, 1]
            // [1, 1, 3]
            let mut sum = state[0];
            sum += state[1];
            sum += state[2];
            state[0] += sum;
            state[1] += sum;
            state[2].double_in_place();
            state[2] += sum;
        },
        _ => {
            let sum: F = state.iter().sum();
            for i in 0..T {
                state[i] *= mat_diag_minus_1[i];
                state[i] += sum;
            }
        },
    }
}

/// One internal round
// @credit `internal_permute_state()` in plonky3
#[inline(always)]
pub(crate) fn permute_state<F: PrimeField, const T: usize>(
    state: &mut [F; T],
    rc: F,
    d: usize,
    mat_diag_minus_1: &'static [F; T],
) {
    state[0] += rc;
    s_box(&mut state[0], d);
    matmul_internal(state, mat_diag_minus_1);
}
