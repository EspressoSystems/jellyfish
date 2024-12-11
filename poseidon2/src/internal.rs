//! Generic implementation for internal layers

use ark_ff::PrimeField;

use crate::add_rc_and_sbox;

/// Matrix multiplication in the internal layers
/// Given a vector v compute the matrix vector product (1 + diag(v))*state
/// with 1 denoting the constant matrix of ones.
// @credit: `matmul_internal()` in zkhash and in plonky3
#[inline(always)]
fn matmul_internal<F: PrimeField, const T: usize>(
    state: &mut [F; T],
    mat_diag_minus_1: &'static [F; T],
) {
    let sum: F = state.iter().sum();
    for i in 0..T {
        state[i] *= mat_diag_minus_1[i];
        state[i] += sum;
    }
}

/// One internal round
// @credit `internal_permute_state()` in plonky3
pub(crate) fn permute_state<F: PrimeField, const T: usize>(
    state: &mut [F; T],
    rc: F,
    d: usize,
    mat_diag_minus_1: &'static [F; T],
) {
    add_rc_and_sbox(&mut state[0], rc, d);
    matmul_internal(state, mat_diag_minus_1);
}
