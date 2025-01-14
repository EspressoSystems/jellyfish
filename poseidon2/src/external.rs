//! Generic implementation for external layers

use ark_ff::PrimeField;

use crate::{add_rcs, s_box};

/// The fastest 4x4 MDS matrix.
/// [ 2 3 1 1 ]
/// [ 1 2 3 1 ]
/// [ 1 1 2 3 ]
/// [ 3 1 1 2 ]
///
/// This requires 7 additions and 2 doubles to compute.
/// credit: Plonky3
#[derive(Clone, Default)]
struct MDSMat4;

impl MDSMat4 {
    /// x := M4 * x where M4 is the 4x4 MDS matrix
    #[inline(always)]
    fn matmul<F: PrimeField>(x: &mut [F; 4]) {
        let t01 = x[0] + x[1];
        let t23 = x[2] + x[3];
        let t0123 = t01 + t23;
        let t01123 = t0123 + x[1];
        let t01233 = t0123 + x[3];
        // The order here is important. Need to overwrite x[0] and x[2] after x[1] and
        // x[3].
        x[3] = t01233 + x[0].double(); // 3*x[0] + x[1] + x[2] + 2*x[3]
        x[1] = t01123 + x[2].double(); // x[0] + 2*x[1] + 3*x[2] + x[3]
        x[0] = t01123 + t01; // 2*x[0] + 3*x[1] + x[2] + x[3]
        x[2] = t01233 + t23; // x[0] + x[1] + 2*x[2] + 3*x[3]
    }
}

#[inline(always)]
/// Matrix multiplication in the external layers
// @credit: `matmul_external` in zkhash, `mds_light_permutation` in plonky3
pub(super) fn matmul_external<F: PrimeField, const T: usize>(state: &mut [F; T]) {
    match T {
        2 => {
            let sum = state[0] + state[1];
            state[0] += sum;
            state[1] += sum;
        },

        3 => {
            let sum = state[0] + state[1] + state[2];
            state[0] += sum;
            state[1] += sum;
            state[2] += sum;
        },

        // Given a 4x4 MDS matrix M, we multiply by the `4N x 4N` matrix
        // `[[2M M  ... M], [M  2M ... M], ..., [M  M ... 2M]]`.
        4 | 8 | 12 | 16 | 20 | 24 => {
            // First, we apply M_4 to each consecutive four elements of the state.
            // In Appendix B's terminology, this replaces each x_i with x_i'.
            for chunk in state.chunks_exact_mut(4) {
                MDSMat4::matmul(chunk.try_into().unwrap());
            }
            // Now, we apply the outer circulant matrix (to compute the y_i values).

            // We first precompute the four sums of every four elements.
            let sums: [F; 4] =
                core::array::from_fn(|k| (0..T).step_by(4).map(|j| state[j + k]).sum::<F>());

            // The formula for each y_i involves 2x_i' term and x_j' terms for each j that
            // equals i mod 4. In other words, we can add a single copy of x_i'
            // to the appropriate one of our precomputed sums
            state
                .iter_mut()
                .enumerate()
                .for_each(|(i, elem)| *elem += sums[i % 4]);
        },

        _ => {
            panic!("Unsupported state size");
        },
    }
}

#[inline(always)]
/// One external round
// @credit `external_terminal_permute_state` in plonky3
pub(crate) fn permute_state<F: PrimeField, const T: usize>(
    state: &mut [F; T],
    rc: &'static [F; T],
    d: usize,
) {
    add_rcs(state, rc);
    for s in state.iter_mut() {
        s_box(s, d);
    }
    matmul_external(state);
}
