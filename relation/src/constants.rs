// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Crate wide constants.

use ark_ff::{FftField, PrimeField};
use ark_std::{rand::SeedableRng, vec, vec::Vec};
use rand_chacha::ChaChaRng;

// ==========================
// Circuit-related constants.
// ==========================

/// The number of input wires.
pub const GATE_WIDTH: usize = 4;
/// The number of multiplication selectors.
pub const N_MUL_SELECTORS: usize = 2;
/// The number of TurboPlonk selectors.
pub const N_TURBO_PLONK_SELECTORS: usize = 13;

/// Compute constants K0, K1, ..., K_{`num_wire_types`-1} so that cosets {Ki *
/// H} are disjoint, each coset |Ki * H| = `coset_size`.
/// `coset_size` is optional, when provided, will accelerate constants
/// searching.
#[inline]
#[allow(non_snake_case)]
pub fn compute_coset_representatives<F: PrimeField>(
    num_wire_types: usize,
    coset_size: Option<usize>,
) -> Vec<F> {
    // check if two cosets `aH == bH` where `a, b` are cosets representations
    fn is_equal_coset<F: PrimeField>(pow_a_N: F, pow_b_N: F) -> bool {
        // check (a^-1 * b)^`N` = 1
        pow_a_N
            .inverse()
            .expect("Unreachable: all elements in a prime field should have inverse")
            * pow_b_N
            == F::one()
    }

    // check if a new k is valid: i.e. doesn't represent the same coset as any
    // previous values `prev`.
    fn is_valid_k<F: PrimeField>(pow_k_N: F, pow_prev_N: &[F]) -> bool {
        !pow_prev_N
            .iter()
            .any(|&pow_k_prev_N| is_equal_coset(pow_k_N, pow_k_prev_N))
    }

    // storing cached `Ki -> Ki^coset_size` values.
    let mut pow_k_N_vec = vec![];
    let mut k_vec = vec![];
    let mut rng = ChaChaRng::from_seed([0u8; 32]); // empty bytes as seed

    // the exponent N for checking membership of domain H
    let N = match coset_size {
        Some(size) => size,
        None => {
            // let `2^s * t` be the size of the multiplicative group defined by the field
            // `F`, for some odd integer `t`, `s` is the 2-adicity of `F*`.
            // `2^s` is a guaranteed to be multiple of |H|.
            2usize.pow(<F as FftField>::TWO_ADICITY)
        },
    };
    for i in 0..num_wire_types {
        if i == 0 {
            // set first K0 = 1, namely the H itself
            k_vec.push(F::one());
            pow_k_N_vec.push(F::one());
        } else {
            let mut next = F::rand(&mut rng);
            let mut pow_next_N = next.pow([N as u64]);
            while !is_valid_k(pow_next_N, &pow_k_N_vec) {
                next = F::rand(&mut rng);
                pow_next_N = next.pow([N as u64]);
            }
            k_vec.push(next);
            pow_k_N_vec.push(pow_next_N);
        }
    }
    k_vec
}
