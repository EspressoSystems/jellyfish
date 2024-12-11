// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! The Poseidon2 permutation.
//!
//! This implementation was based upon the following resources:
//! - https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2.rs
//! - https://eprint.iacr.org/2023/323.pdf
//! - https://github.com/Plonky3/Plonky3/blob/main/poseidon2/

#![no_std]
#![deny(missing_docs)]

use ark_ff::PrimeField;
use ark_std::{borrow::ToOwned, marker::PhantomData};

mod external;
mod internal;

/// Parameters required for a Poseidon2 permutation instance.
///
/// # Generic parameters
/// - `F`: field choice
/// - `T`: state size = rate + capacity, `T` is made generic for easy trait
///   bound on `permute<F,T>(input: [F; N])`.
pub trait Poseidon2Params<F: PrimeField, const T: usize> {
    /// d: sbox degree
    const D: usize;
    /// round_F: number of external rounds (incl. initial and terminal)
    /// round_F = 2 * round_f
    const EXT_ROUNDS: usize;
    /// round_P: number of internal rounds
    const INT_ROUNDS: usize;

    /// round constants for all external rounds
    fn external_rc(&self) -> &'static [&'static [F; T]];
    /// round constants for internal rounds
    fn internal_rc(&self) -> &'static [F];
    /// diffusion (diagonal) matrix minus one used in internal rounds
    fn internal_mat_diag_m_1(&self) -> &'static [F; T];

    /// A default sanity check on the parameters and constant getters
    ///
    /// State size only supports: 2, 3, 4, 8, 12, 16, 20, 24 for now
    /// S-box size only supports: 3, 5, 7, 11
    ///
    /// # Round constants
    /// Rust doesn't permit generic param to be used in const operations, thus
    /// leveraging type system to ensure sanity such as `const INT_RC: &'static
    /// [F; Self::INT_ROUNDS]` is not allowed.
    fn sanity_check(&self) -> bool {
        let ext_rc = self.external_rc();
        let int_rc = self.internal_rc();

        // TODO: consider adding more security-related check, incl. number of internal
        // rounds in terms of field size to achieve 128-bit security. see
        // `poseidon2_round_numbers_128` in plonky3, we skip for now as GCD is not
        // implemented in arkworks, and params are trusted.
        [2, 3, 4, 8, 12, 16, 20, 24].contains(&T)
            && [3, 5, 7, 11].contains(&Self::D)
            && ext_rc.len() == Self::EXT_ROUNDS
            && int_rc.len() == Self::INT_ROUNDS
            && Self::EXT_ROUNDS % 2 == 0
    }
}

/// A Poseidon2 permutation family <https://eprint.iacr.org/2023/323>
pub struct Poseidon2<F: PrimeField>(PhantomData<F>);

impl<F: PrimeField> Poseidon2<F> {
    /// Apply Poseidon2 permutation on `input` and return the permuted result
    pub fn permute<P, const T: usize>(param: &P, input: &[F; T]) -> [F; T]
    where
        P: Poseidon2Params<F, T>,
    {
        let mut input = input.to_owned();
        Self::permute_mut(param, &mut input);
        input
    }

    /// Apply Poseidon2 permutation on `input` in place
    pub fn permute_mut<P, const T: usize>(param: &P, input: &mut [F; T])
    where
        P: Poseidon2Params<F, T>,
    {
        assert!(param.sanity_check(), "Unexpected: Invalid Poseidon2 param!");
        // M_e * x
        external::matmul_external(input);

        // Initial external rounds (first EXT_ROUNDS/2 rounds)
        let ext_rc = param.external_rc();
        for rc in ext_rc.iter().take(P::EXT_ROUNDS / 2) {
            external::permute_state(input, rc, P::D);
        }

        // Internal rounds
        let int_rc = param.internal_rc();
        let mat_diag_minus_1 = param.internal_mat_diag_m_1();
        for rc in int_rc.iter() {
            internal::permute_state(input, *rc, P::D, mat_diag_minus_1);
        }

        // Terminal external rounds (second EXT_ROUNDS/2 rounds)
        for rc in ext_rc.iter().take(P::EXT_ROUNDS).skip(P::EXT_ROUNDS / 2) {
            external::permute_state(input, rc, P::D);
        }
    }
}

/// A generic method performing the transformation, used both in external and
/// internal layers:
///
/// `s -> (s + rc)^d`
// @credit: `add_rc_and_sbox_generic()` in plonky3
#[inline(always)]
pub(crate) fn add_rc_and_sbox<F: PrimeField>(val: &mut F, rc: F, d: usize) {
    *val += rc;
    *val = val.pow([d as u64]);
}
