//! Poseidon2 permutation for spongefish's [`DuplexSponge`]

use crate::{Poseidon2, Poseidon2Params};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use spongefish::{DuplexSponge, Permutation, Unit};

/// Poseidon2 permutation over a state of `N` field elements.
///
/// The permutation itself is stateless; [`DuplexSponge`] owns the state.
pub struct Poseidon2Permutation<F, const N: usize, P> {
    _params: PhantomData<(F, P)>,
}

/// Poseidon2 duplex sponge with state size `N` and rate `R`.
pub type Poseidon2Hash<F, const N: usize, const R: usize, P> =
    DuplexSponge<Poseidon2Permutation<F, N, P>, N, R>;

impl<F, const N: usize, P> Clone for Poseidon2Permutation<F, N, P> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<F, const N: usize, P> Default for Poseidon2Permutation<F, N, P> {
    fn default() -> Self {
        Self {
            _params: PhantomData,
        }
    }
}

impl<F, const N: usize, P> Permutation<N> for Poseidon2Permutation<F, N, P>
where
    F: PrimeField + Unit,
    P: Poseidon2Params<F, N>,
{
    type U = F;

    fn permute(&self, state: &[F; N]) -> [F; N] {
        Poseidon2::permute::<P, N>(state)
    }

    fn permute_mut(&self, state: &mut [F; N]) {
        Poseidon2::permute_mut::<P, N>(state);
    }
}
