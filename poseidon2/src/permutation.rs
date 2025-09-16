//! Poseidon2 permutation implementation for spongefish
//!
//! This follows the pattern established in spongefish-poseidon, providing a
//! clean interface that directly integrates with DuplexSponge.

use crate::{Poseidon2, Poseidon2Params};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use spongefish::{
    duplex_sponge::{DuplexSponge, Permutation},
    Unit,
};
use zeroize::Zeroize;

/// Poseidon2 Permutation for spongefish
///
/// Similar to spongefish-poseidon's PoseidonPermutation but for Poseidon2.
/// Integrates directly with DuplexSponge.
#[derive(Debug, Clone)]
pub struct Poseidon2Permutation<
    F: PrimeField + Unit,
    const N: usize,
    const R: usize,
    P: Poseidon2Params<F, N>,
> {
    /// Permutation state
    pub state: [F; N],
    _params: PhantomData<P>,
}

/// Poseidon2 Hash (DuplexSponge wrapper)
pub type Poseidon2Hash<F, const N: usize, const R: usize, P> =
    DuplexSponge<Poseidon2Permutation<F, N, R, P>>;

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>> AsRef<[F]>
    for Poseidon2Permutation<F, N, R, P>
{
    fn as_ref(&self) -> &[F] {
        &self.state
    }
}

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>> AsMut<[F]>
    for Poseidon2Permutation<F, N, R, P>
{
    fn as_mut(&mut self) -> &mut [F] {
        &mut self.state
    }
}

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>> Zeroize
    for Poseidon2Permutation<F, N, R, P>
{
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>> Permutation
    for Poseidon2Permutation<F, N, R, P>
where
    Self: Default,
{
    type U = F;
    const N: usize = N;
    const R: usize = R;

    fn new(iv: [u8; 32]) -> Self {
        assert!(N >= 2 && R > 0 && N > R);
        // For security, for b-bit security, field size |F|, C*|F|>=2b:
        // at least 100 security required
        assert!((N - R) as u32 * <F as PrimeField>::MODULUS_BIT_SIZE >= 200);

        let mut sponge = Self::default();
        sponge.state[R] = F::from_be_bytes_mod_order(&iv);
        sponge
    }

    fn permute(&mut self) {
        Poseidon2::permute_mut::<P, N>(&mut self.state);
    }
}

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>> Default
    for Poseidon2Permutation<F, N, R, P>
{
    fn default() -> Self {
        Self {
            state: [F::zero(); N],
            _params: PhantomData,
        }
    }
}
