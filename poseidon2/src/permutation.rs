//! Poseidon2 permutation implementation for spongefish

use crate::{Poseidon2, Poseidon2Params};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use spongefish::duplex_sponge::Permutation;
use spongefish::Unit;
use zeroize::Zeroize;

/// A Poseidon2 permutation adaptor for spongefish
/// 
/// This struct maintains the sponge state and implements the Permutation trait
/// required by spongefish's DuplexSponge.
#[derive(Debug, Clone)]
pub struct Poseidon2PermutationState<
    F: PrimeField + Unit,
    const N: usize,
    const R: usize,
    P: Poseidon2Params<F, N>,
> {
    /// Internal state of the sponge
    pub state: [F; N],
    _params: PhantomData<P>,
}

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>> Default
    for Poseidon2PermutationState<F, N, R, P>
{
    fn default() -> Self {
        Self {
            state: [F::default(); N],
            _params: PhantomData,
        }
    }
}

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>>
    Permutation for Poseidon2PermutationState<F, N, R, P>
{
    type U = F;
    const N: usize = N;
    const R: usize = R;

    fn new(iv: [u8; 32]) -> Self {
        assert!(N >= 2 && R > 0 && N > R);
        // For security, for b-bit security, field size |F|, C*|F|>=2b:
        // at least 100 security required
        assert!((N - R) as u32 * <F as PrimeField>::MODULUS_BIT_SIZE >= 200);

        // fill capacity portion with initial vector IV
        let mut state = [F::default(); N];
        state[R] = F::from_be_bytes_mod_order(&iv);
        Self {
            state,
            _params: PhantomData,
        }
    }

    fn permute(&mut self) {
        Poseidon2::permute_mut::<P, N>(&mut self.state);
    }
}

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>> AsRef<[F]>
    for Poseidon2PermutationState<F, N, R, P>
{
    fn as_ref(&self) -> &[F] {
        &self.state
    }
}

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>> AsMut<[F]>
    for Poseidon2PermutationState<F, N, R, P>
{
    fn as_mut(&mut self) -> &mut [F] {
        &mut self.state
    }
}

impl<F: PrimeField + Unit, const N: usize, const R: usize, P: Poseidon2Params<F, N>> Zeroize
    for Poseidon2PermutationState<F, N, R, P>
{
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

/// Convenience type alias for Poseidon2 permutation state
pub type Poseidon2Perm<F, const N: usize, const R: usize, P> =
    Poseidon2PermutationState<F, N, R, P>;
