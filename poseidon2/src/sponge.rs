//! Poseidon2-based Cryptographic Sponge

use crate::{Poseidon2, Poseidon2Params};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use nimue::{hash::sponge::Sponge, Unit};
use zeroize::Zeroize;

/// Poseidon2-based Cryptographic Sponge
///
/// # Generic parameters:
/// - N: state size = rate (R) + capacity (C)
/// - R: rate (number of field abosrbed/squeezed)
///
/// For security, for b=128-bit security, field size |F|, C*|F|>=2b:
/// i.e. 128-bit for 256-bit fields, C>=1.
/// This check is being down during `Poseidon2Sponge::new(&iv)`
/// (See Poseidon2 paper Page 7 Footnote 5)
///
/// For BLS12-381, we choose C=1 for 128 security
/// For BN254, we choose C=1 for (100<*<128)-security
#[derive(Clone, Debug)]
pub struct Poseidon2Sponge<F: PrimeField, const N: usize, const R: usize, P: Poseidon2Params<F, N>>
{
    /// state of sponge
    pub(crate) state: [F; N],
    _rate: PhantomData<[(); R]>,
    _p: PhantomData<P>,
}

impl<F, const N: usize, const R: usize, P> Sponge for Poseidon2Sponge<F, N, R, P>
where
    F: PrimeField + Unit,
    P: Poseidon2Params<F, N>,
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
            _rate: PhantomData,
            _p: PhantomData,
        }
    }

    fn permute(&mut self) {
        Poseidon2::permute_mut::<P, N>(&mut self.state);
    }
}
impl<F, const N: usize, const R: usize, P> Default for Poseidon2Sponge<F, N, R, P>
where
    F: PrimeField,
    P: Poseidon2Params<F, N>,
{
    fn default() -> Self {
        Self {
            state: [F::default(); N],
            _rate: PhantomData,
            _p: PhantomData,
        }
    }
}

impl<F, const N: usize, const R: usize, P> AsRef<[F]> for Poseidon2Sponge<F, N, R, P>
where
    F: PrimeField,
    P: Poseidon2Params<F, N>,
{
    fn as_ref(&self) -> &[F] {
        &self.state
    }
}
impl<F, const N: usize, const R: usize, P> AsMut<[F]> for Poseidon2Sponge<F, N, R, P>
where
    F: PrimeField,
    P: Poseidon2Params<F, N>,
{
    fn as_mut(&mut self) -> &mut [F] {
        &mut self.state
    }
}

impl<F, const N: usize, const R: usize, P> Zeroize for Poseidon2Sponge<F, N, R, P>
where
    F: PrimeField,
    P: Poseidon2Params<F, N>,
{
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}
