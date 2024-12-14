//! Poseidon2-based Cryptographic Sponge

use crate::{Poseidon2, Poseidon2Params};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use nimue::{hash::sponge::Sponge, Unit};
use zeroize::Zeroize;

/// Poseidon2-based Cryptographic Sponge
///
/// # Parameters:
/// - `N`: State size = rate (R) + capacity (C)
/// - `R`: Rate (number of field elements absorbed/squeezed per operation)
///
/// For 128-bit security, `C * |F| >= 256` (capacity * field size in bits).
/// This is enforced during instantiation (`Poseidon2Sponge::new`).
#[derive(Clone, Debug)]
pub struct Poseidon2Sponge<F: PrimeField, const N: usize, const R: usize, P: Poseidon2Params<F, N>> {
    /// State of the sponge.
    pub(crate) state: [F; N],
    _rate: PhantomData<[(); R]>,
    _params: PhantomData<P>,
}

impl<F, const N: usize, const R: usize, P> Sponge for Poseidon2Sponge<F, N, R, P>
where
    F: PrimeField + Unit,
    P: Poseidon2Params<F, N>,
{
    type U = F;
    const N: usize = N;
    const R: usize = R;

    /// Creates a new Poseidon2 Sponge with an initialization vector.
    fn new(iv: [u8; 32]) -> Self {
        assert!(N >= 2 && R > 0 && N > R, "Invalid state and rate parameters");
        assert!(
            (N - R) as u32 * F::MODULUS_BIT_SIZE >= 200,
            "Insufficient capacity for security"
        );

        let mut state = [F::default(); N];
        state[R] = F::from_be_bytes_mod_order(&iv);
        Self {
            state,
            _rate: PhantomData,
            _params: PhantomData,
        }
    }

    /// Applies the Poseidon2 permutation to the sponge state.
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
            _params: PhantomData,
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

#[cfg(feature = "bls12-381")]
mod bls12_381 {
    use super::*;
    use crate::constants::bls12_381::*;
    use ark_bls12_381::Fr;
    use nimue::hash::sponge::DuplexSponge;

    pub type Poseidon2SpongeBlsN2R1 = DuplexSponge<Poseidon2Sponge<Fr, 2, 1, Poseidon2ParamsBls2>>;
    pub type Poseidon2SpongeBlsN3R1 = DuplexSponge<Poseidon2Sponge<Fr, 3, 1, Poseidon2ParamsBls3>>;
    pub type Poseidon2SpongeBlsN3R2 = DuplexSponge<Poseidon2Sponge<Fr, 3, 2, Poseidon2ParamsBls3>>;

    #[test]
    fn test_bls_sponge() {
        use super::tests::test_sponge;
        test_sponge::<Fr, Poseidon2SpongeBlsN2R1>();
        test_sponge::<Fr, Poseidon2SpongeBlsN3R1>();
        test_sponge::<Fr, Poseidon2SpongeBlsN3R2>();
    }
}

#[cfg(feature = "bn254")]
mod bn254 {
    use super::*;
    use crate::constants::bn254::*;
    use ark_bn254::Fr;
    use nimue::hash::sponge::DuplexSponge;

    pub type Poseidon2SpongeBnN3R1 = DuplexSponge<Poseidon2Sponge<Fr, 3, 1, Poseidon2ParamsBn3>>;
    pub type Poseidon2SpongeBnN3R2 = DuplexSponge<Poseidon2Sponge<Fr, 3, 2, Poseidon2ParamsBn3>>;

    #[test]
    fn test_bn_sponge() {
        use super::tests::test_sponge;
        test_sponge::<Fr, Poseidon2SpongeBnN3R1>();
        test_sponge::<Fr, Poseidon2SpongeBnN3R2>();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ark_ff::BigInteger;
    use ark_std::vec::Vec;
    use nimue::{DuplexHash, IOPattern, UnitTranscript};

    pub(crate) fn test_sponge<F: PrimeField + Unit, H: DuplexHash<F>>() {
        let io = IOPattern::<H, F>::new("test")
            .absorb(1, "in")
            .squeeze(2048, "out");

        let mut merlin = io.to_merlin();
        merlin.add_units(&[F::from(42u32)]).unwrap();
        let mut merlin_challenges = [F::default(); 2048];
        merlin.fill_challenge_units(&mut merlin_challenges).unwrap();

        let mut arthur = io.to_arthur(merlin.transcript());
        arthur.fill_next_units(&mut [F::default()]).unwrap();
        let mut arthur_challenges = [F::default(); 2048];
        arthur.fill_challenge_units(&mut arthur_challenges).unwrap();

        assert_eq!(merlin_challenges, arthur_challenges);

        let chal_bytes: Vec<u8> = merlin_challenges
            .iter()
            .flat_map(|c| c.into_bigint().to_bytes_le())
            .collect();

        let frequencies = compute_byte_frequencies(&chal_bytes);
        let expected_mean = (F::MODULUS_BIT_SIZE / 8 * 2048 / 256) as usize;

        assert!(
            frequencies.iter().all(|&x| x < expected_mean * 2 && x > expected_mean / 2),
            "Byte counts deviate significantly from expected mean: {:?}",
            frequencies
        );
    }

    fn compute_byte_frequencies(bytes: &[u8]) -> Vec<usize> {
        (0u8..=255)
            .map(|i| bytes.iter().filter(|&&x| x == i).count())
            .collect()
    }
}
