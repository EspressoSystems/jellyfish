//! Poseidon2-based Cryptographic Sponge

use crate::{Poseidon2, Poseidon2Params};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use nimue::{hash::sponge::Sponge, Unit};
use zeroize::Zeroize;

/// the state of Poseidon2-based Cryptographic Sponge
///
/// # Generic parameters:
/// - N: state size = rate (R) + capacity (C)
/// - R: rate (number of field abosrbed/squeezed)
///
/// For security, for b=128-bit security, field size |F|, C*|F|>=2b:
/// i.e. 128-bit for 256-bit fields, C>=1.
/// This check is being down during `Poseidon2SpongeState::new(&iv)`
/// (See Poseidon2 paper Page 7 Footnote 5)
///
/// For BLS12-381, we choose C=1 for 128 security
/// For BN254, we choose C=1 for (100<*<128)-security
#[derive(Clone, Debug)]
pub struct Poseidon2SpongeState<
    F: PrimeField,
    const N: usize,
    const R: usize,
    P: Poseidon2Params<F, N>,
> {
    /// state of sponge
    pub(crate) state: [F; N],
    _rate: PhantomData<[(); R]>,
    _p: PhantomData<P>,
}

impl<F, const N: usize, const R: usize, P> Sponge for Poseidon2SpongeState<F, N, R, P>
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
impl<F, const N: usize, const R: usize, P> Default for Poseidon2SpongeState<F, N, R, P>
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

impl<F, const N: usize, const R: usize, P> AsRef<[F]> for Poseidon2SpongeState<F, N, R, P>
where
    F: PrimeField,
    P: Poseidon2Params<F, N>,
{
    fn as_ref(&self) -> &[F] {
        &self.state
    }
}
impl<F, const N: usize, const R: usize, P> AsMut<[F]> for Poseidon2SpongeState<F, N, R, P>
where
    F: PrimeField,
    P: Poseidon2Params<F, N>,
{
    fn as_mut(&mut self) -> &mut [F] {
        &mut self.state
    }
}

impl<F, const N: usize, const R: usize, P> Zeroize for Poseidon2SpongeState<F, N, R, P>
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
    #![allow(dead_code)]
    use super::*;
    use crate::constants::bls12_381::*;
    use ark_bls12_381::Fr;
    use nimue::hash::sponge::DuplexSponge;
    /// State of a sponge over BLS12-381 scalar field, state_size=2, rate=1.
    pub type Poseidon2SpongeStateBlsN2R1 = Poseidon2SpongeState<Fr, 2, 1, Poseidon2ParamsBls2>;
    /// A sponge over BLS12-381 scalar field, state_size=2, rate=1.
    pub type Poseidon2SpongeBlsN2R1 = DuplexSponge<Poseidon2SpongeStateBlsN2R1>;

    /// State of a sponge over BLS12-381 scalar field, state_size=3, rate=1.
    pub type Poseidon2SpongeStateBlsN3R1 = Poseidon2SpongeState<Fr, 3, 1, Poseidon2ParamsBls3>;
    /// A sponge over BLS12-381 scalar field, state_size=3, rate=1.
    pub type Poseidon2SpongeBlsN3R1 = DuplexSponge<Poseidon2SpongeStateBlsN3R1>;

    /// State of a sponge over BLS12-381 scalar field, state_size=3, rate=2.
    pub type Poseidon2SpongeStateBlsN3R2 = Poseidon2SpongeState<Fr, 3, 2, Poseidon2ParamsBls3>;
    /// A sponge over BLS12-381 scalar field, state_size=3, rate=2.
    pub type Poseidon2SpongeBlsN3R2 = DuplexSponge<Poseidon2SpongeStateBlsN3R2>;

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
    #![allow(dead_code)]
    use super::*;
    use crate::constants::bn254::*;
    use ark_bn254::Fr;
    use nimue::hash::sponge::DuplexSponge;
    /// State of a sponge over BN254 scalar field, state_size=3, rate=1.
    pub type Poseidon2SpongeStateBnN3R1 = Poseidon2SpongeState<Fr, 3, 1, Poseidon2ParamsBn3>;
    /// A sponge over BN254 scalar field, state_size=3, rate=1.
    pub type Poseidon2SpongeBnN3R1 = DuplexSponge<Poseidon2SpongeStateBnN3R1>;

    /// State of a sponge over BN254 scalar field, state_size=3, rate=2.
    pub type Poseidon2SpongeStateBnN3R2 = Poseidon2SpongeState<Fr, 3, 2, Poseidon2ParamsBn3>;
    /// A sponge over BN254 scalar field, state_size=3, rate=2.
    pub type Poseidon2SpongeBnN3R2 = DuplexSponge<Poseidon2SpongeStateBnN3R2>;

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

    // inspired by:
    // <https://github.com/arkworks-rs/nimue/blob/bdec8c446b804930a8375a8d2a3703a6071abf6b/nimue-poseidon/src/tests.rs#L16C4-L16C44>
    pub(crate) fn test_sponge<F: PrimeField + Unit, H: DuplexHash<F>>() {
        let io = IOPattern::<H, F>::new("test")
            .absorb(1, "in")
            .squeeze(2048, "out");

        // prover transcript
        let mut merlin = io.to_merlin();
        // prover first message (label: "in")
        merlin.add_units(&[F::from(42u32)]).unwrap();

        let mut merlin_challenges = [F::default(); 2048];
        merlin.fill_challenge_units(&mut merlin_challenges).unwrap();

        // verifier transcript
        let mut arthur = io.to_arthur(merlin.transcript());
        // reading prover's first message labelled "in", since we don't need it, read
        // into a one-time throw-away array
        arthur.fill_next_units(&mut [F::default()]).unwrap();
        let mut arthur_challenges = [F::default(); 2048];
        arthur.fill_challenge_units(&mut arthur_challenges).unwrap();

        // challenge computed from both sides should be the same
        assert_eq!(merlin_challenges, arthur_challenges);

        // Looking at byte distribution, whether it's close to uniform
        let chal_bytes: Vec<u8> = merlin_challenges
            .iter()
            .flat_map(|c| c.into_bigint().to_bytes_le())
            .collect();
        let frequencies = (0u8..=255)
            .map(|i| chal_bytes.iter().filter(|&&x| x == i).count())
            .collect::<Vec<_>>();
        // the expected frequency if it's uniformly random
        let expected_mean = (F::MODULUS_BIT_SIZE / 8 * 2048 / 256) as usize;
        assert!(
            frequencies
                .iter()
                .all(|&x| x < expected_mean * 2 && x > expected_mean / 2),
            "Counts for each value shouldn't be too far away from mean: {:?}",
            frequencies
        );
    }
}
