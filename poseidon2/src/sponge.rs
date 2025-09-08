//! Poseidon2-based Cryptographic Sponge

use crate::{permutation::Poseidon2PermutationState, Poseidon2Params};
use ark_ff::PrimeField;
use spongefish::Unit;

/// Marker trait for the state of Poseidon2-based Cryptographic Sponge
pub trait Poseidon2Sponge {}

// Re-export the main types for convenience
pub use crate::permutation::Poseidon2PermutationState as Poseidon2SpongeState;

/// Implement the marker trait for our permutation state
impl<F, const N: usize, const R: usize, P> Poseidon2Sponge for Poseidon2PermutationState<F, N, R, P>
where
    F: PrimeField + Unit,
    P: Poseidon2Params<F, N>,
{
}

#[cfg(feature = "bls12-381")]
/// Poseidon2 sponge types for BLS12-381 scalar field
pub mod bls12_381 {
    #![allow(dead_code)]
    use super::*;
    use crate::constants::bls12_381::*;
    use ark_bls12_381::Fr;
    use spongefish::duplex_sponge::DuplexSponge;
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
/// Poseidon2 sponge types for BN254 scalar field
pub mod bn254 {
    #![allow(dead_code)]
    use super::*;
    use crate::constants::bn254::*;
    use ark_bn254::Fr;
    use spongefish::duplex_sponge::DuplexSponge;
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
    use spongefish::codecs::arkworks_algebra::*;

    // inspired by:
    // <https://github.com/arkworks-rs/nimue/blob/bdec8c446b804930a8375a8d2a3703a6071abf6b/nimue-poseidon/src/tests.rs#L16C4-L16C44>
    pub(crate) fn test_sponge<F: PrimeField + Unit, H: DuplexSpongeInterface<F>>() {
        let io = DomainSeparator::<H, F>::new("test")
            .absorb(1, "in")
            .squeeze(2048, "out");

        // prover transcript
        let mut merlin = io.to_prover_state();
        // prover first message (label: "in")
        merlin.add_units(&[F::from(42u32)]).unwrap();

        let mut merlin_challenges = [F::default(); 2048];
        merlin.fill_challenge_units(&mut merlin_challenges).unwrap();

        // verifier transcript
        let mut arthur = io.to_verifier_state(merlin.narg_string());
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
