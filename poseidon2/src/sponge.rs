//! Poseidon2-based Cryptographic Sponge
//!
//! This module provides clean type aliases following the spongefish-poseidon
//! pattern.

use crate::{permutation::Poseidon2Permutation, Poseidon2Params};
use ark_ff::PrimeField;
use spongefish::{DuplexSponge, DuplexSpongeInterface, Unit};

/// A Poseidon2-based duplex sponge.
pub trait Poseidon2Sponge: DuplexSpongeInterface + Default {
    /// Number of field elements absorbed per permutation call.
    const RATE: usize;
}

impl<F, const N: usize, const R: usize, P> Poseidon2Sponge
    for DuplexSponge<Poseidon2Permutation<F, N, P>, N, R>
where
    F: PrimeField + Unit,
    P: Poseidon2Params<F, N>,
{
    const RATE: usize = R;
}

#[cfg(feature = "bls12-381")]
/// Poseidon2 sponge types for BLS12-381 scalar field
pub mod bls12_381 {
    #![allow(dead_code)]
    use crate::{constants::bls12_381::*, permutation::Poseidon2Hash};
    use ark_bls12_381::Fr;
    /// A sponge over BLS12-381 scalar field, state_size=2, rate=1.
    pub type Poseidon2SpongeBlsN2R1 = Poseidon2Hash<Fr, 2, 1, Poseidon2ParamsBls2>;

    /// A sponge over BLS12-381 scalar field, state_size=3, rate=1.
    pub type Poseidon2SpongeBlsN3R1 = Poseidon2Hash<Fr, 3, 1, Poseidon2ParamsBls3>;

    /// A sponge over BLS12-381 scalar field, state_size=3, rate=2.
    pub type Poseidon2SpongeBlsN3R2 = Poseidon2Hash<Fr, 3, 2, Poseidon2ParamsBls3>;

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
    use crate::{constants::bn254::*, permutation::Poseidon2Hash};
    use ark_bn254::Fr;
    /// A sponge over BN254 scalar field, state_size=3, rate=1.
    pub type Poseidon2SpongeBnN3R1 = Poseidon2Hash<Fr, 3, 1, Poseidon2ParamsBn3>;

    /// A sponge over BN254 scalar field, state_size=3, rate=2.
    pub type Poseidon2SpongeBnN3R2 = Poseidon2Hash<Fr, 3, 2, Poseidon2ParamsBn3>;

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

    pub(crate) fn test_sponge<F: PrimeField + Unit, H: Poseidon2Sponge<U = F>>() {
        let mut sponge = H::default();
        sponge.absorb(&[F::from(42u32)]);
        let mut challenges = [F::default(); 2048];
        sponge.squeeze(&mut challenges);

        // Looking at byte distribution, whether it's close to uniform
        let chal_bytes: Vec<u8> = challenges
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
