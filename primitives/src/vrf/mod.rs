//! Module for verifiable random functions.

use crate::errors::PrimitivesError;
use ark_std::rand::{CryptoRng, RngCore};
pub mod blsvrf;
pub mod ecvrf;

/// A trait for VRF proof, evaluation and verification.
pub trait Vrf<VrfHasher> {
    /// ciphersuite identifier
    const CS_ID: &'static str;

    /// Public parameters
    type PublicParameter;

    /// VRF public key.
    type PublicKey;

    /// VRF secret key.
    type SecretKey;

    /// VRF signature.
    type Proof;

    /// The input of VRF proof.
    type Input;

    /// The output of VRF evaluation.
    type Output;

    /// generate public parameters from RNG.
    /// If the RNG is not presented, use the default group generator.
    // FIXME: the API looks a bit strange when the default generator is used.
    // For example:
    //   `S::param_gen::<StdRng>(None)`
    // wheere `StdRng` is redundent.
    fn param_gen<R: CryptoRng + RngCore>(
        prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, PrimitivesError>;

    /// Creates a pair of VRF public and private keys.
    fn key_gen<R: CryptoRng + RngCore>(
        pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), PrimitivesError>;

    /// Creates the VRF proof associated with a VRF secret key.
    fn prove<R: CryptoRng + RngCore>(
        pp: &Self::PublicParameter,
        secret_key: &Self::SecretKey,
        input: &Self::Input,
        prng: &mut R,
    ) -> Result<Self::Proof, PrimitivesError>;

    /// Computes the VRF output associated with a VRF proof.
    fn evaluate(
        pp: &Self::PublicParameter,
        proof: &Self::Proof,
    ) -> Result<Self::Output, PrimitivesError>;

    /// Verifies a VRF proof.
    fn verify(
        pp: &Self::PublicParameter,
        proof: &Self::Proof,
        public_key: &Self::PublicKey,
        input: &Self::Input,
    ) -> Result<bool, PrimitivesError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{rand::prelude::StdRng, test_rng};

    pub(crate) fn sign_and_verify<V: Vrf<H>, H>(message: &V::Input) {
        let rng = &mut test_rng();
        let parameters = V::param_gen(Some(rng)).unwrap();
        let (sk, pk) = V::key_gen(&parameters, rng).unwrap();
        let vrf_proof = V::prove(&parameters, &sk, message, rng).unwrap();
        let _vrf_output = V::evaluate(&parameters, &vrf_proof).unwrap();
        assert!(V::verify(&parameters, &vrf_proof, &pk, message).unwrap());

        let parameters = V::param_gen::<StdRng>(None).unwrap();
        let (sk, pk) = V::key_gen(&parameters, rng).unwrap();
        let vrf_proof = V::prove(&parameters, &sk, message, rng).unwrap();
        let _vrf_output = V::evaluate(&parameters, &vrf_proof).unwrap();

        assert!(V::verify(&parameters, &vrf_proof, &pk, message).unwrap());
    }

    pub(crate) fn failed_verification<V: Vrf<H>, H>(message: &V::Input, bad_message: &V::Input) {
        let rng = &mut test_rng();
        let parameters = V::param_gen(Some(rng)).unwrap();
        let (sk, pk) = V::key_gen(&parameters, rng).unwrap();
        let vrf_proof = V::prove(&parameters, &sk, message, rng).unwrap();
        let _vrf_output = V::evaluate(&parameters, &vrf_proof).unwrap();

        assert!(!V::verify(&parameters, &vrf_proof, &pk, bad_message).unwrap());
    }
}
