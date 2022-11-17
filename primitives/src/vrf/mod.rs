//! Module for verifiable random functions.

use crate::errors::PrimitivesError;
use ark_std::rand::{CryptoRng, RngCore};
pub mod blsvrf;
pub mod ecvrf;

/// A trait for VRF proof, evaluation and verification.
pub trait Vrf {
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
        &self,
        prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, PrimitivesError>;

    /// Creates a pair of VRF public and private keys.
    fn key_gen<R: CryptoRng + RngCore>(
        &self,
        pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), PrimitivesError>;

    /// Creates the VRF proof associated with a VRF secret key.
    fn prove<R: CryptoRng + RngCore>(
        &self,
        pp: &Self::PublicParameter,
        secret_key: &Self::SecretKey,
        input: &Self::Input,
        prng: &mut R,
    ) -> Result<Self::Proof, PrimitivesError>;

    /// Computes the VRF output associated with a VRF proof.
    fn evaluate(
        &mut self,
        pp: &Self::PublicParameter,
        proof: &Self::Proof,
    ) -> Result<Self::Output, PrimitivesError>;

    /// Verifies a VRF proof.
    fn verify(
        &self,
        pp: &Self::PublicParameter,
        proof: &Self::Proof,
        public_key: &Self::PublicKey,
        input: &Self::Input,
    ) -> Result<bool, PrimitivesError>;
}
