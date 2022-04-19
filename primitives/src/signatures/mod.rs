//! Module for signature primitives.

use crate::errors::PrimitivesError;
use ark_std::rand::{CryptoRng, RngCore};

pub mod bls;
pub mod schnorr;

pub use bls::BLSSignatureScheme;
pub use schnorr::SchnorrSignatureScheme;

/// Trait definition for a signature scheme.
// A signature scheme is associated with a hash function H that is
// to be used for challenge generation.
// FIXME: update H bound once hash-api is merged.
pub trait SignatureScheme {
    /// Signing key.
    type SigningKey;

    /// Verification key
    type VerificationKey;

    /// Public Parameter
    type PublicParameter;

    /// Signature
    type Signature;

    /// A message is &\[MessageUnit\]
    type MessageUnit;

    /// generate public parameters from RNG.
    fn param_gen<R: CryptoRng + RngCore, B: AsRef<[u8]>>(
        prng: &mut R,
        ciphersuite_id: B,
    ) -> Result<Self::PublicParameter, PrimitivesError>;

    /// Sample a pair of keys.
    fn key_gen<R: CryptoRng + RngCore, B: AsRef<[u8]>>(
        pp: &Self::PublicParameter,
        ciphersuite_id: B,
        prng: &mut R,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), PrimitivesError>;

    /// Sign a message with the signing key
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>, B: AsRef<[u8]>>(
        pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        ciphersuite_id: B,
        prng: &mut R,
    ) -> Result<Self::Signature, PrimitivesError>;

    /// Verify a signature.
    fn verify<M: AsRef<[Self::MessageUnit]>, B: AsRef<[u8]>>(
        pp: &Self::PublicParameter,
        vk: &Self::VerificationKey,
        msg: M,
        sig: &Self::Signature,
        ciphersuite_id: B,
    ) -> Result<(), PrimitivesError>;
}

/// Trait for aggregatable signatures.
pub trait AggregateableSignatureSchemes<H>: SignatureScheme {}

#[cfg(test)]
mod tests {

    use super::*;
    use ark_std::test_rng;

    pub(crate) fn sign_and_verify<S: SignatureScheme, B: AsRef<[u8]> + Copy>(
        message: &[S::MessageUnit],
        cs_id: B,
    ) {
        let rng = &mut test_rng();
        let parameters = S::param_gen(rng, cs_id).unwrap();
        let (sk, pk) = S::key_gen(&parameters, cs_id, rng).unwrap();
        let sig = S::sign(&parameters, &sk, &message, cs_id, rng).unwrap();
        assert!(S::verify(&parameters, &pk, &message, &sig, cs_id).is_ok());
    }

    pub(crate) fn failed_verification<S: SignatureScheme, B: AsRef<[u8]> + Copy>(
        message: &[S::MessageUnit],
        bad_message: &[S::MessageUnit],
        cs_id: B,
    ) {
        let rng = &mut test_rng();
        let parameters = S::param_gen(rng, cs_id).unwrap();
        let (sk, pk) = S::key_gen(&parameters, cs_id, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, cs_id, rng).unwrap();
        assert!(!S::verify(&parameters, &pk, bad_message, &sig, cs_id).is_ok());
    }
}
