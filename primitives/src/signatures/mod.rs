//! Module for signature primitives.

use crate::errors::PrimitivesError;
use ark_std::rand::{CryptoRng, RngCore};

pub mod bls_over_bls12381;
pub mod bls_over_bn254;
pub mod schnorr;

pub use bls_over_bls12381::BLSSignatureScheme;
use core::fmt::Debug;
pub use schnorr::SchnorrSignatureScheme;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
/// Trait definition for a signature scheme.
// A signature scheme is associated with a hash function H that is
// to be used for challenge generation.
// FIXME: update H bound once hash-api is merged.
pub trait SignatureScheme {
    /// Ciphersuite Identifier
    const CS_ID: &'static str;

    /// Signing key.
    type SigningKey: Debug
        + Clone
        + Send
        + Sync
        + Zeroize
        + for<'a> Deserialize<'a>
        + Serialize
        + PartialEq
        + Eq;

    /// Verification key
    type VerificationKey: Debug
        + Clone
        + Send
        + Sync
        + for<'a> Deserialize<'a>
        + Serialize
        + PartialEq
        + Eq;

    /// Public Parameter
    type PublicParameter;

    /// Signature
    type Signature: Debug
        + Clone
        + Send
        + Sync
        + for<'a> Deserialize<'a>
        + Serialize
        + PartialEq
        + Eq;

    /// A message is &\[MessageUnit\]
    type MessageUnit: Debug + Clone + Send + Sync;

    /// generate public parameters from RNG.
    /// If the RNG is not presented, use the default group generator.
    // FIXME: the API looks a bit strange when the default generator is used.
    // For example:
    //   `S::param_gen::<StdRng>(None)`
    // where `StdRng` is redundant.
    fn param_gen<R: CryptoRng + RngCore>(
        prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, PrimitivesError>;

    /// Sample a pair of keys.
    fn key_gen<R: CryptoRng + RngCore>(
        pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), PrimitivesError>;

    /// Sign a message with the signing key
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>>(
        pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        prng: &mut R,
    ) -> Result<Self::Signature, PrimitivesError>;

    /// Verify a signature.
    fn verify<M: AsRef<[Self::MessageUnit]>>(
        pp: &Self::PublicParameter,
        vk: &Self::VerificationKey,
        msg: M,
        sig: &Self::Signature,
    ) -> Result<(), PrimitivesError>;
}

/// Trait for aggregatable signatures.
pub trait AggregateableSignatureSchemes<H>: SignatureScheme {
    // TODO: APIs for aggregateable signatures
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::prelude::StdRng;
    use jf_utils::test_rng;

    pub(crate) fn sign_and_verify<S: SignatureScheme>(message: &[S::MessageUnit]) {
        let rng = &mut test_rng();
        let parameters = S::param_gen(Some(rng)).unwrap();
        let (sk, pk) = S::key_gen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, message, &sig).is_ok());

        let parameters = S::param_gen::<StdRng>(None).unwrap();
        let (sk, pk) = S::key_gen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, message, &sig).is_ok());
    }

    pub(crate) fn failed_verification<S: SignatureScheme>(
        message: &[S::MessageUnit],
        bad_message: &[S::MessageUnit],
    ) {
        let rng = &mut test_rng();
        let parameters = S::param_gen(Some(rng)).unwrap();
        let (sk, pk) = S::key_gen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, bad_message, &sig).is_err());
    }
}
