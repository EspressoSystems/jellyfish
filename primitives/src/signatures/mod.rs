//! Module for signature primitives.

use crate::errors::PrimitivesError;
use ark_std::rand::{CryptoRng, RngCore};

pub mod bls;
pub mod schnorr;

/// Trait definition for a signature scheme.
// A signature scheme is associated with a hash function H that is
// to be used for challenge generation.
// FIXME: update H bound once hash-api is merged.
pub trait SignatureScheme<H> {
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
    fn param_gen<R: CryptoRng + RngCore>(
        prng: &mut R,
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
pub trait AggregateableSignatureSchemes<H>: SignatureScheme<H> {}
