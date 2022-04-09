//! Module for signature primitives.

use crate::errors::PrimitivesError;
use ark_std::rand::{CryptoRng, RngCore};

pub mod bls;
pub mod schnorr;

/// Trait definition for a signature scheme.
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
    fn setup<R: CryptoRng + RngCore>(
        prng: &mut R,
    ) -> Result<Self::PublicParameter, PrimitivesError>;

    /// Sample a pair of keys.
    fn keygen<R: CryptoRng + RngCore>(
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

    /// Randomize a public key with a blob
    fn randomize_public_key(
        _pp: &Self::PublicParameter,
        public_key: &Self::VerificationKey,
        randomness: &[u8],
    ) -> Result<Self::VerificationKey, PrimitivesError>;

    /// Randomize a signature key with a blob
    fn randomize_signature(
        _pp: &Self::PublicParameter,
        _signature: &Self::Signature,
        _randomness: &[u8],
    ) -> Result<Self::Signature, PrimitivesError>;
}

/// Trait for aggregatable signatures. (TODO)
pub trait AggregateableSignatureSchemes: SignatureScheme {}
