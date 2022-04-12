//! Module for signature primitives.

pub use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::Rng, vec::Vec};

pub mod bls;
pub mod schnorr;

/// A signature scheme that takes field elements as messages
pub trait FieldBasedSignatureScheme: SignatureScheme {
    /// A message is a slice of prime field elements
    type MessageUnit: PrimeField;

    /// Default implementation of signing field elements.
    fn sign_field_elements<R: Rng>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[Self::MessageUnit],
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        let mut msg = Vec::new();
        for m in message.iter() {
            m.serialize(&mut msg)?
        }
        Self::sign(pp, sk, &msg, rng)
    }
    /// Default implementation of verifying signatures on field elements.
    fn verify_field_elements(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[Self::MessageUnit],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let mut msg = Vec::new();
        for m in message.iter() {
            m.serialize(&mut msg)?
        }
        Self::verify(pp, pk, &msg, signature)
    }
}

/// Trait for aggregatable signatures. (TODO)
pub trait AggregateableSignatureSchemes: SignatureScheme {}
