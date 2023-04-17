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
/// TODO: generic over hash functions
pub trait AggregateableSignatureSchemes: SignatureScheme {
    /// Aggregate multiple signatures into a single signature
    /// The list of public keys is also in the input as some aggregate signature
    /// schemes might also use pks for aggregation
    fn aggregate(
        pp: &Self::PublicParameter,
        vks: &[Self::VerificationKey],
        sigs: &[Self::Signature],
    ) -> Result<Self::Signature, PrimitivesError>;

    /// Verify an aggregate signature w.r.t. a list of messages and public keys.
    /// It is user's responsibility to ensure that the public keys are
    /// validated.
    fn aggregate_verify<M: AsRef<[Self::MessageUnit]>>(
        pp: &Self::PublicParameter,
        vks: &[Self::VerificationKey],
        msgs: &[M],
        sig: &Self::Signature,
    ) -> Result<(), PrimitivesError>;

    /// Verify a multisignature w.r.t. a single message and a list of public
    /// keys. It is user's responsibility to ensure that the public keys are
    /// validated.
    fn multi_sig_verify(
        pp: &Self::PublicParameter,
        vks: &[Self::VerificationKey],
        msg: &[Self::MessageUnit],
        sig: &Self::Signature,
    ) -> Result<(), PrimitivesError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{rand::prelude::StdRng, vec, vec::Vec};
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

    pub(crate) fn agg_sign_and_verify<S: AggregateableSignatureSchemes>(
        messages: &[&[S::MessageUnit]],
        bad_message: &[S::MessageUnit],
    ) {
        let rng = &mut test_rng();
        let parameters = S::param_gen(Some(rng)).unwrap();
        let mut pks = vec![];
        let mut sigs = vec![];
        let mut partial_sigs = vec![];
        let message_for_msig = messages[0];
        for message in messages.iter() {
            let (sk, pk) = S::key_gen(&parameters, rng).unwrap();
            let sig = S::sign(&parameters, &sk, message, rng).unwrap();
            let partial_sig = S::sign(&parameters, &sk, message_for_msig, rng).unwrap();
            pks.push(pk);
            sigs.push(sig);
            partial_sigs.push(partial_sig);
        }
        // happy paths
        let agg_sig = S::aggregate(&parameters, &pks, &sigs).unwrap();
        let multi_sig = S::aggregate(&parameters, &pks, &partial_sigs).unwrap();
        assert!(S::aggregate_verify(&parameters, &pks, messages, &agg_sig).is_ok());
        assert!(S::multi_sig_verify(&parameters, &pks, message_for_msig, &multi_sig).is_ok());
        // wrong messages length
        assert!(S::aggregate_verify(&parameters, &pks, &messages[1..], &agg_sig).is_err());
        // empty pks
        assert!(S::aggregate_verify(&parameters, &[], messages, &agg_sig).is_err());
        assert!(S::multi_sig_verify(&parameters, &[], message_for_msig, &multi_sig).is_err());
        // wrong message
        let mut bad_messages: Vec<&[S::MessageUnit]> = messages.to_vec();
        bad_messages[0] = bad_message;
        assert!(S::aggregate_verify(&parameters, &pks, &bad_messages, &agg_sig).is_err());
        assert!(S::multi_sig_verify(&parameters, &pks, bad_message, &multi_sig).is_err());
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
