// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.
//! Module for signature primitives.

#![cfg_attr(not(feature = "std"), no_std)]
// Temporarily allow warning for nightly compilation with [`displaydoc`].
#![allow(warnings)]
#![deny(missing_docs)]
#[cfg(test)]
extern crate std;

#[cfg(any(test, feature = "schnorr"))]
#[macro_use]
extern crate derivative;

#[cfg(any(not(feature = "std"), target_has_atomic = "ptr"))]
#[doc(hidden)]
extern crate alloc;

use ark_std::rand::{CryptoRng, RngCore};

#[cfg(any(test, feature = "bls"))]
pub mod bls_over_bls12381;
#[cfg(any(test, feature = "bls"))]
pub mod bls_over_bn254;
pub mod constants;
#[cfg(feature = "gadgets")]
pub mod gadgets;
#[cfg(any(test, feature = "schnorr"))]
pub mod schnorr;

use ark_std::{
    format,
    string::{String, ToString},
};
use blst::BLST_ERROR;
use core::fmt::Debug;
use displaydoc::Display;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Signature error type
#[derive(Debug, Display, Eq, PartialEq)]
pub enum SignatureError {
    /// Bad parameter in function call, {0}
    ParameterError(String),
    /// Value is not in the right subgroup
    FailedSubgroupCheck,
    /// Value is not on the right elliptic curve
    FailedOnCurveCheck,
    /// Verification failed, {0}
    VerificationError(String),
}

impl ark_std::error::Error for SignatureError {}

impl From<BLST_ERROR> for SignatureError {
    fn from(e: BLST_ERROR) -> Self {
        match e {
            BLST_ERROR::BLST_SUCCESS => {
                Self::ParameterError("Expecting an error, but got a success.".to_string())
            },
            BLST_ERROR::BLST_VERIFY_FAIL => Self::VerificationError(format!("{e:?}")),
            _ => Self::ParameterError(format!("{e:?}")),
        }
    }
}

/// Trait definition for a signature scheme.
// A signature scheme is associated with a hash function H that is
// to be used for challenge generation.
// FIXME: update H bound once hash-api is merged.
pub trait SignatureScheme: Clone + Send + Sync + 'static {
    /// Ciphersuite Identifier
    const CS_ID: &'static str;

    /// Signing key.
    type SigningKey: Debug + Clone + Send + Sync + Zeroize + PartialEq + Eq;

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
    type PublicParameter: Debug + Clone + PartialEq + for<'a> Deserialize<'a> + Serialize;

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
    ) -> Result<Self::PublicParameter, SignatureError>;

    /// Sample a pair of keys.
    fn key_gen<R: CryptoRng + RngCore>(
        pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), SignatureError>;

    /// Sign a message with the signing key
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>>(
        pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        prng: &mut R,
    ) -> Result<Self::Signature, SignatureError>;

    /// Verify a signature.
    fn verify<M: AsRef<[Self::MessageUnit]>>(
        pp: &Self::PublicParameter,
        vk: &Self::VerificationKey,
        msg: M,
        sig: &Self::Signature,
    ) -> Result<(), SignatureError>;
}

/// Trait for aggregatable signatures.
/// TODO: generic over hash functions
// NOTE: we +Debug here instead of on `SignatureSchemes` because `schnorr <P:
// CurveConfig>` doesn't impl Debug
pub trait AggregateableSignatureSchemes:
    SignatureScheme + Serialize + for<'a> Deserialize<'a> + Debug
{
    /// Aggregate multiple signatures into a single signature
    /// The list of public keys is also in the input as some aggregate signature
    /// schemes might also use pks for aggregation
    fn aggregate(
        pp: &Self::PublicParameter,
        vks: &[Self::VerificationKey],
        sigs: &[Self::Signature],
    ) -> Result<Self::Signature, SignatureError>;

    /// Verify an aggregate signature w.r.t. a list of messages and public keys.
    /// It is user's responsibility to ensure that the public keys are
    /// validated.
    fn aggregate_verify<M: AsRef<[Self::MessageUnit]>>(
        pp: &Self::PublicParameter,
        vks: &[Self::VerificationKey],
        msgs: &[M],
        sig: &Self::Signature,
    ) -> Result<(), SignatureError>;

    /// Verify a multisignature w.r.t. a single message and a list of public
    /// keys. It is user's responsibility to ensure that the public keys are
    /// validated.
    fn multi_sig_verify(
        pp: &Self::PublicParameter,
        vks: &[Self::VerificationKey],
        msg: &[Self::MessageUnit],
        sig: &Self::Signature,
    ) -> Result<(), SignatureError>;
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
