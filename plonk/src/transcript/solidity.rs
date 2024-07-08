// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements solidity transcript.
use super::PlonkTranscript;
use crate::{
    errors::PlonkError,
    proof_system::structs::{ProofEvaluations, VerifyingKey},
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use jf_pcs::prelude::Commitment;
use sha3::{Digest, Keccak256};

/// Transcript with `keccak256` hash function.
///
/// It is currently implemented simply as
/// - an append only vector of field elements
///
/// We keep appending new elements to the transcript vector,
/// and when a challenge is generated they are appended too.
///
/// 1. challenge = hash(transcript)
/// 2. transcript = transcript || challenge
pub struct SolidityTranscript {
    pub(crate) transcript: Vec<u8>,
}

impl<F: PrimeField> PlonkTranscript<F> for SolidityTranscript {
    /// Create a new plonk transcript. `label` is omitted for efficiency.
    fn new(_label: &'static [u8]) -> Self {
        SolidityTranscript {
            transcript: Vec::new(),
        }
    }
    /// Append the message to the transcript. `_label` is omitted for
    /// efficiency.
    fn append_message(&mut self, _label: &'static [u8], msg: &[u8]) -> Result<(), PlonkError> {
        // We remove the labels for better efficiency
        self.transcript.extend_from_slice(msg);
        Ok(())
    }

    // override default implementation since we want to use BigEndian serialization
    fn append_commitment<E, P>(
        &mut self,
        label: &'static [u8],
        comm: &Commitment<E>,
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        P: SWCurveConfig<BaseField = F>,
    {
        let zero = F::zero();
        let (x, y) = if comm.0.is_zero() {
            // this is solidity precompile representation of Points of Infinity
            (&zero, &zero)
        } else {
            comm.0.xy().unwrap()
        };

        <Self as PlonkTranscript<F>>::append_message(
            self,
            label,
            &[x.into_bigint().to_bytes_be(), y.into_bigint().to_bytes_be()].concat(),
        )
    }

    // override default implementation since we want to use BigEndian serialization
    fn append_challenge<E>(
        &mut self,
        label: &'static [u8],
        challenge: &E::ScalarField,
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F>,
        E::ScalarField: PrimeField,
    {
        <Self as PlonkTranscript<F>>::append_message(
            self,
            label,
            &challenge.into_bigint().to_bytes_be(),
        )
    }

    fn append_vk_and_pub_input<E, P>(
        &mut self,
        vk: &VerifyingKey<E>,
        pub_input: &[E::ScalarField],
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        E::ScalarField: PrimeField,
        P: SWCurveConfig<BaseField = F>,
    {
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"field size in bits",
            E::ScalarField::MODULUS_BIT_SIZE.to_be_bytes().as_ref(),
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"domain size",
            vk.domain_size.to_be_bytes().as_ref(),
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"input size",
            vk.num_inputs.to_be_bytes().as_ref(),
        )?;

        for ki in vk.k.iter() {
            <Self as PlonkTranscript<F>>::append_message(
                self,
                b"wire subsets separators",
                &ki.into_bigint().to_bytes_be(),
            )?;
        }
        <Self as PlonkTranscript<F>>::append_commitments(
            self,
            b"selector commitments",
            &vk.selector_comms,
        )?;
        <Self as PlonkTranscript<F>>::append_commitments(
            self,
            b"sigma commitments",
            &vk.sigma_comms,
        )?;

        for input in pub_input.iter() {
            <Self as PlonkTranscript<F>>::append_message(
                self,
                b"public input",
                &input.into_bigint().to_bytes_be(),
            )?;
        }

        Ok(())
    }

    fn append_proof_evaluations<E: Pairing>(
        &mut self,
        evals: &ProofEvaluations<E::ScalarField>,
    ) -> Result<(), PlonkError>
    where
        E::ScalarField: PrimeField,
    {
        for w_eval in &evals.wires_evals {
            <Self as PlonkTranscript<F>>::append_message(
                self,
                b"wire_evals",
                &w_eval.into_bigint().to_bytes_be(),
            )?;
        }
        for sigma_eval in &evals.wire_sigma_evals {
            <Self as PlonkTranscript<F>>::append_message(
                self,
                b"wire_sigma_evals",
                &sigma_eval.into_bigint().to_bytes_be(),
            )?;
        }
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"perm_next_eval",
            &evals.perm_next_eval.into_bigint().to_bytes_be(),
        )
    }

    /// Generate the challenge for the current transcript,
    /// and then append it to the transcript. `_label` is omitted for
    /// efficiency.
    fn get_and_append_challenge<E>(
        &mut self,
        label: &'static [u8],
    ) -> Result<E::ScalarField, PlonkError>
    where
        E: Pairing<BaseField = F>,
        E::ScalarField: PrimeField,
    {
        let mut hasher = Keccak256::new();
        hasher.update(&self.transcript);
        let buf = hasher.finalize();

        let challenge = E::ScalarField::from_be_bytes_mod_order(&buf);
        <Self as PlonkTranscript<F>>::append_challenge::<E>(self, label, &challenge)?;

        Ok(challenge)
    }
}

#[test]
fn test_solidity_keccak() {
    use hex::FromHex;
    use sha3::{Digest, Keccak256};
    let message = "the quick brown fox jumps over the lazy dog".as_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(message);
    let output = hasher.finalize();

    // test example result yanked from smart contract execution
    assert_eq!(
        output[..],
        <[u8; 32]>::from_hex("865bf05cca7ba26fb8051e8366c6d19e21cadeebe3ee6bfa462b5c72275414ec")
            .unwrap()
    );
}
