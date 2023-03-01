// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements three different types of transcripts that are
//! supported.

pub(crate) mod rescue;
pub(crate) mod solidity;
pub(crate) mod standard;

pub use rescue::RescueTranscript;
pub use solidity::SolidityTranscript;
pub use standard::StandardTranscript;

use crate::{
    errors::PlonkError,
    proof_system::structs::{PlookupEvaluations, ProofEvaluations, VerifyingKey},
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig as SWParam},
};
use ark_ff::PrimeField;
use jf_primitives::pcs::prelude::Commitment;
use jf_utils::to_bytes;

/// Defines transcript APIs.
///
/// It has an associated type `F` which defines the native
/// field for the snark circuit.
///
/// The transcript can be either a Merlin transcript
/// (instantiated with Sha-3/keccak), or a Rescue transcript
/// (instantiated with Rescue hash), or a Solidity-friendly transcript
/// (instantiated with Keccak256 hash).
/// The second is only used for recursive snarks.
pub trait PlonkTranscript<F> {
    /// Create a new plonk transcript.
    fn new(label: &'static [u8]) -> Self;

    /// Append the verification key and the public input to the transcript.
    fn append_vk_and_pub_input<E, P>(
        &mut self,
        vk: &VerifyingKey<E>,
        pub_input: &[E::ScalarField],
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        P: SWParam<BaseField = F>,
    {
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"field size in bits",
            E::ScalarField::MODULUS_BIT_SIZE.to_le_bytes().as_ref(),
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"domain size",
            vk.domain_size.to_le_bytes().as_ref(),
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"input size",
            vk.num_inputs.to_le_bytes().as_ref(),
        )?;

        for ki in vk.k.iter() {
            <Self as PlonkTranscript<F>>::append_message(
                self,
                b"wire subsets separators",
                &to_bytes!(ki)?,
            )?;
        }
        for selector_com in vk.selector_comms.iter() {
            <Self as PlonkTranscript<F>>::append_message(
                self,
                b"selector commitments",
                &to_bytes!(selector_com)?,
            )?;
        }

        for sigma_comms in vk.sigma_comms.iter() {
            <Self as PlonkTranscript<F>>::append_message(
                self,
                b"sigma commitments",
                &to_bytes!(sigma_comms)?,
            )?;
        }

        for input in pub_input.iter() {
            <Self as PlonkTranscript<F>>::append_message(
                self,
                b"public input",
                &to_bytes!(input)?,
            )?;
        }

        Ok(())
    }

    /// Append the message to the transcript.
    fn append_message(&mut self, label: &'static [u8], msg: &[u8]) -> Result<(), PlonkError>;

    /// Append a slice of commitments to the transcript.
    fn append_commitments<E, P>(
        &mut self,
        label: &'static [u8],
        comms: &[Commitment<E>],
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        P: SWParam<BaseField = F>,
    {
        for comm in comms.iter() {
            self.append_commitment(label, comm)?;
        }
        Ok(())
    }

    /// Append a single commitment to the transcript.
    fn append_commitment<E, P>(
        &mut self,
        label: &'static [u8],
        comm: &Commitment<E>,
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        P: SWParam<BaseField = F>,
    {
        <Self as PlonkTranscript<F>>::append_message(self, label, &to_bytes!(comm)?)
    }

    /// Append a challenge to the transcript.
    fn append_challenge<E>(
        &mut self,
        label: &'static [u8],
        challenge: &E::ScalarField,
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F>,
    {
        <Self as PlonkTranscript<F>>::append_message(self, label, &to_bytes!(challenge)?)
    }

    /// Append a proof evaluation to the transcript.
    fn append_proof_evaluations<E: Pairing>(
        &mut self,
        evals: &ProofEvaluations<E::ScalarField>,
    ) -> Result<(), PlonkError> {
        for w_eval in &evals.wires_evals {
            <Self as PlonkTranscript<F>>::append_message(self, b"wire_evals", &to_bytes!(w_eval)?)?;
        }
        for sigma_eval in &evals.wire_sigma_evals {
            <Self as PlonkTranscript<F>>::append_message(
                self,
                b"wire_sigma_evals",
                &to_bytes!(sigma_eval)?,
            )?;
        }
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"perm_next_eval",
            &to_bytes!(&evals.perm_next_eval)?,
        )
    }

    /// Append the plookup evaluation to the transcript.
    fn append_plookup_evaluations<E: Pairing>(
        &mut self,
        evals: &PlookupEvaluations<E::ScalarField>,
    ) -> Result<(), PlonkError> {
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"lookup_table_eval",
            &to_bytes!(&evals.range_table_eval)?,
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"h_1_eval",
            &to_bytes!(&evals.h_1_eval)?,
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"prod_next_eval",
            &to_bytes!(&evals.prod_next_eval)?,
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"lookup_table_next_eval",
            &to_bytes!(&evals.range_table_next_eval)?,
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"h_1_next_eval",
            &to_bytes!(&evals.h_1_next_eval)?,
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"h_2_next_eval",
            &to_bytes!(&evals.h_2_next_eval)?,
        )
    }

    /// Generate the challenge for the current transcript,
    /// and then append it to the transcript.
    fn get_and_append_challenge<E>(
        &mut self,
        label: &'static [u8],
    ) -> Result<E::ScalarField, PlonkError>
    where
        E: Pairing<BaseField = F>;
}
