// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements Fiat-Shamir transcripts
use crate::{
    errors::PlonkError,
    proof_system::structs::{ProofEvaluations, VerifyingKey},
};
use ark_ec::{
    short_weierstrass_jacobian::GroupAffine, PairingEngine, SWModelParameters as SWParam,
};
use ark_ff::PrimeField;
use ark_poly_commit::kzg10::Commitment;
use jf_utils::to_bytes;
use merlin::Transcript;

/// Defines transcript APIs.
///
/// It has an associated type `F` which defines the native
/// field for the snark circuit.
pub trait PlonkTranscript<F> {
    /// Create a new plonk transcript.
    fn new(label: &'static [u8]) -> Self;

    /// Append the verification key and the public input to the transcript.
    fn append_vk_and_pub_input<E, P>(
        &mut self,
        vk: &VerifyingKey<E>,
        pub_input: &[E::Fr],
    ) -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWParam<BaseField = F> + Clone,
    {
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"field size in bits",
            E::Fr::size_in_bits().to_le_bytes().as_ref(),
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
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWParam<BaseField = F> + Clone,
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
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWParam<BaseField = F> + Clone,
    {
        <Self as PlonkTranscript<F>>::append_message(self, label, &to_bytes!(comm)?)
    }

    /// Append a challenge to the transcript.
    fn append_challenge<E>(
        &mut self,
        label: &'static [u8],
        challenge: &E::Fr,
    ) -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F>,
    {
        <Self as PlonkTranscript<F>>::append_message(self, label, &to_bytes!(challenge)?)
    }

    /// Append a proof evaluation to the transcript.
    fn append_proof_evaluations<E: PairingEngine>(
        &mut self,
        evals: &ProofEvaluations<E::Fr>,
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

    /// Generate the challenge for the current transcript,
    /// and then append it to the transcript.
    fn get_and_append_challenge<E>(&mut self, label: &'static [u8]) -> Result<E::Fr, PlonkError>
    where
        E: PairingEngine;
}

/// A wrapper of `merlin::Transcript`.
pub struct StandardTranscript(Transcript);

impl<F> PlonkTranscript<F> for StandardTranscript {
    /// create a new plonk transcript
    fn new(label: &'static [u8]) -> Self {
        Self(Transcript::new(label))
    }

    // append the message to the transcript
    fn append_message(&mut self, label: &'static [u8], msg: &[u8]) -> Result<(), PlonkError> {
        self.0.append_message(label, msg);

        Ok(())
    }

    // generate the challenge for the current transcript
    // and append it to the transcript
    fn get_and_append_challenge<E>(&mut self, label: &'static [u8]) -> Result<E::Fr, PlonkError>
    where
        E: PairingEngine,
    {
        let mut buf = [0u8; 64];
        self.0.challenge_bytes(label, &mut buf);
        let challenge = E::Fr::from_le_bytes_mod_order(&buf);
        self.0.append_message(label, &to_bytes!(&challenge)?);
        Ok(challenge)
    }
}
