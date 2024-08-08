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
use ark_std::vec::Vec;
use jf_pcs::prelude::Commitment;
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
        self.append_message(
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

        // include [x]_2 G2 point from SRS
        // all G1 points from SRS are implicit reflected in committed polys
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"SRS G2 element",
            &to_bytes!(&vk.open_key.powers_of_h[1])?,
        )?;

        self.append_field_elems::<E>(b"wire subsets separators", &vk.k)?;
        self.append_commitments(b"selector commitments", &vk.selector_comms)?;
        self.append_commitments(b"sigma commitments", &vk.sigma_comms)?;
        self.append_field_elems::<E>(b"public input", pub_input)?;

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

    /// Append a field element to the transcript.
    fn append_field_elem<E>(
        &mut self,
        label: &'static [u8],
        field: &E::ScalarField,
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F>,
    {
        <Self as PlonkTranscript<F>>::append_message(self, label, &to_bytes!(field)?)
    }

    /// Append a list of field elements to the transcript
    fn append_field_elems<E>(
        &mut self,
        label: &'static [u8],
        fields: &[E::ScalarField],
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F>,
    {
        for f in fields {
            self.append_field_elem::<E>(label, f)?;
        }
        Ok(())
    }

    /// Append a proof evaluation to the transcript.
    fn append_proof_evaluations<E: Pairing<BaseField = F>>(
        &mut self,
        evals: &ProofEvaluations<E::ScalarField>,
    ) -> Result<(), PlonkError> {
        self.append_field_elems::<E>(b"wire_evals", &evals.wires_evals)?;
        self.append_field_elems::<E>(b"wire_sigma_evals", &evals.wire_sigma_evals)?;
        self.append_field_elem::<E>(b"perm_next_eval", &evals.perm_next_eval)
    }

    /// Append the plookup evaluation to the transcript.
    fn append_plookup_evaluations<E: Pairing<BaseField = F>>(
        &mut self,
        evals: &PlookupEvaluations<E::ScalarField>,
    ) -> Result<(), PlonkError> {
        self.append_field_elem::<E>(b"lookup_table_eval", &evals.range_table_eval)?;
        self.append_field_elem::<E>(b"h_1_eval", &evals.h_1_eval)?;
        self.append_field_elem::<E>(b"prod_next_eval", &evals.prod_next_eval)?;
        self.append_field_elem::<E>(b"lookup_table_next_eval", &evals.range_table_next_eval)?;
        self.append_field_elem::<E>(b"h_1_next_eval", &evals.h_1_next_eval)?;
        self.append_field_elem::<E>(b"h_2_next_eval", &evals.h_2_next_eval)
    }

    /// Generate a single challenge for the current round
    fn get_challenge<E>(&mut self, label: &'static [u8]) -> Result<E::ScalarField, PlonkError>
    where
        E: Pairing<BaseField = F>;

    /// Generate multiple challenges for the current round
    /// Implementers should be careful about domain separation for each
    /// challenge The default implementation assume `self.get_challenge()`
    /// already implements proper domain separation for each challenge
    /// generation, thus simply call it multiple times.
    fn get_n_challenges<E>(
        &mut self,
        labels: &[&'static [u8]],
    ) -> Result<Vec<E::ScalarField>, PlonkError>
    where
        E: Pairing<BaseField = F>,
    {
        let mut challenges = Vec::new();
        for label in labels {
            challenges.push(self.get_challenge::<E>(label)?);
        }
        Ok(challenges)
    }
}
