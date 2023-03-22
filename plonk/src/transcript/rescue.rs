// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module is a defines rescue transcript.
use super::PlonkTranscript;
use crate::{
    errors::PlonkError,
    proof_system::structs::{PlookupEvaluations, ProofEvaluations, VerifyingKey},
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig as SWParam},
};
use ark_std::vec::Vec;
use jf_primitives::{
    crhf::{VariableLengthRescueCRHF, CRHF},
    pcs::prelude::Commitment,
    rescue::{RescueParameter, STATE_SIZE},
};
use jf_relation::gadgets::ecc::{Point, SWToTEConParam};
use jf_utils::{bytes_to_field_elements, field_switching, fq_to_fr_with_mask};

/// Transcript with rescue hash function.
///
/// It is currently implemented simply as
/// - an append only vector of field elements
/// - a state that is initialized with 0
///
/// We keep appending new elements to the transcript vector,
/// and when a challenge is to be generated,
/// we reset the state with the fresh challenge.
///
/// 1. state: \[F: STATE_SIZE\] = hash(state|transcript)
/// 2. challenge = state\[0\]
/// 3. transcript = vec!\[challenge\]
pub struct RescueTranscript<F>
where
    F: RescueParameter,
{
    transcript: Vec<F>,
    state: [F; STATE_SIZE],
}

impl<F> PlonkTranscript<F> for RescueTranscript<F>
where
    F: RescueParameter + SWToTEConParam,
{
    /// Create a new plonk transcript. `_label` is omitted for efficiency.
    fn new(_label: &'static [u8]) -> Self {
        RescueTranscript {
            transcript: Vec::new(),
            state: [F::zero(); STATE_SIZE],
        }
    }

    fn append_vk_and_pub_input<E, P>(
        &mut self,
        vk: &VerifyingKey<E>,
        pub_input: &[E::ScalarField],
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        P: SWParam<BaseField = F>,
    {
        // to enable a more efficient verifier circuit, we remove
        // the following messages (c.f. merlin transcript)
        //  - field_size_in_bits
        //  - domain size
        //  - number of inputs
        //  - wire subsets separators

        // selector commitments
        for com in vk.selector_comms.iter() {
            // convert the SW form commitments into TE form
            let te_point: Point<F> = (&com.0).into();
            self.transcript.push(te_point.get_x());
            self.transcript.push(te_point.get_y());
        }
        // sigma commitments
        for com in vk.sigma_comms.iter() {
            // convert the SW form commitments into TE form
            let te_point: Point<F> = (&com.0).into();
            self.transcript.push(te_point.get_x());
            self.transcript.push(te_point.get_y());
        }
        // public input
        for e in pub_input {
            self.transcript.push(field_switching(e))
        }

        Ok(())
    }

    /// Append the message to the transcript. `_label` is omitted for
    /// efficiency.
    fn append_message(&mut self, _label: &'static [u8], msg: &[u8]) -> Result<(), PlonkError> {
        // We remove the labels for better efficiency

        let mut f = bytes_to_field_elements(&msg);
        self.transcript.append(&mut f);
        Ok(())
    }

    /// Append a single commitment to the transcript. `_label` is omitted for
    /// efficiency.
    fn append_commitment<E, P>(
        &mut self,
        _label: &'static [u8],
        comm: &Commitment<E>,
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        P: SWParam<BaseField = F>,
    {
        // convert the SW form commitments into TE form
        let te_point: Point<F> = (&comm.0).into();
        // push the x and y coordinate of comm (in twisted
        // edwards form) to the transcript

        self.transcript.push(te_point.get_x());
        self.transcript.push(te_point.get_y());
        Ok(())
    }

    /// Append a challenge to the transcript. `_label` is omitted for
    /// efficiency.
    fn append_challenge<E>(
        &mut self,
        _label: &'static [u8],
        challenge: &E::ScalarField,
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F>,
    {
        self.transcript.push(field_switching(challenge));
        Ok(())
    }

    fn append_proof_evaluations<E: Pairing>(
        &mut self,
        evals: &ProofEvaluations<E::ScalarField>,
    ) -> Result<(), PlonkError> {
        for e in &evals.wires_evals {
            self.transcript.push(field_switching(e))
        }
        for e in &evals.wire_sigma_evals {
            self.transcript.push(field_switching(e))
        }
        self.transcript.push(field_switching(&evals.perm_next_eval));
        Ok(())
    }

    fn append_plookup_evaluations<E: Pairing>(
        &mut self,
        evals: &PlookupEvaluations<E::ScalarField>,
    ) -> Result<(), PlonkError> {
        for eval in evals.evals_vec().iter() {
            self.transcript.push(field_switching(eval));
        }
        for next_eval in evals.next_evals_vec().iter() {
            self.transcript.push(field_switching(next_eval));
        }
        Ok(())
    }

    /// Generate the challenge for the current transcript,
    /// and then append it to the transcript. `_label` is omitted for
    /// efficiency.
    fn get_and_append_challenge<E>(
        &mut self,
        _label: &'static [u8],
    ) -> Result<E::ScalarField, PlonkError>
    where
        E: Pairing<BaseField = F>,
    {
        // 1. state: [F: STATE_SIZE] = hash(state|transcript)
        // 2. challenge = state[0] in Fr
        // 3. transcript = Vec::new()

        let input = [self.state.as_ref(), self.transcript.as_ref()].concat();
        let tmp: [F; STATE_SIZE] = VariableLengthRescueCRHF::evaluate(&input)?;
        let challenge = fq_to_fr_with_mask::<F, E::ScalarField>(&tmp[0]);
        self.state.copy_from_slice(&tmp);
        self.transcript = Vec::new();
        self.transcript.push(field_switching(&challenge));

        Ok(challenge)
    }
}
