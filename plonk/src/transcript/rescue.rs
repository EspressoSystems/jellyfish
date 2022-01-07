//! This module is a defines rescue transcript.
use super::PlonkTranscript;
use crate::{
    circuit::customized::ecc::{Point, SWToTEConParam},
    errors::PlonkError,
    proof_system::structs::{PlookupEvaluations, ProofEvaluations, VerifyingKey},
};
use ark_ec::{
    short_weierstrass_jacobian::GroupAffine, PairingEngine, SWModelParameters as SWParam,
};
use ark_poly_commit::kzg10::Commitment;
use ark_std::vec::Vec;
use jf_rescue::{Permutation as RescueHash, RescueParameter, STATE_SIZE};
use jf_utils::{bytes_to_field_elements, field_switching, fq_to_fr_with_mask};

/// Rescue transcript is currently implemented simply as
/// - an append only vector of field elements
/// - a state that is initialized with 0
/// we keep appending new elements to the transcript vector,
/// and when a challenge is to be generated:
/// 1. state: [F: STATE_SIZE] = hash(state|transcript)
/// 2. challenge = state[0]
/// 3. transcript = vec![challenge]
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
    /// create a new plonk transcript
    fn new(_label: &'static [u8]) -> Self {
        RescueTranscript {
            transcript: Vec::new(),
            state: [F::zero(); STATE_SIZE],
        }
    }

    // append the verification key and the public input
    fn append_vk_and_pub_input<E, P>(
        &mut self,
        vk: &VerifyingKey<E>,
        pub_input: &[E::Fr],
    ) -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWParam<BaseField = F> + Clone,
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

    // append the message to the transcript
    fn append_message(&mut self, _label: &'static [u8], msg: &[u8]) -> Result<(), PlonkError> {
        // We remove the labels for better efficiency

        let mut f = bytes_to_field_elements(&msg);
        self.transcript.append(&mut f);
        Ok(())
    }

    // append a commitment to the transcript
    fn append_commitment<E, P>(
        &mut self,
        _label: &'static [u8],
        comm: &Commitment<E>,
    ) -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWParam<BaseField = F> + Clone,
    {
        // convert the SW form commitments into TE form
        let te_point: Point<F> = (&comm.0).into();
        // push the x and y coordinate of comm (in twisted
        // edwards form) to the transcript

        self.transcript.push(te_point.get_x());
        self.transcript.push(te_point.get_y());
        Ok(())
    }

    // append a challenge to the transcript
    fn append_challenge<E>(
        &mut self,
        _label: &'static [u8],
        challenge: &E::Fr,
    ) -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F>,
    {
        self.transcript.push(field_switching(challenge));
        Ok(())
    }

    // append the proof evaluation to the transcript
    fn append_proof_evaluations<E: PairingEngine>(
        &mut self,
        evals: &ProofEvaluations<E::Fr>,
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

    // append the plookup evaluation to the transcript
    fn append_plookup_evaluations<E: PairingEngine>(
        &mut self,
        evals: &PlookupEvaluations<E::Fr>,
    ) -> Result<(), PlonkError> {
        for eval in evals.evals_vec().iter() {
            self.transcript.push(field_switching(eval));
        }
        for next_eval in evals.next_evals_vec().iter() {
            self.transcript.push(field_switching(next_eval));
        }
        Ok(())
    }

    // generate the challenge for the current transcript
    // and append it to the transcript
    fn get_and_append_challenge<E>(&mut self, _label: &'static [u8]) -> Result<E::Fr, PlonkError>
    where
        E: PairingEngine,
    {
        // 1. state: [F: STATE_SIZE] = hash(state|transcript)
        // 2. challenge = state[0] in Fr
        // 3. transcript = Vec::new()

        let hasher = RescueHash::default();

        let input = [self.state.as_ref(), self.transcript.as_ref()].concat();
        let tmp = hasher.sponge_with_padding(&input, STATE_SIZE);
        let challenge = fq_to_fr_with_mask::<F, E::Fr>(&tmp[0]);
        self.state.copy_from_slice(&tmp);
        self.transcript = Vec::new();
        self.transcript.push(field_switching(&challenge));

        Ok(challenge)
    }
}
