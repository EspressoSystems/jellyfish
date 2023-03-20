// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementing *native* circuit for rescue transcript

use super::plonk_verifier::*;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_std::{string::ToString, vec::Vec};
use core::marker::PhantomData;
use jf_primitives::{
    circuit::rescue::RescueNativeGadget,
    rescue::{RescueParameter, STATE_SIZE},
};
use jf_relation::{
    errors::CircuitError::{self, ParameterError},
    gadgets::{
        ecc::{PointVariable, SWToTEConParam},
        ultraplonk::mod_arith::FpElemVar,
    },
    Circuit, PlonkCircuit, Variable,
};

/// Struct of variables representing a Rescue transcript type, including
/// `STATE_SIZE` variables for the state, and a vector of variables for
/// the transcript.
pub struct RescueTranscriptVar<F: RescueParameter> {
    transcript_var: Vec<Variable>,
    state_var: [Variable; STATE_SIZE],
    _phantom: PhantomData<F>,
}

impl<F> RescueTranscriptVar<F>
where
    F: RescueParameter + SWToTEConParam,
{
    /// create a new RescueTranscriptVar for a given circuit.
    pub(crate) fn new(circuit: &mut PlonkCircuit<F>) -> Self {
        Self {
            transcript_var: Vec::new(),
            state_var: [circuit.zero(); STATE_SIZE],
            _phantom: PhantomData::default(),
        }
    }

    // append the verification key and the public input
    pub(crate) fn append_vk_and_pub_input_vars<E: Pairing<BaseField = F>>(
        &mut self,
        circuit: &mut PlonkCircuit<F>,
        vk_var: &VerifyingKeyVar<E>,
        pub_input: &[FpElemVar<F>],
    ) -> Result<(), CircuitError> {
        // to enable a more efficient verifier circuit, we remove
        // the following messages (c.f. merlin transcript)
        //  - field_size_in_bits
        //  - domain size
        //  - number of inputs
        //  - wire subsets separators

        // selector commitments
        for com in vk_var.selector_comms.iter() {
            // the commitment vars are already in TE form
            self.transcript_var.push(com.get_x());
            self.transcript_var.push(com.get_y());
        }
        // sigma commitments
        for com in vk_var.sigma_comms.iter() {
            // the commitment vars are already in TE form
            self.transcript_var.push(com.get_x());
            self.transcript_var.push(com.get_y());
        }
        // public input
        for e in pub_input {
            let pub_var = e.convert_to_var(circuit)?;
            self.transcript_var.push(pub_var)
        }
        Ok(())
    }

    // Append the variable to the transcript.
    // For efficiency purpose, label is not used for rescue FS.
    pub(crate) fn append_variable(
        &mut self,
        _label: &'static [u8],
        var: &Variable,
    ) -> Result<(), CircuitError> {
        self.transcript_var.push(*var);

        Ok(())
    }

    // Append the message variables to the transcript.
    // For efficiency purpose, label is not used for rescue FS.
    pub(crate) fn append_message_vars(
        &mut self,
        _label: &'static [u8],
        msg_vars: &[Variable],
    ) -> Result<(), CircuitError> {
        for e in msg_vars.iter() {
            self.append_variable(_label, e)?;
        }

        Ok(())
    }

    // Append a commitment variable (in the form of PointVariable) to the
    // transcript. The caller needs to make sure that the commitment is
    // already converted to TE form before generating the variables.
    // For efficiency purpose, label is not used for rescue FS.
    pub(crate) fn append_commitment_var(
        &mut self,
        _label: &'static [u8],
        poly_comm_var: &PointVariable,
    ) -> Result<(), CircuitError> {
        // push the x and y coordinate of comm to the transcript
        self.transcript_var.push(poly_comm_var.get_x());
        self.transcript_var.push(poly_comm_var.get_y());

        Ok(())
    }

    // Append  a slice of commitment variables (in the form of PointVariable) to the
    // The caller needs to make sure that the commitment is
    // already converted to TE form before generating the variables.
    // transcript For efficiency purpose, label is not used for rescue FS.
    pub(crate) fn append_commitments_vars(
        &mut self,
        _label: &'static [u8],
        poly_comm_vars: &[PointVariable],
    ) -> Result<(), CircuitError> {
        for poly_comm_var in poly_comm_vars.iter() {
            // push the x and y coordinate of comm to the transcript
            self.transcript_var.push(poly_comm_var.get_x());
            self.transcript_var.push(poly_comm_var.get_y());
        }
        Ok(())
    }

    // Append a challenge variable to the transcript.
    // For efficiency purpose, label is not used for rescue FS.
    pub(crate) fn append_challenge_var(
        &mut self,
        _label: &'static [u8],
        challenge_var: &Variable,
    ) -> Result<(), CircuitError> {
        self.append_variable(_label, challenge_var)
    }

    // Append the proof evaluation to the transcript
    pub(crate) fn append_proof_evaluations_vars(
        &mut self,
        circuit: &mut PlonkCircuit<F>,
        evals: &ProofEvaluationsVar<F>,
    ) -> Result<(), CircuitError> {
        for e in &evals.wires_evals {
            let tmp = e.convert_to_var(circuit)?;
            self.transcript_var.push(tmp);
        }
        for e in &evals.wire_sigma_evals {
            let tmp = e.convert_to_var(circuit)?;
            self.transcript_var.push(tmp);
        }
        let tmp = evals.perm_next_eval.convert_to_var(circuit)?;
        self.transcript_var.push(tmp);
        Ok(())
    }

    // generate the challenge for the current transcript
    // and append it to the transcript
    // For efficiency purpose, label is not used for rescue FS.
    // Note that this function currently only supports bls12-377
    // curve due to its decomposition method.
    pub(crate) fn get_and_append_challenge_var<E>(
        &mut self,
        _label: &'static [u8],
        circuit: &mut PlonkCircuit<F>,
    ) -> Result<Variable, CircuitError>
    where
        E: Pairing,
    {
        if !circuit.support_lookup() {
            return Err(ParameterError("does not support range table".to_string()));
        }

        if E::ScalarField::MODULUS_BIT_SIZE != 253 || E::BaseField::MODULUS_BIT_SIZE != 377 {
            return Err(ParameterError(
                "Curve Parameter does not support for rescue transcript circuit".to_string(),
            ));
        }

        // ==================================
        // This algorithm takes in 3 steps
        // 1. state: [F: STATE_SIZE] = hash(state|transcript)
        // 2. challenge = state[0] in Fr
        // 3. transcript = vec![challenge]
        // ==================================

        // step 1. state: [F: STATE_SIZE] = hash(state|transcript)
        let input_var = [self.state_var.as_ref(), self.transcript_var.as_ref()].concat();
        let res_var =
            RescueNativeGadget::<F>::rescue_sponge_with_padding(circuit, &input_var, STATE_SIZE)
                .unwrap();
        let out_var = res_var[0];

        // step 2. challenge = state[0] in Fr
        let challenge_var = circuit.truncate(out_var, 248)?;

        // 3. transcript = vec![challenge]
        // finish and update the states
        self.state_var.copy_from_slice(&res_var[0..STATE_SIZE]);
        self.transcript_var = Vec::new();
        self.append_challenge_var(_label, &challenge_var)?;

        Ok(challenge_var)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proof_system::structs::VerifyingKey,
        transcript::{PlonkTranscript, RescueTranscript},
    };
    use ark_bls12_377::Bls12_377;
    use ark_ec::{
        short_weierstrass::{Affine, SWCurveConfig},
        AffineRepr, CurveGroup,
    };
    use ark_std::{format, UniformRand};
    use jf_primitives::pcs::prelude::{Commitment, UnivariateVerifierParam};
    use jf_relation::gadgets::ecc::Point;
    use jf_utils::{bytes_to_field_elements, field_switching, test_rng};

    const RANGE_BIT_LEN_FOR_TEST: usize = 16;
    #[test]
    fn test_rescue_transcript_challenge_circuit() {
        test_rescue_transcript_challenge_circuit_helper::<Bls12_377, _, _>()
    }
    fn test_rescue_transcript_challenge_circuit_helper<E, F, P>()
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWCurveConfig<BaseField = F>,
    {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let label = "testing".as_ref();

        let mut transcipt_var = RescueTranscriptVar::new(&mut circuit);
        let mut transcript = RescueTranscript::<F>::new(label);

        for _ in 0..10 {
            for i in 0..10 {
                let msg = format!("message {}", i);
                let vals = bytes_to_field_elements(&msg);
                let message_vars: Vec<Variable> = vals
                    .iter()
                    .map(|x| circuit.create_variable(*x).unwrap())
                    .collect();

                transcript.append_message(label, msg.as_bytes()).unwrap();

                transcipt_var
                    .append_message_vars(label, &message_vars)
                    .unwrap();
            }

            let challenge = transcript.get_and_append_challenge::<E>(label).unwrap();

            let challenge_var = transcipt_var
                .get_and_append_challenge_var::<E>(label, &mut circuit)
                .unwrap();

            assert_eq!(
                circuit.witness(challenge_var).unwrap().into_bigint(),
                field_switching::<_, F>(&challenge).into_bigint()
            );
        }
    }

    #[test]
    fn test_rescue_transcript_append_vk_and_input_circuit() {
        test_rescue_transcript_append_vk_and_input_circuit_helper::<Bls12_377, _, _>()
    }
    fn test_rescue_transcript_append_vk_and_input_circuit_helper<E, F, P>()
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWCurveConfig<BaseField = F>,
    {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let mut rng = test_rng();

        let label = "testing".as_ref();

        let mut transcript_var = RescueTranscriptVar::new(&mut circuit);
        let mut transcript = RescueTranscript::<F>::new(label);

        let open_key: UnivariateVerifierParam<E> = UnivariateVerifierParam {
            g: E::G1Affine::generator(),
            h: E::G2Affine::generator(),
            beta_h: E::G2::rand(&mut rng).into_affine(),
        };

        let dummy_vk = VerifyingKey {
            domain_size: 512,
            num_inputs: 0,
            sigma_comms: Vec::new(),
            selector_comms: Vec::new(),
            k: Vec::new(),
            open_key,
            is_merged: false,
            plookup_vk: None,
        };

        let dummy_vk_var = VerifyingKeyVar::new(&mut circuit, &dummy_vk).unwrap();

        // build challenge from transcript and check for correctness
        transcript.append_vk_and_pub_input(&dummy_vk, &[]).unwrap();
        transcript_var
            .append_vk_and_pub_input_vars::<E>(&mut circuit, &dummy_vk_var, &[])
            .unwrap();

        let challenge = transcript.get_and_append_challenge::<E>(label).unwrap();

        let challenge_var = transcript_var
            .get_and_append_challenge_var::<E>(label, &mut circuit)
            .unwrap();

        assert_eq!(
            circuit.witness(challenge_var).unwrap(),
            field_switching(&challenge)
        );

        for _ in 0..10 {
            // inputs
            let input: Vec<E::ScalarField> =
                (0..16).map(|_| E::ScalarField::rand(&mut rng)).collect();

            // sigma commitments
            let sigma_comms: Vec<Commitment<E>> = (0..42)
                .map(|_| Commitment(E::G1::rand(&mut rng).into_affine()))
                .collect();
            let mut sigma_comms_vars: Vec<PointVariable> = Vec::new();
            for e in sigma_comms.iter() {
                // convert point into TE form
                let p: Point<F> = (&e.0).into();
                sigma_comms_vars.push(circuit.create_point_variable(p).unwrap());
            }

            // selector commitments
            let selector_comms: Vec<Commitment<E>> = (0..33)
                .map(|_| Commitment(E::G1::rand(&mut rng).into_affine()))
                .collect();
            let mut selector_comms_vars: Vec<PointVariable> = Vec::new();
            for e in selector_comms.iter() {
                // convert point into TE form
                let p: Point<F> = (&e.0).into();
                selector_comms_vars.push(circuit.create_point_variable(p).unwrap());
            }

            // k
            let k: Vec<E::ScalarField> = (0..5).map(|_| E::ScalarField::rand(&mut rng)).collect();

            let vk = VerifyingKey {
                domain_size: 512,
                num_inputs: input.len(),
                sigma_comms,
                selector_comms,
                k,
                open_key,
                is_merged: false,
                plookup_vk: None,
            };
            let vk_var = VerifyingKeyVar::new(&mut circuit, &vk).unwrap();

            // build challenge from transcript and check for correctness
            transcript.append_vk_and_pub_input(&vk, &input).unwrap();
            let m = 128;
            let input_vars: Vec<Variable> = input
                .iter()
                .map(|&x| circuit.create_public_variable(field_switching(&x)).unwrap())
                .collect();

            let input_fp_elem_vars: Vec<FpElemVar<F>> = input_vars
                .iter()
                .map(|&x| FpElemVar::new_unchecked(&mut circuit, x, m, None).unwrap())
                .collect();
            transcript_var
                .append_vk_and_pub_input_vars::<E>(&mut circuit, &vk_var, &input_fp_elem_vars)
                .unwrap();

            let challenge = transcript.get_and_append_challenge::<E>(label).unwrap();

            let challenge_var = transcript_var
                .get_and_append_challenge_var::<E>(label, &mut circuit)
                .unwrap();

            assert_eq!(
                circuit.witness(challenge_var).unwrap(),
                field_switching(&challenge)
            );
        }
    }
}
