// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuits for building blocks in Plonk verifiers.

use super::{
    challenge_var_to_fp_elem_var, poly, BatchProofVar, ChallengesFpElemVar, ChallengesVar,
    NonNativeFieldInfo, PcsInfoVar, ProofEvaluationsVar, ScalarsAndBasesVar, VerifyingKeyVar,
};
use crate::{
    circuit::transcript::RescueTranscriptVar, constants::EXTRA_TRANSCRIPT_MSG_LABEL,
    errors::PlonkError,
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig as SWParam},
};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{format, vec, vec::Vec};
use jf_relation::{
    gadgets::{
        ecc::{PointVariable, SWToTEConParam},
        ultraplonk::mod_arith::{FpElem, FpElemVar},
    },
    Circuit, CircuitError,
    CircuitError::ParameterError,
    PlonkCircuit,
};
use jf_rescue::RescueParameter;
use jf_utils::{bytes_to_field_elements, field_switching};

/// Aggregates polynomial commitments into a single commitment for batch opening.
/// Returns scalar and bases prepared for MSM and buffer info for u and v powers.
pub(super) fn aggregate_poly_commitments_circuit<E, F>(
    circuit: &mut PlonkCircuit<F>,
    vks: &[&VerifyingKeyVar<E>],
    challenges: &ChallengesFpElemVar<F>,
    poly_evals: &[FpElemVar<F>; 3],
    batch_proof: &BatchProofVar<F>,
    alpha_bases: &[FpElemVar<F>],
    non_native_field_info: NonNativeFieldInfo<F>,
) -> Result<(ScalarsAndBasesVar<F>, Vec<FpElemVar<F>>), CircuitError>
where
    E: Pairing<BaseField = F>,
    F: PrimeField,
{
    // Validate input lengths
    ensure_eq!(
        vks.len(),
        batch_proof.len(),
        "Mismatch in number of verification keys and instances"
    );

    // Compute linearized polynomial commitments
    let mut scalars_and_bases = poly::linearization_scalars_and_bases_circuit(
        circuit,
        vks,
        challenges,
        poly_evals,
        batch_proof,
        alpha_bases,
        non_native_field_info,
    )?;

    let mut v_base = challenges.v;
    let mut uv_base = challenges.u;
    let mut v_and_uv_basis = vec![];

    // Aggregate polynomial commitments
    for (i, vk) in vks.iter().enumerate() {
        add_commitments(
            circuit,
            &mut scalars_and_bases,
            &mut v_base,
            &batch_proof.wires_poly_comms_vec[i],
            &challenges.v,
            &non_native_field_info,
            &mut v_and_uv_basis,
        )?;

        add_commitments(
            circuit,
            &mut scalars_and_bases,
            &mut v_base,
            vk.sigma_comms.iter().take(batch_proof.wires_poly_comms_vec[i].len() - 1),
            &challenges.v,
            &non_native_field_info,
            &mut v_and_uv_basis,
        )?;

        v_and_uv_basis.push(uv_base);
        add_poly_comm_circuit(
            circuit,
            &mut scalars_and_bases,
            &mut uv_base,
            &batch_proof.prod_perm_poly_comms_vec[i],
            &challenges.v,
            &non_native_field_info.modulus_fp_elem,
        )?;
    }

    Ok((scalars_and_bases, v_and_uv_basis))
}

/// Combines polynomial evaluations into a single evaluation for batch opening.
pub(super) fn aggregate_evaluations_circuit<F>(
    circuit: &mut PlonkCircuit<F>,
    lin_poly_constant: &FpElemVar<F>,
    poly_evals_vec: &[ProofEvaluationsVar<F>],
    non_native_field_info: NonNativeFieldInfo<F>,
    buffer_v_and_uv_basis: &[FpElemVar<F>],
) -> Result<FpElemVar<F>, CircuitError>
where
    F: PrimeField,
{
    let mut result = circuit.mod_negate(lin_poly_constant, &non_native_field_info.modulus_in_f)?;
    let mut v_and_uv_basis_iter = buffer_v_and_uv_basis.iter();

    for poly_evals in poly_evals_vec {
        add_evaluations(
            circuit,
            &mut result,
            &mut v_and_uv_basis_iter,
            &poly_evals.wires_evals,
            &poly_evals.wire_sigma_evals,
            &poly_evals.perm_next_eval,
            &non_native_field_info,
        )?;
    }

    if v_and_uv_basis_iter.next().is_some() {
        return Err(PlonkError::IteratorOutOfRange.into());
    }

    Ok(result)
}

/// Computes verifier challenges and their derived variables.
pub(super) fn compute_challenges_vars<E, F, P>(
    circuit: &mut PlonkCircuit<F>,
    verify_keys: &[&VerifyingKeyVar<E>],
    public_inputs: &[&[FpElemVar<F>]],
    batch_proof: &BatchProofVar<F>,
    extra_transcript_init_msg: &Option<Vec<u8>>,
    non_native_field_info: NonNativeFieldInfo<F>,
) -> Result<ChallengesFpElemVar<F>, CircuitError>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWParam<BaseField = F>,
{
    validate_lengths!(verify_keys, batch_proof, public_inputs)?;

    let mut transcript_var = RescueTranscriptVar::new(circuit);
    append_extra_message(&mut transcript_var, extra_transcript_init_msg, circuit)?;

    for (&vk, &pi) in verify_keys.iter().zip(public_inputs.iter()) {
        transcript_var.append_vk_and_pub_input_vars::<E>(circuit, vk, pi)?;
    }

    let challenge_vars = create_challenge_vars(circuit, &mut transcript_var, batch_proof)?;
    challenge_var_to_fp_elem_var(circuit, &challenge_vars, &non_native_field_info)
}

/// Helper to add polynomial commitments and update random combiners.
fn add_commitments<F, C>(
    circuit: &mut PlonkCircuit<F>,
    scalars_and_bases: &mut ScalarsAndBasesVar<F>,
    random_combiner: &mut FpElemVar<F>,
    commitments: C,
    r: &FpElemVar<F>,
    non_native_field_info: &NonNativeFieldInfo<F>,
    v_and_uv_basis: &mut Vec<FpElemVar<F>>,
) -> Result<(), CircuitError>
where
    F: PrimeField,
    C: IntoIterator<Item = &PointVariable>,
{
    for &poly_comm in commitments {
        v_and_uv_basis.push(*random_combiner);
        add_poly_comm_circuit(
            circuit,
            scalars_and_bases,
            random_combiner,
            poly_comm,
            r,
            &non_native_field_info.modulus_fp_elem,
        )?;
    }
    Ok(())
}

/// Helper to add evaluations for aggregation.
fn add_evaluations<F>(
    circuit: &mut PlonkCircuit<F>,
    result: &mut FpElemVar<F>,
    basis_iter: &mut std::slice::Iter<FpElemVar<F>>,
    wires_evals: &[FpElemVar<F>],
    sigma_evals: &[FpElemVar<F>],
    perm_next_eval: &FpElemVar<F>,
    non_native_field_info: &NonNativeFieldInfo<F>,
) -> Result<(), CircuitError>
where
    F: PrimeField,
{
    for eval in wires_evals.iter().chain(sigma_evals.iter()) {
        add_pcs_eval_circuit(
            circuit,
            result,
            basis_iter.next().ok_or(PlonkError::IteratorOutOfRange)?,
            eval,
            &non_native_field_info.modulus_fp_elem,
        )?;
    }
    add_pcs_eval_circuit(
        circuit,
        result,
        basis_iter.next().ok_or(PlonkError::IteratorOutOfRange)?,
        perm_next_eval,
        &non_native_field_info.modulus_fp_elem,
    )
}
