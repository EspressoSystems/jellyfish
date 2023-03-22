// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuits for the building blocks in Plonk verifiers.
use crate::{
    circuit::{plonk_verifier::*, transcript::RescueTranscriptVar},
    constants::EXTRA_TRANSCRIPT_MSG_LABEL,
    errors::PlonkError,
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig as SWParam},
};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{format, vec::Vec};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{
    errors::{CircuitError, CircuitError::ParameterError},
    gadgets::{
        ecc::{PointVariable, SWToTEConParam},
        ultraplonk::mod_arith::{FpElem, FpElemVar},
    },
    Circuit, PlonkCircuit,
};
use jf_utils::{bytes_to_field_elements, field_switching};

/// Aggregate polynomial commitments into a single commitment (in the
/// ScalarsAndBases form). Useful in batch opening.
/// The verification key type is guaranteed to match the Plonk proof type.
/// The returned commitment is a generalization of `[F]1` described
/// in Sec 8.3, step 10 of https://eprint.iacr.org/2019/953.pdf
/// input
/// - vks: verification key variable
/// - challenges: challenge variable in FpElemVar form
/// - poly_evals: zeta^n, zeta^n-1 and Lagrange evaluated at 1
/// - batch_proof: batched proof inputs
/// - non_native_field_info: aux information for non-native field
/// Output
/// - scalar and bases prepared for MSM
/// - buffer info for u and v powers
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
    if vks.len() != batch_proof.len() {
        return Err(ParameterError(format!(
            "the number of verification keys {} != the number of instances {}",
            vks.len(),
            batch_proof.len()
        )));
    }

    // Compute the first part of the batched polynomial commitment `[D]1` described in Sec 8.4, step 9 of https://eprint.iacr.org/2019/953.pdf
    let mut scalars_and_bases = poly::linearization_scalars_and_bases_circuit(
        circuit,
        vks,
        challenges,
        poly_evals,
        batch_proof,
        alpha_bases,
        non_native_field_info,
    )?;
    // the random combiner term for the polynomials evaluated at point `zeta`
    let mut v_base = challenges.v;
    // the random combiner term for the polynomials evaluated at point `zeta * g`
    let mut uv_base = challenges.u;

    // return the buffer data for aggregate_evaluations_circuit
    let mut v_and_uv_basis = vec![];

    for (i, vk) in vks.iter().enumerate() {
        // Add poly commitments to be evaluated at point `zeta`.
        // Add wire witness polynomial commitments.
        for &poly_comm in batch_proof.wires_poly_comms_vec[i].iter() {
            v_and_uv_basis.push(v_base);
            add_poly_comm_circuit(
                circuit,
                &mut scalars_and_bases,
                &mut v_base,
                &poly_comm,
                &challenges.v,
                &non_native_field_info.modulus_fp_elem,
            )?;
        }
        // Add wire sigma polynomial commitments. The last sigma commitment is excluded.
        let num_wire_types = batch_proof.wires_poly_comms_vec[i].len();
        for &poly_comm in vk.sigma_comms.iter().take(num_wire_types - 1) {
            v_and_uv_basis.push(v_base);
            add_poly_comm_circuit(
                circuit,
                &mut scalars_and_bases,
                &mut v_base,
                &poly_comm,
                &challenges.v,
                &non_native_field_info.modulus_fp_elem,
            )?;
        }

        // Add poly commitments to be evaluated at point `zeta * g`.
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

/// Combine the polynomial evaluations into a single evaluation. Useful in
/// batch opening.
/// The returned value is the scalar in `[E]1` described in Sec 8.3, step 11 of https://eprint.iacr.org/2019/953.pdf
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
    let mut v_and_uv_basis = buffer_v_and_uv_basis.iter();

    for poly_evals in poly_evals_vec.iter() {
        // evaluations at point `zeta`
        for wire_eval in poly_evals.wires_evals.iter() {
            add_pcs_eval_circuit(
                circuit,
                &mut result,
                v_and_uv_basis
                    .next()
                    .ok_or(PlonkError::IteratorOutOfRange)?,
                wire_eval,
                &non_native_field_info.modulus_fp_elem,
            )?;
        }
        for sigma_eval in poly_evals.wire_sigma_evals.iter() {
            add_pcs_eval_circuit(
                circuit,
                &mut result,
                v_and_uv_basis
                    .next()
                    .ok_or(PlonkError::IteratorOutOfRange)?,
                sigma_eval,
                &non_native_field_info.modulus_fp_elem,
            )?;
        }
        // evaluations at point `zeta * g`
        add_pcs_eval_circuit(
            circuit,
            &mut result,
            v_and_uv_basis
                .next()
                .ok_or(PlonkError::IteratorOutOfRange)?,
            &poly_evals.perm_next_eval,
            &non_native_field_info.modulus_fp_elem,
        )?;
    }
    // ensure all the buffer has been consumed
    if v_and_uv_basis.next().is_some() {
        return Err(PlonkError::IteratorOutOfRange)?;
    }
    Ok(result)
}

/// Compute verifier challenges `beta`, `gamma`, `alpha`, `zeta`, 'v', 'u'.
/// also compute the `alpha^2` and `alpha^3`.
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
    if verify_keys.len() != batch_proof.len() || verify_keys.len() != public_inputs.len() {
        return Err(ParameterError(format!(
                "the number of verification keys = {}; the number of instances = {}; the number of public inputs = {}",
                verify_keys.len(),
                batch_proof.len(),
                public_inputs.len(),
            )));
    }
    let mut transcript_var = RescueTranscriptVar::new(circuit);
    if let Some(msg) = extra_transcript_init_msg {
        let msg_fs = bytes_to_field_elements::<_, F>(msg);
        let msg_vars = msg_fs
            .iter()
            .map(|x| circuit.create_variable(*x))
            .collect::<Result<Vec<_>, _>>()?;
        transcript_var.append_message_vars(EXTRA_TRANSCRIPT_MSG_LABEL, &msg_vars)?;
    }
    for (&vk, &pi) in verify_keys.iter().zip(public_inputs.iter()) {
        transcript_var.append_vk_and_pub_input_vars::<E>(circuit, vk, pi)?;
    }
    for wires_poly_comms in batch_proof.wires_poly_comms_vec.iter() {
        transcript_var.append_commitments_vars(b"witness_poly_comms", wires_poly_comms)?;
    }
    let tau = transcript_var.get_and_append_challenge_var::<E>(b"tau", circuit)?;

    let beta = transcript_var.get_and_append_challenge_var::<E>(b"beta", circuit)?;
    let gamma = transcript_var.get_and_append_challenge_var::<E>(b"gamma", circuit)?;
    for prod_perm_poly_comm in batch_proof.prod_perm_poly_comms_vec.iter() {
        transcript_var.append_commitment_var(b"perm_poly_comms", prod_perm_poly_comm)?;
    }

    let alpha = transcript_var.get_and_append_challenge_var::<E>(b"alpha", circuit)?;
    transcript_var
        .append_commitments_vars(b"quot_poly_comms", &batch_proof.split_quot_poly_comms)?;
    let zeta = transcript_var.get_and_append_challenge_var::<E>(b"zeta", circuit)?;
    for poly_evals in batch_proof.poly_evals_vec.iter() {
        transcript_var.append_proof_evaluations_vars(circuit, poly_evals)?;
    }

    let v = transcript_var.get_and_append_challenge_var::<E>(b"v", circuit)?;
    transcript_var.append_commitment_var(b"open_proof", &batch_proof.opening_proof)?;
    transcript_var
        .append_commitment_var(b"shifted_open_proof", &batch_proof.shifted_opening_proof)?;
    let u = transcript_var.get_and_append_challenge_var::<E>(b"u", circuit)?;

    // convert challenge vars into FpElemVars
    let challenge_var = ChallengesVar {
        tau,
        alpha,
        beta,
        gamma,
        zeta,
        v,
        u,
    };

    let challenge_fp_elem_var =
        challenge_var_to_fp_elem_var(circuit, &challenge_var, &non_native_field_info)?;
    Ok(challenge_fp_elem_var)
}

/// Prepare the (aggregated) polynomial commitment evaluation information.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_pcs_info_var<E, F, P>(
    circuit: &mut PlonkCircuit<F>,
    verify_keys: &[&VerifyingKeyVar<E>],
    public_inputs: &[&[FpElemVar<F>]],
    batch_proof: &BatchProofVar<F>,
    extra_transcript_init_msg: &Option<Vec<u8>>,

    domain: Radix2EvaluationDomain<E::ScalarField>,
    non_native_field_info: NonNativeFieldInfo<F>,
) -> Result<PcsInfoVar<F>, CircuitError>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWParam<BaseField = F>,
{
    if verify_keys.len() != batch_proof.len() || verify_keys.len() != public_inputs.len() {
        return Err(ParameterError(format!(
                "the number of verification keys = {}; the number of instances =  {}; the number of public inputs = {}",           
                verify_keys.len(),
                batch_proof.len(),
                public_inputs.len(),
            )));
    }

    for (i, (&pub_input, &vk)) in public_inputs.iter().zip(verify_keys.iter()).enumerate() {
        if pub_input.len() != vk.num_inputs {
            return Err(ParameterError(format!(
                    "the circuit pub_input length {} != the {}-th verification key's pub_input length {}",
                    pub_input.len(),
                    i,
                    vk.num_inputs,
                )));
        }

        if vk.domain_size != domain.size() {
            return Err(ParameterError(format!(
                "the domain size {} of the {}-th verification key is different from {}",
                vk.domain_size,
                i,
                domain.size(),
            )));
        }
    }

    // compute challenges and evaluations
    let challenges_fp_elem_var = compute_challenges_vars::<E, F, P>(
        circuit,
        verify_keys,
        public_inputs,
        batch_proof,
        extra_transcript_init_msg,
        non_native_field_info,
    )?;

    // pre-compute alpha_bases: [1, alpha^3, alpha^6, alpha^(3* (vks.len()-1))]
    let alpha_bases = compute_alpha_basis(
        circuit,
        challenges_fp_elem_var.alphas[2],
        verify_keys.len(),
        non_native_field_info,
    )?;

    // the outputs are: zeta^n, vanish_eval, lagrange_1_eval, lagrange_n_eval
    let evals = poly::evaluate_poly_helper::<E, F>(
        circuit,
        &challenges_fp_elem_var.zeta,
        domain.size(),
        non_native_field_info,
    )?;

    // compute the constant term of the linearization polynomial
    let lin_poly_constant = poly::compute_lin_poly_constant_term_circuit(
        circuit,
        domain.size(),
        &challenges_fp_elem_var,
        verify_keys,
        public_inputs,
        batch_proof,
        &evals,
        &alpha_bases,
        non_native_field_info,
    )?;

    // build the (aggregated) polynomial commitment/evaluation instance
    let (comm_scalars_and_bases, v_and_uv_basis) = aggregate_poly_commitments_circuit(
        circuit,
        verify_keys,
        &challenges_fp_elem_var,
        &evals,
        batch_proof,
        &alpha_bases,
        non_native_field_info,
    )?;
    let eval = aggregate_evaluations_circuit::<_>(
        circuit,
        &lin_poly_constant,
        &batch_proof.poly_evals_vec,
        non_native_field_info,
        &v_and_uv_basis,
    )?;

    // next_eval_point: challenges.zeta * domain.group_gen
    let group_gen = FpElem::new(
        &field_switching(&domain.group_gen),
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;
    let next_point = circuit.mod_mul_constant(
        &challenges_fp_elem_var.zeta,
        &group_gen,
        &non_native_field_info.modulus_fp_elem,
    )?;

    Ok(PcsInfoVar {
        u: challenges_fp_elem_var.u,
        eval_point: challenges_fp_elem_var.zeta,
        next_eval_point: next_point,
        eval,
        comm_scalars_and_bases,
        opening_proof: batch_proof.opening_proof,
        shifted_opening_proof: batch_proof.shifted_opening_proof,
    })
}

/// Merge a polynomial commitment into the aggregated polynomial commitment
/// (in the ScalarAndBases form), update the random combiner afterward.
#[inline]
fn add_poly_comm_circuit<F>(
    circuit: &mut PlonkCircuit<F>,
    scalars_and_bases: &mut ScalarsAndBasesVar<F>,
    random_combiner: &mut FpElemVar<F>,
    comm: &PointVariable,
    r: &FpElemVar<F>,
    p: &FpElem<F>,
) -> Result<(), CircuitError>
where
    F: PrimeField,
{
    scalars_and_bases.scalars.push(*random_combiner);
    scalars_and_bases.bases.push(*comm);
    *random_combiner = circuit.mod_mul(random_combiner, r, p)?;
    Ok(())
}

/// Add a polynomial commitment evaluation value to the aggregated
/// polynomial evaluation, update the random combiner afterward.
#[inline]
fn add_pcs_eval_circuit<F>(
    circuit: &mut PlonkCircuit<F>,
    result: &mut FpElemVar<F>,
    random_combiner: &FpElemVar<F>,
    eval: &FpElemVar<F>,
    p: &FpElem<F>,
) -> Result<(), CircuitError>
where
    F: PrimeField,
{
    let tmp = circuit.mod_mul(random_combiner, eval, p)?;
    *result = circuit.mod_add(result, &tmp, p)?;

    Ok(())
}

// pre-compute alpha_bases: [1, alpha^3, alpha^6, alpha^(3*(len-1))]
#[inline]
fn compute_alpha_basis<F: PrimeField>(
    circuit: &mut PlonkCircuit<F>,
    alpha_to_3: FpElemVar<F>,
    len: usize,
    non_native_field_info: NonNativeFieldInfo<F>,
) -> Result<Vec<FpElemVar<F>>, CircuitError> {
    let mut res = Vec::new();
    let mut alpha_base_elem_var = FpElemVar::<F>::one(
        circuit,
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    );
    res.push(alpha_base_elem_var);
    for _ in 0..len - 1 {
        alpha_base_elem_var = circuit.mod_mul(
            &alpha_base_elem_var,
            &alpha_to_3,
            &non_native_field_info.modulus_fp_elem,
        )?;
        res.push(alpha_base_elem_var);
    }
    Ok(res)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        proof_system::{
            batch_arg::{new_mergeable_circuit_for_test, BatchArgument},
            PlonkKzgSnark, UniversalSNARK,
        },
        transcript::{PlonkTranscript, RescueTranscript},
    };
    use ark_bls12_377::{g1::Config as Param377, Bls12_377};
    use ark_ec::{short_weierstrass::SWCurveConfig, twisted_edwards::TECurveConfig};
    use ark_std::{vec, UniformRand};
    use jf_primitives::rescue::RescueParameter;
    use jf_relation::{Circuit, MergeableCircuitType};
    use jf_utils::{field_switching, test_rng};

    const RANGE_BIT_LEN_FOR_TEST: usize = 16;
    #[test]
    fn test_compute_challenges_vars_circuit() -> Result<(), CircuitError> {
        test_compute_challenges_vars_circuit_helper::<Bls12_377, _, _, Param377, RescueTranscript<_>>(
        )
    }

    fn test_compute_challenges_vars_circuit_helper<E, F, P, Q, T>() -> Result<(), CircuitError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWCurveConfig<BaseField = F> + TECurveConfig,
        Q: TEParam<BaseField = F>,
        T: PlonkTranscript<F>,
    {
        // 1. Simulate universal setup
        let rng = &mut test_rng();
        let n = 128;
        let max_degree = n + 2;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        // 2. Setup instances
        let shared_public_input = E::ScalarField::rand(rng);
        let mut instances_type_a = vec![];
        let mut instances_type_b = vec![];
        for i in 32..50 {
            let circuit = new_mergeable_circuit_for_test::<E>(
                shared_public_input,
                i,
                MergeableCircuitType::TypeA,
            )?;
            let instance =
                BatchArgument::setup_instance(&srs, circuit, MergeableCircuitType::TypeA)?;
            instances_type_a.push(instance);

            let circuit = new_mergeable_circuit_for_test::<E>(
                shared_public_input,
                i,
                MergeableCircuitType::TypeB,
            )?;
            let instance =
                BatchArgument::setup_instance(&srs, circuit, MergeableCircuitType::TypeB)?;
            instances_type_b.push(instance);
        }
        // 3. Batch Proving
        let batch_proof =
            BatchArgument::batch_prove::<_, T>(rng, &instances_type_a, &instances_type_b)?;

        // 4. Aggregate verification keys
        let vks_type_a: Vec<&VerifyingKey<E>> = instances_type_a
            .iter()
            .map(|pred| pred.verify_key_ref())
            .collect();
        let vks_type_b: Vec<&VerifyingKey<E>> = instances_type_b
            .iter()
            .map(|pred| pred.verify_key_ref())
            .collect();
        let merged_vks = BatchArgument::aggregate_verify_keys(&vks_type_a, &vks_type_b)?;
        // error path: inconsistent length between vks_type_a and vks_type_b
        assert!(BatchArgument::aggregate_verify_keys(&vks_type_a[1..], &vks_type_b).is_err());

        // 5. Verification
        let open_key_ref = &vks_type_a[0].open_key;
        let beta_g_ref = &srs.powers_of_g[1];
        let blinding_factor = E::ScalarField::rand(rng);
        let (inner1, inner2) = BatchArgument::partial_verify::<T>(
            beta_g_ref,
            &open_key_ref.g,
            &merged_vks,
            &[shared_public_input],
            &batch_proof,
            blinding_factor,
        )?;
        assert!(BatchArgument::decide(open_key_ref, inner1, inner2)?);

        // =======================================
        // begin challenge circuit
        // =======================================
        let mut circuit = PlonkCircuit::<E::BaseField>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        // constants
        let m = 128;
        let two_power_m = Some(E::BaseField::from(2u8).pow([m as u64]));

        let fr_modulus_bits = <E::ScalarField as PrimeField>::MODULUS.to_bytes_le();
        let modulus_in_f = F::from_le_bytes_mod_order(&fr_modulus_bits);
        let modulus_fp_elem = FpElem::new(&modulus_in_f, m, two_power_m)?;
        let non_native_field_info = NonNativeFieldInfo::<F> {
            m,
            two_power_m,
            modulus_in_f,
            modulus_fp_elem,
        };

        // vk
        let vk_vars = merged_vks
            .iter()
            .map(|x| VerifyingKeyVar::new(&mut circuit, x))
            .collect::<Result<Vec<_>, _>>()?;
        let merged_vks_ref: Vec<&VerifyingKeyVar<E>> = vk_vars.iter().collect();

        let shared_public_input_var =
            circuit.create_public_variable(field_switching(&shared_public_input))?;
        let shared_public_input_fp_elem_var =
            [FpElemVar::new_unchecked(&mut circuit, shared_public_input_var, m, two_power_m)?; 1];
        let shared_public_input_fp_elem_var_ref = shared_public_input_fp_elem_var.as_ref();

        // proof
        let batch_proof_vars = batch_proof.create_variables(&mut circuit, m, two_power_m)?;

        let _challenges_fp_elem_var = compute_challenges_vars::<E, F, P>(
            &mut circuit,
            &merged_vks_ref,
            &[shared_public_input_fp_elem_var_ref; 18],
            &batch_proof_vars,
            &None,
            non_native_field_info,
        )?;

        let tmp = field_switching(&shared_public_input);
        let public_inputs = [tmp];

        assert!(
            circuit
                .check_circuit_satisfiability(public_inputs.as_ref())
                .is_ok(),
            "{:?}",
            circuit.check_circuit_satisfiability(public_inputs.as_ref())
        );

        Ok(())
    }
}
