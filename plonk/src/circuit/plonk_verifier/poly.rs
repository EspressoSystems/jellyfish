// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuits for the polynomial evaluations within Plonk verifiers.
use crate::{circuit::plonk_verifier::*, errors::PlonkError};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{format, string::ToString, vec, vec::Vec, One};
use jf_relation::{
    constants::GATE_WIDTH,
    errors::{CircuitError, CircuitError::ParameterError},
    gadgets::ultraplonk::mod_arith::{FpElem, FpElemVar},
    PlonkCircuit,
};
use jf_utils::field_switching;

/// This helper function generate the variables for the following data
/// - Circuit evaluation of vanishing polynomial at point `zeta` i.e., output =
///   zeta ^ domain_size - 1 mod Fr::modulus
/// - Evaluations of the first and the last lagrange polynomial at point `zeta`
///
/// Note that outputs and zeta are both Fr element
/// so this needs to be carried out over a non-native circuit
/// using parameter m.
/// The output is lifted to Fq and in the FpElemVar form for:
///
/// - zeta^n
/// - zeta^n - 1
/// - lagrange evaluation at 1
///
/// Note that evaluation at n is commented out as we don't need it for
/// partial verification circuit.
pub(super) fn evaluate_poly_helper<E, F>(
    circuit: &mut PlonkCircuit<F>,
    zeta_fp_elem_var: &FpElemVar<F>,
    domain_size: usize,
    non_native_field_info: NonNativeFieldInfo<F>,
) -> Result<[FpElemVar<F>; 3], CircuitError>
where
    E: Pairing<BaseField = F>,
    F: PrimeField,
{
    // constants
    let domain_size_fp_elem = FpElem::new(
        &F::from(domain_size as u64),
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;

    // zeta
    let zeta = zeta_fp_elem_var.witness(circuit)?;
    let zeta_fr = field_switching::<_, E::ScalarField>(&zeta);

    // ================================
    // compute zeta^n - 1
    // ================================

    // compute zeta^n for n = domain_size a power of 2
    let mut ctr = 1;
    let mut zeta_n_fp_elem_var = *zeta_fp_elem_var;
    while ctr < domain_size {
        ctr <<= 1;
        zeta_n_fp_elem_var = circuit.mod_mul(
            &zeta_n_fp_elem_var,
            &zeta_n_fp_elem_var,
            &non_native_field_info.modulus_fp_elem,
        )?;
    }

    // to compute zeta^n -1 we need to compute it over Fr
    // we cannot simply do
    //  let zeta_n_minus_one_var = circuit.sub(zeta_n_var, circuit.one())?;
    // since it may be overflowing if zeta_n = 0
    //
    // Option 1: to write the subtraction in non-native field
    //
    // Option 2, which is what is implemented here
    // - if zeta_n = 0, output Fr::modulus - 1
    // - else output zeta_n -1
    // this circuit should still be cheaper than non-native circuit.
    //
    //
    // Question(ZZ): second thought, this should be fine since we know that
    // zeta !=0 mod fr with 1 - 1/|Fr| probability as zeta is a output from
    // RO. Nonetheless, I am implementing it with non-native field first.
    // We may switch to native field if this is fine...
    //

    // zeta^n = zeta_n_minus_1 + 1
    let zeta_n = zeta_n_fp_elem_var.witness(circuit)?;
    let zeta_n_minus_one = field_switching::<_, F>(
        &(field_switching::<_, E::ScalarField>(&zeta_n) - E::ScalarField::one()),
    );
    let zeta_n_minus_one_fp_elem_var = FpElemVar::new_from_field_element(
        circuit,
        &zeta_n_minus_one,
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;
    let one_fp_elem = FpElem::new(
        &F::one(),
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;
    let zeta_n_fp_elem_var_rec = circuit.mod_add_constant(
        &zeta_n_minus_one_fp_elem_var,
        &one_fp_elem,
        &non_native_field_info.modulus_fp_elem,
    )?;
    zeta_n_fp_elem_var.enforce_equal(circuit, &zeta_n_fp_elem_var_rec)?;

    // ================================
    // evaluate lagrange at 1
    //  lagrange_1_eval = (zeta^n - 1) / (zeta - 1) / domain_size
    //
    // which is proven via
    //  domain_size * lagrange_1_eval * (zeta - 1) = zeta^n - 1 mod Fr::modulus
    // ================================

    // lagrange_1_eval
    let zeta_n_minus_one = field_switching::<_, E::ScalarField>(&zeta_n_minus_one);
    let divisor = E::ScalarField::from(domain_size as u64) * (zeta_fr - E::ScalarField::one());
    let lagrange_1_eval = zeta_n_minus_one / divisor;
    let lagrange_1_eval_fp_elem_var = FpElemVar::new_from_field_element(
        circuit,
        &field_switching(&lagrange_1_eval),
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;

    // zeta - 1
    let zeta_minus_one_fr = zeta_fr - E::ScalarField::one();
    let zeta_minus_one_fp_elem_var = FpElemVar::new_from_field_element(
        circuit,
        &field_switching(&zeta_minus_one_fr),
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;
    let zeta_fp_elem_var_rec = circuit.mod_add_constant(
        &zeta_minus_one_fp_elem_var,
        &one_fp_elem,
        &non_native_field_info.modulus_fp_elem,
    )?;
    zeta_fp_elem_var.enforce_equal(circuit, &zeta_fp_elem_var_rec)?;

    // left
    let mut left = circuit.mod_mul_constant(
        &lagrange_1_eval_fp_elem_var,
        &domain_size_fp_elem,
        &non_native_field_info.modulus_fp_elem,
    )?;
    left = circuit.mod_mul(
        &left,
        &zeta_minus_one_fp_elem_var,
        &non_native_field_info.modulus_fp_elem,
    )?;
    left.enforce_equal(circuit, &zeta_n_minus_one_fp_elem_var)?;

    Ok([
        zeta_n_fp_elem_var,
        zeta_n_minus_one_fp_elem_var,
        lagrange_1_eval_fp_elem_var,
    ])
}

/// Evaluate public input polynomial at point `z`.
/// Define the following as
/// - H: The domain with generator g
/// - n: The size of the domain H
/// - Z_H: The vanishing polynomial for H.
/// - v_i: A sequence of values, where v_i = g^i / n
///
/// We then compute L_{i,H}(z) as `L_{i,H}(z) = Z_H(z) * v_i / (z - g^i)`
/// The public input polynomial evaluation for the merged circuit is:
///
/// \sum_{i=0..l/2} L_{i,H}(z) * pub_input[i] +
/// \sum_{i=0..l/2} L_{n-i,H}(z) * pub_input[l/2+i]
pub(super) fn evaluate_pi_poly_circuit<E, F>(
    circuit: &mut PlonkCircuit<F>,
    domain_size: usize,
    pub_inputs_fp_elem_var: &[FpElemVar<F>],
    zeta_fp_elem_var: &FpElemVar<F>,
    vanish_eval_fp_elem_var: &FpElemVar<F>,
    circuit_is_merged: bool,
    non_native_field_info: NonNativeFieldInfo<F>,
) -> Result<FpElemVar<F>, CircuitError>
where
    E: Pairing<BaseField = F>,
    F: PrimeField,
{
    // the circuit is already merged
    if !circuit_is_merged {
        return Err(CircuitError::ParameterError(
            "Circuit should already been merged".to_string(),
        ));
    }
    let len = pub_inputs_fp_elem_var.len() >> 1;

    // constants
    let zeta = field_switching::<_, E::ScalarField>(&zeta_fp_elem_var.witness(circuit)?);
    let vanish_eval =
        field_switching::<_, E::ScalarField>(&vanish_eval_fp_elem_var.witness(circuit)?);

    // compute v_i = g^i / n in the clear
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(domain_size).unwrap();
    let v_i: Vec<E::ScalarField> = (0..domain_size)
        .map(|x| domain.element(x) / E::ScalarField::from(domain_size as u64))
        .collect();

    // compute L_{i,H}(zeta) = Z_H(zeta) * v_i / (zeta - g^i)
    // where Z_H(z) is the vanishing evaluation
    // compute for both i in [0, len) and [domain_size-len, domain_size)
    let mut lagrange_eval_fp_elem_var: Vec<FpElemVar<F>> = Vec::new();
    let range = (0..len).chain(domain_size - len..domain_size);

    for i in range {
        // compute L_{i,H}(zeta) and related values in the clear
        let v_i_fp_elem = FpElem::<F>::new(
            &field_switching(&v_i[i]),
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?;
        let g_i_fp_elem = FpElem::<F>::new(
            &field_switching(&domain.element(i)),
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?;
        let zeta_minus_gi = zeta - domain.element(i);
        let eval_i = vanish_eval * v_i[i] / zeta_minus_gi;

        // prove zeta_minus_gi = zeta - g^i
        let zeta_minus_gi_elem_var = FpElemVar::new_from_field_element(
            circuit,
            &field_switching(&zeta_minus_gi),
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?;
        let zeta_fp_elem_var_rec = circuit.mod_add_constant(
            &zeta_minus_gi_elem_var,
            &g_i_fp_elem,
            &non_native_field_info.modulus_fp_elem,
        )?;
        zeta_fp_elem_var.enforce_equal(circuit, &zeta_fp_elem_var_rec)?;

        // prove L_{i,H}(zeta) * zeta_minus_gi = Z_H(zeta) * v_i
        let eval_i_fp_elem_var = FpElemVar::new_from_field_element(
            circuit,
            &field_switching(&eval_i),
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?;
        let left = circuit.mod_mul(
            &eval_i_fp_elem_var,
            &zeta_minus_gi_elem_var,
            &non_native_field_info.modulus_fp_elem,
        )?;
        let right = circuit.mod_mul_constant(
            vanish_eval_fp_elem_var,
            &v_i_fp_elem,
            &non_native_field_info.modulus_fp_elem,
        )?;
        left.enforce_equal(circuit, &right)?;

        // finish
        lagrange_eval_fp_elem_var.push(eval_i_fp_elem_var);
    }

    // \sum_{i=0..l/2} L_{i,H}(z) * pub_input[i] + \sum_{i=0..l/2} L_{n-i,H}(z)
    // * pub_input[l/2+i]
    let mut res_i_fp_elem_var = Vec::new();
    for i in 0..len {
        let first_term = circuit.mod_mul(
            &lagrange_eval_fp_elem_var[i],
            &pub_inputs_fp_elem_var[i],
            &non_native_field_info.modulus_fp_elem,
        )?;
        let second_term = circuit.mod_mul(
            &lagrange_eval_fp_elem_var[(len << 1) - i - 1],
            &pub_inputs_fp_elem_var[len + i],
            &non_native_field_info.modulus_fp_elem,
        )?;
        res_i_fp_elem_var.push(first_term);
        res_i_fp_elem_var.push(second_term);
    }
    let res = circuit.mod_add_vec(&res_i_fp_elem_var, &non_native_field_info.modulus_fp_elem)?;

    Ok(res)
}

/// Compute the constant term of the linearization polynomial:
/// For each instance j:
///
/// r_plonk_j
///  = PI - L1(x) * alpha^2 - alpha *
///  \prod_i=1..m-1 (w_{j,i} + beta * sigma_{j,i} + gamma)
///  * (w_{j,m} + gamma) * z_j(xw)
///
/// return r_0 = \sum_{j=1..m} alpha^{k_j} * r_plonk_j
/// where m is the number of instances, and k_j is the number of alpha power
/// terms added to the first j-1 instances.
///
/// - input evals: zeta^n, zeta^n-1 and Lagrange evaluated at 1
///
/// Note that this function cannot evaluate plookup verification circuits.
#[allow(clippy::too_many_arguments)]
pub(super) fn compute_lin_poly_constant_term_circuit<E, F>(
    circuit: &mut PlonkCircuit<F>,
    domain_size: usize,
    challenges: &ChallengesFpElemVar<F>,
    verify_keys: &[&VerifyingKeyVar<E>],
    public_inputs: &[&[FpElemVar<F>]],
    batch_proof: &BatchProofVar<F>,
    evals: &[FpElemVar<F>; 3],
    alpha_bases: &[FpElemVar<F>],
    non_native_field_info: NonNativeFieldInfo<F>,
) -> Result<FpElemVar<F>, CircuitError>
where
    E: Pairing<BaseField = F>,
    F: PrimeField,
{
    if verify_keys.len() != batch_proof.len() || verify_keys.len() != public_inputs.len() {
        return Err(ParameterError(format!(
            "the number of verification keys = {}; the number of instances = {}; the number of public inputs = {}",
            verify_keys.len(),
            batch_proof.len(),
            public_inputs.len(),
        )));
    }

    let zeta_fp_elem_var = challenges.zeta;

    let mut alpha_bases_elem_var = alpha_bases.iter();
    let mut r_0_components = Vec::new();

    // making sure the public inputs are the same for all instances
    let pi = public_inputs[0];
    for &pi_i in public_inputs.iter().skip(1) {
        if pi != pi_i {
            return Err(PlonkError::PublicInputsDoNotMatch)?;
        }
    }

    // compute public inputs
    let pi_fp_elem_var = evaluate_pi_poly_circuit::<E, F>(
        circuit,
        domain_size,
        pi,
        &zeta_fp_elem_var,
        &evals[1],
        true,
        non_native_field_info,
    )?;
    let pi_fr = field_switching::<_, E::ScalarField>(&pi_fp_elem_var.witness(circuit)?);

    // L1(x)*alpha_2
    let l1_mul_alpha_2_fp_elem_var = circuit.mod_mul(
        &evals[2],
        &challenges.alphas[1],
        &non_native_field_info.modulus_fp_elem,
    )?;

    let l1_mul_alpha_2_fr =
        field_switching::<_, E::ScalarField>(&l1_mul_alpha_2_fp_elem_var.witness(circuit)?);

    // the big loop to compute r_0[j]
    //
    // For each instance j:
    //
    // r_plonk_j
    //  = PI - L1(x) * alpha^2 - alpha *
    //  \prod_i=1..m-1 (w_{j,i} + beta * sigma_{j,i} + gamma)
    //  * (w_{j,m} + gamma) * z_j(xw)
    //
    // r_0[j] = alpha^{k_j} * r_plonk_j
    // where m is the number of instances, and k_j is the number of alpha power
    // terms added to the first j-1 instances.
    for poly_evals in batch_proof.poly_evals_vec.iter() {
        // =====================================================
        // r_plonk_j
        //  = PI - L1(x) * alpha^2 - alpha *
        //  \prod_i=1..m-1 (w_{j,i} + beta * sigma_{j,i} + gamma)
        //  * (w_{j,m} + gamma) * z_j(xw)
        // =====================================================

        // \prod_i=1..m-1 (w_{j,i} + beta * sigma_{j,i} + gamma)
        let mut prod = FpElemVar::one(
            circuit,
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        );
        for (w_j_i_var, sigma_j_i_var) in poly_evals.wires_evals[..GATE_WIDTH]
            .iter()
            .zip(poly_evals.wire_sigma_evals.iter())
        {
            let beta_sigma_j_i = circuit.mod_mul(
                &challenges.beta,
                sigma_j_i_var,
                &non_native_field_info.modulus_fp_elem,
            )?;
            let sum = circuit.mod_add_vec(
                &[*w_j_i_var, beta_sigma_j_i, challenges.gamma],
                &non_native_field_info.modulus_fp_elem,
            )?;
            prod = circuit.mod_mul(&prod, &sum, &non_native_field_info.modulus_fp_elem)?;
        }

        // tmp = (w_{j,m} + gamma) * z_j(xw)
        let mut tmp = circuit.mod_add(
            &poly_evals.wires_evals[GATE_WIDTH],
            &challenges.gamma,
            &non_native_field_info.modulus_fp_elem,
        )?;
        tmp = circuit.mod_mul(
            &tmp,
            &poly_evals.perm_next_eval,
            &non_native_field_info.modulus_fp_elem,
        )?;

        // tmp = alpha *
        //  \prod_i=1..m-1 (w_{j,i} + beta * sigma_{j,i} + gamma)
        //  * (w_{j,m} + gamma) * z_j(xw)
        tmp = circuit.mod_mul(
            &tmp,
            &challenges.alphas[0],
            &non_native_field_info.modulus_fp_elem,
        )?;
        tmp = circuit.mod_mul(&tmp, &prod, &non_native_field_info.modulus_fp_elem)?;
        let tmp_fr = field_switching::<_, E::ScalarField>(&tmp.witness(circuit)?);

        // r_plonk_j
        let r_plonk_j_fr = pi_fr - l1_mul_alpha_2_fr - tmp_fr;
        let r_plonk_j_fp_elem_var = FpElemVar::new_from_field_element(
            circuit,
            &field_switching(&r_plonk_j_fr),
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?;

        // proving r_plonk_j + L1(x)*alpha_2 + tmp = PI
        let mut left = circuit.mod_add(
            &r_plonk_j_fp_elem_var,
            &l1_mul_alpha_2_fp_elem_var,
            &non_native_field_info.modulus_fp_elem,
        )?;
        left = circuit.mod_add(&left, &tmp, &non_native_field_info.modulus_fp_elem)?;
        left.enforce_equal(circuit, &pi_fp_elem_var)?;

        // preparing data for second statement
        let r_0_component = circuit.mod_mul(
            alpha_bases_elem_var
                .next()
                .ok_or(PlonkError::IteratorOutOfRange)?,
            &r_plonk_j_fp_elem_var,
            &non_native_field_info.modulus_fp_elem,
        )?;

        r_0_components.push(r_0_component);
    }
    // ensure all the buffer has been consumed
    if alpha_bases_elem_var.next().is_some() {
        return Err(PlonkError::IteratorOutOfRange)?;
    }
    // =====================================================
    // second statement
    // r_0 = \sum_{j=1..m} alpha^{k_j} * r_plonk_j
    // =====================================================
    let res_elem_var =
        circuit.mod_add_vec(&r_0_components, &non_native_field_info.modulus_fp_elem)?;

    Ok(res_elem_var)
}

/// Compute the bases and scalars in the batched polynomial commitment,
/// which is a generalization of `[D]1` specified in Sec 8.3, Verifier
/// algorithm step 9 of https://eprint.iacr.org/2019/953.pdf.
///
/// - input evals: zeta^n, zeta^n-1 and Lagrange evaluated at 1
///
/// Do not compute plookup related variables.
pub(super) fn linearization_scalars_and_bases_circuit<E, F>(
    circuit: &mut PlonkCircuit<F>,
    vks: &[&VerifyingKeyVar<E>],
    challenges: &ChallengesFpElemVar<F>,
    poly_evals: &[FpElemVar<F>; 3],
    batch_proof: &BatchProofVar<F>,
    alpha_bases: &[FpElemVar<F>],
    non_native_field_info: NonNativeFieldInfo<F>,
) -> Result<ScalarsAndBasesVar<F>, CircuitError>
where
    E: Pairing<BaseField = F>,
    F: PrimeField,
{
    let beta_times_zeta_fp_elem_var = circuit.mod_mul(
        &challenges.beta,
        &challenges.zeta,
        &non_native_field_info.modulus_fp_elem,
    )?;
    let alpha_times_beta_fp_elem_var = circuit.mod_mul(
        &challenges.alphas[0],
        &challenges.beta,
        &non_native_field_info.modulus_fp_elem,
    )?;

    let alpha_2_mul_l1 = circuit.mod_mul(
        &challenges.alphas[1],
        &poly_evals[2],
        &non_native_field_info.modulus_fp_elem,
    )?;

    let mut alpha_bases_elem_var = alpha_bases.iter();

    let mut scalars_and_bases = ScalarsAndBasesVar::new();
    for (i, vk) in vks.iter().enumerate() {
        // ============================================
        // Compute coefficient for the permutation product polynomial commitment.
        // coeff = [z]_1 *
        //       ( L1(zeta) * alpha^2
        //          + alpha
        //              * (beta * zeta      + a_bar + gamma)    <- computed via the loop
        //              * (beta * k1 * zeta + b_bar + gamma)    <- computed via the loop
        //              * (beta * k2 * zeta + c_bar + gamma)    <- computed via the loop
        //       )
        // where a_bar, b_bar and c_bar are in w_evals
        // ============================================

        let current_alpha_bases = alpha_bases_elem_var
            .next()
            .ok_or(PlonkError::IteratorOutOfRange)?;

        let mut coeff_fp_elem_var = alpha_2_mul_l1;
        let w_evals = &batch_proof.poly_evals_vec[i].wires_evals;
        let mut prod = challenges.alphas[0];
        for (&x_bar, k_i) in w_evals.iter().zip(vk.k.iter()) {
            let beta_k_zeta_fp_elem_var = circuit.mod_mul_constant(
                &beta_times_zeta_fp_elem_var,
                &FpElem::new(
                    &field_switching::<_, F>(k_i),
                    non_native_field_info.m,
                    non_native_field_info.two_power_m,
                )?,
                &non_native_field_info.modulus_fp_elem,
            )?;

            let sum = circuit.mod_add_vec(
                &[beta_k_zeta_fp_elem_var, x_bar, challenges.gamma],
                &non_native_field_info.modulus_fp_elem,
            )?;
            prod = circuit.mod_mul(&prod, &sum, &non_native_field_info.modulus_fp_elem)?;
        }
        coeff_fp_elem_var = circuit.mod_add(
            &coeff_fp_elem_var,
            &prod,
            &non_native_field_info.modulus_fp_elem,
        )?;
        // multiply the final results with alpha_base
        coeff_fp_elem_var = circuit.mod_mul(
            &coeff_fp_elem_var,
            current_alpha_bases,
            &non_native_field_info.modulus_fp_elem,
        )?;
        // Add permutation product polynomial commitment.
        scalars_and_bases.scalars.push(coeff_fp_elem_var);
        scalars_and_bases
            .bases
            .push(batch_proof.prod_perm_poly_comms_vec[i]);

        // ============================================
        // Compute coefficient for the last wire sigma polynomial commitment.
        // coeff = alpha * beta * z_w * [s_sigma_3]_1
        //       * (a_bar + gamma + beta * s_bar_sigma_1)
        //       * (b_bar + gamma + beta * s_bar_sigma_2)
        // ============================================
        let num_wire_types = batch_proof.wires_poly_comms_vec[i].len();
        let sigma_evals = &batch_proof.poly_evals_vec[i].wire_sigma_evals;
        let mut coeff_fp_elem_var = circuit.mod_mul(
            &alpha_times_beta_fp_elem_var,
            &batch_proof.poly_evals_vec[i].perm_next_eval,
            &non_native_field_info.modulus_fp_elem,
        )?;

        for (&x_bar, sigma_i) in w_evals
            .iter()
            .take(num_wire_types - 1)
            .zip(sigma_evals.iter())
        {
            let beta_times_s_bar_sigma_1 = circuit.mod_mul(
                &challenges.beta,
                sigma_i,
                &non_native_field_info.modulus_fp_elem,
            )?;
            let sum = circuit.mod_add_vec(
                &[x_bar, challenges.gamma, beta_times_s_bar_sigma_1],
                &non_native_field_info.modulus_fp_elem,
            )?;

            coeff_fp_elem_var = circuit.mod_mul(
                &coeff_fp_elem_var,
                &sum,
                &non_native_field_info.modulus_fp_elem,
            )?;
        }

        // multiply the final results with alpha_base
        coeff_fp_elem_var = circuit.mod_mul(
            &coeff_fp_elem_var,
            current_alpha_bases,
            &non_native_field_info.modulus_fp_elem,
        )?;

        // Add output wire sigma polynomial commitment.
        scalars_and_bases.scalars.push(coeff_fp_elem_var);
        let tmp = circuit.inverse_point(vk.sigma_comms.last().ok_or(CircuitError::IndexError)?)?;

        scalars_and_bases.bases.push(tmp);

        // ============================================
        // Add selector polynomial commitments.
        // Compute coefficients for selector polynomial commitments.
        // The order: q_lc, q_mul, q_hash, q_o, q_c, q_ecc
        // ============================================
        // q_scalars[0..3]
        let mut q_scalars_fp_elem_vars = vec![w_evals[0], w_evals[1], w_evals[2], w_evals[3]];
        // q_scalars[4] = w_evals[0] * w_evals[1];
        q_scalars_fp_elem_vars.push(circuit.mod_mul(
            &w_evals[0],
            &w_evals[1],
            &non_native_field_info.modulus_fp_elem,
        )?);
        // q_scalars[5] = w_evals[2] * w_evals[3];
        q_scalars_fp_elem_vars.push(circuit.mod_mul(
            &w_evals[2],
            &w_evals[3],
            &non_native_field_info.modulus_fp_elem,
        )?);
        // q_scalars[6] = w_evals[0].pow([5]);
        q_scalars_fp_elem_vars.push(circuit.non_native_power_5_gen::<E::ScalarField>(&w_evals[0])?);
        // q_scalars[7] = w_evals[1].pow([5]);
        q_scalars_fp_elem_vars.push(circuit.non_native_power_5_gen::<E::ScalarField>(&w_evals[1])?);
        // q_scalars[8] = w_evals[2].pow([5]);
        q_scalars_fp_elem_vars.push(circuit.non_native_power_5_gen::<E::ScalarField>(&w_evals[2])?);
        // q_scalars[9] = w_evals[3].pow([5]);
        q_scalars_fp_elem_vars.push(circuit.non_native_power_5_gen::<E::ScalarField>(&w_evals[3])?);
        // q_scalars[10] = -w_evals[4];
        // note that we push w_eval to the buffer, so we will need to inverse the basis
        q_scalars_fp_elem_vars.push(w_evals[4]);
        // q_scalars[11] = E::ScalarField::one();
        // TODO(optimization): public wire?
        q_scalars_fp_elem_vars.push(FpElemVar::one(
            circuit,
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        ));
        // q_scalars[12]
        // = w_evals[0] * w_evals[1] * w_evals[2] * w_evals[3] * w_evals[4];
        let mut tmp = circuit.mod_mul(
            &w_evals[0],
            &w_evals[1],
            &non_native_field_info.modulus_fp_elem,
        )?;
        tmp = circuit.mod_mul(&tmp, &w_evals[2], &non_native_field_info.modulus_fp_elem)?;
        tmp = circuit.mod_mul(&tmp, &w_evals[3], &non_native_field_info.modulus_fp_elem)?;
        tmp = circuit.mod_mul(&tmp, &w_evals[4], &non_native_field_info.modulus_fp_elem)?;
        q_scalars_fp_elem_vars.push(tmp);

        for (i, (s, &poly)) in q_scalars_fp_elem_vars
            .iter()
            .zip(vk.selector_comms.iter())
            .enumerate()
        {
            // inverse the bases for w_eval[10]
            let bases = if i == 10 {
                circuit.inverse_point(&poly)?
            } else {
                poly
            };

            let tmp = circuit.mod_mul(
                s,
                current_alpha_bases,
                &non_native_field_info.modulus_fp_elem,
            )?;
            scalars_and_bases.scalars.push(tmp);
            scalars_and_bases.bases.push(bases);
        }
    }

    // ensure all the buffer has been consumed
    if alpha_bases_elem_var.next().is_some() {
        return Err(PlonkError::IteratorOutOfRange)?;
    }
    // ============================================
    // Add splitted quotient commitments
    // ============================================
    let zeta_square_fp_elem_var = circuit.mod_mul(
        &challenges.zeta,
        &challenges.zeta,
        &non_native_field_info.modulus_fp_elem,
    )?;
    let zeta_to_n_plus_2 = circuit.mod_mul(
        &zeta_square_fp_elem_var,
        &poly_evals[0],
        &non_native_field_info.modulus_fp_elem,
    )?;

    let mut coeff = poly_evals[1];
    let tmp = circuit.inverse_point(
        batch_proof
            .split_quot_poly_comms
            .first()
            .ok_or(CircuitError::IndexError)?,
    )?;
    scalars_and_bases.scalars.push(poly_evals[1]);
    scalars_and_bases.bases.push(tmp);

    for &poly in batch_proof.split_quot_poly_comms.iter().skip(1) {
        coeff = circuit.mod_mul(
            &coeff,
            &zeta_to_n_plus_2,
            &non_native_field_info.modulus_fp_elem,
        )?;
        let poly = circuit.inverse_point(&poly)?;
        scalars_and_bases.scalars.push(coeff);
        scalars_and_bases.bases.push(poly);
    }

    Ok(scalars_and_bases)
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::Bls12_377;
    use ark_ff::Field;
    use ark_poly::Radix2EvaluationDomain;
    use ark_std::{One, UniformRand};
    use jf_relation::Circuit;
    use jf_utils::{field_switching, test_rng};

    const RANGE_BIT_LEN_FOR_TEST: usize = 16;

    #[test]
    fn test_evaluate_poly() {
        test_evaluate_poly_helper::<Bls12_377>();
    }

    fn test_evaluate_poly_helper<E: Pairing>() {
        let mut rng = test_rng();

        let mut circuit = PlonkCircuit::<E::BaseField>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        let zeta = E::ScalarField::rand(&mut rng);
        let zeta_var = circuit.create_variable(field_switching(&zeta)).unwrap();

        for domain_size in [64, 128, 256, 512, 1024] {
            // compute the result in the clear
            let domain = Radix2EvaluationDomain::<E::ScalarField>::new(domain_size).unwrap();
            let vanish_eval = domain.evaluate_vanishing_polynomial(zeta);
            let zeta_n = vanish_eval + E::ScalarField::one();
            let divisor = E::ScalarField::from(domain_size as u32) * (zeta - E::ScalarField::one());
            let lagrange_1_eval = vanish_eval / divisor;

            // compute the variables
            let m = 128;
            // constants
            let two_power_m = Some(E::BaseField::from(2u8).pow([m as u64]));

            let fr_modulus_bits = <E::ScalarField as PrimeField>::MODULUS.to_bytes_le();
            let modulus_in_f = E::BaseField::from_le_bytes_mod_order(&fr_modulus_bits);
            let modulus_fp_elem = FpElem::new(&modulus_in_f, m, two_power_m).unwrap();

            let non_native_field_info = NonNativeFieldInfo::<E::BaseField> {
                m,
                two_power_m,
                modulus_in_f,
                modulus_fp_elem,
            };

            let zeta_fp_elem_var =
                FpElemVar::new_unchecked(&mut circuit, zeta_var, m, None).unwrap();
            let eval_results = evaluate_poly_helper::<E, _>(
                &mut circuit,
                &zeta_fp_elem_var,
                domain_size,
                non_native_field_info,
            )
            .unwrap();

            // check the correctness
            let tmp = eval_results[0].convert_to_var(&mut circuit).unwrap();
            assert_eq!(
                field_switching::<_, E::BaseField>(&zeta_n),
                circuit.witness(tmp).unwrap(),
            );

            let tmp = eval_results[1].convert_to_var(&mut circuit).unwrap();
            assert_eq!(
                field_switching::<_, E::BaseField>(&vanish_eval),
                circuit.witness(tmp).unwrap(),
            );

            let tmp = eval_results[2].convert_to_var(&mut circuit).unwrap();
            assert_eq!(
                field_switching::<_, E::BaseField>(&lagrange_1_eval),
                circuit.witness(tmp).unwrap(),
            );
        }
    }
}
