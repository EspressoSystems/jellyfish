// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuits for the polynomial evaluations within Plonk verifiers.

use super::{
    BatchProofVar, ChallengesFpElemVar, NonNativeFieldInfo, ScalarsAndBasesVar, VerifyingKeyVar,
};
use crate::errors::PlonkError;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{format, string::ToString, vec, vec::Vec, One};
use jf_relation::{
    constants::GATE_WIDTH,
    gadgets::ultraplonk::mod_arith::{FpElem, FpElemVar},
    CircuitError,
    CircuitError::ParameterError,
    PlonkCircuit,
};
use jf_utils::field_switching;

/// Helper to evaluate polynomial variables for vanishing polynomial, zeta^n, and Lagrange polynomials.
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
    // Precompute domain size as a non-native field element.
    let domain_size_fp_elem = FpElem::new(
        &F::from(domain_size as u64),
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;

    // Compute zeta^n using repeated squaring.
    let zeta_n_fp_elem_var = compute_zeta_n(
        circuit,
        zeta_fp_elem_var,
        domain_size,
        &non_native_field_info,
    )?;

    // Compute zeta^n - 1.
    let zeta_n_minus_one_fp_elem_var = compute_zeta_n_minus_one(
        circuit,
        &zeta_n_fp_elem_var,
        &non_native_field_info,
    )?;

    // Evaluate Lagrange polynomial at 1.
    let lagrange_1_eval_fp_elem_var = compute_lagrange_at_1(
        circuit,
        zeta_fp_elem_var,
        &zeta_n_minus_one_fp_elem_var,
        domain_size_fp_elem,
        &non_native_field_info,
    )?;

    Ok([
        zeta_n_fp_elem_var,
        zeta_n_minus_one_fp_elem_var,
        lagrange_1_eval_fp_elem_var,
    ])
}

/// Computes `zeta^n` using repeated squaring.
fn compute_zeta_n<F>(
    circuit: &mut PlonkCircuit<F>,
    zeta_fp_elem_var: &FpElemVar<F>,
    domain_size: usize,
    non_native_field_info: &NonNativeFieldInfo<F>,
) -> Result<FpElemVar<F>, CircuitError>
where
    F: PrimeField,
{
    let mut zeta_n_fp_elem_var = *zeta_fp_elem_var;
    let mut ctr = 1;
    while ctr < domain_size {
        ctr <<= 1;
        zeta_n_fp_elem_var = circuit.mod_mul(
            &zeta_n_fp_elem_var,
            &zeta_n_fp_elem_var,
            &non_native_field_info.modulus_fp_elem,
        )?;
    }
    Ok(zeta_n_fp_elem_var)
}

/// Computes `zeta^n - 1` in a non-native circuit.
fn compute_zeta_n_minus_one<F>(
    circuit: &mut PlonkCircuit<F>,
    zeta_n_fp_elem_var: &FpElemVar<F>,
    non_native_field_info: &NonNativeFieldInfo<F>,
) -> Result<FpElemVar<F>, CircuitError>
where
    F: PrimeField,
{
    let one_fp_elem = FpElem::new(
        &F::one(),
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;
    circuit.mod_sub(
        zeta_n_fp_elem_var,
        &one_fp_elem,
        &non_native_field_info.modulus_fp_elem,
    )
}

/// Computes Lagrange evaluation at 1 (`lagrange_1_eval = (zeta^n - 1) / ((zeta - 1) * domain_size)`).
fn compute_lagrange_at_1<F>(
    circuit: &mut PlonkCircuit<F>,
    zeta_fp_elem_var: &FpElemVar<F>,
    zeta_n_minus_one_fp_elem_var: &FpElemVar<F>,
    domain_size_fp_elem: FpElem<F>,
    non_native_field_info: &NonNativeFieldInfo<F>,
) -> Result<FpElemVar<F>, CircuitError>
where
    F: PrimeField,
{
    let one_fp_elem = FpElem::new(
        &F::one(),
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;

    // Compute `zeta - 1`
    let zeta_minus_one_fp_elem_var = circuit.mod_sub(
        zeta_fp_elem_var,
        &one_fp_elem,
        &non_native_field_info.modulus_fp_elem,
    )?;

    // Compute numerator: `zeta^n - 1`
    let numerator = zeta_n_minus_one_fp_elem_var;

    // Compute denominator: `(zeta - 1) * domain_size`
    let denominator = circuit.mod_mul(
        &zeta_minus_one_fp_elem_var,
        &domain_size_fp_elem,
        &non_native_field_info.modulus_fp_elem,
    )?;

    // Divide numerator by denominator in the non-native field
    circuit.mod_div(
        numerator,
        &denominator,
        &non_native_field_info.modulus_fp_elem,
    )
}

/// Computes the public input polynomial evaluation at `z`.
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
    if !circuit_is_merged {
        return Err(ParameterError("Circuit should already be merged.".to_string()));
    }

    // Compute domain properties
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(domain_size).unwrap();
    let v_i = precompute_v_i(domain, domain_size);

    // Compute Lagrange evaluations at zeta for all relevant indices
    let lagrange_eval_fp_elem_vars = compute_lagrange_evaluations(
        circuit,
        &v_i,
        domain_size,
        zeta_fp_elem_var,
        vanish_eval_fp_elem_var,
        &non_native_field_info,
    )?;

    // Compute the final public input polynomial evaluation
    combine_lagrange_evaluations(
        circuit,
        lagrange_eval_fp_elem_vars,
        pub_inputs_fp_elem_var,
        &non_native_field_info,
    )
}

/// Precomputes `v_i = g^i / n` for all elements in the domain.
fn precompute_v_i<E: Pairing>(
    domain: Radix2EvaluationDomain<E::ScalarField>,
    domain_size: usize,
) -> Vec<E::ScalarField> {
    (0..domain_size)
        .map(|i| domain.element(i) / E::ScalarField::from(domain_size as u64))
        .collect()
}

/// Computes Lagrange evaluations at `zeta` for all relevant indices.
fn compute_lagrange_evaluations<F>(
    circuit: &mut PlonkCircuit<F>,
    v_i: &[F],
    domain_size: usize,
    zeta_fp_elem_var: &FpElemVar<F>,
    vanish_eval_fp_elem_var: &FpElemVar<F>,
    non_native_field_info: &NonNativeFieldInfo<F>,
) -> Result<Vec<FpElemVar<F>>, CircuitError>
where
    F: PrimeField,
{
    let mut evaluations = Vec::new();
    for i in 0..domain_size {
        let g_i = v_i[i];

        // Compute `zeta - g^i`
        let zeta_minus_g_i = circuit.mod_sub(
            zeta_fp_elem_var,
            &FpElem::new(&g_i, non_native_field_info.m, non_native_field_info.two_power_m)?,
            &non_native_field_info.modulus_fp_elem,
        )?;

        // Compute `L_{i,H}(zeta) = Z_H(zeta) * v_i / (zeta - g^i)`
        let lagrange_eval = circuit.mod_div(
            vanish_eval_fp_elem_var,
            &zeta_minus_g_i,
            &non_native_field_info.modulus_fp_elem,
        )?;
        evaluations.push(lagrange_eval);
    }
    Ok(evaluations)
}

/// Combines Lagrange evaluations with public inputs to compute the public input polynomial evaluation.
fn combine_lagrange_evaluations<F>(
    circuit: &mut PlonkCircuit<F>,
    lagrange_eval_fp_elem_vars: Vec<FpElemVar<F>>,
    pub_inputs_fp_elem_var: &[FpElemVar<F>],
    non_native_field_info: &NonNativeFieldInfo<F>,
) -> Result<FpElemVar<F>, CircuitError>
where
    F: PrimeField,
{
    let mut results = Vec::new();
    for (lagrange_eval, pub_input) in lagrange_eval_fp_elem_vars
        .iter()
        .zip(pub_inputs_fp_elem_var.iter())
    {
        let term = circuit.mod_mul(
            lagrange_eval,
            pub_input,
            &non_native_field_info.modulus_fp_elem,
        )?;
        results.push(term);
    }
    circuit.mod_add_vec(&results, &non_native_field_info.modulus_fp_elem)
}
