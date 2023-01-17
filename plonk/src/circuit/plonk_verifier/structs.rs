// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use ark_ff::PrimeField;
use ark_std::vec::Vec;
use jf_relation::{
    errors::CircuitError,
    gadgets::{
        ecc::PointVariable,
        ultraplonk::mod_arith::{FpElem, FpElemVar},
    },
    PlonkCircuit, Variable,
};

/// Plonk IOP verifier challenges.
#[derive(Debug, Default)]
pub(crate) struct ChallengesVar {
    pub(crate) tau: Variable,
    pub(crate) alpha: Variable,
    pub(crate) beta: Variable,
    pub(crate) gamma: Variable,
    pub(crate) zeta: Variable,
    pub(crate) v: Variable,
    pub(crate) u: Variable,
}

/// Plonk IOP verifier challenges.
#[derive(Debug, Default)]
pub(crate) struct ChallengesFpElemVar<F: PrimeField> {
    pub(crate) _tau: FpElemVar<F>,
    pub(crate) alphas: [FpElemVar<F>; 3],
    pub(crate) beta: FpElemVar<F>,
    pub(crate) gamma: FpElemVar<F>,
    pub(crate) zeta: FpElemVar<F>,
    pub(crate) v: FpElemVar<F>,
    pub(crate) u: FpElemVar<F>,
}

pub(crate) fn challenge_var_to_fp_elem_var<F: PrimeField>(
    circuit: &mut PlonkCircuit<F>,
    challenge_var: &ChallengesVar,
    non_native_field_info: &NonNativeFieldInfo<F>,
) -> Result<ChallengesFpElemVar<F>, CircuitError> {
    let alpha_fp_elem_var = FpElemVar::new_unchecked(
        circuit,
        challenge_var.alpha,
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;
    let alpha_2_fp_elem_var = circuit.mod_mul(
        &alpha_fp_elem_var,
        &alpha_fp_elem_var,
        &non_native_field_info.modulus_fp_elem,
    )?;
    let alpha_3_fp_elem_var = circuit.mod_mul(
        &alpha_2_fp_elem_var,
        &alpha_fp_elem_var,
        &non_native_field_info.modulus_fp_elem,
    )?;

    Ok(ChallengesFpElemVar {
        _tau: FpElemVar::new_unchecked(
            circuit,
            challenge_var.tau,
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?,
        alphas: [alpha_fp_elem_var, alpha_2_fp_elem_var, alpha_3_fp_elem_var],
        beta: FpElemVar::new_unchecked(
            circuit,
            challenge_var.beta,
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?,
        gamma: FpElemVar::new_unchecked(
            circuit,
            challenge_var.gamma,
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?,
        zeta: FpElemVar::new_unchecked(
            circuit,
            challenge_var.zeta,
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?,
        u: FpElemVar::new_unchecked(
            circuit,
            challenge_var.u,
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?,
        v: FpElemVar::new_unchecked(
            circuit,
            challenge_var.v,
            non_native_field_info.m,
            non_native_field_info.two_power_m,
        )?,
    })
}

/// The vector representation of bases and corresponding scalars.
#[derive(Debug)]
pub(crate) struct ScalarsAndBasesVar<F: PrimeField> {
    pub(crate) scalars: Vec<FpElemVar<F>>,
    pub(crate) bases: Vec<PointVariable>,
}

impl<F: PrimeField> ScalarsAndBasesVar<F> {
    pub(crate) fn new() -> Self {
        Self {
            scalars: Vec::new(),
            bases: Vec::new(),
        }
    }
}

/// (Aggregated) polynomial commitment evaluation info.
/// * `u` - a random combiner that was used to combine evaluations at point
///   `eval_point` and `next_eval_point`.
/// * `eval_point` - the point to be evaluated at.
/// * `next_eval_point` - the shifted point to be evaluated at.
/// * `eval` - the (aggregated) polynomial evaluation value.
/// * `comm_scalars_and_bases` - the scalars-and-bases form of the (aggregated)
///   polynomial commitment.
/// * `opening_proof` - (aggregated) proof of evaluations at point `eval_point`.
/// * `shifted_opening_proof` - (aggregated) proof of evaluations at point
///   `next_eval_point`.
#[derive(Debug)]
pub(crate) struct PcsInfoVar<F: PrimeField> {
    pub(crate) u: FpElemVar<F>,
    pub(crate) eval_point: FpElemVar<F>,
    pub(crate) next_eval_point: FpElemVar<F>,
    pub(crate) eval: FpElemVar<F>,
    pub(crate) comm_scalars_and_bases: ScalarsAndBasesVar<F>,
    pub(crate) opening_proof: PointVariable,
    pub(crate) shifted_opening_proof: PointVariable,
}

#[derive(Debug, Clone, Eq, PartialEq)]
/// Represent variables of an aggregated SNARK proof that batchly proving
/// multiple instances.
pub struct BatchProofVar<F: PrimeField> {
    /// The list of wire witness polynomials commitments.
    pub(crate) wires_poly_comms_vec: Vec<Vec<PointVariable>>,

    /// The list of polynomial commitment for the wire permutation argument.
    pub(crate) prod_perm_poly_comms_vec: Vec<PointVariable>,

    /// The list of polynomial evaluations.
    pub(crate) poly_evals_vec: Vec<ProofEvaluationsVar<F>>,

    // /// The list of partial proofs for Plookup argument
    // not used for plonk verification circuit
    // pub(crate) plookup_proofs_vec: Vec<Option<PlookupProofVar>>,
    /// Splitted quotient polynomial commitments.
    pub(crate) split_quot_poly_comms: Vec<PointVariable>,

    /// (Aggregated) proof of evaluations at challenge point `zeta`.
    pub(crate) opening_proof: PointVariable,

    /// (Aggregated) proof of evaluation at challenge point `zeta * g` where `g`
    /// is the root of unity.
    pub(crate) shifted_opening_proof: PointVariable,
}

impl<F: PrimeField> BatchProofVar<F> {
    /// The number of instances being proved in a batch proof.
    pub(crate) fn len(&self) -> usize {
        self.prod_perm_poly_comms_vec.len()
    }
}

/// Represent variables for a struct that stores the polynomial evaluations in a
/// Plonk proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProofEvaluationsVar<F: PrimeField> {
    /// Wire witness polynomials evaluations at point `zeta`.
    pub(crate) wires_evals: Vec<FpElemVar<F>>,

    /// Extended permutation (sigma) polynomials evaluations at point `zeta`.
    /// We do not include the last sigma polynomial evaluation.
    pub(crate) wire_sigma_evals: Vec<FpElemVar<F>>,

    /// Permutation product polynomial evaluation at point `zeta * g`.
    pub(crate) perm_next_eval: FpElemVar<F>,
}

/// Information related to non-native field
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) struct NonNativeFieldInfo<F: PrimeField> {
    pub(crate) m: usize,
    pub(crate) two_power_m: Option<F>,
    pub(crate) modulus_in_f: F,
    pub(crate) modulus_fp_elem: FpElem<F>,
}
