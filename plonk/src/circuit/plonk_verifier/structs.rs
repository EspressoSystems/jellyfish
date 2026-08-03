// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use ark_ff::PrimeField;
use ark_std::vec::Vec;
use jf_relation::{
    gadgets::{
        ecc::PointVariable,
        ultraplonk::mod_arith::{FpElem, FpElemVar},
    },
    CircuitError, PlonkCircuit, Variable,
};

/// Plonk IOP verifier challenges.
#[derive(Debug, Default)]
pub(crate) struct ChallengesVar {
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
    pub(crate) alphas: [FpElemVar<F>; 3],
    pub(crate) beta: FpElemVar<F>,
    pub(crate) gamma: FpElemVar<F>,
    pub(crate) zeta: FpElemVar<F>,
    pub(crate) v: FpElemVar<F>,
    pub(crate) u: FpElemVar<F>,
}

/// Split a challenge variable into limbs, enforcing that each limb is in
/// `[0, 2^m)`.
///
/// `FpElemVar::new_unchecked` only binds the limbs to the challenge with the
/// single linear constraint `limb_0 + 2^m * limb_1 = challenge`, which a prover
/// can also satisfy with non-canonical limbs. Since the challenges are consumed
/// by `mod_mul`, which reads the limbs back as integers, non-canonical limbs
/// make the emulated arithmetic wrap the native modulus and produce a wrong
/// residue modulo the emulated one. The transcript range-checks only the
/// squeezed challenge, never its decomposition, so the range checks have to
/// happen here.
///
/// Once `jf-relation` is released with `FpElemVar::new_checked`, this helper
/// can be replaced by a call to it.
fn challenge_var_to_range_checked_limbs<F: PrimeField>(
    circuit: &mut PlonkCircuit<F>,
    challenge_var: Variable,
    non_native_field_info: &NonNativeFieldInfo<F>,
) -> Result<FpElemVar<F>, CircuitError> {
    let elem = FpElemVar::new_unchecked(
        circuit,
        challenge_var,
        non_native_field_info.m,
        non_native_field_info.two_power_m,
    )?;
    let (limb_0, limb_1) = elem.components();
    circuit.enforce_in_range(limb_0, non_native_field_info.m)?;
    circuit.enforce_in_range(limb_1, non_native_field_info.m)?;
    Ok(elem)
}

pub(crate) fn challenge_var_to_fp_elem_var<F: PrimeField>(
    circuit: &mut PlonkCircuit<F>,
    challenge_var: &ChallengesVar,
    non_native_field_info: &NonNativeFieldInfo<F>,
) -> Result<ChallengesFpElemVar<F>, CircuitError> {
    let alpha_fp_elem_var =
        challenge_var_to_range_checked_limbs(circuit, challenge_var.alpha, non_native_field_info)?;
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
        alphas: [alpha_fp_elem_var, alpha_2_fp_elem_var, alpha_3_fp_elem_var],
        beta: challenge_var_to_range_checked_limbs(
            circuit,
            challenge_var.beta,
            non_native_field_info,
        )?,
        gamma: challenge_var_to_range_checked_limbs(
            circuit,
            challenge_var.gamma,
            non_native_field_info,
        )?,
        zeta: challenge_var_to_range_checked_limbs(
            circuit,
            challenge_var.zeta,
            non_native_field_info,
        )?,
        u: challenge_var_to_range_checked_limbs(circuit, challenge_var.u, non_native_field_info)?,
        v: challenge_var_to_range_checked_limbs(circuit, challenge_var.v, non_native_field_info)?,
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
    /// Split quotient polynomial commitments.
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

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::{Fq as Fq377, Fr as Fr377};
    use ark_ff::{BigInteger, Field};
    use ark_std::One;
    use jf_relation::Circuit;

    const RANGE_BIT_LEN_FOR_TEST: usize = 16;

    // Regression test: the limb decomposition of every Fiat-Shamir challenge
    // must be range-checked.
    //
    // `FpElemVar::new_unchecked` binds the limbs to the challenge with a single
    // linear constraint, `vars.0 + 2^m * vars.1 = challenge`, which a prover can
    // satisfy with non-canonical limbs by shifting one down by `2^m` and the
    // other up by 1. The challenges are then consumed by `mod_mul`, which reads
    // the limbs as integers -- so an aliased challenge wraps the native modulus
    // and multiplies by a wrong residue modulo the emulated one, breaking the
    // soundness of the in-circuit verifier. The transcript range-checks only the
    // squeezed challenge (< 2^248), never its decomposition.
    #[test]
    fn test_challenge_limbs_are_range_checked() -> Result<(), CircuitError> {
        let m = 128;
        let two_power_m = Fq377::from(2u8).pow([m as u64]);
        let modulus_in_f =
            Fq377::from_le_bytes_mod_order(&<Fr377 as PrimeField>::MODULUS.to_bytes_le());
        let non_native_field_info = NonNativeFieldInfo::<Fq377> {
            m,
            two_power_m: Some(two_power_m),
            modulus_in_f,
            modulus_fp_elem: FpElem::new(&modulus_in_f, m, Some(two_power_m))?,
        };

        let mut circuit = PlonkCircuit::<Fq377>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        let challenge_var = ChallengesVar {
            alpha: circuit.create_variable(Fq377::from(7u8))?,
            beta: circuit.create_variable(Fq377::from(11u8))?,
            gamma: circuit.create_variable(Fq377::from(13u8))?,
            zeta: circuit.create_variable(Fq377::from(17u8))?,
            v: circuit.create_variable(Fq377::from(19u8))?,
            u: circuit.create_variable(Fq377::from(23u8))?,
        };
        let challenges_fp_elem_var =
            challenge_var_to_fp_elem_var(&mut circuit, &challenge_var, &non_native_field_info)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // `beta` is not consumed inside `challenge_var_to_fp_elem_var`, so the
        // limb range checks are the only thing that can reject the alias.
        let (beta_0, beta_1) = challenges_fp_elem_var.beta.components();
        *circuit.witness_mut(beta_0) -= two_power_m;
        *circuit.witness_mut(beta_1) += Fq377::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }
}
