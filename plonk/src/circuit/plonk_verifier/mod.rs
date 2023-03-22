// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuits for Plonk verifiers.
use crate::proof_system::{structs::VerifyingKey, verifier::Verifier};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig as SWParam},
    twisted_edwards::TECurveConfig as TEParam,
};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{format, string::ToString, vec, vec::Vec};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{
    errors::{CircuitError, CircuitError::ParameterError},
    gadgets::{
        ecc::{MultiScalarMultiplicationCircuit, Point, PointVariable, SWToTEConParam},
        ultraplonk::mod_arith::{FpElem, FpElemVar},
    },
    Circuit, PlonkCircuit, Variable,
};

mod gadgets;
mod poly;
mod structs;

use gadgets::*;
pub use structs::*;

#[derive(Debug, Clone, Eq, PartialEq)]
/// Represent variable of a Plonk verifying key.
pub struct VerifyingKeyVar<E: Pairing> {
    /// The variables for the permutation polynomial commitments.
    pub(crate) sigma_comms: Vec<PointVariable>,
    /// The variables for the selector polynomial commitments.
    pub(crate) selector_comms: Vec<PointVariable>,
    /// A flag indicating whether the key is a merged key.
    is_merged: bool,

    /// The size of the evaluation domain. Should be a power of two.
    domain_size: usize,

    /// The number of public inputs.
    num_inputs: usize,

    /// The constants K0, ..., K_num_wire_types that ensure wire subsets are
    /// disjoint.
    k: Vec<E::ScalarField>,
}

impl<E: Pairing> VerifyingKeyVar<E> {
    /// Create a variable for a Plonk verifying key.
    pub fn new<F, P>(
        circuit: &mut PlonkCircuit<F>,
        verify_key: &VerifyingKey<E>,
    ) -> Result<Self, CircuitError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: PrimeField + SWToTEConParam,
        P: SWParam<BaseField = F>,
    {
        let sigma_comms = verify_key
            .sigma_comms
            .iter()
            .map(|comm| circuit.create_point_variable(Point::from(&comm.0)))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let selector_comms = verify_key
            .selector_comms
            .iter()
            .map(|comm| circuit.create_point_variable(Point::from(&comm.0)))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        Ok(Self {
            sigma_comms,
            selector_comms,
            is_merged: verify_key.is_merged,
            domain_size: verify_key.domain_size,
            num_inputs: verify_key.num_inputs,
            k: verify_key.k.clone(),
        })
    }

    /// Convert to a list of variables.
    pub fn to_vec(&self) -> Vec<Variable> {
        let mut res = vec![];
        for sigma_comm in self.sigma_comms.iter() {
            res.push(sigma_comm.get_x());
            res.push(sigma_comm.get_y());
        }
        for selector_comm in self.selector_comms.iter() {
            res.push(selector_comm.get_x());
            res.push(selector_comm.get_y());
        }
        res
    }

    /// Merge with another Plonk verifying key variable.
    pub(crate) fn merge<F, P>(
        &self,
        circuit: &mut PlonkCircuit<F>,
        other: &Self,
    ) -> Result<Self, CircuitError>
    where
        F: PrimeField,
        P: TEParam<BaseField = F>,
    {
        if self.is_merged || other.is_merged {
            return Err(ParameterError(
                "cannot merge a merged key again".to_string(),
            ));
        }
        if self.domain_size != other.domain_size {
            return Err(ParameterError(
                "cannot merge a verifying key with different domain size".to_string(),
            ));
        }
        if self.num_inputs != other.num_inputs {
            return Err(ParameterError(
                "cannot merge a verifying key with different public input length".to_string(),
            ));
        }
        let sigma_comms = self
            .sigma_comms
            .iter()
            .zip(other.sigma_comms.iter())
            .map(|(com1, com2)| circuit.ecc_add::<P>(com1, com2))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let selector_comms = self
            .selector_comms
            .iter()
            .zip(other.selector_comms.iter())
            .map(|(com1, com2)| circuit.ecc_add::<P>(com1, com2))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        Ok(Self {
            sigma_comms,
            selector_comms,
            is_merged: true,
            domain_size: self.domain_size,
            num_inputs: self.num_inputs + other.num_inputs,
            k: self.k.clone(),
        })
    }

    /// Circuit for partially verifying a batched proof without performing the
    /// pairing. Return the variables for the two group elements used in the
    /// final pairing.
    /// The public inputs are already in the form of FpElemVars.
    pub fn partial_verify_circuit<F, P>(
        circuit: &mut PlonkCircuit<F>,
        beta_g: &Point<F>,
        generator_g: &Point<F>,
        merged_vks: &[Self],
        shared_public_input_vars: &[FpElemVar<F>],
        batch_proof: &BatchProofVar<F>,
        blinding_factor: Variable,
    ) -> Result<(PointVariable, PointVariable), CircuitError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWParam<BaseField = F> + TEParam,
    {
        if merged_vks.is_empty() {
            return Err(ParameterError("empty merged verification keys".to_string()));
        }
        if merged_vks.len() != batch_proof.len() {
            return Err(ParameterError(format!(
                "the number of verification keys {} is different from the number of instances {}.",
                merged_vks.len(),
                batch_proof.len()
            )));
        }

        let domain_size = merged_vks[0].domain_size;
        for (i, vk) in merged_vks.iter().skip(1).enumerate() {
            if vk.domain_size != domain_size {
                return Err(ParameterError(format!(
                    "the {}-th verification key's domain size {} is different from {}.",
                    i, vk.domain_size, domain_size
                )));
            }
        }

        let range_bit_len = circuit.range_bit_len()?;
        let m2 = (<E::ScalarField as PrimeField>::MODULUS_BIT_SIZE as usize + 1) >> 1;
        // m should be a multiple of `range_bit_len`
        let m = (m2 - 1) / range_bit_len * range_bit_len + range_bit_len;

        // constants
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

        let verifier = Verifier::<E>::new(domain_size)?;
        let domain = verifier.domain;

        // we need to copy the public input once after merging the circuit
        let shared_public_input_vars =
            [shared_public_input_vars, shared_public_input_vars].concat();
        let public_inputs = vec![&shared_public_input_vars[..]; merged_vks.len()];
        let merged_vks_ref: Vec<&VerifyingKeyVar<E>> = merged_vks.iter().collect();

        // generate the PCS info
        let pcs_info_var = prepare_pcs_info_var(
            circuit,
            &merged_vks_ref,
            &public_inputs,
            batch_proof,
            &None,
            domain,
            non_native_field_info,
        )?;

        // inner1
        //  = [open_proof]
        //  + u * [shifted_open_proof]
        //  + blinding_factor * [1]1
        let generator_g_var = circuit.create_constant_point_variable(*generator_g)?;
        let bases = [
            pcs_info_var.opening_proof,
            pcs_info_var.shifted_opening_proof,
            generator_g_var,
        ];
        let u_var = pcs_info_var.u.convert_to_var(circuit)?;
        let scalars = [circuit.one(), u_var, blinding_factor];

        let inner1 = MultiScalarMultiplicationCircuit::<_, P>::msm(circuit, &bases, &scalars)?;

        // inner2
        //  = eval_point * [open_proof]
        //  + next_eval_point * u * [shifted_open_proof]
        //  + [aggregated_comm]
        //  - aggregated_eval * [1]1
        //  + blinding_factor * [beta]1
        let mut scalars_and_bases = pcs_info_var.comm_scalars_and_bases;
        scalars_and_bases.scalars.push(pcs_info_var.eval_point);
        scalars_and_bases.bases.push(pcs_info_var.opening_proof);

        let tmp = circuit.mod_mul(
            &pcs_info_var.next_eval_point,
            &pcs_info_var.u,
            &modulus_fp_elem,
        )?;
        scalars_and_bases.scalars.push(tmp);
        scalars_and_bases
            .bases
            .push(pcs_info_var.shifted_opening_proof);

        let generator_g_inv_var = circuit.create_constant_point_variable(generator_g.inverse())?;
        scalars_and_bases.scalars.push(pcs_info_var.eval);
        scalars_and_bases.bases.push(generator_g_inv_var);

        let mut scalars = scalars_and_bases
            .scalars
            .iter()
            .map(|x| x.convert_to_var(circuit))
            .collect::<Result<Vec<_>, _>>()?;
        scalars.push(blinding_factor);

        let mut bases = scalars_and_bases.bases;
        let beta_g = circuit.create_constant_point_variable(*beta_g)?;
        bases.push(beta_g);
        let inner2 = MultiScalarMultiplicationCircuit::<_, P>::msm(circuit, &bases, &scalars)?;

        Ok((inner1, inner2))
    }
}

/// Plonk Circuit that support batch verification
pub trait BatchableCircuit<F> {
    /// Aggregate verification keys
    fn aggregate_verify_keys<E, P>(
        &mut self,
        vk_type_a_vars: &[VerifyingKeyVar<E>],
        vk_type_b_vars: &[VerifyingKeyVar<E>],
    ) -> Result<Vec<VerifyingKeyVar<E>>, CircuitError>
    where
        E: Pairing,
        P: TEParam<BaseField = F>;
}

/// Instances batching scheme related gates
impl<F> BatchableCircuit<F> for PlonkCircuit<F>
where
    F: PrimeField,
{
    fn aggregate_verify_keys<E, P>(
        &mut self,
        vk_type_a_vars: &[VerifyingKeyVar<E>],
        vk_type_b_vars: &[VerifyingKeyVar<E>],
    ) -> Result<Vec<VerifyingKeyVar<E>>, CircuitError>
    where
        E: Pairing,
        P: TEParam<BaseField = F>,
    {
        if vk_type_a_vars.len() != vk_type_b_vars.len() {
            return Err(ParameterError(format!(
                "the number of type A verification key variables {} is different from the number of type B verification key variables {}.",
                vk_type_a_vars.len(),
                vk_type_b_vars.len())
            ));
        }
        vk_type_a_vars
            .iter()
            .zip(vk_type_b_vars.iter())
            .map(|(vk_b, vk_d)| vk_b.merge::<F, P>(self, vk_d))
            .collect::<Result<Vec<_>, CircuitError>>()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        proof_system::{
            batch_arg::{new_mergeable_circuit_for_test, BatchArgument},
            structs::BatchProof,
            PlonkKzgSnark, UniversalSNARK,
        },
        transcript::{PlonkTranscript, RescueTranscript},
    };
    use ark_bls12_377::{g1::Config as Param377, Bls12_377, Fq as Fq377};
    use ark_ec::{short_weierstrass::SWCurveConfig, twisted_edwards::TECurveConfig, CurveGroup};
    use ark_std::{vec, UniformRand};
    use jf_primitives::rescue::RescueParameter;
    use jf_relation::{
        gadgets::{ecc::Point, test_utils::test_variable_independence_for_circuit},
        Circuit, MergeableCircuitType,
    };
    use jf_utils::{field_switching, test_rng};

    const RANGE_BIT_LEN_FOR_TEST: usize = 16;

    #[test]
    fn test_aggregate_vks() -> Result<(), CircuitError> {
        test_aggregate_vks_helper::<Bls12_377, Fq377, _, Param377>()
    }

    fn test_aggregate_vks_helper<E, F, P, Q>() -> Result<(), CircuitError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: PrimeField + RescueParameter + SWToTEConParam,
        P: SWParam<BaseField = F>,
        Q: TEParam<BaseField = F>,
    {
        // Simulate universal setup
        let rng = &mut test_rng();
        let n = 32;
        let max_degree = n + 2;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        // Setup instances and create verifying keys
        let mut vks_type_a = vec![];
        let mut vks_type_b = vec![];
        let shared_public_input = E::ScalarField::rand(rng);
        for i in 0..5 {
            let circuit = new_mergeable_circuit_for_test::<E>(
                shared_public_input,
                i,
                MergeableCircuitType::TypeA,
            )?;
            let instance =
                BatchArgument::setup_instance(&srs, circuit, MergeableCircuitType::TypeA)?;
            vks_type_a.push(instance.verify_key_ref().clone());

            let circuit = new_mergeable_circuit_for_test::<E>(
                shared_public_input,
                i,
                MergeableCircuitType::TypeB,
            )?;
            let instance =
                BatchArgument::setup_instance(&srs, circuit, MergeableCircuitType::TypeB)?;
            vks_type_b.push(instance.verify_key_ref().clone());
        }
        // Compute merged verifying keys
        let vks_type_a_ref: Vec<&VerifyingKey<E>> = vks_type_a.iter().collect();
        let vks_type_b_ref: Vec<&VerifyingKey<E>> = vks_type_b.iter().collect();
        let merged_vks = BatchArgument::aggregate_verify_keys(&vks_type_a_ref, &vks_type_b_ref)?;

        // Check circuits
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        let vk_type_a_vars = vks_type_a
            .iter()
            .map(|vk| VerifyingKeyVar::new(&mut circuit, vk))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        for (vk_var, vk) in vk_type_a_vars.iter().zip(vks_type_a.iter()) {
            check_vk_equality(&circuit, vk_var, vk);
        }

        let vk_type_b_vars = vks_type_b
            .iter()
            .map(|vk| VerifyingKeyVar::new(&mut circuit, vk))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        for (vk_var, vk) in vk_type_b_vars.iter().zip(vks_type_b.iter()) {
            check_vk_equality(&circuit, vk_var, vk);
        }

        let merged_vk_vars =
            circuit.aggregate_verify_keys::<E, Q>(&vk_type_a_vars, &vk_type_b_vars)?;
        for (vk_var, vk) in merged_vk_vars.iter().zip(merged_vks.iter()) {
            check_vk_equality(&circuit, vk_var, vk);
        }

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Error paths
        // wrong witness
        let tmp = circuit.witness(merged_vk_vars[0].sigma_comms[0].get_x())?;
        *circuit.witness_mut(merged_vk_vars[0].sigma_comms[0].get_x()) = F::from(0u8);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(merged_vk_vars[0].sigma_comms[0].get_x()) = tmp;

        // inconsistent length between `vk_type_a_vars` and `vk_type_b_vars`
        assert!(circuit
            .aggregate_verify_keys::<E, Q>(&vk_type_a_vars[1..], &vk_type_b_vars)
            .is_err());

        // merged keys can't be merged again.
        let mut bad_vk_vars = vk_type_a_vars.clone();
        bad_vk_vars[0].is_merged = true;
        assert!(circuit
            .aggregate_verify_keys::<E, Q>(&bad_vk_vars, &vk_type_b_vars)
            .is_err());

        Ok(())
    }

    fn check_vk_equality<E, F, P>(
        circuit: &PlonkCircuit<F>,
        vk_var: &VerifyingKeyVar<E>,
        vk: &VerifyingKey<E>,
    ) where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: PrimeField + SWToTEConParam,
        P: SWParam<BaseField = F>,
    {
        for (comm_var, comm) in vk_var.sigma_comms.iter().zip(vk.sigma_comms.iter()) {
            let expected_comm = Point::from(&comm.0);
            assert_eq!(circuit.point_witness(comm_var).unwrap(), expected_comm);
        }
        for (comm_var, comm) in vk_var.selector_comms.iter().zip(vk.selector_comms.iter()) {
            let expected_comm = Point::from(&comm.0);
            assert_eq!(circuit.point_witness(comm_var).unwrap(), expected_comm);
        }
        assert_eq!(vk_var.is_merged, vk.is_merged);
    }

    #[test]
    fn test_partial_verification_circuit() -> Result<(), CircuitError> {
        test_partial_verification_circuit_helper::<Bls12_377, _, _, Param377, RescueTranscript<_>>()
    }

    fn test_partial_verification_circuit_helper<E, F, P, Q, T>() -> Result<(), CircuitError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWCurveConfig<BaseField = F> + TECurveConfig,
        Q: TEParam<BaseField = F>,
        T: PlonkTranscript<F>,
    {
        let rng = &mut test_rng();

        for log_circuit_size in 8..12 {
            // =======================================
            // setup
            // =======================================

            // 1. Simulate universal setup
            let n = 1 << log_circuit_size;
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

            {
                // =======================================
                // good path
                // =======================================
                let public_inputs = [[field_switching(&shared_public_input)].as_ref()].concat();

                let (mut circuit, partial_verify_points) = build_circuit::<E, F, P>(
                    &shared_public_input,
                    &merged_vks,
                    &batch_proof,
                    beta_g_ref,
                    &open_key_ref.g,
                    &blinding_factor,
                )?;

                assert!(
                    circuit.check_circuit_satisfiability(&public_inputs).is_ok(),
                    "{:?}",
                    circuit.check_circuit_satisfiability(&public_inputs)
                );
                assert_eq!(
                    circuit.point_witness(&partial_verify_points.0)?,
                    Point::<F>::from(&inner1.into_affine())
                );
                assert_eq!(
                    circuit.point_witness(&partial_verify_points.1)?,
                    Point::<F>::from(&inner2.into_affine())
                );

                // ark_std::println!("#variables: {}", circuit.num_vars());
                // ark_std::println!("#constraints: {}\n", circuit.num_gates());

                // =======================================
                // bad path: wrong pub inputs
                // =======================================
                // instance inputs = partial verify inputs != satisfiability inputs
                let wrong_public_inputs = [[F::rand(rng)].as_ref()].concat();
                assert!(circuit
                    .check_circuit_satisfiability(&wrong_public_inputs)
                    .is_err(),);

                // =======================================
                // bad path: wrong number of pub inputs
                // =======================================
                let wrong_public_inputs =
                    [[field_switching(&shared_public_input); 3].as_ref()].concat();
                assert!(circuit
                    .check_circuit_satisfiability(&wrong_public_inputs)
                    .is_err(),);

                // =======================================
                // bad path: wrong witness
                // =======================================
                *circuit.witness_mut(10) = F::from(0u32);
                assert!(circuit
                    .check_circuit_satisfiability(&public_inputs)
                    .is_err());
            }
            // ==============================================
            // more bad path: wrong inputs length
            // ==============================================
            {
                // wrong vks length (less by 1)
                // should not be able to generate circuit
                let mut wrong_merge_vks = merged_vks.clone();
                let tmp = wrong_merge_vks.pop().unwrap();
                assert!(build_circuit::<E, F, P>(
                    &shared_public_input,
                    &wrong_merge_vks,
                    &batch_proof,
                    beta_g_ref,
                    &open_key_ref.g,
                    &blinding_factor,
                )
                .is_err());

                // wrong vks length (more by 1)
                // should not be able to generate circuit
                let mut wrong_merge_vks = merged_vks.clone();
                wrong_merge_vks.push(tmp);
                assert!(build_circuit::<E, F, P>(
                    &shared_public_input,
                    &wrong_merge_vks,
                    &batch_proof,
                    beta_g_ref,
                    &open_key_ref.g,
                    &blinding_factor,
                )
                .is_err());
            }

            // ==============================================
            // more bad path: wrong inputs to the function
            // ==============================================
            {
                // wrong shared input, the circuit is not satisfied
                // instance inputs = satisfiability inputs != partial verify inputs
                let public_inputs = [[field_switching(&shared_public_input)].as_ref()].concat();
                let wrong_shared_public_input = E::ScalarField::rand(rng);
                let (circuit, partial_verify_points) = build_circuit::<E, F, P>(
                    &wrong_shared_public_input,
                    &merged_vks,
                    &batch_proof,
                    beta_g_ref,
                    &open_key_ref.g,
                    &blinding_factor,
                )?;

                assert!(
                    circuit
                        .check_circuit_satisfiability(&public_inputs)
                        .is_err(),
                    "{:?}",
                    circuit.check_circuit_satisfiability(public_inputs.as_ref())
                );
                assert_ne!(
                    circuit.point_witness(&partial_verify_points.0)?,
                    Point::<F>::from(&inner1.into_affine())
                );
                assert_ne!(
                    circuit.point_witness(&partial_verify_points.1)?,
                    Point::<F>::from(&inner2.into_affine())
                );

                // wrong shared input and circuit input
                // instance inputs != partial verify inputs = satisfiability inputs
                // the circuit is satisfied because partial verify inputs = satisfiability
                // inputs both output must be different so it will not verify
                // original instance
                let wrong_public_inputs =
                    [[field_switching(&wrong_shared_public_input)].as_ref()].concat();
                assert!(
                    circuit
                        .check_circuit_satisfiability(&wrong_public_inputs)
                        .is_ok(),
                    "{:?}",
                    circuit.check_circuit_satisfiability(wrong_public_inputs.as_ref())
                );
                assert_ne!(
                    circuit.point_witness(&partial_verify_points.0)?,
                    Point::<F>::from(&inner1.into_affine())
                );
                assert_ne!(
                    circuit.point_witness(&partial_verify_points.1)?,
                    Point::<F>::from(&inner2.into_affine())
                );
            }
        }

        Ok(())
    }

    fn build_circuit<E, F, P>(
        shared_public_input: &E::ScalarField,
        merged_vks: &[VerifyingKey<E>],
        batch_proof: &BatchProof<E>,
        beta_g_ref: &Affine<P>,
        generator_g: &Affine<P>,
        blinding_factor: &E::ScalarField,
    ) -> Result<(PlonkCircuit<F>, (PointVariable, PointVariable)), CircuitError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWCurveConfig<BaseField = F> + TECurveConfig,
    {
        let mut circuit = PlonkCircuit::<E::BaseField>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        // constants
        let m = 128;
        let two_power_m = Some(E::BaseField::from(2u8).pow([m as u64]));

        // public inputs
        let shared_public_input_var =
            circuit.create_public_variable(field_switching(shared_public_input))?;
        let shared_public_input_fp_elem_var =
            FpElemVar::new_unchecked(&mut circuit, shared_public_input_var, m, two_power_m)?;

        // vk
        let vk_vars = merged_vks
            .iter()
            .map(|x| VerifyingKeyVar::new(&mut circuit, x))
            .collect::<Result<Vec<_>, _>>()?;

        // proof
        let batch_proof_vars = (*batch_proof).create_variables(&mut circuit, m, two_power_m)?;

        let beta_g: Point<F> = beta_g_ref.into();
        let generator_g = &generator_g.into();
        let blinding_factor_var = circuit.create_variable(field_switching(blinding_factor))?;

        let partial_verify_points = VerifyingKeyVar::partial_verify_circuit(
            &mut circuit,
            &beta_g,
            generator_g,
            &vk_vars,
            &[shared_public_input_fp_elem_var],
            &batch_proof_vars,
            blinding_factor_var,
        )?;

        Ok((circuit, partial_verify_points))
    }

    #[test]
    fn test_variable_independence_for_partial_verification_circuit() -> Result<(), CircuitError> {
        test_variable_independence_for_partial_verification_circuit_helper::<
            Bls12_377,
            _,
            _,
            Param377,
            RescueTranscript<_>,
        >()
    }

    fn test_variable_independence_for_partial_verification_circuit_helper<E, F, P, Q, T>(
    ) -> Result<(), CircuitError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWCurveConfig<BaseField = F> + TECurveConfig,
        Q: TEParam<BaseField = F>,
        T: PlonkTranscript<F>,
    {
        let rng = &mut test_rng();
        let i = 8;
        let mut circuits = vec![];

        // 1. Simulate universal setup
        let n = 1 << i;
        let max_degree = n + 2;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        for _ in 0..2 {
            // =======================================
            // set up
            // =======================================

            // 2. Setup instances
            let shared_public_input = E::ScalarField::rand(rng);
            let mut instances_type_a = vec![];
            let mut instances_type_b = vec![];

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

            // 5. Build circuit
            let open_key_ref = &vks_type_a[0].open_key;
            let beta_g_ref = &srs.powers_of_g[1];
            let blinding_factor = E::ScalarField::rand(rng);

            let (mut circuit, _partial_verify_points) = build_circuit::<E, F, P>(
                &shared_public_input,
                &merged_vks,
                &batch_proof,
                beta_g_ref,
                &open_key_ref.g,
                &blinding_factor,
            )?;

            circuit.finalize_for_arithmetization()?;
            circuits.push(circuit);
        }

        test_variable_independence_for_circuit(circuits[0].clone(), circuits[1].clone())?;

        Ok(())
    }
}
