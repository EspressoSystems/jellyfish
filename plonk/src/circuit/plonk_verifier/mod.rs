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
use jf_relation::{
    gadgets::{
        ecc::{MultiScalarMultiplicationCircuit, PointVariable, SWToTEConParam, TEPoint},
        ultraplonk::mod_arith::{FpElem, FpElemVar},
    },
    Circuit, CircuitError, PlonkCircuit, Variable,
};
use jf_rescue::RescueParameter;

mod gadgets;
mod poly;
mod structs;

use gadgets::*;
pub use structs::*;

/// Represents a variable of a Plonk verifying key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifyingKeyVar<E: Pairing> {
    pub(crate) sigma_comms: Vec<PointVariable>,
    pub(crate) selector_comms: Vec<PointVariable>,
    pub(crate) is_merged: bool,
    pub(crate) domain_size: usize,
    pub(crate) num_inputs: usize,
    pub(crate) k: Vec<E::ScalarField>,
}

impl<E: Pairing> VerifyingKeyVar<E> {
    /// Creates a variable for a Plonk verifying key.
    pub fn new<F, P>(
        circuit: &mut PlonkCircuit<F>,
        verify_key: &VerifyingKey<E>,
    ) -> Result<Self, CircuitError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: PrimeField + SWToTEConParam,
        P: SWParam<BaseField = F>,
    {
        Ok(Self {
            sigma_comms: Self::create_point_variables(circuit, &verify_key.sigma_comms)?,
            selector_comms: Self::create_point_variables(circuit, &verify_key.selector_comms)?,
            is_merged: verify_key.is_merged,
            domain_size: verify_key.domain_size,
            num_inputs: verify_key.num_inputs,
            k: verify_key.k.clone(),
        })
    }

    /// Converts the verification key variables into a list of circuit variables.
    pub fn to_vec(&self) -> Vec<Variable> {
        self.sigma_comms
            .iter()
            .chain(&self.selector_comms)
            .flat_map(|comm| vec![comm.get_x(), comm.get_y()])
            .collect()
    }

    /// Merges this verifying key variable with another one.
    pub(crate) fn merge<F, P>(
        &self,
        circuit: &mut PlonkCircuit<F>,
        other: &Self,
    ) -> Result<Self, CircuitError>
    where
        F: PrimeField,
        P: TEParam<BaseField = F>,
    {
        self.validate_merge(other)?;
        let sigma_comms = Self::merge_point_variables(circuit, &self.sigma_comms, &other.sigma_comms)?;
        let selector_comms = Self::merge_point_variables(circuit, &self.selector_comms, &other.selector_comms)?;
        Ok(Self {
            sigma_comms,
            selector_comms,
            is_merged: true,
            domain_size: self.domain_size,
            num_inputs: self.num_inputs + other.num_inputs,
            k: self.k.clone(),
        })
    }

    /// Partially verifies a batched proof without performing pairings.
    pub fn partial_verify_circuit<F, P>(
        circuit: &mut PlonkCircuit<F>,
        beta_g: &TEPoint<F>,
        generator_g: &TEPoint<F>,
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
        Self::validate_partial_verify_inputs(merged_vks, batch_proof)?;

        let non_native_field_info = Self::compute_non_native_field_info(circuit)?;

        let verifier = Verifier::<E>::new(merged_vks[0].domain_size)?;
        let domain = verifier.domain;

        let shared_public_input_vars = Self::duplicate_inputs(shared_public_input_vars);
        let public_inputs = vec![&shared_public_input_vars[..]; merged_vks.len()];
        let merged_vks_ref: Vec<&VerifyingKeyVar<E>> = merged_vks.iter().collect();

        let pcs_info_var = prepare_pcs_info_var(
            circuit,
            &merged_vks_ref,
            &public_inputs,
            batch_proof,
            &None,
            domain,
            non_native_field_info,
        )?;

        let inner1 = Self::compute_inner1(
            circuit,
            &pcs_info_var,
            generator_g,
            blinding_factor,
        )?;
        let inner2 = Self::compute_inner2(
            circuit,
            &pcs_info_var,
            beta_g,
            generator_g,
            blinding_factor,
        )?;
        Ok((inner1, inner2))
    }

    // Helper functions for code modularity.
    fn validate_merge(&self, other: &Self) -> Result<(), CircuitError> {
        if self.is_merged || other.is_merged {
            return Err(ParameterError("Cannot merge a merged key again.".to_string()));
        }
        if self.domain_size != other.domain_size {
            return Err(ParameterError("Domain sizes must match for merging.".to_string()));
        }
        if self.num_inputs != other.num_inputs {
            return Err(ParameterError("Input counts must match for merging.".to_string()));
        }
        Ok(())
    }

    fn merge_point_variables<F, P>(
        circuit: &mut PlonkCircuit<F>,
        vars1: &[PointVariable],
        vars2: &[PointVariable],
    ) -> Result<Vec<PointVariable>, CircuitError>
    where
        F: PrimeField,
        P: TEParam<BaseField = F>,
    {
        vars1
            .iter()
            .zip(vars2.iter())
            .map(|(var1, var2)| circuit.ecc_add::<P>(var1, var2))
            .collect()
    }

    fn create_point_variables<F, P>(
        circuit: &mut PlonkCircuit<F>,
        points: &[Affine<P>],
    ) -> Result<Vec<PointVariable>, CircuitError>
    where
        F: PrimeField,
        P: SWParam<BaseField = F>,
    {
        points
            .iter()
            .map(|&point| circuit.create_point_variable(TEPoint::from(point)))
            .collect()
    }

    fn validate_partial_verify_inputs(
        merged_vks: &[Self],
        batch_proof: &BatchProofVar<_>,
    ) -> Result<(), CircuitError> {
        if merged_vks.is_empty() {
            return Err(ParameterError("No merged verifying keys provided.".to_string()));
        }
        if merged_vks.len() != batch_proof.len() {
            return Err(ParameterError(format!(
                "Mismatched verification keys ({}) and proof instances ({}).",
                merged_vks.len(),
                batch_proof.len()
            )));
        }
        Ok(())
    }

    fn compute_non_native_field_info<F>(
        circuit: &mut PlonkCircuit<F>,
    ) -> Result<NonNativeFieldInfo<F>, CircuitError>
    where
        F: PrimeField,
    {
        let range_bit_len = circuit.range_bit_len()?;
        let modulus_bits = <F as PrimeField>::MODULUS.to_bytes_le();
        let modulus = F::from_le_bytes_mod_order(&modulus_bits);

        let m = ((<F as PrimeField>::MODULUS_BIT_SIZE as usize + 1) >> 1) / range_bit_len * range_bit_len + range_bit_len;
        let two_power_m = Some(F::from(2u8).pow([m as u64]));

        Ok(NonNativeFieldInfo {
            m,
            two_power_m,
            modulus_in_f: modulus,
            modulus_fp_elem: FpElem::new(&modulus, m, two_power_m)?,
        })
    }

    fn duplicate_inputs<F>(
        shared_public_input_vars: &[FpElemVar<F>],
    ) -> Vec<FpElemVar<F>>
    where
        F: PrimeField,
    {
        [shared_public_input_vars, shared_public_input_vars].concat()
    }
}
