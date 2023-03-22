// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use crate::rescue::{
    Permutation, RescueMatrix, RescueParameter, RescueVector, PRP, ROUNDS, STATE_SIZE,
};
use ark_ff::PrimeField;
use ark_std::{boxed::Box, format, string::ToString, vec, vec::Vec};
use itertools::Itertools;
use jf_relation::{
    constants::GATE_WIDTH,
    errors::{CircuitError, CircuitError::ParameterError},
    gates::{FifthRootGate, Gate},
    Circuit, PlonkCircuit, Variable,
};
use jf_utils::compute_len_to_next_multiple;

use super::{PermutationGadget, RescueGadget, SpongeStateVar};

#[derive(Clone, Debug)]
/// Array of variables representing a Rescue state (4 field elements).
pub struct RescueStateVar(pub(crate) [Variable; STATE_SIZE]);

/// Type wrapper for the RescueGadget over the native field.
pub type RescueNativeGadget<F> = dyn RescueGadget<RescueStateVar, F, F>;

/// For the native field, there is only really one field `F`.
impl<F> SpongeStateVar<F, F> for RescueStateVar {
    type Native = F;
    type NonNative = F;
    type Var = Variable;
}

impl From<[Variable; STATE_SIZE]> for RescueStateVar {
    fn from(arr: [Variable; STATE_SIZE]) -> Self {
        RescueStateVar(arr)
    }
}

impl RescueStateVar {
    /// Expose the state array.
    pub fn array(&self) -> &[Variable; STATE_SIZE] {
        &self.0
    }
    /// Expose the mutable state array.
    pub fn array_mut(&mut self) -> &mut [Variable; STATE_SIZE] {
        &mut self.0
    }
}

////////////////////////////////////////////////////////////
// Rescue related gates/////////////////////////////////////
////////////////////////////////////////////////////////////

#[derive(Debug, Clone)]
pub(crate) struct RescueAffineGate<F> {
    pub(crate) matrix_vector: RescueVector<F>,
    pub(crate) constant: F,
}

impl<F: PrimeField> Gate<F> for RescueAffineGate<F> {
    fn name(&self) -> &'static str {
        "Affine gate"
    }

    fn q_lc(&self) -> [F; GATE_WIDTH] {
        let elems = self.matrix_vector.elems();
        [elems[0], elems[1], elems[2], elems[3]]
    }

    fn q_c(&self) -> F {
        self.constant
    }

    fn q_o(&self) -> F {
        F::one()
    }
}

/// Gate for the following computation:
/// 1. x = (var1^5, var2^5, var3^5, var4^5)  
/// 2. f = <matrix_vector, x>
/// 3. var_output = f + constant
#[derive(Debug, Clone)]
pub(crate) struct Power5NonLinearGate<F> {
    pub(crate) matrix_vector: RescueVector<F>,
    pub(crate) constant: F,
}

impl<F: PrimeField> Gate<F> for Power5NonLinearGate<F> {
    fn name(&self) -> &'static str {
        "Non linear gate"
    }

    fn q_hash(&self) -> [F; GATE_WIDTH] {
        let elems = self.matrix_vector.elems();
        [elems[0], elems[1], elems[2], elems[3]]
    }

    fn q_c(&self) -> F {
        self.constant
    }

    fn q_o(&self) -> F {
        F::one()
    }
}

impl<F> RescueGadget<RescueStateVar, F, F> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn rescue_permutation(
        &mut self,
        input_var: RescueStateVar,
    ) -> Result<RescueStateVar, CircuitError> {
        let permutation = Permutation::default();
        let keys = permutation.round_keys_ref();
        let keys = keys
            .iter()
            .map(|key| RescueVector::from(key.elems().as_slice()))
            .collect_vec();
        let mds_matrix = permutation.mds_matrix_ref();

        self.permutation_with_const_round_keys(input_var, mds_matrix, keys.as_slice())
    }

    fn prp(
        &mut self,
        key_var: &RescueStateVar,
        input_var: &RescueStateVar,
    ) -> Result<RescueStateVar, CircuitError> {
        let prp_instance = PRP::<F>::default();
        let mds_states = prp_instance.mds_matrix_ref();
        let keys_vars =
            RescueNativeGadget::<F>::key_schedule(self, mds_states, key_var, &prp_instance)?;
        self.prp_with_round_keys(input_var, mds_states, &keys_vars)
    }

    fn rescue_sponge_no_padding(
        &mut self,
        data_vars: &[Variable],
        num_output: usize,
    ) -> Result<Vec<Variable>, CircuitError> {
        if (data_vars.is_empty()) || (data_vars.len() % (STATE_SIZE - 1) != 0) {
            return Err(ParameterError("empty data vars".to_string()));
        }
        let zero_var = self.zero();
        let rate = STATE_SIZE - 1;

        // ABSORB PHASE
        let mut state_var =
            RescueStateVar::from([data_vars[0], data_vars[1], data_vars[2], zero_var]);
        state_var = RescueNativeGadget::<F>::rescue_permutation(self, state_var)?;

        for block in data_vars[rate..].chunks_exact(rate) {
            state_var = self.add_state(
                &state_var,
                &RescueStateVar::from([block[0], block[1], block[2], zero_var]),
            )?;
            state_var = self.rescue_permutation(state_var)?;
        }

        // SQUEEZE PHASE
        let mut result = vec![];
        let mut remaining = num_output;
        // extract current rate before calling PRP again
        loop {
            let extract = remaining.min(rate);
            result.extend_from_slice(&state_var.0[0..extract]);
            remaining -= extract;
            if remaining == 0 {
                break;
            }
            state_var = self.rescue_permutation(state_var)?;
        }

        Ok(result)
    }

    fn rescue_sponge_with_padding(
        &mut self,
        data_vars: &[Variable],
        num_output: usize,
    ) -> Result<Vec<Variable>, CircuitError> {
        if data_vars.is_empty() {
            return Err(ParameterError("empty data vars".to_string()));
        }
        let zero_var = self.zero();
        let rate = STATE_SIZE - 1;
        let data_len = compute_len_to_next_multiple(data_vars.len() + 1, rate);

        let data_vars: Vec<Variable> = [
            data_vars,
            &[self.one()],
            vec![zero_var; data_len - data_vars.len() - 1].as_ref(),
        ]
        .concat();

        RescueNativeGadget::<F>::rescue_sponge_no_padding(self, &data_vars, num_output)
    }

    fn rescue_full_state_keyed_sponge_no_padding(
        &mut self,
        key: Variable,
        data_vars: &[Variable],
    ) -> Result<Variable, CircuitError> {
        if data_vars.len() % STATE_SIZE != 0 {
            return Err(ParameterError(format!(
                "Bad input length for FSKS circuit: {:}, it must be multiple of STATE_SIZE",
                data_vars.len()
            )));
        }
        // set key
        let mut state = RescueStateVar::from([self.zero(), self.zero(), self.zero(), key]);
        // absorb phase
        let chunks = data_vars.chunks_exact(STATE_SIZE);
        for chunk in chunks {
            let chunk_var = RescueStateVar::from([chunk[0], chunk[1], chunk[2], chunk[3]]);
            state = self.add_state(&state, &chunk_var)?;
            state = RescueNativeGadget::<F>::rescue_permutation(self, state)?;
        }
        // squeeze phase, but only a single output, can return directly from state
        Ok(state.0[0])
    }

    fn rescue_full_state_keyed_sponge_with_zero_padding(
        &mut self,
        key: Variable,
        data_vars: &[Variable],
    ) -> Result<Variable, CircuitError> {
        if data_vars.is_empty() {
            return Err(ParameterError("empty data vars".to_string()));
        }

        let zero_var = self.zero();
        let data_vars = [
            data_vars,
            vec![
                zero_var;
                compute_len_to_next_multiple(data_vars.len(), STATE_SIZE) - data_vars.len()
            ]
            .as_ref(),
        ]
        .concat();

        RescueNativeGadget::<F>::rescue_full_state_keyed_sponge_no_padding(self, key, &data_vars)
    }

    fn key_schedule(
        &mut self,
        mds: &RescueMatrix<F>,
        key_var: &RescueStateVar,
        prp_instance: &PRP<F>,
    ) -> Result<Vec<RescueStateVar>, CircuitError> {
        let mut aux = *prp_instance.init_vec_ref();
        let key_injection_vec = prp_instance.key_injection_vec_ref();

        let mut key_state_var = self.add_constant_state(key_var, &aux)?;
        let mut result = vec![key_state_var.clone()];

        for (r, key_injection_item) in key_injection_vec.iter().enumerate() {
            aux.linear(mds, key_injection_item);
            if r % 2 == 0 {
                key_state_var = self.pow_alpha_inv_state(&key_state_var)?;
                key_state_var = self.affine_transform(&key_state_var, mds, key_injection_item)?;
            } else {
                key_state_var =
                    self.non_linear_transform(&key_state_var, mds, key_injection_item)?;
            }
            result.push(key_state_var.clone());
        }

        Ok(result)
    }
    fn create_rescue_state_variable(
        &mut self,
        state: &RescueVector<F>,
    ) -> Result<RescueStateVar, CircuitError> {
        let mut vars = [Variable::default(); STATE_SIZE];
        for (var, state) in vars.iter_mut().zip(state.elems().iter()) {
            *var = self.create_variable(*state)?;
        }
        Ok(RescueStateVar::from(vars))
    }

    /// Return the variable corresponding to the output of the of the Rescue
    /// PRP where the rounds keys have already been computed "dynamically"
    /// * `input_var` - variable corresponding to the plain text
    /// * `mds_states` - Rescue MDS matrix
    /// * `key_vars` - variables corresponding to the scheduled keys
    /// * `returns` -
    fn prp_with_round_keys(
        &mut self,
        input_var: &RescueStateVar,
        mds: &RescueMatrix<F>,
        keys_vars: &[RescueStateVar],
    ) -> Result<RescueStateVar, CircuitError> {
        if (keys_vars.len() != 2 * ROUNDS + 1) || (mds.len() != STATE_SIZE) {
            return Err(CircuitError::ParameterError("data_vars".to_string()));
        }

        let zero_state = RescueVector::from(&[F::zero(); STATE_SIZE]);
        let mut state_var = self.add_state(input_var, &keys_vars[0])?;
        for (r, key_var) in keys_vars.iter().skip(1).enumerate() {
            if r % 2 == 0 {
                state_var = self.pow_alpha_inv_state(&state_var)?;
                state_var = self.affine_transform(&state_var, mds, &zero_state)?;
            } else {
                state_var = self.non_linear_transform(&state_var, mds, &zero_state)?;
            }

            state_var = self.add_state(&state_var, key_var)?;
        }
        Ok(state_var)
    }
}

impl<F> PermutationGadget<RescueStateVar, F, F> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn check_var_bound_rescue_state(
        &self,
        rescue_state: &RescueStateVar,
    ) -> Result<(), CircuitError> {
        for var in &rescue_state.0 {
            self.check_var_bound(*var)?;
        }
        Ok(())
    }

    fn add_constant_state(
        &mut self,
        input_var: &RescueStateVar,
        constant: &RescueVector<F>,
    ) -> Result<RescueStateVar, CircuitError> {
        // Check bounds for every variable
        self.check_var_bound_rescue_state(input_var)?;

        let vars: Result<Vec<Variable>, CircuitError> = input_var
            .0
            .iter()
            .zip(constant.elems().iter())
            .map(|(&var, elem)| self.add_constant(var, elem))
            .collect();
        let vars = vars?;
        Ok(RescueStateVar::from([vars[0], vars[1], vars[2], vars[3]]))
    }

    fn pow_alpha_inv_state(
        &mut self,
        input_var: &RescueStateVar,
    ) -> Result<RescueStateVar, CircuitError> {
        // Check bounds for every variable
        self.check_var_bound_rescue_state(input_var)?;

        let vars: Result<Vec<Variable>, CircuitError> = input_var
            .0
            .iter()
            .map(|var| PermutationGadget::<RescueStateVar, F, F>::pow_alpha_inv(self, *var))
            .collect();
        let vars = vars?;
        Ok(RescueStateVar::from([vars[0], vars[1], vars[2], vars[3]]))
    }

    fn affine_transform(
        &mut self,
        input_var: &RescueStateVar,
        matrix: &RescueMatrix<F>,
        constant: &RescueVector<F>,
    ) -> Result<RescueStateVar, CircuitError> {
        // Check bounds for every variable
        self.check_var_bound_rescue_state(input_var)?;

        let input_val_fields_elems: Result<Vec<F>, CircuitError> =
            input_var.0.iter().map(|x| self.witness(*x)).collect();

        let input_val = RescueVector::from(input_val_fields_elems?.as_slice());

        let mut output_val = input_val;
        output_val.linear(matrix, constant);

        let mut output_vars = [Variable::default(); STATE_SIZE];
        for (i, output) in output_vars.iter_mut().enumerate().take(STATE_SIZE) {
            let matrix_vec_i = matrix.vec(i);
            *output = self.create_variable(output_val.elems()[i])?;
            let wire_vars = &[
                input_var.0[0],
                input_var.0[1],
                input_var.0[2],
                input_var.0[3],
                *output,
            ];
            let constant_i = constant.elems()[i];
            self.insert_gate(
                wire_vars,
                Box::new(RescueAffineGate {
                    matrix_vector: matrix_vec_i,
                    constant: constant_i,
                }),
            )?;
        }
        Ok(RescueStateVar::from(output_vars))
    }

    fn non_linear_transform(
        &mut self,
        input_var: &RescueStateVar,
        matrix: &RescueMatrix<F>,
        constant: &RescueVector<F>,
    ) -> Result<RescueStateVar, CircuitError> {
        // Check bounds for every variable
        self.check_var_bound_rescue_state(input_var)?;

        let input_val_fields_elems: Result<Vec<F>, CircuitError> =
            input_var.0.iter().map(|x| self.witness(*x)).collect();

        let input_val = RescueVector::from(input_val_fields_elems?.as_slice());

        if F::A == 5 {
            let mut output_val = input_val;
            output_val.non_linear(matrix, constant);

            let mut output_vars = [Variable::default(); STATE_SIZE];
            for (i, output) in output_vars.iter_mut().enumerate().take(STATE_SIZE) {
                let matrix_vec_i = matrix.vec(i);
                *output = self.create_variable(output_val.elems()[i])?;
                let wire_vars = &[
                    input_var.0[0],
                    input_var.0[1],
                    input_var.0[2],
                    input_var.0[3],
                    *output,
                ];
                let constant_i = constant.elems()[i];
                self.insert_gate(
                    wire_vars,
                    Box::new(Power5NonLinearGate {
                        matrix_vector: matrix_vec_i,
                        constant: constant_i,
                    }),
                )?;
            }

            Ok(RescueStateVar::from(output_vars))
        } else if F::A == 11 {
            // generate the `power 11 vector` and its wires
            let mut input_power_11_vars = RescueStateVar([Variable::default(); STATE_SIZE]);
            for (e, f) in input_var.0.iter().zip(input_power_11_vars.0.iter_mut()) {
                let val = self.witness(*e)?.pow([11]);
                let var = self.create_variable(val)?;
                self.power_11_gate(*e, var)?;
                *f = var;
            }
            // perform linear transformation
            self.affine_transform(&input_power_11_vars, matrix, constant)
        } else {
            Err(CircuitError::ParameterError(
                "incorrect Rescue parameters".to_string(),
            ))
        }
    }

    fn pow_alpha_inv(&mut self, input_var: Variable) -> Result<Variable, CircuitError> {
        self.check_var_bound(input_var)?;
        let input_val = self.witness(input_var)?;

        let output_val = input_val.pow(F::A_INV);
        let output_var = self.create_variable(output_val)?;
        if F::A == 5 {
            let wire_vars = &[output_var, 0, 0, 0, input_var];
            self.insert_gate(wire_vars, Box::new(FifthRootGate))?;
            Ok(output_var)
        } else if F::A == 11 {
            self.power_11_gate(output_var, input_var)?;
            Ok(output_var)
        } else {
            Err(CircuitError::ParameterError(
                "incorrect Rescue parameters".to_string(),
            ))
        }
    }

    fn add_state(
        &mut self,
        left_state_var: &RescueStateVar,
        right_state_var: &RescueStateVar,
    ) -> Result<RescueStateVar, CircuitError> {
        let mut res = RescueStateVar([Variable::default(); STATE_SIZE]);

        for (res1, (&left_var, &right_var)) in res
            .0
            .iter_mut()
            .zip(left_state_var.0.iter().zip(right_state_var.0.iter()))
        {
            *res1 = self.add(left_var, right_var)?;
        }
        Ok(res)
    }

    fn permutation_with_const_round_keys(
        &mut self,
        input_var: RescueStateVar,
        mds: &RescueMatrix<F>,
        round_keys: &[RescueVector<F>],
    ) -> Result<RescueStateVar, CircuitError> {
        if (round_keys.len() != 2 * ROUNDS + 1) || (mds.len() != STATE_SIZE) {
            return Err(CircuitError::ParameterError("data_vars".to_string()));
        }

        let mut state_var = self.add_constant_state(&input_var, &round_keys[0])?;
        for (r, key) in round_keys.iter().skip(1).enumerate() {
            if r % 2 == 0 {
                state_var = self.pow_alpha_inv_state(&state_var)?;
                state_var = self.affine_transform(&state_var, mds, key)?;
            } else {
                state_var = self.non_linear_transform(&state_var, mds, key)?;
            }
        }
        Ok(state_var)
    }
}

#[cfg(test)]
mod tests {

    use super::{PermutationGadget, RescueGadget, RescueStateVar};
    use crate::{
        circuit::rescue::RescueNativeGadget,
        rescue::{
            sponge::{RescueCRHF, RescuePRFCore},
            Permutation, RescueMatrix, RescueParameter, RescueVector, CRHF_RATE, PRP, STATE_SIZE,
        },
    };
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::{FftField, PrimeField};
    use ark_std::{vec, vec::Vec};
    use itertools::Itertools;
    use jf_relation::{Circuit, PlonkCircuit, Variable};

    fn gen_state_matrix_constant<F: PrimeField>(
    ) -> (RescueVector<F>, RescueMatrix<F>, RescueVector<F>) {
        let state_in =
            RescueVector::from(&[F::from(12u32), F::from(2u32), F::from(8u32), F::from(9u32)]);

        let matrix = RescueMatrix::from(&[
            RescueVector::from(&[F::from(2u32), F::from(3u32), F::from(4u32), F::from(5u32)]),
            RescueVector::from(&[F::from(3u32), F::from(3u32), F::from(3u32), F::from(3u32)]),
            RescueVector::from(&[F::from(5u32), F::from(3u32), F::from(5u32), F::from(5u32)]),
            RescueVector::from(&[F::from(1u32), F::from(0u32), F::from(2u32), F::from(17u32)]),
        ]);

        let constant =
            RescueVector::from(&[F::from(2u32), F::from(3u32), F::from(4u32), F::from(5u32)]);

        (state_in, matrix, constant)
    }

    fn check_state<F: PrimeField>(
        circuit: &PlonkCircuit<F>,
        out_var: &RescueStateVar,
        out_value: &RescueVector<F>,
    ) {
        for i in 0..STATE_SIZE {
            assert_eq!(circuit.witness(out_var.0[i]).unwrap(), out_value.elems()[i]);
        }
    }

    fn check_circuit_satisfiability<F: FftField>(
        circuit: &mut PlonkCircuit<F>,
        out_value: Vec<F>,
        out_var: RescueStateVar,
    ) {
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        for (i, v) in out_value.iter().enumerate() {
            *circuit.witness_mut(out_var.0[i]) = F::from(888_u32);
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(out_var.0[i]) = *v;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        }
    }

    #[test]
    fn test_add_constant_state() {
        test_add_constant_state_helper::<FqEd254>();
        test_add_constant_state_helper::<FqEd377>();
        test_add_constant_state_helper::<FqEd381>();
    }
    fn test_add_constant_state_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::new_turbo_plonk();

        let state = RescueVector::from(&[F::from(12_u32), F::one(), F::one(), F::one()]);
        let constant = RescueVector::from(&[F::zero(), F::one(), F::one(), F::one()]);

        let input_var = circuit.create_rescue_state_variable(&state).unwrap();
        let out_var = circuit.add_constant_state(&input_var, &constant).unwrap();

        let out_value: Vec<F> = (0..STATE_SIZE)
            .map(|i| constant.elems()[i] + state.elems()[i])
            .collect();

        check_state(
            &circuit,
            &out_var,
            &RescueVector::from(out_value.as_slice()),
        );

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the input state
        *circuit.witness_mut(input_var.0[0]) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Restablish the input state
        *circuit.witness_mut(input_var.0[0]) = state.elems()[0];
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the output state
        *circuit.witness_mut(out_var.0[1]) = F::from(888_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_state_inversion() {
        test_state_inversion_helper::<FqEd254>();
        test_state_inversion_helper::<FqEd377>();
        test_state_inversion_helper::<FqEd381>()
    }
    fn test_state_inversion_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::new_turbo_plonk();

        let state =
            RescueVector::from(&[F::from(12u32), F::from(2u32), F::from(8u32), F::from(9u32)]);

        let input_var = circuit.create_rescue_state_variable(&state).unwrap();
        let out_var = circuit.pow_alpha_inv_state(&input_var).unwrap();

        let out_value: Vec<F> = (0..STATE_SIZE)
            .map(|i| state.elems()[i].pow(F::A_INV))
            .collect();

        check_state(
            &circuit,
            &out_var,
            &RescueVector::from(out_value.as_slice()),
        );

        check_circuit_satisfiability(&mut circuit, out_value, out_var);
    }

    #[test]
    fn test_affine_transformation() {
        test_affine_transformation_helper::<FqEd254>();
        test_affine_transformation_helper::<FqEd377>();
        test_affine_transformation_helper::<FqEd381>();
    }

    fn test_affine_transformation_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let (state_in, matrix, constant) = gen_state_matrix_constant();

        let input_var = circuit.create_rescue_state_variable(&state_in).unwrap();

        let out_var = circuit
            .affine_transform(&input_var, &matrix, &constant)
            .unwrap();

        let mut out_value = state_in;
        out_value.linear(&matrix, &constant);

        check_state(&circuit, &out_var, &out_value);

        check_circuit_satisfiability(&mut circuit, out_value.elems(), out_var);
    }

    #[test]
    fn test_non_linear_transformation() {
        test_non_linear_transformation_helper::<FqEd254>();
        test_non_linear_transformation_helper::<FqEd377>();
        test_non_linear_transformation_helper::<FqEd381>();
    }
    fn test_non_linear_transformation_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let (state_in, matrix, constant) = gen_state_matrix_constant();

        let input_var = circuit.create_rescue_state_variable(&state_in).unwrap();

        let out_var = circuit
            .non_linear_transform(&input_var, &matrix, &constant)
            .unwrap();

        let mut out_value = state_in;
        out_value.non_linear(&matrix, &constant);

        check_state(&circuit, &out_var, &out_value);

        check_circuit_satisfiability(&mut circuit, out_value.elems(), out_var);
    }

    #[test]
    fn test_rescue_perm() {
        test_rescue_perm_helper::<FqEd254>();
        test_rescue_perm_helper::<FqEd377>();
        test_rescue_perm_helper::<FqEd381>();
    }
    fn test_rescue_perm_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let state_in =
            RescueVector::from(&[F::from(1u32), F::from(2u32), F::from(3u32), F::from(4u32)]);

        let state_in_var = circuit.create_rescue_state_variable(&state_in).unwrap();

        let perm = Permutation::default();
        let state_out = perm.eval(&state_in);

        let out_var = circuit.rescue_permutation(state_in_var).unwrap();

        check_state(&circuit, &out_var, &state_out);

        check_circuit_satisfiability(&mut circuit, state_out.elems(), out_var);
    }

    #[test]
    fn test_add_state() {
        test_add_state_helper::<FqEd254>();
        test_add_state_helper::<FqEd377>();
        test_add_state_helper::<FqEd381>();
    }

    fn test_add_state_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let state1 = RescueVector::from(&[
            F::from(12_u32),
            F::from(7_u32),
            F::from(4_u32),
            F::from(3_u32),
        ]);

        let state2 = RescueVector::from(&[
            F::from(1_u32),
            F::from(2_u32),
            F::from(2555_u32),
            F::from(888_u32),
        ]);

        let input1_var = circuit.create_rescue_state_variable(&state1).unwrap();
        let input2_var = circuit.create_rescue_state_variable(&state2).unwrap();
        let out_var = circuit.add_state(&input1_var, &input2_var).unwrap();

        let out_value: Vec<F> = (0..STATE_SIZE)
            .map(|i| state1.elems()[i] + state2.elems()[i])
            .collect();

        check_state(
            &circuit,
            &out_var,
            &RescueVector::from(out_value.as_slice()),
        );

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the input state
        *circuit.witness_mut(input1_var.0[0]) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Re-establish the input state
        *circuit.witness_mut(input1_var.0[0]) = state1.elems()[0];
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the input state
        *circuit.witness_mut(input2_var.0[0]) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Re-establish the input state
        *circuit.witness_mut(input2_var.0[0]) = state2.elems()[0];
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the output state
        *circuit.witness_mut(out_var.0[1]) = F::from(777_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_prp() {
        test_prp_helper::<FqEd254>();
        test_prp_helper::<FqEd377>();
        test_prp_helper::<FqEd381>();
    }

    fn test_prp_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let prp = PRP::default();
        let mut prng = jf_utils::test_rng();
        let key_vec = RescueVector::from(&[
            F::rand(&mut prng),
            F::rand(&mut prng),
            F::rand(&mut prng),
            F::rand(&mut prng),
        ]);
        let input_vec = RescueVector::from(&[
            F::rand(&mut prng),
            F::rand(&mut prng),
            F::rand(&mut prng),
            F::rand(&mut prng),
        ]);
        let key_var = circuit.create_rescue_state_variable(&key_vec).unwrap();
        let input_var = circuit.create_rescue_state_variable(&input_vec).unwrap();
        let out_var = circuit.prp(&key_var, &input_var).unwrap();

        let out_val = prp.prp(&key_vec, &input_vec);

        // Check consistency between witness[input_var] and input_vec
        check_state(&circuit, &input_var, &input_vec);

        // Check consistency between witness[key_var] and key_vec
        check_state(&circuit, &key_var, &key_vec);

        // Check consistency between witness[out_var] and rescue cipher output
        check_state(&circuit, &out_var, &out_val);

        // Check good witness
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Check bad witness
        // Alter the input state
        *circuit.witness_mut(key_var.0[0]) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_rescue_sponge_no_padding_single_output() {
        test_rescue_sponge_no_padding_single_output_helper::<FqEd254>();
        test_rescue_sponge_no_padding_single_output_helper::<FqEd377>();
        test_rescue_sponge_no_padding_single_output_helper::<FqEd381>();
    }
    fn test_rescue_sponge_no_padding_single_output_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::new_turbo_plonk();

        let mut prng = jf_utils::test_rng();
        let data = (0..2 * CRHF_RATE).map(|_| F::rand(&mut prng)).collect_vec();
        let data_vars = data
            .iter()
            .map(|&x| circuit.create_variable(x).unwrap())
            .collect_vec();

        let expected_sponge = RescueCRHF::sponge_no_padding(&data, 1).unwrap()[0];
        let sponge_var = RescueNativeGadget::<F>::rescue_sponge_no_padding(
            &mut circuit,
            data_vars.as_slice(),
            1,
        )
        .unwrap()[0];

        assert_eq!(expected_sponge, circuit.witness(sponge_var).unwrap());

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        *circuit.witness_mut(sponge_var) = F::from(1_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // If the data length is not a multiple of RATE==3 then an error is triggered
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let size = 2 * CRHF_RATE + 1; // Non multiple of RATE
        let data = (0..size).map(|_| F::rand(&mut prng)).collect_vec();
        let data_vars = data
            .iter()
            .map(|&x| circuit.create_variable(x).unwrap())
            .collect_vec();

        assert!(RescueNativeGadget::<F>::rescue_sponge_no_padding(
            &mut circuit,
            data_vars.as_slice(),
            1
        )
        .is_err());
    }

    #[test]
    fn test_rescue_sponge_no_padding() {
        test_rescue_sponge_no_padding_helper::<FqEd254>();
        test_rescue_sponge_no_padding_helper::<FqEd377>();
        test_rescue_sponge_no_padding_helper::<FqEd381>();
    }
    fn test_rescue_sponge_no_padding_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::new_turbo_plonk();

        let rate = 3;

        let input_vec = vec![F::from(11_u32), F::from(144_u32), F::from(87_u32)];
        let input_var = [
            circuit.create_variable(input_vec[0]).unwrap(),
            circuit.create_variable(input_vec[1]).unwrap(),
            circuit.create_variable(input_vec[2]).unwrap(),
        ];

        for output_len in 1..10 {
            let out_var = RescueNativeGadget::<F>::rescue_sponge_no_padding(
                &mut circuit,
                &input_var,
                output_len,
            )
            .unwrap();

            // Check consistency between inputs
            for i in 0..rate {
                assert_eq!(input_vec[i], circuit.witness(input_var[i]).unwrap());
            }

            // Check consistency between outputs
            let expected_hash = RescueCRHF::sponge_no_padding(&input_vec, output_len).unwrap();

            for (e, f) in out_var.iter().zip(expected_hash.iter()) {
                assert_eq!(*f, circuit.witness(*e).unwrap());
            }

            // Check constraints
            // good path
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            // bad path: incorrect output
            let w = circuit.witness(out_var[0]).unwrap();
            *circuit.witness_mut(out_var[0]) = F::from(1_u32);
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(out_var[0]) = w;
        }

        // bad path: incorrect number of inputs
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let input_vec = vec![
            F::from(11_u32),
            F::from(144_u32),
            F::from(87_u32),
            F::from(45_u32),
        ];
        let input_var = [
            circuit.create_variable(input_vec[0]).unwrap(),
            circuit.create_variable(input_vec[1]).unwrap(),
            circuit.create_variable(input_vec[2]).unwrap(),
            circuit.create_variable(input_vec[3]).unwrap(),
        ];
        assert!(
            RescueNativeGadget::<F>::rescue_sponge_no_padding(&mut circuit, &input_var, 1).is_err()
        );
    }

    #[test]
    fn test_rescue_sponge_with_padding() {
        test_rescue_sponge_with_padding_helper::<FqEd254>();
        test_rescue_sponge_with_padding_helper::<FqEd377>();
        test_rescue_sponge_with_padding_helper::<FqEd381>();
    }
    fn test_rescue_sponge_with_padding_helper<F: RescueParameter>() {
        for input_len in 1..10 {
            for output_len in 1..10 {
                let mut circuit = PlonkCircuit::new_turbo_plonk();

                let input_vec: Vec<F> = (0..input_len).map(|i| F::from((i + 10) as u32)).collect();
                let input_var: Vec<Variable> = input_vec
                    .iter()
                    .map(|x| circuit.create_variable(*x).unwrap())
                    .collect();

                let out_var = RescueNativeGadget::<F>::rescue_sponge_with_padding(
                    &mut circuit,
                    &input_var,
                    output_len,
                )
                .unwrap();

                // Check consistency between inputs
                for i in 0..input_len {
                    assert_eq!(input_vec[i], circuit.witness(input_var[i]).unwrap());
                }

                // Check consistency between outputs
                let expected_hash = RescueCRHF::sponge_with_bit_padding(&input_vec, output_len);

                for (&e, &f) in expected_hash.iter().zip(out_var.iter()) {
                    assert_eq!(e, circuit.witness(f).unwrap());
                }

                // Check constraints
                // good path
                assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
                // bad path: incorrect output
                let w = circuit.witness(out_var[0]).unwrap();
                *circuit.witness_mut(out_var[0]) = F::from(1_u32);
                assert!(circuit.check_circuit_satisfiability(&[]).is_err());
                *circuit.witness_mut(out_var[0]) = w;
            }
        }
    }

    #[test]
    fn test_fsks() {
        test_fsks_helper::<FqEd254>();
        test_fsks_helper::<FqEd377>();
        test_fsks_helper::<FqEd381>();
    }
    fn test_fsks_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let mut prng = jf_utils::test_rng();
        let key = F::rand(&mut prng);
        let key_var = circuit.create_variable(key).unwrap();
        let input_len = 8;
        let data: Vec<F> = (0..input_len).map(|_| F::rand(&mut prng)).collect_vec();
        let data_vars: Vec<Variable> = data
            .iter()
            .map(|&x| circuit.create_variable(x).unwrap())
            .collect_vec();

        let expected_fsks_output =
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &data, 1).unwrap();

        let fsks_var = RescueNativeGadget::<F>::rescue_full_state_keyed_sponge_no_padding(
            &mut circuit,
            key_var,
            &data_vars,
        )
        .unwrap();

        // Check prf output consistency
        assert_eq!(expected_fsks_output[0], circuit.witness(fsks_var).unwrap());

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(fsks_var) = F::from(1_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // make data_vars of bad length
        let mut data_vars = data_vars;
        data_vars.push(circuit.zero());
        assert!(
            RescueNativeGadget::<F>::rescue_full_state_keyed_sponge_no_padding(
                &mut circuit,
                key_var,
                &data_vars
            )
            .is_err()
        );
    }
}
