// Copyright (c) 2022 Espresso Systems (goespresso.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements rescue circuit with non-native arithmetics.
//! The overall structure of the module mimics what is in rescue.rs
//! The major adjustment is to move from `Variable`s (that are native to
//! a plonk circuit) to `FpElemVar`s that are non-native to the circuit.

use crate::{
    circuit::{
        customized::ultraplonk::mod_arith::{FpElem, FpElemVar},
        Circuit, PlonkCircuit,
    },
    errors::{CircuitError::ParameterError, PlonkError},
};
use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_std::{format, string::ToString, vec, vec::Vec};
use itertools::Itertools;
use jf_rescue::{
    Permutation, RescueMatrix, RescueParameter, RescueVector, PRP, ROUNDS, STATE_SIZE,
};
use jf_utils::{compute_len_to_next_multiple, field_switching};

/// Array of variables representing a Rescue state (4 field elements), and also
/// the modulus of the non-native evaluating field.
#[derive(Clone, Debug)]
pub struct RescueNonNativeStateVar<F: PrimeField> {
    pub(crate) state: [FpElemVar<F>; STATE_SIZE],
    pub(crate) modulus: FpElem<F>,
}

/// Trait for rescue circuit over non-native field.
pub trait RescueNonNativeGadget<F: PrimeField> {
    /// Given an input state st_0 and an output state st_1, ensure that st_1 =
    /// rescue_permutation(st_0)  where rescue_permutation is the instance
    /// of the Rescue permutation defined by its respective constants
    /// * `input_var` - variables corresponding to the input state
    /// * `returns` - variables corresponding to the output state
    fn rescue_permutation<T: RescueParameter>(
        &mut self,
        input_var: RescueNonNativeStateVar<F>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError>;

    /// Rescue based Pseudo Random Permutation (PRP)
    /// * `key_var` - rescue state variable corresponding to the cipher key
    /// * `input_var` - rescue state variable corresponding to the plaintext
    /// * `returns` - state variable corresponding to the cipher text
    fn prp<T: RescueParameter>(
        &mut self,
        key_var: &RescueNonNativeStateVar<F>,
        input_var: &RescueNonNativeStateVar<F>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError>;

    /// Sponge-based hashes from Rescue permutations
    /// * `data_vars` - sponge input variables, `data_vars.len()` should be a
    ///   positive integer that is a multiple of the sponge rate (i.e. 3)
    /// * `num_output` - number of output variables
    /// * `returns` - a vector of variables that refers to the sponge hash
    ///   output
    fn rescue_sponge_no_padding<T: RescueParameter>(
        &mut self,
        data_vars: &[FpElemVar<F>],
        num_output: usize,
    ) -> Result<Vec<FpElemVar<F>>, PlonkError>;

    /// Sponge-based hashes from Rescue permutations
    /// * `data_vars` - sponge input variables,
    /// * `num_output` - number of output variables
    /// * `returns` - a vector of variables that refers to the sponge hash
    ///   output
    fn rescue_sponge_with_padding<T: RescueParameter>(
        &mut self,
        data_vars: &[FpElemVar<F>],
        num_output: usize,
    ) -> Result<Vec<FpElemVar<F>>, PlonkError>;

    /// Full-State-Keyed-Sponge with a single output
    /// * `key` - key variable
    /// * `input` - input variables,
    /// * `returns` a variable that refers to the output
    fn rescue_full_state_keyed_sponge_no_padding<T: RescueParameter>(
        &mut self,
        key: FpElemVar<F>,
        data_vars: &[FpElemVar<F>],
    ) -> Result<FpElemVar<F>, PlonkError>;
}

impl<F> RescueNonNativeGadget<F> for PlonkCircuit<F>
where
    F: PrimeField,
{
    fn rescue_permutation<T: RescueParameter>(
        &mut self,
        input_var: RescueNonNativeStateVar<F>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        let permutation = Permutation::<T>::default();
        let keys = permutation.round_keys_ref();
        let keys = keys
            .iter()
            .map(|key| RescueVector::from(key.elems().as_slice()))
            .collect_vec();
        let mds_matrix = permutation.mds_matrix_ref();

        self.permutation_with_const_round_keys(input_var, mds_matrix, keys.as_slice())
    }

    fn prp<T: RescueParameter>(
        &mut self,
        key_var: &RescueNonNativeStateVar<F>,
        input_var: &RescueNonNativeStateVar<F>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        let prp_instance = PRP::<T>::default();
        let mds_states = prp_instance.mds_matrix_ref();
        let keys_vars = self.key_schedule(mds_states, key_var, &prp_instance)?;
        self.prp_with_round_keys(input_var, mds_states, &keys_vars)
    }

    fn rescue_sponge_with_padding<T: RescueParameter>(
        &mut self,
        data_vars: &[FpElemVar<F>],
        num_output: usize,
    ) -> Result<Vec<FpElemVar<F>>, PlonkError> {
        if data_vars.is_empty() {
            return Err(ParameterError("empty data vars".to_string()).into());
        }

        let m = data_vars[0].param_m();
        let two_power_m = data_vars[0].two_power_m();

        let one_var = FpElemVar::<F>::one(self, m, Some(two_power_m));
        let zero_var = FpElemVar::<F>::zero(self, m, Some(two_power_m));
        let rate = STATE_SIZE - 1;
        let data_len = compute_len_to_next_multiple(data_vars.len() + 1, rate);

        let data_vars = [
            data_vars,
            &[one_var],
            vec![zero_var; data_len - data_vars.len() - 1].as_ref(),
        ]
        .concat();

        self.rescue_sponge_no_padding::<T>(&data_vars, num_output)
    }

    fn rescue_sponge_no_padding<T: RescueParameter>(
        &mut self,
        data_vars: &[FpElemVar<F>],
        num_output: usize,
    ) -> Result<Vec<FpElemVar<F>>, PlonkError> {
        if (data_vars.is_empty()) || (data_vars.len() % (STATE_SIZE - 1) != 0) {
            return Err(ParameterError("data_vars".to_string()).into());
        }

        let rate = STATE_SIZE - 1;

        // parameter m and 2^m
        let m = data_vars[0].param_m();
        let two_power_m = Some(data_vars[0].two_power_m());

        let zero_var = FpElemVar::<F>::zero(self, m, two_power_m);

        // TODO(ZZ): hmmm think of a way to pre-compute modulus in FpELem
        // Doesn't save #constraints though
        // move the modulus to the right field
        let t_modulus = F::from_le_bytes_mod_order(T::Params::MODULUS.to_bytes_le().as_ref());
        let modulus = FpElem::new(&t_modulus, m, two_power_m)?;

        // ABSORB PHASE
        let mut state_var = RescueNonNativeStateVar {
            state: [data_vars[0], data_vars[1], data_vars[2], zero_var],
            modulus,
        };
        state_var = self.rescue_permutation::<T>(state_var)?;

        for block in data_vars[rate..].chunks_exact(rate) {
            state_var = self.add_state(
                &state_var,
                &RescueNonNativeStateVar {
                    state: [block[0], block[1], block[2], zero_var],
                    modulus,
                },
            )?;
            state_var = self.rescue_permutation::<T>(state_var)?;
        }
        // SQUEEZE PHASE
        let mut result = vec![];
        let mut remaining = num_output;
        // extract current rate before calling PRP again
        loop {
            let extract = remaining.min(rate);
            result.extend_from_slice(&state_var.state[0..extract]);
            remaining -= extract;
            if remaining == 0 {
                break;
            }
            state_var = self.rescue_permutation::<T>(state_var)?;
        }

        Ok(result)
    }

    fn rescue_full_state_keyed_sponge_no_padding<T: RescueParameter>(
        &mut self,
        key: FpElemVar<F>,
        data_vars: &[FpElemVar<F>],
    ) -> Result<FpElemVar<F>, PlonkError> {
        if data_vars.len() % STATE_SIZE != 0 {
            return Err(ParameterError(format!(
                "Bad input length for FSKS circuit: {:}, it must be multiple of STATE_SIZE",
                data_vars.len()
            ))
            .into());
        }

        // parameter m and 2^m
        let m = data_vars[0].param_m();
        let two_power_m = Some(data_vars[0].two_power_m());

        let zero_var = FpElemVar::zero(self, m, two_power_m);

        // TODO(ZZ): hmmm think of a way to pre-compute modulus in FpELem
        // Doesn't save #constraints though
        // move the modulus to the right field
        let t_modulus = F::from_le_bytes_mod_order(T::Params::MODULUS.to_bytes_le().as_ref());
        let modulus = FpElem::new(&t_modulus, m, two_power_m)?;

        // set key
        let mut state = RescueNonNativeStateVar {
            state: [zero_var, zero_var, zero_var, key],
            modulus,
        };

        // absorb phase
        let chunks = data_vars.chunks_exact(STATE_SIZE);
        for chunk in chunks {
            let chunk_var = RescueNonNativeStateVar {
                state: [chunk[0], chunk[1], chunk[2], chunk[3]],
                modulus,
            };
            state = self.add_state(&state, &chunk_var)?;
            state = self.rescue_permutation::<T>(state)?;
        }
        // squeeze phase, but only a single output, can return directly from state
        Ok(state.state[0])
    }
}

pub(crate) trait RescueNonNativeHelperGadget<F: PrimeField>: Circuit<F> {
    fn check_var_bound_rescue_state(
        &self,
        rescue_state: &RescueNonNativeStateVar<F>,
    ) -> Result<(), PlonkError>;

    fn create_rescue_state_variable<T: RescueParameter>(
        &mut self,
        state: &RescueVector<T>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError>;

    fn add_constant_state<T: RescueParameter>(
        &mut self,
        input_var: &RescueNonNativeStateVar<F>,
        constant: &RescueVector<T>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError>;

    fn add_state(
        &mut self,
        left_state_var: &RescueNonNativeStateVar<F>,
        right_state_var: &RescueNonNativeStateVar<F>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError>;

    /// Given a state st_0=(x_1,...,x_w) and st_1=(y_1,...,y_w),
    /// add the constraints that ensure we have y_i=x_i ^{1/11} for i in
    /// [1,...,w]
    /// * `input_var` - rescue state variables st_0
    /// * `returns` - rescue state variables st_1
    fn pow_alpha_inv_state<T: RescueParameter>(
        &mut self,
        input_var: &RescueNonNativeStateVar<F>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError>;

    /// Given an input state st_0 and an output state st_1, ensure that st_1 = M
    /// st_0 + C where M is a Rescue matrix and c is a constant vector
    /// * `input_var` - variables corresponding to the input state
    /// * `matrix` - matrix M in the description above
    /// * `constant` - constant c in the description above
    /// * `returns` - variables corresponding to the output state
    fn affine_transform<T: RescueParameter>(
        &mut self,
        input_var: &RescueNonNativeStateVar<F>,
        matrix: &RescueMatrix<T>,
        constant: &RescueVector<T>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError>;

    /// Given an input state st_0=(x_1,...,x_w) and an output state
    /// st_1=(y_1,...,y_m) y_i = \sum_{j=1}^w M_{i,j}x_j^alpha+c_i for all i in
    /// [1,..,w] where M is a Rescue matrix and c=(c_1,...,c_w) is a
    /// constant vector
    /// * `input_var` - variables corresponding to the input state
    /// * `matrix` - matrix M in the description above
    /// * `constant` - constant c in the description above
    /// * `returns` - variables corresponding to the output state
    fn non_linear_transform<T: RescueParameter>(
        &mut self,
        input_var: &RescueNonNativeStateVar<F>,
        matrix: &RescueMatrix<T>,
        constant: &RescueVector<T>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError>;

    /// Define a constraint such that y = x^(1/alpha).
    /// It is implemented by setting q_{H1} y^alpha = q_O x
    /// * `input_var`  - variable id corresponding to x in the equation above
    /// * `returns` - the variable id corresponding to y
    fn pow_alpha_inv<T: RescueParameter>(
        &mut self,
        input_var: FpElemVar<F>,
    ) -> Result<FpElemVar<F>, PlonkError>;

    /// Return the round keys variables for the Rescue block cipher
    /// * `mds_states` - Rescue MDS matrix
    /// * `key_var` - state variable representing the cipher key
    /// * `returns` - state variables corresponding to the scheduled keys
    fn key_schedule<T: RescueParameter>(
        &mut self,
        mds_states: &RescueMatrix<T>,
        key_var: &RescueNonNativeStateVar<F>,
        prp_instance: &PRP<T>,
    ) -> Result<Vec<RescueNonNativeStateVar<F>>, PlonkError>;

    /// Return the variable corresponding to the output of the of the Rescue
    /// PRP where the rounds keys have already been computed "dynamically"
    /// * `input_var` - variable corresponding to the plain text
    /// * `mds_states` - Rescue MDS matrix
    /// * `key_vars` - variables corresponding to the scheduled keys
    /// * `returns` -
    fn prp_with_round_keys<T: RescueParameter>(
        &mut self,
        input_var: &RescueNonNativeStateVar<F>,
        mds: &RescueMatrix<T>,
        keys_vars: &[RescueNonNativeStateVar<F>],
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        if (keys_vars.len() != 2 * ROUNDS + 1) || (mds.len() != STATE_SIZE) {
            return Err(PlonkError::CircuitError(ParameterError(
                "data_vars".to_string(),
            )));
        }

        let zero_state = RescueVector::from(&[T::zero(); STATE_SIZE]);
        let mut state_var = self.add_state(input_var, &keys_vars[0])?;
        for (r, key_var) in keys_vars.iter().skip(1).enumerate() {
            if r % 2 == 0 {
                state_var = self.pow_alpha_inv_state::<T>(&state_var)?;
                state_var = self.affine_transform(&state_var, mds, &zero_state)?;
            } else {
                state_var = self.non_linear_transform(&state_var, mds, &zero_state)?;
            }

            state_var = self.add_state(&state_var, key_var)?;
        }
        Ok(state_var)
    }

    /// Given an input state st_0 and an output state st_1, ensure that st_1 is
    /// obtained by applying the rescue permutation with a specific  list of
    /// round keys (i.e. the keys are constants) and a matrix
    /// * `input_var` - variables corresponding to the input state
    /// * `mds` - Rescue matrix
    /// * `round_keys` - list of round keys
    /// * `returns` - variables corresponding to the output state
    fn permutation_with_const_round_keys<T: RescueParameter>(
        &mut self,
        input_var: RescueNonNativeStateVar<F>,
        mds: &RescueMatrix<T>,
        round_keys: &[RescueVector<T>],
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        if (round_keys.len() != 2 * ROUNDS + 1) || (mds.len() != STATE_SIZE) {
            return Err(PlonkError::CircuitError(ParameterError(
                "data_vars".to_string(),
            )));
        }

        let mut state_var = self.add_constant_state(&input_var, &round_keys[0])?;
        for (r, key) in round_keys.iter().skip(1).enumerate() {
            if r % 2 == 0 {
                state_var = self.pow_alpha_inv_state::<T>(&state_var)?;
                state_var = self.affine_transform(&state_var, mds, key)?;
            } else {
                state_var = self.non_linear_transform(&state_var, mds, key)?;
            }
        }
        Ok(state_var)
    }
}

impl<F> RescueNonNativeHelperGadget<F> for PlonkCircuit<F>
where
    F: PrimeField,
{
    fn check_var_bound_rescue_state(
        &self,
        non_native_rescue_state: &RescueNonNativeStateVar<F>,
    ) -> Result<(), PlonkError> {
        for elem_var in &non_native_rescue_state.state {
            let vars = elem_var.components();
            self.check_var_bound(vars.0)?;
            self.check_var_bound(vars.1)?;
        }
        Ok(())
    }

    fn add_constant_state<T: RescueParameter>(
        &mut self,
        input_var: &RescueNonNativeStateVar<F>,
        constant: &RescueVector<T>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        // Check bounds for every variable
        self.check_var_bound_rescue_state(input_var)?;

        // move constant to the plonk field
        let constant_f: Vec<F> = constant
            .elems()
            .iter()
            .map(|x| field_switching::<T, F>(x))
            .collect();

        let constant_split: Vec<FpElem<F>> = constant_f
            .iter()
            .map(|x| {
                FpElem::new(
                    x,
                    input_var.state[0].param_m(),
                    Some(input_var.state[0].two_power_m()),
                )
            })
            .collect::<Result<Vec<FpElem<F>>, _>>()?;

        // add constant to input
        let mut state = [FpElemVar::default(); STATE_SIZE];
        for (z, (x, y)) in state
            .iter_mut()
            .zip(input_var.state.iter().zip(constant_split.iter()))
        {
            *z = self.mod_add_constant(x, y, &input_var.modulus)?
        }

        Ok(RescueNonNativeStateVar {
            state,
            modulus: input_var.modulus,
        })
    }

    fn pow_alpha_inv_state<T: RescueParameter>(
        &mut self,
        input_var: &RescueNonNativeStateVar<F>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        // Check bounds for every variable
        self.check_var_bound_rescue_state(input_var)?;

        let mut state = [FpElemVar::default(); STATE_SIZE];
        for (e, f) in state.iter_mut().zip(input_var.state.iter()) {
            *e = self.pow_alpha_inv::<T>(*f)?;
        }

        Ok(RescueNonNativeStateVar {
            state,
            modulus: input_var.modulus,
        })
    }

    fn affine_transform<T: RescueParameter>(
        &mut self,
        input_var: &RescueNonNativeStateVar<F>,
        matrix: &RescueMatrix<T>,
        constant: &RescueVector<T>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        // Check bounds for every variable
        self.check_var_bound_rescue_state(input_var)?;

        let m = input_var.state[0].param_m();

        // 1.1 prepare the input vector
        let input_fp_elem = input_var.state;

        let input_val_fields_elems_f: Vec<F> = input_fp_elem
            .iter()
            .map(|x| x.witness(self))
            .collect::<Result<Vec<F>, PlonkError>>()?;

        let input_val_fields_elems_t: Vec<T> = input_val_fields_elems_f
            .iter()
            .map(|x| field_switching::<F, T>(x))
            .collect();

        let input_val = RescueVector::from(input_val_fields_elems_t.as_slice());

        // 1.2 prepare the constant vector
        let constant_fp_elem: Vec<FpElem<F>> = constant
            .elems()
            .iter()
            .map(|x| {
                FpElem::new(
                    &field_switching::<T, F>(x),
                    m,
                    Some(input_fp_elem[0].two_power_m()),
                )
            })
            .collect::<Result<Vec<FpElem<F>>, _>>()?;

        // 1.3 prepare the output vector
        let mut output_val_t = input_val;
        output_val_t.linear(matrix, constant);

        let mut output_fp_elem = [FpElemVar::<F>::default(); STATE_SIZE];
        for (fp_elem, var) in output_fp_elem.iter_mut().zip(output_val_t.elems().iter()) {
            *fp_elem = FpElemVar::new_from_field_element(
                self,
                &field_switching::<T, F>(var),
                m,
                Some(input_fp_elem[0].two_power_m()),
            )?;
        }

        // 2. equality statement
        for i in 0..STATE_SIZE {
            // 2.1 prepare matrix vector
            // matrix vectors are public constants to the circuit
            // so we do not need to create variables for them
            let matrix_vec_i_t = matrix.vec(i);
            let vec_fp_elem: Vec<FpElem<F>> = matrix_vec_i_t
                .elems()
                .iter()
                .map(|x| {
                    FpElem::new(
                        &field_switching::<T, F>(x),
                        m,
                        Some(input_fp_elem[0].two_power_m()),
                    )
                })
                .collect::<Result<Vec<FpElem<F>>, _>>()?;

            // 2.2 output = <input, matrix[i]> + c[i]
            let output_var2 = self.non_native_linear_gen::<T>(
                &input_fp_elem,
                &vec_fp_elem,
                &constant_fp_elem[i],
            )?;
            self.equal_gate(output_fp_elem[i].components().0, output_var2.components().0)?;
            self.equal_gate(output_fp_elem[i].components().1, output_var2.components().1)?;
        }
        Ok(RescueNonNativeStateVar {
            state: output_fp_elem,
            modulus: input_var.modulus,
        })
    }

    fn non_linear_transform<T: RescueParameter>(
        &mut self,
        input_var: &RescueNonNativeStateVar<F>,
        matrix: &RescueMatrix<T>,
        constant: &RescueVector<T>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        let m = input_var.modulus.param_m();

        // Check bounds for every variable
        self.check_var_bound_rescue_state(input_var)?;

        // 1 prepare the input vector
        let input_fp_elem_var = input_var.state;

        let input_val_fields_elems_f: Vec<F> = input_fp_elem_var
            .iter()
            .map(|x| x.witness(self))
            .collect::<Result<Vec<F>, PlonkError>>()?;

        let input_val_fields_elems_t: Vec<T> = input_val_fields_elems_f
            .iter()
            .map(|x| field_switching::<F, T>(x))
            .collect();

        if T::A == 11 {
            // generate the `power 11 vector` and its wires
            let mut input_power_11_vars = RescueNonNativeStateVar {
                state: [FpElemVar::default(); STATE_SIZE],
                modulus: input_var.modulus,
            };
            for i in 0..STATE_SIZE {
                let power_eleventh_t = input_val_fields_elems_t[i].pow(&[T::A]);
                let power_eleventh_f = field_switching::<T, F>(&power_eleventh_t);
                let power_eleventh_fp_elem_var = FpElemVar::new_from_field_element(
                    self,
                    &power_eleventh_f,
                    m,
                    Some(input_fp_elem_var[0].two_power_m()),
                )?;

                self.non_native_power_11_gate::<T>(
                    &input_fp_elem_var[i],
                    &power_eleventh_fp_elem_var,
                )?;
                input_power_11_vars.state[i] = power_eleventh_fp_elem_var;
            }
            // perform linear transformation
            self.affine_transform(&input_power_11_vars, matrix, constant)
        } else {
            // Note that we do not support for alpha = 5 which will be the
            // parameter for bn254 and bls12-381 curves.
            // The target use case of this non-native circuit is
            // bls12-377 which only requires alpha = 11.
            Err(PlonkError::InvalidParameters(
                "incorrect Rescue parameters".to_string(),
            ))
        }
    }

    fn pow_alpha_inv<T: RescueParameter>(
        &mut self,
        input_var: FpElemVar<F>,
    ) -> Result<FpElemVar<F>, PlonkError> {
        self.check_var_bound(input_var.components().0)?;
        self.check_var_bound(input_var.components().1)?;

        if T::A == 11 {
            // recover the field element y and compute y^-11
            let input_f = input_var.witness(self)?;
            let input_t = field_switching::<F, T>(&input_f);

            // generate the 11-th root and move back to F
            let eleventh_root_t = input_t.pow(T::A_INV);
            let eleventh_root_f = field_switching::<T, F>(&eleventh_root_t);
            let output_var = FpElemVar::new_from_field_element(
                self,
                &eleventh_root_f,
                input_var.param_m(),
                Some(input_var.two_power_m()),
            )?;

            // ensure input = output^11
            self.non_native_power_11_gate::<T>(&output_var, &input_var)?;
            Ok(output_var)
        } else {
            // Note that we do not support for alpha = 5 which will be the
            // parameter for bn254 and bls12-381 curves.
            // The target use case of this non-native circuit is
            // bls12-377 which only requires alpha = 11.
            Err(PlonkError::InvalidParameters(
                "incorrect Rescue parameters".to_string(),
            ))
        }
    }

    fn create_rescue_state_variable<T: RescueParameter>(
        &mut self,
        state: &RescueVector<T>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        // parameter m
        let m = (T::size_in_bits() / 2 / self.range_bit_len()? + 1) * self.range_bit_len()?;

        // move the modulus to the right field
        let t_modulus = F::from_le_bytes_mod_order(T::Params::MODULUS.to_bytes_le().as_ref());
        let t = FpElem::new(&t_modulus, m, None)?;

        // move rescue state to the plonk field
        let state_f: Vec<F> = state
            .elems()
            .iter()
            .map(|x| field_switching::<T, F>(x))
            .collect();

        // create vars for states
        let mut state_split_var = [FpElemVar::<F>::default(); STATE_SIZE];
        for (var, f) in state_split_var.iter_mut().zip(state_f.iter()) {
            *var = FpElemVar::new_from_field_element(self, f, m, Some(t.two_power_m()))?;
        }

        Ok(RescueNonNativeStateVar {
            state: state_split_var,
            modulus: t,
        })
    }

    fn add_state(
        &mut self,
        left_state_var: &RescueNonNativeStateVar<F>,
        right_state_var: &RescueNonNativeStateVar<F>,
    ) -> Result<RescueNonNativeStateVar<F>, PlonkError> {
        self.check_var_bound_rescue_state(left_state_var)?;
        self.check_var_bound_rescue_state(right_state_var)?;

        if left_state_var.modulus != right_state_var.modulus {
            return Err(PlonkError::InvalidParameters(
                "Rescue modulus do not match".to_string(),
            ));
        }
        let modulus = left_state_var.modulus;

        let output_var: Vec<FpElemVar<F>> = left_state_var
            .state
            .iter()
            .zip(right_state_var.state.iter())
            .map(|(&left_var, &right_var)| -> Result<_, PlonkError> {
                self.mod_add(&left_var, &right_var, &modulus)
            })
            .collect::<Result<Vec<FpElemVar<F>>, _>>()?;

        Ok(RescueNonNativeStateVar {
            state: [output_var[0], output_var[1], output_var[2], output_var[3]],
            modulus,
        })
    }

    fn key_schedule<T: RescueParameter>(
        &mut self,
        mds: &RescueMatrix<T>,
        key_var: &RescueNonNativeStateVar<F>,
        prp_instance: &PRP<T>,
    ) -> Result<Vec<RescueNonNativeStateVar<F>>, PlonkError> {
        let mut aux = *prp_instance.init_vec_ref();
        let key_injection_vec = prp_instance.key_injection_vec_ref();

        let mut key_state_var = self.add_constant_state(key_var, &aux)?;
        let mut result = vec![key_state_var.clone()];

        for (r, key_injection_item) in key_injection_vec.iter().enumerate() {
            aux.linear(mds, key_injection_item);
            if r % 2 == 0 {
                key_state_var = self.pow_alpha_inv_state::<T>(&key_state_var)?;
                key_state_var = self.affine_transform(&key_state_var, mds, key_injection_item)?;
            } else {
                key_state_var =
                    self.non_linear_transform(&key_state_var, mds, key_injection_item)?;
            }
            result.push(key_state_var.clone());
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {

    use super::{RescueNonNativeGadget, RescueNonNativeHelperGadget, RescueNonNativeStateVar};
    use crate::circuit::{
        customized::ultraplonk::mod_arith::{FpElem, FpElemVar},
        Circuit, PlonkCircuit,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ff::PrimeField;
    use ark_std::{vec, vec::Vec};
    use itertools::Itertools;
    use jf_rescue::{
        Permutation, RescueMatrix, RescueParameter, RescueVector, PRP, RATE, STATE_SIZE,
    };
    use jf_utils::field_switching;

    const RANGE_BIT_LEN_FOR_TEST: usize = 8;

    fn gen_state_matrix_constant<T: RescueParameter>(
    ) -> (RescueVector<T>, RescueMatrix<T>, RescueVector<T>) {
        let state_in =
            RescueVector::from(&[T::from(12u32), T::from(2u32), T::from(8u32), T::from(9u32)]);

        let matrix = RescueMatrix::from(&[
            RescueVector::from(&[T::from(2u32), T::from(3u32), T::from(4u32), T::from(5u32)]),
            RescueVector::from(&[T::from(3u32), T::from(3u32), T::from(3u32), T::from(3u32)]),
            RescueVector::from(&[T::from(5u32), T::from(3u32), T::from(5u32), T::from(5u32)]),
            RescueVector::from(&[T::from(1u32), T::from(0u32), T::from(2u32), T::from(17u32)]),
        ]);

        let constant =
            RescueVector::from(&[T::from(2u32), T::from(3u32), T::from(4u32), T::from(5u32)]);

        (state_in, matrix, constant)
    }

    fn check_state<T: RescueParameter, F: PrimeField>(
        circuit: &PlonkCircuit<F>,
        out_var: &RescueNonNativeStateVar<F>,
        out_value: &RescueVector<T>,
    ) {
        let two_power_m = out_var.state[0].two_power_m();
        for i in 0..STATE_SIZE {
            let fp_split_var = out_var.state[i];
            let res = circuit.witness(fp_split_var.components().0).unwrap()
                + circuit.witness(fp_split_var.components().1).unwrap() * two_power_m;
            let res2 = field_switching::<T, F>(&out_value.elems()[i]);

            assert_eq!(res, res2);
        }
    }

    fn check_circuit_satisfiability<T: RescueParameter, F: PrimeField>(
        circuit: &mut PlonkCircuit<F>,
        out_value: Vec<T>,
        out_var: RescueNonNativeStateVar<F>,
    ) {
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        for (i, v) in out_value.iter().enumerate() {
            let v_f = field_switching::<T, F>(v);
            let v_f = FpElem::new(&v_f, out_var.state[i].param_m(), None).unwrap();

            *circuit.witness_mut(out_var.state[i].components().0) = F::from(888_u32);
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(out_var.state[i].components().0) = v_f.components().0;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        }
    }

    #[test]
    fn test_add_constant_state() {
        test_add_constant_state_helper::<FqEd377, Fq377>()
    }
    fn test_add_constant_state_helper<T: RescueParameter, F: PrimeField>() {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let state = RescueVector::from(&[T::from(12_u32), T::one(), T::one(), T::one()]);
        let constant = RescueVector::from(&[T::zero(), T::one(), T::one(), T::one()]);

        let input_var = circuit.create_rescue_state_variable(&state).unwrap();
        let out_var = circuit.add_constant_state(&input_var, &constant).unwrap();

        let out_value: Vec<T> = (0..STATE_SIZE)
            .map(|i| constant.elems()[i] + state.elems()[i])
            .collect();

        check_state(
            &circuit,
            &out_var,
            &RescueVector::<T>::from(out_value.as_slice()),
        );

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the input state
        let witness = circuit.witness(input_var.state[0].components().0).unwrap();
        *circuit.witness_mut(input_var.state[0].components().0) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Restablish the input state
        *circuit.witness_mut(input_var.state[0].components().0) = witness;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the output state
        *circuit.witness_mut(out_var.state[1].components().0) = F::from(888_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_state_inversion() {
        test_state_inversion_helper::<FqEd377, Fq377>()
    }
    fn test_state_inversion_helper<T: RescueParameter, F: PrimeField>() {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let state =
            RescueVector::from(&[T::from(12u32), T::from(2u32), T::from(8u32), T::from(9u32)]);

        let input_var = circuit.create_rescue_state_variable(&state).unwrap();
        let out_var = circuit.pow_alpha_inv_state::<T>(&input_var).unwrap();

        let out_value: Vec<T> = (0..STATE_SIZE)
            .map(|i| state.elems()[i].pow(&T::A_INV))
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
        test_affine_transformation_helper::<FqEd377, Fq377>()
    }

    fn test_affine_transformation_helper<T: RescueParameter, F: PrimeField>() {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let (state_in, matrix, constant) = gen_state_matrix_constant::<T>();

        let input_var = circuit.create_rescue_state_variable(&state_in).unwrap();

        let out_var = circuit
            .affine_transform(&input_var, &matrix, &constant)
            .unwrap();

        let mut out_value = state_in.clone();
        out_value.linear(&matrix, &constant);

        check_state(&circuit, &out_var, &out_value);

        check_circuit_satisfiability(&mut circuit, out_value.elems(), out_var);
    }

    #[test]
    fn test_non_linear_transformation() {
        test_non_linear_transformation_helper::<FqEd377, Fq377>()
    }
    fn test_non_linear_transformation_helper<T: RescueParameter, F: PrimeField>() {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let (state_in, matrix, constant) = gen_state_matrix_constant::<T>();

        let input_var = circuit.create_rescue_state_variable(&state_in).unwrap();

        let out_var = circuit
            .non_linear_transform(&input_var, &matrix, &constant)
            .unwrap();

        let mut out_value = state_in.clone();
        out_value.non_linear(&matrix, &constant);

        check_state(&circuit, &out_var, &out_value);

        check_circuit_satisfiability(&mut circuit, out_value.elems(), out_var);
    }

    #[test]
    fn test_rescue_perm() {
        test_rescue_perm_helper::<FqEd377, Fq377>()
    }
    fn test_rescue_perm_helper<T: RescueParameter, F: PrimeField>() {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let state_in =
            RescueVector::from(&[T::from(1u32), T::from(2u32), T::from(3u32), T::from(4u32)]);

        let state_in_var = circuit.create_rescue_state_variable(&state_in).unwrap();

        let perm = Permutation::<T>::default();
        let state_out = perm.eval(&state_in);

        let out_var = circuit.rescue_permutation::<T>(state_in_var).unwrap();

        check_state(&circuit, &out_var, &state_out);

        check_circuit_satisfiability(&mut circuit, state_out.elems(), out_var);
    }

    #[test]
    fn test_add_state() {
        test_add_state_helper::<FqEd377, Fq377>()
    }

    fn test_add_state_helper<T: RescueParameter, F: PrimeField>() {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let state1 = RescueVector::from(&[
            T::from(12_u32),
            T::from(7_u32),
            T::from(4_u32),
            T::from(3_u32),
        ]);

        let state2 = RescueVector::from(&[
            T::from(1_u32),
            T::from(2_u32),
            T::from(2555_u32),
            T::from(888_u32),
        ]);

        let input1_var = circuit.create_rescue_state_variable(&state1).unwrap();
        let input2_var = circuit.create_rescue_state_variable(&state2).unwrap();
        let out_var = circuit.add_state(&input1_var, &input2_var).unwrap();

        let out_value: Vec<T> = (0..STATE_SIZE)
            .map(|i| state1.elems()[i] + state2.elems()[i])
            .collect();

        check_state(
            &circuit,
            &out_var,
            &RescueVector::from(out_value.as_slice()),
        );

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the input state
        let witness = circuit.witness(input1_var.state[0].components().0).unwrap();
        *circuit.witness_mut(input1_var.state[0].components().0) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Restablish the input state
        *circuit.witness_mut(input1_var.state[0].components().0) = witness;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the input state
        let witness = circuit.witness(input2_var.state[0].components().0).unwrap();
        *circuit.witness_mut(input2_var.state[0].components().0) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Restablish the input state
        *circuit.witness_mut(input2_var.state[0].components().0) = witness;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter the output state
        *circuit.witness_mut(out_var.state[0].components().0) = F::from(777_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_prp() {
        test_prp_helper::<FqEd377, Fq377>()
    }

    fn test_prp_helper<T: RescueParameter, F: PrimeField>() {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let prp = PRP::<T>::default();
        let mut prng = ark_std::test_rng();
        let key_vec = RescueVector::from(&[
            T::rand(&mut prng),
            T::rand(&mut prng),
            T::rand(&mut prng),
            T::rand(&mut prng),
        ]);
        let input_vec = RescueVector::from(&[
            T::rand(&mut prng),
            T::rand(&mut prng),
            T::rand(&mut prng),
            T::rand(&mut prng),
        ]);
        let key_var = circuit.create_rescue_state_variable(&key_vec).unwrap();
        let input_var = circuit.create_rescue_state_variable(&input_vec).unwrap();
        let out_var = circuit.prp::<T>(&key_var, &input_var).unwrap();

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
        *circuit.witness_mut(key_var.state[0].components().0) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_rescue_sponge_no_padding() {
        test_rescue_sponge_no_padding_helper::<FqEd377, Fq377>(true)
    }

    #[test]
    #[ignore]
    fn test_rescue_sponge_no_padding_long() {
        test_rescue_sponge_no_padding_helper::<FqEd377, Fq377>(false)
    }
    fn test_rescue_sponge_no_padding_helper<T: RescueParameter, F: PrimeField>(ignored: bool) {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let max_output_len = if ignored { 3 } else { 10 };
        // parameter m
        let m = (T::size_in_bits() / 2 / RANGE_BIT_LEN_FOR_TEST + 1) * RANGE_BIT_LEN_FOR_TEST;

        let mut prng = ark_std::test_rng();

        // setup the inputs
        let data_t: Vec<T> = (0..2 * RATE).map(|_| T::rand(&mut prng)).collect_vec();
        let data_f: Vec<F> = data_t.iter().map(|x| field_switching(x)).collect();
        let data_vars: Vec<FpElemVar<F>> = data_f
            .iter()
            .map(|x| FpElemVar::new_from_field_element(&mut circuit, x, m, None).unwrap())
            .collect();

        // sponge no padding with output length 1
        let rescue_perm = Permutation::<T>::default();
        let expected_sponge = rescue_perm.sponge_no_padding(&data_t, 1).unwrap()[0];
        let sponge_var = circuit
            .rescue_sponge_no_padding::<T>(data_vars.as_slice(), 1)
            .unwrap()[0];

        assert_eq!(
            field_switching::<T, F>(&expected_sponge),
            sponge_var.witness(&circuit).unwrap()
        );

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        let witness = circuit.witness(sponge_var.components().0).unwrap();
        *circuit.witness_mut(sponge_var.components().0) = F::from(1_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(sponge_var.components().0) = witness;

        // general sponge no padding
        for output_len in 1..max_output_len {
            let rescue_perm = Permutation::<T>::default();
            let expected_sponge = rescue_perm.sponge_no_padding(&data_t, output_len).unwrap();
            let sponge_var = circuit
                .rescue_sponge_no_padding::<T>(data_vars.as_slice(), output_len)
                .unwrap();
            for (e, f) in expected_sponge.iter().zip(sponge_var.iter()) {
                assert_eq!(field_switching::<T, F>(e), f.witness(&circuit).unwrap());
            }

            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            let witness = circuit.witness(sponge_var[0].components().0).unwrap();
            *circuit.witness_mut(sponge_var[0].components().0) = F::from(1_u32);
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(sponge_var[0].components().0) = witness;
        }

        // If the data length is not a multiple of RATE==3 then an error is triggered
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let size = 2 * RATE + 1; // Non multiple of RATE
        let data_t = (0..size).map(|_| T::rand(&mut prng)).collect_vec();
        let data_f: Vec<F> = data_t.iter().map(|x| field_switching(x)).collect();
        let data_vars: Vec<FpElemVar<F>> = data_f
            .iter()
            .map(|x| FpElemVar::new_from_field_element(&mut circuit, x, m, None).unwrap())
            .collect();

        assert!(circuit
            .rescue_sponge_no_padding::<T>(data_vars.as_slice(), 1)
            .is_err());
    }

    #[test]
    fn test_rescue_sponge_with_padding() {
        test_rescue_sponge_with_padding_helper::<FqEd377, Fq377>(true)
    }

    #[test]
    #[ignore]
    fn test_rescue_sponge_with_padding_long() {
        test_rescue_sponge_with_padding_helper::<FqEd377, Fq377>(false)
    }
    fn test_rescue_sponge_with_padding_helper<T: RescueParameter, F: PrimeField>(ignored: bool) {
        // parameter m
        let m = (T::size_in_bits() / 2 / RANGE_BIT_LEN_FOR_TEST + 1) * RANGE_BIT_LEN_FOR_TEST;

        let mut prng = ark_std::test_rng();
        let max_input_len = if ignored { 3 } else { 10 };
        let max_output_len = max_input_len;

        for input_len in 1..max_input_len {
            let mut circuit = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

            // setup the inputs
            let data_t: Vec<T> = (0..input_len).map(|_| T::rand(&mut prng)).collect_vec();
            let data_f: Vec<F> = data_t.iter().map(|x| field_switching(x)).collect();
            let data_vars: Vec<FpElemVar<F>> = data_f
                .iter()
                .map(|x| FpElemVar::new_from_field_element(&mut circuit, x, m, None).unwrap())
                .collect();

            let rescue_perm = Permutation::<T>::default();
            let expected_sponge = rescue_perm.sponge_with_padding(&data_t, 1);

            // sponge with padding
            let sponge_var = circuit
                .rescue_sponge_with_padding::<T>(data_vars.as_slice(), 1)
                .unwrap()[0];

            assert_eq!(
                field_switching::<T, F>(&expected_sponge[0]),
                sponge_var.witness(&circuit).unwrap()
            );

            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            let witness = circuit.witness(sponge_var.components().0).unwrap();
            *circuit.witness_mut(sponge_var.components().0) = F::from(1_u32);
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(sponge_var.components().0) = witness;

            // sponge full with padding
            for output_len in 1..max_output_len {
                let rescue_perm = Permutation::<T>::default();
                let expected_sponge = rescue_perm.sponge_with_padding(&data_t, output_len);

                let sponge_var = circuit
                    .rescue_sponge_with_padding::<T>(data_vars.as_slice(), output_len)
                    .unwrap();

                for (e, f) in expected_sponge.iter().zip(sponge_var.iter()) {
                    assert_eq!(field_switching::<T, F>(e), f.witness(&circuit).unwrap());
                }

                assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

                let witness = circuit.witness(sponge_var[0].components().0).unwrap();
                *circuit.witness_mut(sponge_var[0].components().0) = F::from(1_u32);
                assert!(circuit.check_circuit_satisfiability(&[]).is_err());
                *circuit.witness_mut(sponge_var[0].components().0) = witness;
            }
        }
    }

    #[test]
    fn test_rescue_hash() {
        test_rescue_hash_helper::<FqEd377, Fq377>()
    }
    fn test_rescue_hash_helper<T: RescueParameter, F: PrimeField>() {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        // parameter m
        let m = (T::size_in_bits() / 2 / RANGE_BIT_LEN_FOR_TEST + 1) * RANGE_BIT_LEN_FOR_TEST;

        let rate = 3;

        let input_vec_t: Vec<T> = vec![T::from(11_u32), T::from(144_u32), T::from(87_u32)];
        let input_vec_f: Vec<F> = input_vec_t.iter().map(|x| field_switching(x)).collect();

        let input_var = [
            FpElemVar::new_from_field_element(&mut circuit, &input_vec_f[0], m, None).unwrap(),
            FpElemVar::new_from_field_element(&mut circuit, &input_vec_f[1], m, None).unwrap(),
            FpElemVar::new_from_field_element(&mut circuit, &input_vec_f[2], m, None).unwrap(),
        ];
        let out_var = circuit
            .rescue_sponge_no_padding::<T>(&input_var, 1)
            .unwrap()[0];

        let rescue_hash = Permutation::<T>::default();

        // Check consistency between inputs
        for i in 0..rate {
            assert_eq!(input_vec_f[i], input_var[i].witness(&circuit).unwrap());
        }

        // Check consistency between outputs
        let expected_hash =
            rescue_hash.hash_3_to_1(&[input_vec_t[0], input_vec_t[1], input_vec_t[2]]);
        assert_eq!(
            field_switching::<T, F>(&expected_hash),
            out_var.witness(&circuit).unwrap()
        );

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        *circuit.witness_mut(out_var.components().0) = F::from(1_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_fsks() {
        test_fsks_helper::<FqEd377, Fq377>()
    }
    fn test_fsks_helper<T: RescueParameter, F: PrimeField>() {
        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        // parameter m
        let m = (T::size_in_bits() / 2 / RANGE_BIT_LEN_FOR_TEST + 1) * RANGE_BIT_LEN_FOR_TEST;

        let mut prng = ark_std::test_rng();

        // keys
        let key_t = T::rand(&mut prng);
        let key_f = field_switching::<T, F>(&key_t);
        let key_var = FpElemVar::new_from_field_element(&mut circuit, &key_f, m, None).unwrap();

        // data
        let input_len = 8;
        let data_t: Vec<T> = (0..input_len).map(|_| T::rand(&mut prng)).collect_vec();
        let data_f: Vec<F> = data_t.iter().map(|x| field_switching(x)).collect();
        let data_vars: Vec<FpElemVar<F>> = data_f
            .iter()
            .map(|x| {
                FpElemVar::new_from_field_element(&mut circuit, x, m, Some(key_var.two_power_m()))
                    .unwrap()
            })
            .collect();

        let perm = Permutation::<T>::default();
        let expected_fsks_output = perm
            .full_state_keyed_sponge_no_padding(&key_t, &data_t, 1)
            .unwrap();

        let fsks_var = circuit
            .rescue_full_state_keyed_sponge_no_padding::<T>(key_var, &data_vars)
            .unwrap();

        // Check prf output consistency
        assert_eq!(
            field_switching::<T, F>(&expected_fsks_output[0]),
            fsks_var.witness(&circuit).unwrap()
        );

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(fsks_var.components().0) = F::from(1_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // make data_vars of bad lenth
        let mut data_vars = data_vars;
        let zero_var = FpElemVar::zero(
            &circuit,
            data_vars[0].param_m(),
            Some(key_var.two_power_m()),
        );
        data_vars.push(zero_var);
        assert!(circuit
            .rescue_full_state_keyed_sponge_no_padding::<T>(key_var, &data_vars)
            .is_err());
    }
}
