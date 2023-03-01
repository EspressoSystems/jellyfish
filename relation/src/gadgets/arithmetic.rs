// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation for arithmetic extensions

use super::utils::next_multiple;
use crate::{
    constants::{GATE_WIDTH, N_MUL_SELECTORS},
    errors::CircuitError,
    gates::{
        ConstantAdditionGate, ConstantMultiplicationGate, FifthRootGate, LinCombGate, MulAddGate,
        QuadPolyGate,
    },
    Circuit, PlonkCircuit, Variable,
};
use ark_ff::PrimeField;
use ark_std::{borrow::ToOwned, boxed::Box, string::ToString, vec::Vec};
use num_bigint::BigUint;

impl<F: PrimeField> PlonkCircuit<F> {
    /// Arithmetic gates
    ///
    /// Quadratic polynomial gate: q1 * a + q2 * b + q3 * c + q4 * d + q12 * a *
    /// b + q34 * c * d + q_c = q_o * e, where q1, q2, q3, q4, q12, q34,
    /// q_c, q_o are selectors; a, b, c, d are input wires; e is the output
    /// wire. Return error if variables are invalid.
    pub fn quad_poly_gate(
        &mut self,
        wires: &[Variable; GATE_WIDTH + 1],
        q_lc: &[F; GATE_WIDTH],
        q_mul: &[F; N_MUL_SELECTORS],
        q_o: F,
        q_c: F,
    ) -> Result<(), CircuitError> {
        self.check_vars_bound(wires)?;

        self.insert_gate(
            wires,
            Box::new(QuadPolyGate {
                q_lc: *q_lc,
                q_mul: *q_mul,
                q_o,
                q_c,
            }),
        )?;
        Ok(())
    }

    /// Arithmetic gates
    ///
    /// Quadratic polynomial gate:
    /// e = q1 * a + q2 * b + q3 * c + q4 * d + q12 * a *
    /// b + q34 * c * d + q_c, where q1, q2, q3, q4, q12, q34,
    /// q_c are selectors; a, b, c, d are input wires
    ///
    /// Return the variable for
    /// Return error if variables are invalid.
    pub fn gen_quad_poly(
        &mut self,
        wires: &[Variable; GATE_WIDTH],
        q_lc: &[F; GATE_WIDTH],
        q_mul: &[F; N_MUL_SELECTORS],
        q_c: F,
    ) -> Result<Variable, CircuitError> {
        self.check_vars_bound(wires)?;
        let output_val = q_lc[0] * self.witness(wires[0])?
            + q_lc[1] * self.witness(wires[1])?
            + q_lc[2] * self.witness(wires[2])?
            + q_lc[3] * self.witness(wires[3])?
            + q_mul[0] * self.witness(wires[0])? * self.witness(wires[1])?
            + q_mul[1] * self.witness(wires[2])? * self.witness(wires[3])?
            + q_c;
        let output_var = self.create_variable(output_val)?;
        let wires = [wires[0], wires[1], wires[2], wires[3], output_var];

        self.insert_gate(
            &wires,
            Box::new(QuadPolyGate {
                q_lc: *q_lc,
                q_mul: *q_mul,
                q_o: F::one(),
                q_c,
            }),
        )?;

        Ok(output_var)
    }

    /// Constrain a linear combination gate:
    /// q1 * a + q2 * b + q3 * c + q4 * d  = y
    pub fn lc_gate(
        &mut self,
        wires: &[Variable; GATE_WIDTH + 1],
        coeffs: &[F; GATE_WIDTH],
    ) -> Result<(), CircuitError> {
        self.check_vars_bound(wires)?;

        let wire_vars = [wires[0], wires[1], wires[2], wires[3], wires[4]];
        self.insert_gate(&wire_vars, Box::new(LinCombGate { coeffs: *coeffs }))?;
        Ok(())
    }

    /// Obtain a variable representing a linear combination.
    /// Return error if variables are invalid.
    pub fn lc(
        &mut self,
        wires_in: &[Variable; GATE_WIDTH],
        coeffs: &[F; GATE_WIDTH],
    ) -> Result<Variable, CircuitError> {
        self.check_vars_bound(wires_in)?;

        let vals_in: Vec<F> = wires_in
            .iter()
            .map(|&var| self.witness(var))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // calculate y as the linear combination of coeffs and vals_in
        let y_val = vals_in
            .iter()
            .zip(coeffs.iter())
            .map(|(&val, &coeff)| val * coeff)
            .sum();
        let y = self.create_variable(y_val)?;

        let wires = [wires_in[0], wires_in[1], wires_in[2], wires_in[3], y];
        self.lc_gate(&wires, coeffs)?;
        Ok(y)
    }

    /// Constrain a mul-addition gate:
    /// q_muls\[0\] * wires\[0\] *  wires\[1\] +  q_muls\[1\] * wires\[2\] *
    /// wires\[3\] = wires\[4\]
    pub fn mul_add_gate(
        &mut self,
        wires: &[Variable; GATE_WIDTH + 1],
        q_muls: &[F; N_MUL_SELECTORS],
    ) -> Result<(), CircuitError> {
        self.check_vars_bound(wires)?;

        let wire_vars = [wires[0], wires[1], wires[2], wires[3], wires[4]];
        self.insert_gate(&wire_vars, Box::new(MulAddGate { coeffs: *q_muls }))?;
        Ok(())
    }

    /// Obtain a variable representing `q12 * a * b + q34 * c * d`,
    /// where `a, b, c, d` are input wires, and `q12`, `q34` are selectors.
    /// Return error if variables are invalid.
    pub fn mul_add(
        &mut self,
        wires_in: &[Variable; GATE_WIDTH],
        q_muls: &[F; N_MUL_SELECTORS],
    ) -> Result<Variable, CircuitError> {
        self.check_vars_bound(wires_in)?;

        let vals_in: Vec<F> = wires_in
            .iter()
            .map(|&var| self.witness(var))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // calculate y as the mul-addition of coeffs and vals_in
        let y_val = q_muls[0] * vals_in[0] * vals_in[1] + q_muls[1] * vals_in[2] * vals_in[3];
        let y = self.create_variable(y_val)?;

        let wires = [wires_in[0], wires_in[1], wires_in[2], wires_in[3], y];
        self.mul_add_gate(&wires, q_muls)?;
        Ok(y)
    }

    /// Obtain a variable representing the sum of a list of variables.
    /// Return error if variables are invalid.
    pub fn sum(&mut self, elems: &[Variable]) -> Result<Variable, CircuitError> {
        if elems.is_empty() {
            return Err(CircuitError::ParameterError(
                "Sum over an empty slice of variables is undefined".to_string(),
            ));
        }
        self.check_vars_bound(elems)?;

        let sum = {
            let sum_val: F = elems
                .iter()
                .map(|&elem| self.witness(elem))
                .collect::<Result<Vec<_>, CircuitError>>()?
                .iter()
                .sum();
            self.create_variable(sum_val)?
        };

        // pad to ("next multiple of 3" + 1) in length
        let mut padded: Vec<Variable> = elems.to_owned();
        let rate = GATE_WIDTH - 1; // rate at which each lc add
        let padded_len = next_multiple(elems.len() - 1, rate)? + 1;
        padded.resize(padded_len, self.zero());

        // z_0 = = x_0
        // z_i = z_i-1 + x_3i-2 + x_3i-1 + x_3i
        let coeffs = [F::one(); GATE_WIDTH];
        let mut accum = padded[0];
        for i in 1..padded_len / rate {
            accum = self.lc(
                &[
                    accum,
                    padded[rate * i - 2],
                    padded[rate * i - 1],
                    padded[rate * i],
                ],
                &coeffs,
            )?;
        }
        // final round
        let wires = [
            accum,
            padded[padded_len - 3],
            padded[padded_len - 2],
            padded[padded_len - 1],
            sum,
        ];
        self.lc_gate(&wires, &coeffs)?;

        Ok(sum)
    }

    /// Constrain variable `y` to the addition of `a` and `c`, where `c` is a
    /// constant value Return error if the input variables are invalid.
    fn add_constant_gate(&mut self, x: Variable, c: F, y: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(x)?;
        self.check_var_bound(y)?;

        let wire_vars = &[x, self.one(), 0, 0, y];
        self.insert_gate(wire_vars, Box::new(ConstantAdditionGate(c)))?;
        Ok(())
    }

    /// Obtains a variable representing an addition with a constant value
    /// Return error if the input variable is invalid
    pub fn add_constant(
        &mut self,
        input_var: Variable,
        elem: &F,
    ) -> Result<Variable, CircuitError> {
        self.check_var_bound(input_var)?;

        let input_val = self.witness(input_var).unwrap();
        let output_val = *elem + input_val;
        let output_var = self.create_variable(output_val).unwrap();

        self.add_constant_gate(input_var, *elem, output_var)?;

        Ok(output_var)
    }

    /// Constrain variable `y` to the product of `a` and `c`, where `c` is a
    /// constant value Return error if the input variables are invalid.
    pub fn mul_constant_gate(
        &mut self,
        x: Variable,
        c: F,
        y: Variable,
    ) -> Result<(), CircuitError> {
        self.check_var_bound(x)?;
        self.check_var_bound(y)?;

        let wire_vars = &[x, 0, 0, 0, y];
        self.insert_gate(wire_vars, Box::new(ConstantMultiplicationGate(c)))?;
        Ok(())
    }

    /// Obtains a variable representing a multiplication with a constant value
    /// Return error if the input variable is invalid
    pub fn mul_constant(
        &mut self,
        input_var: Variable,
        elem: &F,
    ) -> Result<Variable, CircuitError> {
        self.check_var_bound(input_var)?;

        let input_val = self.witness(input_var).unwrap();
        let output_val = *elem * input_val;
        let output_var = self.create_variable(output_val).unwrap();

        self.mul_constant_gate(input_var, *elem, output_var)?;

        Ok(output_var)
    }

    /// Return a variable to be the 11th power of the input variable.
    /// Cost: 3 constraints.
    pub fn power_11_gen(&mut self, x: Variable) -> Result<Variable, CircuitError> {
        self.check_var_bound(x)?;

        // now we prove that x^11 = x_to_11
        let x_val = self.witness(x)?;
        let x_to_5_val = x_val.pow([5]);
        let x_to_5 = self.create_variable(x_to_5_val)?;
        let wire_vars = &[x, 0, 0, 0, x_to_5];
        self.insert_gate(wire_vars, Box::new(FifthRootGate))?;

        let x_to_10 = self.mul(x_to_5, x_to_5)?;
        self.mul(x_to_10, x)
    }

    /// Constraint a variable to be the 11th power of another variable.
    /// Cost: 3 constraints.
    pub fn power_11_gate(&mut self, x: Variable, x_to_11: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(x)?;
        self.check_var_bound(x_to_11)?;

        // now we prove that x^11 = x_to_11
        let x_val = self.witness(x)?;
        let x_to_5_val = x_val.pow([5]);
        let x_to_5 = self.create_variable(x_to_5_val)?;
        let wire_vars = &[x, 0, 0, 0, x_to_5];
        self.insert_gate(wire_vars, Box::new(FifthRootGate))?;

        let x_to_10 = self.mul(x_to_5, x_to_5)?;
        self.mul_gate(x_to_10, x, x_to_11)
    }

    /// Obtain the truncation of the input.
    /// Constrain that the input and output values congruent modulo
    /// 2^bit_length. Return error if the input is invalid.
    pub fn truncate(&mut self, a: Variable, bit_length: usize) -> Result<Variable, CircuitError> {
        self.check_var_bound(a)?;
        let a_val = self.witness(a)?;
        let a_uint: BigUint = a_val.into();
        let modulus = F::from(2u8).pow([bit_length as u64]);
        let modulus_uint: BigUint = modulus.into();
        let res = F::from(a_uint % modulus_uint);
        let b = self.create_variable(res)?;
        self.truncate_gate(a, b, bit_length)?;
        Ok(b)
    }

    /// Truncation gate.
    /// Constrain that b == a modulo 2^bit_length.
    /// Return error if the inputs are invalid; or b >= 2^bit_length.
    pub fn truncate_gate(
        &mut self,
        a: Variable,
        b: Variable,
        bit_length: usize,
    ) -> Result<(), CircuitError> {
        if !self.support_lookup() {
            return Err(CircuitError::ParameterError(
                "does not support range table".to_string(),
            ));
        }

        self.check_var_bound(a)?;
        self.check_var_bound(b)?;

        let a_val = self.witness(a)?;
        let b_val = self.witness(b)?;
        let modulus = F::from(2u8).pow([bit_length as u64]);
        let modulus_uint: BigUint = modulus.into();

        if b_val >= modulus {
            return Err(CircuitError::ParameterError(
                "Truncation error: b is greater than 2^bit_length".to_string(),
            ));
        }

        let native_field_bit_length = F::MODULUS_BIT_SIZE as usize;
        if native_field_bit_length <= bit_length {
            return Err(CircuitError::ParameterError(
                "Truncation error: native field is not greater than truncation target".to_string(),
            ));
        }

        let bit_length_non_lookup_range = bit_length % self.range_bit_len()?;
        let bit_length_lookup_component = bit_length - bit_length_non_lookup_range;

        // we need to show that a and b satisfy the following
        // relationship:
        // (1) b = a mod modulus
        // where
        // * a is native_field_bit_length bits
        // * b is bit_length bits
        //
        // which is
        // (2) a = b + z * modulus
        // for some z, where
        // * z < 2^(native_field_bit_length - bit_length)
        //
        // So we set delta_length = native_field_bit_length - bit_length

        let delta_length = native_field_bit_length - bit_length;
        let delta_length_non_lookup_range = delta_length % self.range_bit_len()?;
        let delta_length_lookup_component = delta_length - delta_length_non_lookup_range;

        // Now (2) becomes
        // (3) a = b1 + b2 * 2^bit_length_lookup_component
        //       + modulus * (z1 + 2^delta_length_lookup_component * z2)
        // with
        //   b1 < 2^bit_length_lookup_component
        //   b2 < 2^bit_length_non_lookup_range
        //   z1 < 2^delta_length_lookup_component
        //   z2 < 2^delta_length_non_lookup_range

        // The concrete statements we need to prove becomes
        // (4) b = b1 + b2 * 2^bit_length_lookup_component
        // (5) a = b + modulus * z1
        //       + modulus * 2^delta_length_lookup_component * z2
        // (6) b1 < 2^bit_length_lookup_component
        // (7) b2 < 2^bit_length_non_lookup_range
        // (8) z1 < 2^delta_length_lookup_component
        // (9) z2 < 2^delta_length_non_lookup_range

        // step 1. setup the constants
        let two_to_bit_length_lookup_component =
            F::from(2u8).pow([bit_length_lookup_component as u64]);
        let two_to_bit_length_lookup_component_uint: BigUint =
            two_to_bit_length_lookup_component.into();

        let two_to_delta_length_lookup_component =
            F::from(2u8).pow([delta_length_lookup_component as u64]);
        let two_to_delta_length_lookup_component_uint: BigUint =
            two_to_delta_length_lookup_component.into();

        let modulus_mul_two_to_delta_length_lookup_component_uint =
            &two_to_delta_length_lookup_component_uint * &modulus_uint;
        let modulus_mul_two_to_delta_length_lookup_component =
            F::from(modulus_mul_two_to_delta_length_lookup_component_uint);

        // step 2. get the intermediate data in the clear
        let a_uint: BigUint = a_val.into();
        let b_uint: BigUint = b_val.into();
        let b1_uint = &b_uint % &two_to_bit_length_lookup_component_uint;
        let b2_uint = &b_uint / &two_to_bit_length_lookup_component_uint;

        let z_uint = (&a_uint - &b_uint) / &modulus_uint;
        let z1_uint = &z_uint % &two_to_delta_length_lookup_component_uint;
        let z2_uint = &z_uint / &two_to_delta_length_lookup_component_uint;

        // step 3. create intermediate variables
        let b1_var = self.create_variable(F::from(b1_uint))?;
        let b2_var = self.create_variable(F::from(b2_uint))?;
        let z1_var = self.create_variable(F::from(z1_uint))?;
        let z2_var = self.create_variable(F::from(z2_uint))?;

        // step 4. prove equations (4) - (9)
        // (4) b = b1 + b2 * 2^bit_length_lookup_component
        let wires = [b1_var, b2_var, self.zero(), self.zero(), b];
        let coeffs = [
            F::one(),
            two_to_bit_length_lookup_component,
            F::zero(),
            F::zero(),
        ];
        self.lc_gate(&wires, &coeffs)?;

        // (5) a = b + modulus * z1
        //       + modulus * 2^delta_length_lookup_component * z2
        let wires = [b, z1_var, z2_var, self.zero(), a];
        let coeffs = [
            F::one(),
            modulus,
            modulus_mul_two_to_delta_length_lookup_component,
            F::zero(),
        ];
        self.lc_gate(&wires, &coeffs)?;

        // (6) b1 < 2^bit_length_lookup_component
        // note that bit_length_lookup_component is public information
        // so we don't need to add a selection gate here
        if bit_length_lookup_component != 0 {
            self.range_gate_with_lookup(b1_var, bit_length_lookup_component)?;
        }

        // (7) b2 < 2^bit_length_non_lookup_range
        // note that bit_length_non_lookup_range is public information
        // so we don't need to add a selection gate here
        if bit_length_non_lookup_range != 0 {
            self.enforce_in_range(b2_var, bit_length_non_lookup_range)?;
        }

        // (8) z1 < 2^delta_length_lookup_component
        // note that delta_length_lookup_component is public information
        // so we don't need to add a selection gate here
        if delta_length_lookup_component != 0 {
            self.range_gate_with_lookup(z1_var, delta_length_lookup_component)?;
        }

        // (9) z2 < 2^delta_length_non_lookup_range
        // note that delta_length_non_lookup_range is public information
        // so we don't need to add a selection gate here
        if delta_length_non_lookup_range != 0 {
            self.enforce_in_range(z2_var, delta_length_non_lookup_range)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        constants::GATE_WIDTH, errors::CircuitError,
        gadgets::test_utils::test_variable_independence_for_circuit, Circuit, PlonkCircuit,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::PrimeField;
    use ark_std::{convert::TryInto, vec, vec::Vec};
    use jf_utils::test_rng;
    use num_bigint::BigUint;

    #[test]
    fn test_quad_poly_gate() -> Result<(), CircuitError> {
        test_quad_poly_gate_helper::<FqEd254>()?;
        test_quad_poly_gate_helper::<FqEd377>()?;
        test_quad_poly_gate_helper::<FqEd381>()?;
        test_quad_poly_gate_helper::<Fq377>()
    }
    fn test_quad_poly_gate_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let q_lc = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        let q_mul = [F::one(), F::from(2u8)];
        let q_o = F::one();
        let q_c = F::from(9u8);
        let wires_1: Vec<_> = [
            F::from(23u32),
            F::from(8u32),
            F::from(1u32),
            -F::from(20u32),
            F::from(188u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();
        let wires_2: Vec<_> = [
            F::zero(),
            -F::from(8u32),
            F::from(1u32),
            F::zero(),
            -F::from(10u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();

        // 23 * 2 + 8 * 3 + 1 * 5 + (-20) * 2 + 23 * 8 + 2 * 1 * (-20) + 9 = 188
        let var = wires_1[0];
        circuit.quad_poly_gate(&wires_1.try_into().unwrap(), &q_lc, &q_mul, q_o, q_c)?;
        // 0 * 2 + (-8) * 3 + 1 * 5 + 0 * 2 + 0 * -8 + 1 * 0 + 9 = -10
        circuit.quad_poly_gate(&wires_2.try_into().unwrap(), &q_lc, &q_mul, q_o, q_c)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(var) = F::from(34u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .quad_poly_gate(&[0, 1, 1, circuit.num_vars(), 0], &q_lc, &q_mul, q_o, q_c)
            .is_err());

        let circuit_1 = build_quad_poly_gate_circuit([
            -F::from(98973u32),
            F::from(4u32),
            F::zero(),
            F::from(79u32),
            F::one(),
        ])?;
        let circuit_2 = build_quad_poly_gate_circuit([
            F::one(),
            F::zero(),
            F::from(6u32),
            -F::from(9u32),
            F::one(),
        ])?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }
    fn build_quad_poly_gate_circuit<F: PrimeField>(
        wires: [F; GATE_WIDTH + 1],
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let wires: Vec<_> = wires
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let q_lc = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        let q_mul = [F::one(), F::from(2u8)];
        let q_o = F::one();
        let q_c = F::from(9u8);
        circuit.quad_poly_gate(&wires.try_into().unwrap(), &q_lc, &q_mul, q_o, q_c)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_lc() -> Result<(), CircuitError> {
        test_lc_helper::<FqEd254>()?;
        test_lc_helper::<FqEd377>()?;
        test_lc_helper::<FqEd381>()?;
        test_lc_helper::<Fq377>()
    }
    fn test_lc_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let wire_in_1: Vec<_> = [
            F::from(23u32),
            F::from(8u32),
            F::from(1u32),
            -F::from(20u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();
        let wire_in_2: Vec<_> = [F::zero(), -F::from(8u32), F::from(1u32), F::zero()]
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let coeffs = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        let y_1 = circuit.lc(&wire_in_1.try_into().unwrap(), &coeffs)?;
        let y_2 = circuit.lc(&wire_in_2.try_into().unwrap(), &coeffs)?;

        // 23 * 2 + 8 * 3 + 1 * 5 + (-20) * 2 = 35
        assert_eq!(circuit.witness(y_1)?, F::from(35u32));
        // 0 * 2 + (-8) * 3 + 1 * 5 + 0 * 2 = -19
        assert_eq!(circuit.witness(y_2)?, -F::from(19u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(y_1) = F::from(34u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.lc(&[0, 1, 1, circuit.num_vars()], &coeffs).is_err());

        let circuit_1 =
            build_lc_circuit([-F::from(98973u32), F::from(4u32), F::zero(), F::from(79u32)])?;
        let circuit_2 = build_lc_circuit([F::one(), F::zero(), F::from(6u32), -F::from(9u32)])?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_lc_circuit<F: PrimeField>(wires_in: [F; 4]) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let wires_in: Vec<_> = wires_in
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let coeffs = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        circuit.lc(&wires_in.try_into().unwrap(), &coeffs)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_mul_add() -> Result<(), CircuitError> {
        test_mul_add_helper::<FqEd254>()?;
        test_mul_add_helper::<FqEd377>()?;
        test_mul_add_helper::<FqEd381>()?;
        test_mul_add_helper::<Fq377>()
    }

    fn test_mul_add_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let wire_in_1: Vec<_> = [
            F::from(23u32),
            F::from(8u32),
            F::from(1u32),
            -F::from(20u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();
        let wire_in_2: Vec<_> = [F::one(), -F::from(8u32), F::one(), F::one()]
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let q_muls = [F::from(3u32), F::from(5u32)];
        let y_1 = circuit.mul_add(&wire_in_1.try_into().unwrap(), &q_muls)?;
        let y_2 = circuit.mul_add(&wire_in_2.try_into().unwrap(), &q_muls)?;

        // 3 * (23 * 8) + 5 * (1 * -20) = 452
        assert_eq!(circuit.witness(y_1)?, F::from(452u32));
        // 3 * (1 * -8) + 5 * (1 * 1)= -19
        assert_eq!(circuit.witness(y_2)?, -F::from(19u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(y_1) = F::from(34u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .mul_add(&[0, 1, 1, circuit.num_vars()], &q_muls)
            .is_err());

        let circuit_1 =
            build_mul_add_circuit([-F::from(98973u32), F::from(4u32), F::zero(), F::from(79u32)])?;
        let circuit_2 =
            build_mul_add_circuit([F::one(), F::zero(), F::from(6u32), -F::from(9u32)])?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_mul_add_circuit<F: PrimeField>(
        wires_in: [F; 4],
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let wires_in: Vec<_> = wires_in
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let q_muls = [F::from(3u32), F::from(5u32)];
        circuit.mul_add(&wires_in.try_into().unwrap(), &q_muls)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_sum() -> Result<(), CircuitError> {
        test_sum_helper::<FqEd254>()?;
        test_sum_helper::<FqEd377>()?;
        test_sum_helper::<FqEd381>()?;
        test_sum_helper::<Fq377>()
    }

    fn test_sum_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let mut vars = vec![];
        for i in 0..11 {
            vars.push(circuit.create_variable(F::from(i as u32))?);
        }

        // sum over an empty array should be undefined behavior, thus fail
        assert!(circuit.sum(&[]).is_err());

        for until in 1..11 {
            let expected_sum = F::from((0..until).sum::<u32>());
            let sum = circuit.sum(&vars[..until as usize])?;
            assert_eq!(circuit.witness(sum)?, expected_sum);
        }
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // if mess up the wire value, should fail
        *circuit.witness_mut(vars[5]) = F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.sum(&[circuit.num_vars()]).is_err());

        let circuit_1 = build_sum_circuit(vec![
            -F::from(73u32),
            F::from(4u32),
            F::zero(),
            F::from(79u32),
            F::from(23u32),
        ])?;
        let circuit_2 = build_sum_circuit(vec![
            F::one(),
            F::zero(),
            F::from(6u32),
            -F::from(9u32),
            F::one(),
        ])?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_sum_circuit<F: PrimeField>(vals: Vec<F>) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let mut vars = vec![];
        for val in vals {
            vars.push(circuit.create_variable(val)?);
        }
        circuit.sum(&vars[..])?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_power_11_gen_gate() -> Result<(), CircuitError> {
        test_power_11_gen_gate_helper::<FqEd254>()?;
        test_power_11_gen_gate_helper::<FqEd377>()?;
        test_power_11_gen_gate_helper::<FqEd381>()?;
        test_power_11_gen_gate_helper::<Fq377>()
    }
    fn test_power_11_gen_gate_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut rng = test_rng();
        let x = F::rand(&mut rng);
        let y = F::rand(&mut rng);
        let x11 = x.pow([11]);

        // Create a satisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();

        let x_var = circuit.create_variable(x)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        let x_to_11_var_rec = circuit.power_11_gen(x_var)?;
        circuit.enforce_equal(x_to_11_var, x_to_11_var_rec)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();

        let y_var = circuit.create_variable(y)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        let x_to_11_var_rec = circuit.power_11_gen(y_var)?;
        circuit.enforce_equal(x_to_11_var, x_to_11_var_rec)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let x_var = circuit.create_variable(x)?;
        let y_var = circuit.create_variable(y)?;

        let x_to_11_var_rec = circuit.power_11_gen(x_var)?;
        circuit.enforce_equal(y_var, x_to_11_var_rec)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_power_11_gate() -> Result<(), CircuitError> {
        test_power_11_gate_helper::<FqEd254>()?;
        test_power_11_gate_helper::<FqEd377>()?;
        test_power_11_gate_helper::<FqEd381>()?;
        test_power_11_gate_helper::<Fq377>()
    }
    fn test_power_11_gate_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut rng = test_rng();
        let x = F::rand(&mut rng);
        let y = F::rand(&mut rng);
        let x11 = x.pow([11]);

        // Create a satisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let x_var = circuit.create_variable(x)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        circuit.power_11_gate(x_var, x_to_11_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let y_var = circuit.create_variable(y)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        circuit.power_11_gate(y_var, x_to_11_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let x_var = circuit.create_variable(x)?;
        let y = circuit.create_variable(y)?;

        circuit.power_11_gate(x_var, y)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_truncation_gate() -> Result<(), CircuitError> {
        test_truncation_gate_helper::<FqEd254>()?;
        test_truncation_gate_helper::<FqEd377>()?;
        test_truncation_gate_helper::<FqEd381>()?;
        test_truncation_gate_helper::<Fq377>()
    }
    fn test_truncation_gate_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut rng = test_rng();
        let x = F::rand(&mut rng);
        let x_uint: BigUint = x.into();

        // Create a satisfied circuit
        for len in [80, 100, 201, 248] {
            let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(16);
            let x_var = circuit.create_variable(x)?;
            let modulus = F::from(2u8).pow([len as u64]);
            let modulus_uint: BigUint = modulus.into();
            let y_var = circuit.truncate(x_var, len)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            let y = circuit.witness(y_var)?;
            assert!(y < modulus);
            assert_eq!(y, F::from(&x_uint % &modulus_uint))
        }

        // more tests
        for minus_len in 1..=16 {
            let len = F::MODULUS_BIT_SIZE as usize - minus_len;
            let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(16);
            let x_var = circuit.create_variable(x)?;
            let modulus = F::from(2u8).pow([len as u64]);
            let modulus_uint: BigUint = modulus.into();
            let y_var = circuit.truncate(x_var, len)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            let y = circuit.witness(y_var)?;
            assert!(y < modulus);
            assert_eq!(y, F::from(&x_uint % &modulus_uint))
        }

        // Bad path: b > 2^bit_len
        {
            let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(16);
            let x = F::rand(&mut rng);
            let x_var = circuit.create_variable(x)?;
            let y = F::rand(&mut rng);
            let y_var = circuit.create_variable(y)?;

            assert!(circuit.truncate_gate(x_var, y_var, 16).is_err());
        }

        // Bad path: b!= a % 2^bit_len
        {
            let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(16);
            let x = F::rand(&mut rng);
            let x_var = circuit.create_variable(x)?;
            let y = F::one();
            let y_var = circuit.create_variable(y)?;
            circuit.truncate_gate(x_var, y_var, 192)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        }

        // Bad path: bit_len = F::MODULUS_BIT_SIZE
        {
            let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(16);
            let x = F::rand(&mut rng);
            let x_var = circuit.create_variable(x)?;
            let y = F::one();
            let y_var = circuit.create_variable(y)?;
            assert!(circuit
                .truncate_gate(x_var, y_var, F::MODULUS_BIT_SIZE as usize)
                .is_err());
        }

        Ok(())
    }

    #[test]
    fn test_arithmetization() -> Result<(), CircuitError> {
        test_arithmetization_helper::<FqEd254>()?;
        test_arithmetization_helper::<FqEd377>()?;
        test_arithmetization_helper::<FqEd381>()?;
        test_arithmetization_helper::<Fq377>()
    }

    fn test_arithmetization_helper<F: PrimeField>() -> Result<(), CircuitError> {
        // Create the circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        // is_equal gate
        let val = F::from(31415u32);
        let a = circuit.create_variable(val)?;
        let b = circuit.create_variable(val)?;
        circuit.is_equal(a, b)?;

        // lc gate
        let wire_in: Vec<_> = [
            F::from(23u32),
            F::from(8u32),
            F::from(1u32),
            -F::from(20u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();
        let coeffs = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        circuit.lc(&wire_in.try_into().unwrap(), &coeffs)?;

        // conditional select gate
        let bit_true = circuit.create_boolean_variable(true)?;
        let x_0 = circuit.create_variable(F::from(23u32))?;
        let x_1 = circuit.create_variable(F::from(24u32))?;
        circuit.conditional_select(bit_true, x_0, x_1)?;

        // range gate
        let b = circuit.create_variable(F::from(1023u32))?;
        circuit.enforce_in_range(b, 10)?;

        // sum gate
        let mut vars = vec![];
        for i in 0..11 {
            vars.push(circuit.create_variable(F::from(i as u32))?);
        }
        circuit.sum(&vars[..vars.len()])?;

        // Finalize the circuit
        circuit.finalize_for_arithmetization()?;
        let pub_inputs = vec![];
        crate::constraint_system::test::test_arithmetization_for_circuit(circuit, pub_inputs)?;
        Ok(())
    }
}
