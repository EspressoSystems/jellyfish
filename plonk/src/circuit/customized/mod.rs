// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Customized gates and gadgets for rescue hash related, elliptic curve
//! related, rescue-based transcript and lookup table etc.

use self::gates::*;
use super::{Circuit, PlonkCircuit, PlonkError, Variable};
use crate::{
    circuit::gates::{ConstantAdditionGate, ConstantMultiplicationGate, FifthRootGate},
    constants::{GATE_WIDTH, N_MUL_SELECTORS},
    errors::CircuitError,
};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{borrow::ToOwned, boxed::Box, cmp::Ordering, format, string::ToString, vec::Vec};

pub mod ecc;
mod gates;
pub mod rescue;

impl<F> PlonkCircuit<F>
where
    F: PrimeField,
{
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
    ) -> Result<(), PlonkError> {
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
    ) -> Result<Variable, PlonkError> {
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
    ) -> Result<(), PlonkError> {
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
    ) -> Result<Variable, PlonkError> {
        self.check_vars_bound(wires_in)?;

        let vals_in: Vec<F> = wires_in
            .iter()
            .map(|&var| self.witness(var))
            .collect::<Result<Vec<_>, PlonkError>>()?;

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
    ) -> Result<(), PlonkError> {
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
    ) -> Result<Variable, PlonkError> {
        self.check_vars_bound(wires_in)?;

        let vals_in: Vec<F> = wires_in
            .iter()
            .map(|&var| self.witness(var))
            .collect::<Result<Vec<_>, PlonkError>>()?;

        // calculate y as the mul-addition of coeffs and vals_in
        let y_val = q_muls[0] * vals_in[0] * vals_in[1] + q_muls[1] * vals_in[2] * vals_in[3];
        let y = self.create_variable(y_val)?;

        let wires = [wires_in[0], wires_in[1], wires_in[2], wires_in[3], y];
        self.mul_add_gate(&wires, q_muls)?;
        Ok(y)
    }

    /// Obtain a variable representing the sum of a list of variables.
    /// Return error if variables are invalid.
    pub fn sum(&mut self, elems: &[Variable]) -> Result<Variable, PlonkError> {
        if elems.is_empty() {
            return Err(CircuitError::ParameterError(
                "Sum over an empty slice of variables is undefined".to_string(),
            )
            .into());
        }
        self.check_vars_bound(elems)?;

        let sum = {
            let sum_val: F = elems
                .iter()
                .map(|&elem| self.witness(elem))
                .collect::<Result<Vec<_>, PlonkError>>()?
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

    /// Obtain a variable that equals `x_0` if `b` is zero, or `x_1` if `b` is
    /// one. Return error if variables are invalid.
    pub fn conditional_select(
        &mut self,
        b: Variable,
        x_0: Variable,
        x_1: Variable,
    ) -> Result<Variable, PlonkError> {
        self.check_var_bound(b)?;
        self.check_var_bound(x_0)?;
        self.check_var_bound(x_1)?;

        // y = x_bit
        let y = if self.witness(b)? == F::zero() {
            self.create_variable(self.witness(x_0)?)?
        } else if self.witness(b)? == F::one() {
            self.create_variable(self.witness(x_1)?)?
        } else {
            return Err(CircuitError::ParameterError(
                "b in Conditional Selection gate is not a boolean variable".to_string(),
            )
            .into());
        };
        let wire_vars = [b, x_0, b, x_1, y];
        self.insert_gate(&wire_vars, Box::new(CondSelectGate))?;
        Ok(y)
    }

    /// Constrain variable `y` to the addition of `a` and `c`, where `c` is a
    /// constant value Return error if the input variables are invalid.
    fn add_constant_gate(&mut self, x: Variable, c: F, y: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(x)?;
        self.check_var_bound(y)?;

        let wire_vars = &[x, self.one(), 0, 0, y];
        self.insert_gate(wire_vars, Box::new(ConstantAdditionGate(c)))?;
        Ok(())
    }

    /// Obtains a variable representing an addition with a constant value
    /// Return error if the input variable is invalid
    pub fn add_constant(&mut self, input_var: Variable, elem: &F) -> Result<Variable, PlonkError> {
        self.check_var_bound(input_var)?;

        let input_val = self.witness(input_var).unwrap();
        let output_val = *elem + input_val;
        let output_var = self.create_variable(output_val).unwrap();

        self.add_constant_gate(input_var, *elem, output_var)?;

        Ok(output_var)
    }

    /// Constrain variable `y` to the product of `a` and `c`, where `c` is a
    /// constant value Return error if the input variables are invalid.
    fn mul_constant_gate(&mut self, x: Variable, c: F, y: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(x)?;
        self.check_var_bound(y)?;

        let wire_vars = &[x, 0, 0, 0, y];
        self.insert_gate(wire_vars, Box::new(ConstantMultiplicationGate(c)))?;
        Ok(())
    }

    /// Obtains a variable representing a multiplication with a constant value
    /// Return error if the input variable is invalid
    pub fn mul_constant(&mut self, input_var: Variable, elem: &F) -> Result<Variable, PlonkError> {
        self.check_var_bound(input_var)?;

        let input_val = self.witness(input_var).unwrap();
        let output_val = *elem * input_val;
        let output_var = self.create_variable(output_val).unwrap();

        self.mul_constant_gate(input_var, *elem, output_var)?;

        Ok(output_var)
    }

    /// Logic gates

    /// Constrain that `a` is true or `b` is true.
    /// Return error if variables are invalid.
    pub fn logic_or_gate(&mut self, a: Variable, b: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let wire_vars = &[a, b, 0, 0, 0];
        self.insert_gate(wire_vars, Box::new(LogicOrGate))?;
        Ok(())
    }

    /// Obtain a bool variable representing whether two input variables are
    /// equal. Return error if variables are invalid.
    pub fn check_equal(&mut self, a: Variable, b: Variable) -> Result<Variable, PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let delta = self.sub(a, b)?;
        self.check_is_zero(delta)
    }

    /// Obtain a bool variable representing whether input variable is zero.
    /// Return error if the input variable is invalid.
    pub fn check_is_zero(&mut self, a: Variable) -> Result<Variable, PlonkError> {
        self.check_var_bound(a)?;

        // y is the bit indicating if a == zero
        // a_inv is the inverse of a when it's not 0
        let a_val = self.witness(a)?;
        let (y, a_inv) = if a_val.is_zero() {
            (F::one(), F::zero())
        } else {
            (
                F::zero(),
                a_val.inverse().ok_or_else(|| {
                    CircuitError::FieldAlgebraError("Unable to find inverse".to_string())
                })?,
            )
        };
        let y = self.create_variable(y)?;
        let a_inv = self.create_variable(a_inv)?;

        // constraint 1: 1 - a * a^(-1) = y, i.e., a * a^(-1) + 1 * y = 1
        self.mul_add_gate(
            &[a, a_inv, self.one(), y, self.one()],
            &[F::one(), F::one()],
        )?;
        // constraint 2: multiplication y * a = 0
        self.mul_gate(y, a, self.zero())?;
        Ok(y)
    }

    /// Constrain a variable to be non-zero.
    /// Return error if the variable is invalid.
    pub fn non_zero_gate(&mut self, var: Variable) -> Result<(), PlonkError> {
        let inverse = self.witness(var)?.inverse().unwrap_or_else(F::zero);
        let inv_var = self.create_variable(inverse)?;
        let one_var = self.one();
        self.mul_gate(var, inv_var, one_var)
    }

    /// Assuming value represented by `a` is boolean, obtain a
    /// variable representing the result of a logic negation gate. Return the
    /// index of the variable. Return error if the input variable is invalid.
    pub fn logic_neg(&mut self, a: Variable) -> Result<Variable, PlonkError> {
        self.check_is_zero(a)
    }

    /// Assuming values represented by `a` and `b` are boolean, obtain a
    /// variable representing the result of a logic AND gate. Return the
    /// index of the variable. Return error if the input variables are
    /// invalid.
    pub fn logic_and(&mut self, a: Variable, b: Variable) -> Result<Variable, PlonkError> {
        self.mul(a, b)
    }

    /// Given a list of boolean variables, obtain a
    /// variable representing the result of a logic AND gate. Return the
    /// index of the variable. Return error if the input variables are
    /// invalid.
    pub fn logic_and_all(&mut self, vars: &[Variable]) -> Result<Variable, PlonkError> {
        if vars.is_empty() {
            return Err(PlonkError::InvalidParameters(
                "logic_and_all: empty variable list".to_string(),
            ));
        }
        let mut res = vars[0];
        for &var in vars.iter().skip(1) {
            res = self.logic_and(res, var)?;
        }
        Ok(res)
    }

    /// Assuming values represented by `a` and `b` are boolean, obtain a
    /// variable representing the result of a logic OR gate. Return the
    /// index of the variable. Return error if the input variables are
    /// invalid.
    pub fn logic_or(&mut self, a: Variable, b: Variable) -> Result<Variable, PlonkError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let a_val = self.witness(a)?;
        let b_val = self.witness(b)?;
        let c_val = a_val + b_val - a_val * b_val;
        let c = self.create_variable(c_val)?;
        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(LogicOrValueGate))?;
        Ok(c)
    }

    /// Assuming values represented by `a` is boolean.
    /// Constrain `a` is true
    pub fn enforce_true(&mut self, a: Variable) -> Result<(), PlonkError> {
        self.constant_gate(a, F::one())
    }

    /// Assuming values represented by `a` is boolean.
    /// Constrain `a` is false
    pub fn enforce_false(&mut self, a: Variable) -> Result<(), PlonkError> {
        self.constant_gate(a, F::zero())
    }

    /// Return a variable to be the 11th power of the input variable.
    /// Cost: 3 constraints.
    pub fn power_11_gen(&mut self, x: Variable) -> Result<Variable, PlonkError> {
        self.check_var_bound(x)?;

        // now we prove that x^11 = x_to_11
        let x_val = self.witness(x)?;
        let x_to_5_val = x_val.pow(&[5]);
        let x_to_5 = self.create_variable(x_to_5_val)?;
        let wire_vars = &[x, 0, 0, 0, x_to_5];
        self.insert_gate(wire_vars, Box::new(FifthRootGate))?;

        let x_to_10 = self.mul(x_to_5, x_to_5)?;
        self.mul(x_to_10, x)
    }

    /// Constraint a variable to be the 11th power of another variable.
    /// Cost: 3 constraints.
    pub fn power_11_gate(&mut self, x: Variable, x_to_11: Variable) -> Result<(), PlonkError> {
        self.check_var_bound(x)?;
        self.check_var_bound(x_to_11)?;

        // now we prove that x^11 = x_to_11
        let x_val = self.witness(x)?;
        let x_to_5_val = x_val.pow(&[5]);
        let x_to_5 = self.create_variable(x_to_5_val)?;
        let wire_vars = &[x, 0, 0, 0, x_to_5];
        self.insert_gate(wire_vars, Box::new(FifthRootGate))?;

        let x_to_10 = self.mul(x_to_5, x_to_5)?;
        self.mul_gate(x_to_10, x, x_to_11)
    }
}

impl<F: PrimeField> PlonkCircuit<F> {
    /// Constrain a variable to be within the [0, 2^`bit_len`) range
    /// Return error if the variable is invalid.
    pub fn range_gate(&mut self, a: Variable, bit_len: usize) -> Result<(), PlonkError> {
        self.range_gate_internal(a, bit_len)?;
        Ok(())
    }

    /// Return a boolean variable indicating whether variable `a` is in the
    /// range [0, 2^`bit_len`). Return error if the variable is invalid.
    /// TODO: optimize the gate for UltraPlonk.
    pub fn check_in_range(&mut self, a: Variable, bit_len: usize) -> Result<Variable, PlonkError> {
        let a_bit_le = self.unpack(a, F::size_in_bits())?;
        // a is in range if and only if the bits in `a_bit_le[bit_len..]` are all
        // zeroes.
        let higher_bit_sum = self.sum(&a_bit_le[bit_len..])?;
        self.check_is_zero(higher_bit_sum)
    }

    /// Obtain the `bit_len`-long binary representation of variable `a`
    /// Return a list of variables [b0, ..., b_`bit_len`] which is the binary
    /// representation of `a`.
    /// Return error if the `a` is not the range of [0, 2^`bit_len`).
    pub fn unpack(&mut self, a: Variable, bit_len: usize) -> Result<Vec<Variable>, PlonkError> {
        if bit_len < F::size_in_bits() && self.witness(a)? >= F::from(2u32).pow([bit_len as u64]) {
            return Err(CircuitError::ParameterError(
                "Failed to unpack variable to a range of smaller than 2^bit_len".to_string(),
            )
            .into());
        }
        self.range_gate_internal(a, bit_len)
    }

    // internal of a range check gate
    fn range_gate_internal(
        &mut self,
        a: Variable,
        bit_len: usize,
    ) -> Result<Vec<Variable>, PlonkError> {
        self.check_var_bound(a)?;
        if bit_len == 0 {
            return Err(CircuitError::ParameterError(
                "Only allows positive bit length for range upper bound".to_string(),
            )
            .into());
        }

        let a_bits_le: Vec<bool> = self.witness(a)?.into_repr().to_bits_le();
        if bit_len > a_bits_le.len() {
            return Err(CircuitError::ParameterError(format!(
                "Maximum field bit size: {}, requested range upper bound bit len: {}",
                a_bits_le.len(),
                bit_len
            ))
            .into());
        }
        // convert to variable in the circuit from the vector of boolean as binary
        // representation
        let a_bits_le: Vec<Variable> = a_bits_le
            .iter()
            .take(bit_len) // since little-endian, truncate would remove MSBs
            .map(|&b| {
                self.create_bool_variable(b)
            })
            .collect::<Result<Vec<_>, PlonkError>>()?;

        self.decompose_vars_gate(a_bits_le.clone(), a, F::from(2u8))?;

        Ok(a_bits_le)
    }

    pub(crate) fn decompose_vars_gate(
        &mut self,
        mut padded: Vec<Variable>,
        a: Variable,
        range_size: F,
    ) -> Result<(), PlonkError> {
        // ensure (padded_len - 1) % 3 = 0
        let len = padded.len();
        let rate = GATE_WIDTH - 1; // rate at which lc add each round
        let padded_len = next_multiple(len - 1, rate)? + 1;
        padded.resize(padded_len, self.zero());

        let range_size_square = range_size.square();
        let range_size_cube = range_size * range_size_square;
        let coeffs = [range_size_cube, range_size_square, range_size, F::one()];
        let mut accum = padded[padded_len - 1];
        for i in 1..padded_len / rate {
            accum = self.lc(
                &[
                    accum,
                    padded[padded_len - 1 - rate * i + 2],
                    padded[padded_len - 1 - rate * i + 1],
                    padded[padded_len - 1 - rate * i],
                ],
                &coeffs,
            )?;
        }
        // final round
        let wires = [accum, padded[2], padded[1], padded[0], a];
        self.lc_gate(&wires, &coeffs)?;

        Ok(())
    }
}

// helper function to find the next multiple of `divisor` for `current` value
pub(crate) fn next_multiple(current: usize, divisor: usize) -> Result<usize, PlonkError> {
    if divisor == 0 || divisor == 1 {
        return Err(CircuitError::InternalError(
            "can only be a multiple of divisor >= 2".to_string(),
        )
        .into());
    }
    match current.cmp(&divisor) {
        Ordering::Equal => Ok(current),
        Ordering::Less => Ok(divisor),
        Ordering::Greater => Ok((current / divisor + 1) * divisor),
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::circuit::{self, Arithmetization, Circuit};
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_std::{convert::TryInto, test_rng, vec};

    // two circuit with the same statement should have the same extended permutation
    // polynomials even with different variable assignment
    pub(crate) fn test_variable_independence_for_circuit<F: PrimeField>(
        circuit_1: PlonkCircuit<F>,
        circuit_2: PlonkCircuit<F>,
    ) -> Result<(), PlonkError> {
        assert_eq!(circuit_1.num_gates(), circuit_2.num_gates());
        assert_eq!(circuit_1.num_vars(), circuit_2.num_vars());
        // Check extended permutation polynomials
        let sigma_polys_1 = circuit_1.compute_extended_permutation_polynomials()?;
        let sigma_polys_2 = circuit_2.compute_extended_permutation_polynomials()?;
        sigma_polys_1
            .iter()
            .zip(sigma_polys_2.iter())
            .for_each(|(p1, p2)| assert_eq!(p1, p2));
        Ok(())
    }

    #[test]
    fn test_helper_next_multiple() -> Result<(), PlonkError> {
        assert!(next_multiple(5, 0).is_err());
        assert!(next_multiple(5, 1).is_err());

        assert_eq!(next_multiple(5, 2)?, 6);
        assert_eq!(next_multiple(5, 3)?, 6);
        assert_eq!(next_multiple(5, 4)?, 8);
        assert_eq!(next_multiple(5, 5)?, 5);
        assert_eq!(next_multiple(5, 11)?, 11);
        Ok(())
    }

    #[test]
    fn test_logic_or() -> Result<(), PlonkError> {
        test_logic_or_helper::<FqEd254>()?;
        test_logic_or_helper::<FqEd377>()?;
        test_logic_or_helper::<FqEd381>()?;
        test_logic_or_helper::<Fq377>()
    }

    fn test_logic_or_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let zero_var = circuit.zero();
        let one_var = circuit.one();
        // Good path
        circuit.logic_or_gate(zero_var, one_var)?;
        circuit.logic_or_gate(one_var, zero_var)?;
        circuit.logic_or_gate(one_var, one_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // Error path
        circuit.logic_or_gate(zero_var, zero_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        let circuit_1 = build_logic_or_circuit(F::one(), F::one())?;
        let circuit_2 = build_logic_or_circuit(F::zero(), F::one())?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_logic_or_circuit<F: PrimeField>(a: F, b: F) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(a)?;
        let b = circuit.create_variable(b)?;
        circuit.logic_or_gate(a, b)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_logic_and() -> Result<(), PlonkError> {
        test_logic_and_helper::<FqEd254>()?;
        test_logic_and_helper::<FqEd377>()?;
        test_logic_and_helper::<FqEd381>()?;
        test_logic_and_helper::<Fq377>()
    }

    fn test_logic_and_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let zero_var = circuit.zero();
        let one_var = circuit.one();
        // Good path
        let a = circuit.logic_and(zero_var, one_var)?;
        assert_eq!(F::zero(), circuit.witness(a)?);
        let b = circuit.logic_and(one_var, zero_var)?;
        assert_eq!(F::zero(), circuit.witness(b)?);
        let c = circuit.logic_and(one_var, one_var)?;
        assert_eq!(F::one(), circuit.witness(c)?);
        let d = circuit.logic_and_all(&[zero_var, one_var, one_var])?;
        assert_eq!(F::zero(), circuit.witness(d)?);
        let e = circuit.logic_and_all(&[one_var, one_var, one_var])?;
        assert_eq!(F::one(), circuit.witness(e)?);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // Error path
        *circuit.witness_mut(e) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(e) = F::one();
        assert!(circuit.logic_and_all(&[]).is_err());

        let circuit_1 = build_logic_and_circuit(F::one(), F::one())?;
        let circuit_2 = build_logic_and_circuit(F::zero(), F::one())?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_logic_and_circuit<F: PrimeField>(a: F, b: F) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(a)?;
        let b = circuit.create_variable(b)?;
        circuit.logic_and(a, b)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_is_equal() -> Result<(), PlonkError> {
        test_is_equal_helper::<FqEd254>()?;
        test_is_equal_helper::<FqEd377>()?;
        test_is_equal_helper::<FqEd381>()?;
        test_is_equal_helper::<Fq377>()
    }
    fn test_is_equal_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit = PlonkCircuit::<F>::new();
        let val = F::from(31415u32);
        let a = circuit.create_variable(val)?;
        let b = circuit.create_variable(val)?;
        let a_b_eq = circuit.check_equal(a, b)?;
        let a_zero_eq = circuit.check_equal(a, circuit.zero())?;

        // check circuit
        assert_eq!(circuit.witness(a_b_eq)?, F::one());
        assert_eq!(circuit.witness(a_zero_eq)?, F::zero());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(b) = val + F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.check_equal(circuit.num_vars(), a).is_err());

        let circuit_1 = build_is_equal_circuit(F::one(), F::one())?;
        let circuit_2 = build_is_equal_circuit(F::zero(), F::one())?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_is_equal_circuit<F: PrimeField>(a: F, b: F) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(a)?;
        let b = circuit.create_variable(b)?;
        circuit.check_equal(a, b)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_check_is_zero() -> Result<(), PlonkError> {
        test_check_is_zero_helper::<FqEd254>()?;
        test_check_is_zero_helper::<FqEd377>()?;
        test_check_is_zero_helper::<FqEd381>()?;
        test_check_is_zero_helper::<Fq377>()
    }
    fn test_check_is_zero_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit = PlonkCircuit::<F>::new();
        let val = F::from(31415u32);
        let a = circuit.create_variable(val)?;
        let a_zero_eq = circuit.check_is_zero(a)?;
        let zero_zero_eq = circuit.check_is_zero(circuit.zero())?;

        // check circuit
        assert_eq!(circuit.witness(a_zero_eq)?, F::zero());
        assert_eq!(circuit.witness(zero_zero_eq)?, F::one());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(zero_zero_eq) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(zero_zero_eq) = F::one();
        *circuit.witness_mut(a) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.check_is_zero(circuit.num_vars()).is_err());

        let circuit_1 = build_check_is_zero_circuit(F::one())?;
        let circuit_2 = build_check_is_zero_circuit(F::zero())?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_check_is_zero_circuit<F: PrimeField>(a: F) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit = PlonkCircuit::new();
        let a = circuit.create_variable(a)?;
        circuit.check_is_zero(a)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_quad_poly_gate() -> Result<(), PlonkError> {
        test_quad_poly_gate_helper::<FqEd254>()?;
        test_quad_poly_gate_helper::<FqEd377>()?;
        test_quad_poly_gate_helper::<FqEd381>()?;
        test_quad_poly_gate_helper::<Fq377>()
    }
    fn test_quad_poly_gate_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
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
    ) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
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
    fn test_lc() -> Result<(), PlonkError> {
        test_lc_helper::<FqEd254>()?;
        test_lc_helper::<FqEd377>()?;
        test_lc_helper::<FqEd381>()?;
        test_lc_helper::<Fq377>()
    }
    fn test_lc_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
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

    fn build_lc_circuit<F: PrimeField>(wires_in: [F; 4]) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
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
    fn test_mul_add() -> Result<(), PlonkError> {
        test_mul_add_helper::<FqEd254>()?;
        test_mul_add_helper::<FqEd377>()?;
        test_mul_add_helper::<FqEd381>()?;
        test_mul_add_helper::<Fq377>()
    }

    fn test_mul_add_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit = PlonkCircuit::<F>::new();
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
    ) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit = PlonkCircuit::new();
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
    fn test_conditional_select() -> Result<(), PlonkError> {
        test_conditional_select_helper::<FqEd254>()?;
        test_conditional_select_helper::<FqEd377>()?;
        test_conditional_select_helper::<FqEd381>()?;
        test_conditional_select_helper::<Fq377>()
    }

    fn test_conditional_select_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let bit_true = circuit.create_variable(F::one())?;
        let bit_false = circuit.create_variable(F::zero())?;
        let x_0 = circuit.create_variable(F::from(23u32))?;
        let x_1 = circuit.create_variable(F::from(24u32))?;
        let select_true = circuit.conditional_select(bit_true, x_0, x_1)?;
        let select_false = circuit.conditional_select(bit_false, x_0, x_1)?;

        assert_eq!(circuit.witness(select_true)?, circuit.witness(x_1)?);
        assert_eq!(circuit.witness(select_false)?, circuit.witness(x_0)?);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // if bit is NOT a boolean variable, should fail
        let non_bool = circuit.create_variable(F::from(2u32))?;
        assert!(circuit.conditional_select(non_bool, x_0, x_1).is_err());
        // if mess up the wire value, should fail
        *circuit.witness_mut(bit_false) = F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .conditional_select(bit_false, circuit.num_vars(), x_1)
            .is_err());

        // build two fixed circuits with different variable assignments, checking that
        // the arithmetized extended permutation polynomial is variable
        // independent
        let circuit_1 = build_conditional_select_circuit(F::one(), F::from(23u32), F::from(24u32))?;
        let circuit_2 =
            build_conditional_select_circuit(F::zero(), F::from(99u32), F::from(98u32))?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;
        Ok(())
    }

    fn build_conditional_select_circuit<F: PrimeField>(
        bit: F,
        x_0: F,
        x_1: F,
    ) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let bit_var = circuit.create_variable(bit)?;
        let x_0_var = circuit.create_variable(x_0)?;
        let x_1_var = circuit.create_variable(x_1)?;
        circuit.conditional_select(bit_var, x_0_var, x_1_var)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_sum() -> Result<(), PlonkError> {
        test_sum_helper::<FqEd254>()?;
        test_sum_helper::<FqEd377>()?;
        test_sum_helper::<FqEd381>()?;
        test_sum_helper::<Fq377>()
    }

    fn test_sum_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
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

    fn build_sum_circuit<F: PrimeField>(vals: Vec<F>) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let mut vars = vec![];
        for val in vals {
            vars.push(circuit.create_variable(val)?);
        }
        circuit.sum(&vars[..])?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_unpack() -> Result<(), PlonkError> {
        test_unpack_helper::<FqEd254>()?;
        test_unpack_helper::<FqEd377>()?;
        test_unpack_helper::<FqEd381>()?;
        test_unpack_helper::<Fq377>()
    }

    fn test_unpack_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::one())?;
        let b = circuit.create_variable(F::from(1023u32))?;

        circuit.range_gate(a, 1)?;
        let a_le = circuit.unpack(a, 3)?;
        assert_eq!(a_le.len(), 3);
        let b_le = circuit.unpack(b, 10)?;
        assert_eq!(b_le.len(), 10);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        assert!(circuit.unpack(b, 9).is_err());
        Ok(())
    }

    #[test]
    fn test_range_gate() -> Result<(), PlonkError> {
        test_range_gate_helper::<FqEd254>()?;
        test_range_gate_helper::<FqEd377>()?;
        test_range_gate_helper::<FqEd381>()?;
        test_range_gate_helper::<Fq377>()
    }
    fn test_range_gate_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::one())?;
        let b = circuit.create_variable(F::from(1023u32))?;

        circuit.range_gate(a, 1)?;
        circuit.range_gate(a, 3)?;
        circuit.range_gate(b, 10)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        circuit.range_gate(b, 9)?;
        assert!(circuit.range_gate(a, 0).is_err());
        // non-positive bit length is undefined, thus fail
        assert!(circuit.range_gate(a, 0).is_err());
        // bit length bigger than that of a field element (bit length takes 256 or 381
        // bits)
        let bit_len = (F::size_in_bits() / 8 + 1) * 8;
        assert!(circuit.range_gate(a, bit_len + 1).is_err());
        // if mess up the wire value, should fail
        *circuit.witness_mut(b) = F::from(1024u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.range_gate(circuit.num_vars(), 10).is_err());

        // build two fixed circuits with different variable assignments, checking that
        // the arithmetized extended permutation polynomial is variable
        // independent
        let circuit_1 = build_range_gate_circuit(F::from(314u32))?;
        let circuit_2 = build_range_gate_circuit(F::from(489u32))?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_range_gate_circuit<F: PrimeField>(a: F) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a_var = circuit.create_variable(a)?;
        circuit.range_gate(a_var, 10)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_check_in_range() -> Result<(), PlonkError> {
        test_check_in_range_helper::<FqEd254>()?;
        test_check_in_range_helper::<FqEd377>()?;
        test_check_in_range_helper::<FqEd381>()?;
        test_check_in_range_helper::<Fq377>()
    }
    fn test_check_in_range_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a = circuit.create_variable(F::from(1023u32))?;

        let b1 = circuit.check_in_range(a, 5)?;
        let b2 = circuit.check_in_range(a, 10)?;
        let b3 = circuit.check_in_range(a, 0)?;
        assert_eq!(circuit.witness(b1)?, F::zero());
        assert_eq!(circuit.witness(b2)?, F::one());
        assert_eq!(circuit.witness(b3)?, F::zero());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // if mess up the wire value, should fail
        *circuit.witness_mut(a) = F::from(1024u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.check_in_range(circuit.num_vars(), 10).is_err());

        // build two fixed circuits with different variable assignments, checking that
        // the arithmetized extended permutation polynomial is variable
        // independent
        let circuit_1 = build_check_in_range_circuit(F::from(314u32))?;
        let circuit_2 = build_check_in_range_circuit(F::from(1489u32))?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_check_in_range_circuit<F: PrimeField>(a: F) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let a_var = circuit.create_variable(a)?;
        circuit.check_in_range(a_var, 10)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_arithmetization() -> Result<(), PlonkError> {
        test_arithmetization_helper::<FqEd254>()?;
        test_arithmetization_helper::<FqEd377>()?;
        test_arithmetization_helper::<FqEd381>()?;
        test_arithmetization_helper::<Fq377>()
    }

    fn test_arithmetization_helper<F: PrimeField>() -> Result<(), PlonkError> {
        // Create the circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        // is_equal gate
        let val = F::from(31415u32);
        let a = circuit.create_variable(val)?;
        let b = circuit.create_variable(val)?;
        circuit.check_equal(a, b)?;

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
        let bit_true = circuit.create_variable(F::one())?;
        let x_0 = circuit.create_variable(F::from(23u32))?;
        let x_1 = circuit.create_variable(F::from(24u32))?;
        circuit.conditional_select(bit_true, x_0, x_1)?;

        // range gate
        let b = circuit.create_variable(F::from(1023u32))?;
        circuit.range_gate(b, 10)?;

        // sum gate
        let mut vars = vec![];
        for i in 0..11 {
            vars.push(circuit.create_variable(F::from(i as u32))?);
        }
        circuit.sum(&vars[..vars.len()])?;

        // Finalize the circuit
        circuit.finalize_for_arithmetization()?;
        let pub_inputs = vec![];
        circuit::basic::test::test_arithmetization_for_circuit(circuit, pub_inputs)?;
        Ok(())
    }

    #[test]
    fn test_non_zero_gate() -> Result<(), PlonkError> {
        test_non_zero_gate_helper::<FqEd254>()?;
        test_non_zero_gate_helper::<FqEd377>()?;
        test_non_zero_gate_helper::<FqEd381>()?;
        test_non_zero_gate_helper::<Fq377>()
    }
    fn test_non_zero_gate_helper<F: PrimeField>() -> Result<(), PlonkError> {
        // Create the circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let non_zero_var = circuit.create_variable(F::from(2_u32))?;
        let _ = circuit.non_zero_gate(non_zero_var);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let zero_var = circuit.create_variable(F::from(0_u32))?;
        let _ = circuit.non_zero_gate(zero_var);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_power_11_gen_gate() -> Result<(), PlonkError> {
        test_power_11_gen_gate_helper::<FqEd254>()?;
        test_power_11_gen_gate_helper::<FqEd377>()?;
        test_power_11_gen_gate_helper::<FqEd381>()?;
        test_power_11_gen_gate_helper::<Fq377>()
    }
    fn test_power_11_gen_gate_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut rng = test_rng();
        let x = F::rand(&mut rng);
        let y = F::rand(&mut rng);
        let x11 = x.pow(&[11]);

        // Create a satisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();

        let x_var = circuit.create_variable(x)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        let x_to_11_var_rec = circuit.power_11_gen(x_var)?;
        circuit.equal_gate(x_to_11_var, x_to_11_var_rec)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();

        let y_var = circuit.create_variable(y)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        let x_to_11_var_rec = circuit.power_11_gen(y_var)?;
        circuit.equal_gate(x_to_11_var, x_to_11_var_rec)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let x_var = circuit.create_variable(x)?;
        let y_var = circuit.create_variable(y)?;

        let x_to_11_var_rec = circuit.power_11_gen(x_var)?;
        circuit.equal_gate(y_var, x_to_11_var_rec)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_power_11_gate() -> Result<(), PlonkError> {
        test_power_11_gate_helper::<FqEd254>()?;
        test_power_11_gate_helper::<FqEd377>()?;
        test_power_11_gate_helper::<FqEd381>()?;
        test_power_11_gate_helper::<Fq377>()
    }
    fn test_power_11_gate_helper<F: PrimeField>() -> Result<(), PlonkError> {
        let mut rng = test_rng();
        let x = F::rand(&mut rng);
        let y = F::rand(&mut rng);
        let x11 = x.pow(&[11]);

        // Create a satisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let x_var = circuit.create_variable(x)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        circuit.power_11_gate(x_var, x_to_11_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let y_var = circuit.create_variable(y)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        circuit.power_11_gate(y_var, x_to_11_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();
        let x_var = circuit.create_variable(x)?;
        let y = circuit.create_variable(y)?;

        circuit.power_11_gate(x_var, y)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }
}
