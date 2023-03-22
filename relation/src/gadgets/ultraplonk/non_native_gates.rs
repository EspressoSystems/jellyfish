// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements non-native circuits that are mainly
//! useful for rescue hash function.

use super::mod_arith::{FpElem, FpElemVar};
use crate::{errors::CircuitError, Circuit, PlonkCircuit};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{format, vec::Vec};

impl<F: PrimeField> PlonkCircuit<F> {
    /// generate a non-native circuit for the statement x^11 = y
    ///
    /// Input:
    ///  - variable representation of x over a target field `T` whose order is
    ///    less than F.
    ///  - variable representation of x^11 over a same field
    ///
    /// Cost: 5 mod_mul + 2 equal gate
    pub fn non_native_power_11_gate<T: PrimeField>(
        &mut self,
        x: &FpElemVar<F>,
        x_to_11: &FpElemVar<F>,
    ) -> Result<(), CircuitError> {
        self.check_var_bound(x.components().0)?;
        self.check_var_bound(x.components().1)?;
        self.check_var_bound(x_to_11.components().0)?;
        self.check_var_bound(x_to_11.components().1)?;

        if T::MODULUS_BIT_SIZE >= F::MODULUS_BIT_SIZE {
            return Err(CircuitError::NotSupported(format!(
                "Target field size ({}) is greater than evaluation field size (P{})",
                T::MODULUS_BIT_SIZE,
                F::MODULUS_BIT_SIZE
            )));
        }

        // x^11 = y
        let y = self.non_native_power_11_gen::<T>(x)?;
        self.enforce_equal(x_to_11.components().0, y.components().0)?;
        self.enforce_equal(x_to_11.components().1, y.components().1)
    }

    /// generate a non-native circuit for the statement x^11 = y
    ///
    /// Input: variable representation of x over a target
    /// field `T` whose order is less than F.
    ///
    /// Output: variable representation of x^11
    ///
    /// Cost: 5 mod_mul
    pub fn non_native_power_11_gen<T: PrimeField>(
        &mut self,
        x: &FpElemVar<F>,
    ) -> Result<FpElemVar<F>, CircuitError> {
        // // checks already done by the caller
        // if T::MODULUS_BIT_SIZE >= F::MODULUS_BIT_SIZE {
        //     return Err(CircuitError::NotSupported(format!(
        //         "Target field size ({}) is greater than evaluation field size (P{})",
        //         T::MODULUS_BIT_SIZE,
        //         F::MODULUS_BIT_SIZE
        //     ))
        //     .into());
        // }

        // convert T::MODULUS into an element in F
        // Guaranteed without mod reduction since T::MODULUS_BIT_SIZE <
        // F::MODULUS_BIT_SIZE
        let t_modulus = F::from_le_bytes_mod_order(T::MODULUS.to_bytes_le().as_ref());

        // convert t_modulus into FpElem
        let m = x.param_m();
        let two_power_m = Some(x.two_power_m());
        let p = FpElem::new(&t_modulus, m, two_power_m)?;

        // x^11 = y
        let x2 = self.mod_mul(x, x, &p)?;
        let x3 = self.mod_mul(&x2, x, &p)?;
        let x4 = self.mod_mul(&x2, &x2, &p)?;
        let x8 = self.mod_mul(&x4, &x4, &p)?;
        self.mod_mul(&x3, &x8, &p)
    }

    /// generate a non-native circuit for the statement x^5 = y
    ///
    /// Input: variable representation of x over a target
    /// field `T` whose order is less than F.
    ///
    /// Output: variable representation of x^5
    ///
    /// Cost: 3 mod_mul
    pub fn non_native_power_5_gen<T: PrimeField>(
        &mut self,
        x: &FpElemVar<F>,
    ) -> Result<FpElemVar<F>, CircuitError> {
        // checks already done by the caller
        if T::MODULUS_BIT_SIZE >= F::MODULUS_BIT_SIZE {
            return Err(CircuitError::NotSupported(format!(
                "Target field size ({}) is greater than evaluation field size (P{})",
                T::MODULUS_BIT_SIZE,
                F::MODULUS_BIT_SIZE
            )));
        }

        // convert T::MODULUS into an element in F
        // Guaranteed without mod reduction since T::MODULUS_BIT_SIZE <
        // F::MODULUS_BIT_SIZE
        let t_modulus = F::from_le_bytes_mod_order(T::MODULUS.to_bytes_le().as_ref());

        // convert t_modulus into FpElem
        let m = x.param_m();
        let two_power_m = Some(x.two_power_m());
        let p = FpElem::new(&t_modulus, m, two_power_m)?;

        // x^5 = y
        let x2 = self.mod_mul(x, x, &p)?;
        let x3 = self.mod_mul(&x2, x, &p)?;
        self.mod_mul(&x2, &x3, &p)
    }

    /// Input vector x and y, and a constant c,
    /// generate a non-native circuit for the statement
    ///     var_output = inner_product(x, y) + c
    /// Input: variable representation of x, y, c over a target
    /// field `T` whose order is less than F.
    ///
    /// Cost: 4 mod_mul_constant + 1 mod_add_internal
    #[allow(clippy::many_single_char_names)]
    pub fn non_native_linear_gen<T: PrimeField>(
        &mut self,
        x: &[FpElemVar<F>],
        y: &[FpElem<F>],
        c: &FpElem<F>,
    ) -> Result<FpElemVar<F>, CircuitError> {
        let m = c.param_m();
        let two_power_m = Some(c.two_power_m());

        // check the correctness of parameters
        if T::MODULUS_BIT_SIZE >= F::MODULUS_BIT_SIZE {
            return Err(CircuitError::NotSupported(format!(
                "Target field size ({}) is greater than evaluation field size ({})",
                T::MODULUS_BIT_SIZE,
                F::MODULUS_BIT_SIZE
            )));
        }

        if x.len() != y.len() {
            return Err(CircuitError::ParameterError(format!(
                "inputs x any y has different length ({} vs {})",
                x.len(),
                y.len()
            )));
        }
        for e in x {
            if m != e.param_m() {
                return Err(CircuitError::ParameterError(format!(
                    "inputs x any c has different m parameter ({} vs {})",
                    e.param_m(),
                    m
                )));
            }
        }
        for e in y {
            if m != e.param_m() {
                return Err(CircuitError::ParameterError(format!(
                    "inputs y any c has different m parameter ({} vs {})",
                    e.param_m(),
                    m
                )));
            }
        }

        // convert T::MODULUS into an element in F
        // Guaranteed without mod reduction since T::MODULUS_BIT_SIZE <
        // F::MODULUS_BIT_SIZE
        let t_modulus = F::from_le_bytes_mod_order(T::MODULUS.to_bytes_le().as_ref());

        // convert t_modulus into FpElem
        let p = FpElem::new(&t_modulus, m, two_power_m)?;

        // generate the linear statement
        // (\sum x[i] * y[i]) + c
        let xiyi: Vec<FpElemVar<F>> = x
            .iter()
            .zip(y)
            .map(|(xi, yi)| self.mod_mul_constant(xi, yi, &p))
            .collect::<Result<Vec<FpElemVar<F>>, _>>()?;
        let sum_xiyi = self.mod_add_vec(xiyi.as_ref(), &p)?;
        self.mod_add_constant(&sum_xiyi, c, &p)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Circuit, Variable};
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use jf_utils::test_rng;

    const RANGE_BIT_LEN_FOR_TEST: usize = 8;

    #[test]
    fn test_non_native_power_11_gen() -> Result<(), CircuitError> {
        // use bls12-377 base field to prove rescue over jubjub377 base field
        test_non_native_power_11_gen_helper::<FqEd377, Fq377>()
    }

    fn test_non_native_power_11_gen_helper<T: PrimeField, F: PrimeField>(
    ) -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let mut rng = test_rng();
        let x_t = T::rand(&mut rng);
        let y_t = x_t.pow([11]);
        let x_p = F::from_le_bytes_mod_order(x_t.into_bigint().to_bytes_le().as_ref());
        let y_p = F::from_le_bytes_mod_order(y_t.into_bigint().to_bytes_le().as_ref());

        let m = (T::MODULUS_BIT_SIZE as usize / 2 / RANGE_BIT_LEN_FOR_TEST + 1)
            * RANGE_BIT_LEN_FOR_TEST;

        let x_var = circuit.create_variable(x_p)?;
        let y_var = circuit.create_variable(y_p)?;

        let x_split_vars = FpElemVar::new_unchecked(&mut circuit, x_var, m, None)?;
        let x11_split_vars = circuit.non_native_power_11_gen::<T>(&x_split_vars)?;
        let x11_var = x11_split_vars.convert_to_var(&mut circuit)?;

        // good path
        circuit.enforce_equal(x11_var, y_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // bad path: wrong witness should fail
        let witness = circuit.witness(y_var)?;
        *circuit.witness_mut(y_var) = F::rand(&mut rng);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(y_var) = witness;

        // bad path: wrong value should fail
        let y_wrong = F::rand(&mut rng);
        let y_wrong_var = circuit.create_variable(y_wrong)?;
        circuit.enforce_equal(x11_var, y_wrong_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_non_native_power_5_gen() -> Result<(), CircuitError> {
        // use bls12-377 base field to prove rescue over jubjub377 base field
        test_non_native_power_5_gen_helper::<FqEd377, Fq377>()
    }

    fn test_non_native_power_5_gen_helper<T: PrimeField, F: PrimeField>() -> Result<(), CircuitError>
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let mut rng = test_rng();
        let x_t = T::rand(&mut rng);
        let y_t = x_t.pow([5]);
        let x_p = F::from_le_bytes_mod_order(x_t.into_bigint().to_bytes_le().as_ref());
        let y_p = F::from_le_bytes_mod_order(y_t.into_bigint().to_bytes_le().as_ref());

        let m = (T::MODULUS_BIT_SIZE as usize / 2 / RANGE_BIT_LEN_FOR_TEST + 1)
            * RANGE_BIT_LEN_FOR_TEST;

        let x_var = circuit.create_variable(x_p)?;
        let y_var = circuit.create_variable(y_p)?;

        let x_split_vars = FpElemVar::new_unchecked(&mut circuit, x_var, m, None)?;
        let x5_split_vars = circuit.non_native_power_5_gen::<T>(&x_split_vars)?;
        let x5_var = x5_split_vars.convert_to_var(&mut circuit)?;

        // good path
        circuit.enforce_equal(x5_var, y_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // bad path: wrong witness should fail
        let witness = circuit.witness(y_var)?;
        *circuit.witness_mut(y_var) = F::rand(&mut rng);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(y_var) = witness;

        // bad path: wrong value should fail
        let y_wrong = F::rand(&mut rng);
        let y_wrong_var = circuit.create_variable(y_wrong)?;
        circuit.enforce_equal(x5_var, y_wrong_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_non_native_power_11_gate() -> Result<(), CircuitError> {
        // use bls12-377 base field to prove rescue over bls scalar field
        test_non_native_power_11_gate_helper::<FqEd377, Fq377>()
    }

    fn test_non_native_power_11_gate_helper<T: PrimeField, F: PrimeField>(
    ) -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let mut rng = test_rng();
        let x_t = T::rand(&mut rng);
        let y_t = x_t.pow([11]);
        let x_p = F::from_le_bytes_mod_order(x_t.into_bigint().to_bytes_le().as_ref());
        let y_p = F::from_le_bytes_mod_order(y_t.into_bigint().to_bytes_le().as_ref());

        let m = (T::MODULUS_BIT_SIZE as usize / 2 / RANGE_BIT_LEN_FOR_TEST + 1)
            * RANGE_BIT_LEN_FOR_TEST;

        let x_var = circuit.create_variable(x_p)?;
        let y_var = circuit.create_variable(y_p)?;

        let x_split_vars = FpElemVar::new_unchecked(&mut circuit, x_var, m, None)?;
        let y_split_vars =
            FpElemVar::new_unchecked(&mut circuit, y_var, m, Some(x_split_vars.two_power_m()))?;

        circuit.non_native_power_11_gate::<T>(&x_split_vars, &y_split_vars)?;

        // good path
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // bad path: wrong witness should fail
        let witness = circuit.witness(y_var)?;
        *circuit.witness_mut(y_var) = F::rand(&mut rng);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(y_var) = witness;

        // bad path: wrong value should fail
        let y_wrong = F::rand(&mut rng);
        let y_wrong_var = circuit.create_variable(y_wrong)?;
        let y_wrong_split_vars = FpElemVar::new_unchecked(
            &mut circuit,
            y_wrong_var,
            m,
            Some(x_split_vars.two_power_m()),
        )?;
        circuit.non_native_power_11_gate::<T>(&x_split_vars, &y_wrong_split_vars)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_non_native_linear_gate() -> Result<(), CircuitError> {
        // use bls12-377 base field to prove rescue over jubjub377 base field
        test_non_native_linear_gate_helper::<FqEd377, Fq377>()
    }

    fn test_non_native_linear_gate_helper<T: PrimeField, F: PrimeField>() -> Result<(), CircuitError>
    {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        let m = (T::MODULUS_BIT_SIZE as usize / 2 / RANGE_BIT_LEN_FOR_TEST + 1)
            * RANGE_BIT_LEN_FOR_TEST;

        let mut rng = test_rng();

        let x_t: Vec<T> = (0..4).map(|_| T::rand(&mut rng)).collect();
        let y_t: Vec<T> = (0..4).map(|_| T::rand(&mut rng)).collect();
        let c_t = T::rand(&mut rng);
        let mut res_t = c_t;
        for (&xi, &yi) in x_t.iter().zip(y_t.iter()) {
            res_t += xi * yi;
        }
        let res_p = F::from_le_bytes_mod_order(res_t.into_bigint().to_bytes_le().as_ref());

        let x_p: Vec<F> = x_t
            .iter()
            .map(|x| F::from_le_bytes_mod_order(x.into_bigint().to_bytes_le().as_ref()))
            .collect();
        let y_p: Vec<F> = y_t
            .iter()
            .map(|y| F::from_le_bytes_mod_order(y.into_bigint().to_bytes_le().as_ref()))
            .collect();
        let c_p = F::from_le_bytes_mod_order(c_t.into_bigint().to_bytes_le().as_ref());

        let x_vars: Vec<Variable> = x_p
            .iter()
            .map(|x| circuit.create_variable(*x))
            .collect::<Result<Vec<Variable>, _>>()?;

        let x_split_vars: Vec<FpElemVar<F>> = x_vars
            .iter()
            .map(|x| FpElemVar::new_unchecked(&mut circuit, *x, m, None))
            .collect::<Result<Vec<FpElemVar<F>>, _>>()?;
        let y_split: Vec<FpElem<F>> = y_p
            .iter()
            .map(|y| FpElem::new(y, m, Some(x_split_vars[0].two_power_m())))
            .collect::<Result<Vec<FpElem<F>>, _>>()?;
        let c_split = FpElem::new(&c_p, m, Some(x_split_vars[0].two_power_m()))?;

        // check the result is correct
        let res_split_var =
            circuit.non_native_linear_gen::<T>(&x_split_vars, &y_split, &c_split)?;
        let res_var = res_split_var.convert_to_var(&mut circuit)?;
        assert_eq!(circuit.witness(res_var)?, res_p);

        // good path: the circuit is satisfied
        let res_var2 = circuit.create_variable(res_p)?;
        circuit.enforce_equal(res_var, res_var2)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // bad path: wrong witness should fail
        let witness = circuit.witness(x_vars[0])?;
        *circuit.witness_mut(x_vars[0]) = F::rand(&mut rng);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(x_vars[0]) = witness;

        // bad path: wrong value should fail
        let res_var3 = F::rand(&mut rng);
        let res_var3 = circuit.create_variable(res_var3)?;
        circuit.enforce_equal(res_var, res_var3)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }
}
