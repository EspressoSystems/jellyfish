// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Logic related circuit implementations

use crate::{
    errors::CircuitError,
    gates::{CondSelectGate, LogicOrGate, LogicOrOutputGate},
    BoolVar, Circuit, PlonkCircuit, Variable,
};
use ark_ff::PrimeField;
use ark_std::{boxed::Box, string::ToString};

impl<F: PrimeField> PlonkCircuit<F> {
    /// Constrain that `a` is true or `b` is true.
    /// Return error if variables are invalid.
    pub fn logic_or_gate(&mut self, a: BoolVar, b: BoolVar) -> Result<(), CircuitError> {
        self.check_var_bound(a.into())?;
        self.check_var_bound(b.into())?;
        let wire_vars = &[a.into(), b.into(), 0, 0, 0];
        self.insert_gate(wire_vars, Box::new(LogicOrGate))?;
        Ok(())
    }

    /// Obtain a bool variable representing whether two input variables are
    /// equal. Return error if variables are invalid.
    pub fn is_equal(&mut self, a: Variable, b: Variable) -> Result<BoolVar, CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let delta = self.sub(a, b)?;
        self.is_zero(delta)
    }

    /// Obtain a bool variable representing whether input variable is zero.
    /// Return error if the input variable is invalid.
    pub fn is_zero(&mut self, a: Variable) -> Result<BoolVar, CircuitError> {
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
        let y = self.create_boolean_variable_unchecked(y)?;
        let a_inv = self.create_variable(a_inv)?;

        // constraint 1: 1 - a * a^(-1) = y, i.e., a * a^(-1) + 1 * y = 1
        self.mul_add_gate(
            &[a, a_inv, self.one(), y.into(), self.one()],
            &[F::one(), F::one()],
        )?;
        // constraint 2: multiplication y * a = 0
        self.mul_gate(y.into(), a, self.zero())?;
        Ok(y)
    }

    /// Constrain a variable to be non-zero.
    /// Return error if the variable is invalid.
    pub fn non_zero_gate(&mut self, var: Variable) -> Result<(), CircuitError> {
        let inverse = self.witness(var)?.inverse().unwrap_or_else(F::zero);
        let inv_var = self.create_variable(inverse)?;
        let one_var = self.one();
        self.mul_gate(var, inv_var, one_var)
    }

    /// Obtain a variable representing the result of a logic negation gate.
    /// Return the index of the variable. Return error if the input variable
    /// is invalid.
    pub fn logic_neg(&mut self, a: BoolVar) -> Result<BoolVar, CircuitError> {
        self.is_zero(a.into())
    }

    /// Obtain a variable representing the result of a logic AND gate. Return
    /// the index of the variable. Return error if the input variables are
    /// invalid.
    pub fn logic_and(&mut self, a: BoolVar, b: BoolVar) -> Result<BoolVar, CircuitError> {
        let c = self
            .create_boolean_variable_unchecked(self.witness(a.into())? * self.witness(b.into())?)?;
        self.mul_gate(a.into(), b.into(), c.into())?;
        Ok(c)
    }

    /// Given a list of boolean variables, obtain a variable representing the
    /// result of a logic AND gate. Return the index of the variable. Return
    /// error if the input variables are invalid.
    pub fn logic_and_all(&mut self, vars: &[BoolVar]) -> Result<BoolVar, CircuitError> {
        if vars.is_empty() {
            return Err(CircuitError::ParameterError(
                "logic_and_all: empty variable list".to_string(),
            ));
        }
        let mut res = vars[0];
        for &var in vars.iter().skip(1) {
            res = self.logic_and(res, var)?;
        }
        Ok(res)
    }

    /// Obtain a variable representing the result of a logic OR gate. Return the
    /// index of the variable. Return error if the input variables are
    /// invalid.
    pub fn logic_or(&mut self, a: BoolVar, b: BoolVar) -> Result<BoolVar, CircuitError> {
        self.check_var_bound(a.into())?;
        self.check_var_bound(b.into())?;

        let a_val = self.witness(a.into())?;
        let b_val = self.witness(b.into())?;
        let c_val = a_val + b_val - a_val * b_val;

        let c = self.create_boolean_variable_unchecked(c_val)?;
        let wire_vars = &[a.into(), b.into(), 0, 0, c.into()];
        self.insert_gate(wire_vars, Box::new(LogicOrOutputGate))?;

        Ok(c)
    }

    /// Assuming values represented by `a` is boolean.
    /// Constrain `a` is true
    pub fn enforce_true(&mut self, a: Variable) -> Result<(), CircuitError> {
        self.enforce_constant(a, F::one())
    }

    /// Assuming values represented by `a` is boolean.
    /// Constrain `a` is false
    pub fn enforce_false(&mut self, a: Variable) -> Result<(), CircuitError> {
        self.enforce_constant(a, F::zero())
    }

    /// Obtain a variable that equals `x_0` if `b` is zero, or `x_1` if `b` is
    /// one. Return error if variables are invalid.
    pub fn conditional_select(
        &mut self,
        b: BoolVar,
        x_0: Variable,
        x_1: Variable,
    ) -> Result<Variable, CircuitError> {
        self.check_var_bound(b.into())?;
        self.check_var_bound(x_0)?;
        self.check_var_bound(x_1)?;

        // y = x_bit
        let y = if self.witness(b.into())? == F::zero() {
            self.create_variable(self.witness(x_0)?)?
        } else if self.witness(b.into())? == F::one() {
            self.create_variable(self.witness(x_1)?)?
        } else {
            return Err(CircuitError::ParameterError(
                "b in Conditional Selection gate is not a boolean variable".to_string(),
            ));
        };
        let wire_vars = [b.into(), x_0, b.into(), x_1, y];
        self.insert_gate(&wire_vars, Box::new(CondSelectGate))?;
        Ok(y)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        errors::CircuitError, gadgets::test_utils::test_variable_independence_for_circuit, Circuit,
        PlonkCircuit,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::PrimeField;

    #[test]
    fn test_logic_or() -> Result<(), CircuitError> {
        test_logic_or_helper::<FqEd254>()?;
        test_logic_or_helper::<FqEd377>()?;
        test_logic_or_helper::<FqEd381>()?;
        test_logic_or_helper::<Fq377>()
    }

    fn test_logic_or_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let false_var = circuit.false_var();
        let true_var = circuit.true_var();
        // Good path
        let should_be_true = circuit.logic_or(false_var, true_var)?;
        assert!(circuit.witness(should_be_true.into())?.eq(&F::one()));
        let should_be_true = circuit.logic_or(true_var, false_var)?;
        assert!(circuit.witness(should_be_true.into())?.eq(&F::one()));
        let should_be_true = circuit.logic_or(true_var, true_var)?;
        assert!(circuit.witness(should_be_true.into())?.eq(&F::one()));
        // Error path
        let should_be_false = circuit.logic_or(false_var, false_var)?;
        assert!(circuit.witness(should_be_false.into())?.eq(&F::zero()));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        Ok(())
    }
    #[test]
    fn test_logic_or_gate() -> Result<(), CircuitError> {
        test_logic_or_gate_helper::<FqEd254>()?;
        test_logic_or_gate_helper::<FqEd377>()?;
        test_logic_or_gate_helper::<FqEd381>()?;
        test_logic_or_gate_helper::<Fq377>()
    }

    fn test_logic_or_gate_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let false_var = circuit.false_var();
        let true_var = circuit.true_var();
        // Good path
        circuit.logic_or_gate(false_var, true_var)?;
        circuit.logic_or_gate(true_var, false_var)?;
        circuit.logic_or_gate(true_var, true_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // Error path
        circuit.logic_or_gate(false_var, false_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        let circuit_1 = build_logic_or_circuit(true, true)?;
        let circuit_2 = build_logic_or_circuit(false, true)?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_logic_or_circuit<F: PrimeField>(
        a: bool,
        b: bool,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_boolean_variable(a)?;
        let b = circuit.create_boolean_variable(b)?;
        circuit.logic_or_gate(a, b)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_logic_and() -> Result<(), CircuitError> {
        test_logic_and_helper::<FqEd254>()?;
        test_logic_and_helper::<FqEd377>()?;
        test_logic_and_helper::<FqEd381>()?;
        test_logic_and_helper::<Fq377>()
    }

    fn test_logic_and_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let false_var = circuit.false_var();
        let true_var = circuit.true_var();
        // Good path
        let a = circuit.logic_and(false_var, true_var)?;
        assert_eq!(F::zero(), circuit.witness(a.into())?);
        let b = circuit.logic_and(true_var, false_var)?;
        assert_eq!(F::zero(), circuit.witness(b.into())?);
        let c = circuit.logic_and(true_var, true_var)?;
        assert_eq!(F::one(), circuit.witness(c.into())?);
        let d = circuit.logic_and_all(&[false_var, true_var, true_var])?;
        assert_eq!(F::zero(), circuit.witness(d.into())?);
        let e = circuit.logic_and_all(&[true_var, true_var, true_var])?;
        assert_eq!(F::one(), circuit.witness(e.into())?);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // Error path
        *circuit.witness_mut(e.into()) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(e.into()) = F::one();
        assert!(circuit.logic_and_all(&[]).is_err());

        let circuit_1 = build_logic_and_circuit(true, true)?;
        let circuit_2 = build_logic_and_circuit(false, true)?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_logic_and_circuit<F: PrimeField>(
        a: bool,
        b: bool,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_boolean_variable(a)?;
        let b = circuit.create_boolean_variable(b)?;
        circuit.logic_and(a, b)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_is_equal() -> Result<(), CircuitError> {
        test_is_equal_helper::<FqEd254>()?;
        test_is_equal_helper::<FqEd377>()?;
        test_is_equal_helper::<FqEd381>()?;
        test_is_equal_helper::<Fq377>()
    }
    fn test_is_equal_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let val = F::from(31415u32);
        let a = circuit.create_variable(val)?;
        let b = circuit.create_variable(val)?;
        let a_b_eq = circuit.is_equal(a, b)?;
        let a_zero_eq = circuit.is_equal(a, circuit.zero())?;

        // check circuit
        assert_eq!(circuit.witness(a_b_eq.into())?, F::one());
        assert_eq!(circuit.witness(a_zero_eq.into())?, F::zero());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(b) = val + F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.is_equal(circuit.num_vars(), a).is_err());

        let circuit_1 = build_is_equal_circuit(F::one(), F::one())?;
        let circuit_2 = build_is_equal_circuit(F::zero(), F::one())?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_is_equal_circuit<F: PrimeField>(a: F, b: F) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(a)?;
        let b = circuit.create_variable(b)?;
        circuit.is_equal(a, b)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_check_is_zero() -> Result<(), CircuitError> {
        test_check_is_zero_helper::<FqEd254>()?;
        test_check_is_zero_helper::<FqEd377>()?;
        test_check_is_zero_helper::<FqEd381>()?;
        test_check_is_zero_helper::<Fq377>()
    }
    fn test_check_is_zero_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let val = F::from(31415u32);
        let a = circuit.create_variable(val)?;
        let a_zero_eq = circuit.is_zero(a)?;
        let zero_zero_eq = circuit.is_zero(circuit.zero())?;

        // check circuit
        assert_eq!(circuit.witness(a_zero_eq.into())?, F::zero());
        assert_eq!(circuit.witness(zero_zero_eq.into())?, F::one());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(zero_zero_eq.into()) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(zero_zero_eq.into()) = F::one();
        *circuit.witness_mut(a) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.is_zero(circuit.num_vars()).is_err());

        let circuit_1 = build_check_is_zero_circuit(F::one())?;
        let circuit_2 = build_check_is_zero_circuit(F::zero())?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;

        Ok(())
    }

    fn build_check_is_zero_circuit<F: PrimeField>(a: F) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(a)?;
        circuit.is_zero(a)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_conditional_select() -> Result<(), CircuitError> {
        test_conditional_select_helper::<FqEd254>()?;
        test_conditional_select_helper::<FqEd377>()?;
        test_conditional_select_helper::<FqEd381>()?;
        test_conditional_select_helper::<Fq377>()
    }

    fn test_conditional_select_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let bit_true = circuit.true_var();
        let bit_false = circuit.false_var();

        let x_0 = circuit.create_variable(F::from(23u32))?;
        let x_1 = circuit.create_variable(F::from(24u32))?;
        let select_true = circuit.conditional_select(bit_true, x_0, x_1)?;
        let select_false = circuit.conditional_select(bit_false, x_0, x_1)?;

        assert_eq!(circuit.witness(select_true)?, circuit.witness(x_1)?);
        assert_eq!(circuit.witness(select_false)?, circuit.witness(x_0)?);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // if mess up the wire value, should fail
        *circuit.witness_mut(bit_false.into()) = F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit
            .conditional_select(bit_false, circuit.num_vars(), x_1)
            .is_err());

        // build two fixed circuits with different variable assignments, checking that
        // the arithmetized extended permutation polynomial is variable
        // independent
        let circuit_1 = build_conditional_select_circuit(true, F::from(23u32), F::from(24u32))?;
        let circuit_2 = build_conditional_select_circuit(false, F::from(99u32), F::from(98u32))?;
        test_variable_independence_for_circuit(circuit_1, circuit_2)?;
        Ok(())
    }

    fn build_conditional_select_circuit<F: PrimeField>(
        bit: bool,
        x_0: F,
        x_1: F,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let bit_var = circuit.create_boolean_variable(bit)?;
        let x_0_var = circuit.create_variable(x_0)?;
        let x_1_var = circuit.create_variable(x_1)?;
        circuit.conditional_select(bit_var, x_0_var, x_1_var)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_non_zero_gate() -> Result<(), CircuitError> {
        test_non_zero_gate_helper::<FqEd254>()?;
        test_non_zero_gate_helper::<FqEd377>()?;
        test_non_zero_gate_helper::<FqEd381>()?;
        test_non_zero_gate_helper::<Fq377>()
    }
    fn test_non_zero_gate_helper<F: PrimeField>() -> Result<(), CircuitError> {
        // Create the circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let non_zero_var = circuit.create_variable(F::from(2_u32))?;
        let _ = circuit.non_zero_gate(non_zero_var);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let zero_var = circuit.create_variable(F::from(0_u32))?;
        let _ = circuit.non_zero_gate(zero_var);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }
}
