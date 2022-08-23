// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Comparison gadgets for circuit

use crate::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit, Variable};
use ark_ff::{BigInteger, PrimeField};

impl<F: PrimeField> PlonkCircuit<F> {
    /// Constrain that `a` < `b`.
    pub fn enforce_lt(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.enforce_lt_internal(a, b)
    }

    /// Constrain that `a` <= `b`
    pub fn enforce_leq(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError>
    where
        F: PrimeField,
    {
        let c = self.is_lt(b, a)?;
        self.enforce_constant(c.0, F::zero())
    }

    /// Constrain that `a` > `b`.
    pub fn enforce_gt(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError>
    where
        F: PrimeField,
    {
        self.enforce_lt(b, a)
    }

    /// Constrain that `a` >= `b`.
    pub fn enforce_geq(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError>
    where
        F: PrimeField,
    {
        let c = self.is_lt(a, b)?;
        self.enforce_constant(c.into(), F::zero())
    }

    /// Returns a `BoolVar` indicating whether `a` < `b`.
    pub fn is_lt(&mut self, a: Variable, b: Variable) -> Result<BoolVar, CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.is_lt_internal(a, b)
    }

    /// Returns a `BoolVar` indicating whether `a` > `b`.
    pub fn is_gt(&mut self, a: Variable, b: Variable) -> Result<BoolVar, CircuitError>
    where
        F: PrimeField,
    {
        self.is_lt(b, a)
    }

    /// Returns a `BoolVar` indicating whether `a` <= `b`.
    pub fn is_leq(&mut self, a: Variable, b: Variable) -> Result<BoolVar, CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let c = self.is_lt_internal(b, a)?;
        self.logic_neg(c)
    }

    /// Returns a `BoolVar` indicating whether `a` >= `b`.
    pub fn is_geq(&mut self, a: Variable, b: Variable) -> Result<BoolVar, CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let c = self.is_lt_internal(a, b)?;
        self.logic_neg(c)
    }
}

/// Private helper functions for comparison gate
impl<F: PrimeField> PlonkCircuit<F> {
    /// Returns 2 `BoolVar`s.
    /// First indicates whether `a` <= (q-1)/2 and `b` > (q-1)/2.
    /// Second indicates whether `a` and `b` are both <= (q-1)/2
    /// or both > (q-1)/2.
    fn msb_check_internal(
        &mut self,
        a: Variable,
        b: Variable,
    ) -> Result<(BoolVar, BoolVar), CircuitError> {
        let a_gt_const =
            self.is_gt_constant_internal(a, &F::from(F::modulus_minus_one_div_two()))?;
        let b_gt_const =
            self.is_gt_constant_internal(b, &F::from(F::modulus_minus_one_div_two()))?;
        let a_leq_const = self.logic_neg(a_gt_const)?;
        // Check whether `a` <= (q-1)/2 and `b` > (q-1)/2
        let msb_check = self.logic_and(a_leq_const, b_gt_const)?;
        // Check whether `a` and `b` are both <= (q-1)/2 or
        // are both > (q-1)/2
        let msb_eq = self.is_equal(a_gt_const.into(), b_gt_const.into())?;
        Ok((msb_check, msb_eq))
    }

    /// Return a variable indicating whether `a` < `b`.
    fn is_lt_internal(&mut self, a: Variable, b: Variable) -> Result<BoolVar, CircuitError> {
        let (msb_check, msb_eq) = self.msb_check_internal(a, b)?;
        // check whether (a-b) > (q-1)/2
        let c = self.sub(a, b)?;
        let cmp_result =
            self.is_gt_constant_internal(c, &F::from(F::modulus_minus_one_div_two()))?;
        let cmp_result = self.logic_and(msb_eq, cmp_result)?;

        self.logic_or(msb_check, cmp_result)
    }

    /// Constrain that `a` < `b`
    fn enforce_lt_internal(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError> {
        let (msb_check, msb_eq) = self.msb_check_internal(a, b)?;
        // check whether (a-b) <= (q-1)/2
        let c = self.sub(a, b)?;
        let cmp_result =
            self.is_gt_constant_internal(c, &F::from(F::modulus_minus_one_div_two()))?;
        let cmp_result = self.logic_and(msb_eq, cmp_result)?;

        self.logic_or_gate(msb_check, cmp_result)
    }

    /// Helper function to check whether `a` is greater than a given
    /// constant. Let N = F::size_in_bits(), it assumes that the
    /// constant < 2^N. And it uses at most N AND/OR gates.
    fn is_gt_constant_internal(
        &mut self,
        a: Variable,
        constant: &F,
    ) -> Result<BoolVar, CircuitError> {
        let a_bits_le = self.unpack(a, F::size_in_bits())?;
        let const_bits_le = constant.into_repr().to_bits_le();

        // Iterating from LSB to MSB. Skip the front consecutive 1's.
        // Put an OR gate for bit 0 and an AND gate for bit 1.
        let mut zipped = const_bits_le
            .into_iter()
            .chain(ark_std::iter::repeat(false))
            .take(a_bits_le.len())
            .zip(a_bits_le.iter())
            .skip_while(|(b, _)| *b);
        if let Some((_, &var)) = zipped.next() {
            zipped.try_fold(var, |current, (b, a)| -> Result<BoolVar, CircuitError> {
                if b {
                    self.logic_and(*a, current)
                } else {
                    self.logic_or(*a, current)
                }
            })
        } else {
            // the constant is all one
            Ok(BoolVar(self.zero()))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{errors::CircuitError, Circuit, PlonkCircuit};
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::PrimeField;

    #[test]
    fn test_cmp_gates() -> Result<(), CircuitError> {
        test_cmp_helper::<FqEd254>()?;
        test_cmp_helper::<FqEd377>()?;
        test_cmp_helper::<FqEd381>()?;
        test_cmp_helper::<Fq377>()
    }

    fn test_cmp_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let list = [
            (F::from(5u32), F::from(5u32)),
            (F::from(1u32), F::from(2u32)),
            (
                F::from(F::modulus_minus_one_div_two()).add(F::one()),
                F::from(2u32),
            ),
            (
                F::from(F::modulus_minus_one_div_two()).add(F::one()),
                F::from(F::modulus_minus_one_div_two()).mul(F::from(2u32)),
            ),
        ];
        list.iter()
            .try_for_each(|(a, b)| -> Result<(), CircuitError> {
                test_is_le(a, b)?;
                test_is_leq(a, b)?;
                test_is_ge(a, b)?;
                test_is_geq(a, b)?;
                test_enforce_le(a, b)?;
                test_enforce_leq(a, b)?;
                test_enforce_ge(a, b)?;
                test_enforce_geq(a, b)?;
                test_is_le(b, a)?;
                test_is_leq(b, a)?;
                test_is_ge(b, a)?;
                test_is_geq(b, a)?;
                test_enforce_le(b, a)?;
                test_enforce_leq(b, a)?;
                test_enforce_ge(b, a)?;
                test_enforce_geq(b, a)
            })
    }

    fn test_is_le<F: PrimeField>(a: &F, b: &F) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result = if a < b { F::one() } else { F::zero() };
        let a = circuit.create_variable(*a)?;
        let b = circuit.create_variable(*b)?;

        let c = circuit.is_lt(a, b)?;
        assert!(circuit.witness(c.into())?.eq(&expected_result));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
    fn test_is_leq<F: PrimeField>(a: &F, b: &F) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result = if a <= b { F::one() } else { F::zero() };
        let a = circuit.create_variable(*a)?;
        let b = circuit.create_variable(*b)?;

        let c = circuit.is_leq(a, b)?;
        assert!(circuit.witness(c.into())?.eq(&expected_result));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
    fn test_is_ge<F: PrimeField>(a: &F, b: &F) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result = if a > b { F::one() } else { F::zero() };
        let a = circuit.create_variable(*a)?;
        let b = circuit.create_variable(*b)?;

        let c = circuit.is_gt(a, b)?;
        assert!(circuit.witness(c.into())?.eq(&expected_result));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
    fn test_is_geq<F: PrimeField>(a: &F, b: &F) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result = if a >= b { F::one() } else { F::zero() };
        let a = circuit.create_variable(*a)?;
        let b = circuit.create_variable(*b)?;

        let c = circuit.is_geq(a, b)?;
        assert!(circuit.witness(c.into())?.eq(&expected_result));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
    fn test_enforce_le<F: PrimeField>(a: &F, b: &F) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result = a < b;
        let a = circuit.create_variable(*a)?;
        let b = circuit.create_variable(*b)?;
        circuit.enforce_lt(a, b)?;
        if expected_result {
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok())
        } else {
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        }
        Ok(())
    }
    fn test_enforce_leq<F: PrimeField>(a: &F, b: &F) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result = a <= b;
        let a = circuit.create_variable(*a)?;
        let b = circuit.create_variable(*b)?;
        circuit.enforce_leq(a, b)?;
        if expected_result {
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok())
        } else {
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        }
        Ok(())
    }
    fn test_enforce_ge<F: PrimeField>(a: &F, b: &F) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result = a > b;
        let a = circuit.create_variable(*a)?;
        let b = circuit.create_variable(*b)?;
        circuit.enforce_gt(a, b)?;
        if expected_result {
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok())
        } else {
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        }
        Ok(())
    }
    fn test_enforce_geq<F: PrimeField>(a: &F, b: &F) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result = a >= b;
        let a = circuit.create_variable(*a)?;
        let b = circuit.create_variable(*b)?;
        circuit.enforce_geq(a, b)?;
        if expected_result {
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok())
        } else {
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        }
        Ok(())
    }
}
