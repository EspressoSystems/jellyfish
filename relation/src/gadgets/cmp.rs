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

    /// Returns a `BoolVar` indicating whether the variable `a` is less than a
    /// given constant `val`.
    pub fn is_lt_constant(&mut self, a: Variable, val: F) -> Result<BoolVar, CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        let b = self.create_constant_variable(val)?;
        self.is_lt(a, b)
    }

    /// Returns a `BoolVar` indicating whether the variable `a` is less than or
    /// equal to a given constant `val`.
    pub fn is_leq_constant(&mut self, a: Variable, val: F) -> Result<BoolVar, CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        let b = self.create_constant_variable(val)?;
        self.is_leq(a, b)
    }

    /// Returns a `BoolVar` indicating whether the variable `a` is greater than
    /// a given constant `val`.
    pub fn is_gt_constant(&mut self, a: Variable, val: F) -> Result<BoolVar, CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        self.is_gt_constant_internal(a, &val)
    }

    /// Returns a `BoolVar` indicating whether the variable `a` is greater than
    /// or equal a given constant `val`.
    pub fn is_geq_constant(&mut self, a: Variable, val: F) -> Result<BoolVar, CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        let b = self.create_constant_variable(val)?;
        self.is_geq(a, b)
    }

    /// Enforce the variable `a` to be less than a
    /// given constant `val`.
    pub fn enforce_lt_constant(&mut self, a: Variable, val: F) -> Result<(), CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        let b = self.create_constant_variable(val)?;
        self.enforce_lt(a, b)
    }

    /// Enforce the variable `a` to be less than or
    /// equal to a given constant `val`.
    pub fn enforce_leq_constant(&mut self, a: Variable, val: F) -> Result<(), CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        let b = self.create_constant_variable(val)?;
        self.enforce_leq(a, b)
    }

    /// Enforce the variable `a` to be greater than
    /// a given constant `val`.
    pub fn enforce_gt_constant(&mut self, a: Variable, val: F) -> Result<(), CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        let b = self.create_constant_variable(val)?;
        self.enforce_gt(a, b)
    }

    /// Enforce the variable `a` to be greater than
    /// or equal a given constant `val`.
    pub fn enforce_geq_constant(&mut self, a: Variable, val: F) -> Result<(), CircuitError>
    where
        F: PrimeField,
    {
        self.check_var_bound(a)?;
        let b = self.create_constant_variable(val)?;
        self.enforce_geq(a, b)
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
        let a_gt_const = self.is_gt_constant_internal(a, &F::from(F::MODULUS_MINUS_ONE_DIV_TWO))?;
        let b_gt_const = self.is_gt_constant_internal(b, &F::from(F::MODULUS_MINUS_ONE_DIV_TWO))?;
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
        let cmp_result = self.is_gt_constant_internal(c, &F::from(F::MODULUS_MINUS_ONE_DIV_TWO))?;
        let cmp_result = self.logic_and(msb_eq, cmp_result)?;

        self.logic_or(msb_check, cmp_result)
    }

    /// Constrain that `a` < `b`
    fn enforce_lt_internal(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError> {
        let (msb_check, msb_eq) = self.msb_check_internal(a, b)?;
        // check whether (a-b) <= (q-1)/2
        let c = self.sub(a, b)?;
        let cmp_result = self.is_gt_constant_internal(c, &F::from(F::MODULUS_MINUS_ONE_DIV_TWO))?;
        let cmp_result = self.logic_and(msb_eq, cmp_result)?;

        self.logic_or_gate(msb_check, cmp_result)
    }

    /// Helper function to check whether `a` is greater than a given
    /// constant. Let N = F::MODULUS_BIT_SIZE, it assumes that the
    /// constant < 2^N. And it uses at most N AND/OR gates.
    fn is_gt_constant_internal(
        &mut self,
        a: Variable,
        constant: &F,
    ) -> Result<BoolVar, CircuitError> {
        let a_bits_le = self.unpack(a, F::MODULUS_BIT_SIZE as usize)?;
        let const_bits_le = constant.into_bigint().to_bits_le();

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
    use crate::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit};
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::PrimeField;
    use ark_std::cmp::Ordering;
    use itertools::multizip;

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
                F::from(F::MODULUS_MINUS_ONE_DIV_TWO).add(F::one()),
                F::from(2u32),
            ),
            (
                F::from(F::MODULUS_MINUS_ONE_DIV_TWO).add(F::one()),
                F::from(F::MODULUS_MINUS_ONE_DIV_TWO).mul(F::from(2u32)),
            ),
        ];
        multizip((
            list,
            [Ordering::Less, Ordering::Greater],
            [false, true],
            [false, true],
        )).try_for_each(
                |((a, b), ordering, should_also_check_equality,
                 is_b_constant)|
                 -> Result<(), CircuitError> {
                    test_enforce_cmp_helper(&a, &b, ordering, should_also_check_equality, is_b_constant)?;
                    test_enforce_cmp_helper(&b, &a, ordering, should_also_check_equality, is_b_constant)?;
                    test_is_cmp_helper(&a, &b, ordering, should_also_check_equality, is_b_constant)?;
                    test_is_cmp_helper(&b, &a, ordering, should_also_check_equality, is_b_constant)
                },
            )
    }

    fn test_is_cmp_helper<F: PrimeField>(
        a: &F,
        b: &F,
        ordering: Ordering,
        should_also_check_equality: bool,
        is_b_constant: bool,
    ) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result = if a.cmp(b) == ordering
            || (a.cmp(b) == Ordering::Equal && should_also_check_equality)
        {
            F::one()
        } else {
            F::zero()
        };
        let a = circuit.create_variable(*a)?;
        let c: BoolVar = if is_b_constant {
            match ordering {
                Ordering::Less => {
                    if should_also_check_equality {
                        circuit.is_leq_constant(a, *b)?
                    } else {
                        circuit.is_lt_constant(a, *b)?
                    }
                },
                Ordering::Greater => {
                    if should_also_check_equality {
                        circuit.is_geq_constant(a, *b)?
                    } else {
                        circuit.is_gt_constant(a, *b)?
                    }
                },
                // Equality test will be handled elsewhere, comparison gate test will not enter here
                Ordering::Equal => circuit.create_boolean_variable_unchecked(expected_result)?,
            }
        } else {
            let b = circuit.create_variable(*b)?;
            match ordering {
                Ordering::Less => {
                    if should_also_check_equality {
                        circuit.is_leq(a, b)?
                    } else {
                        circuit.is_lt(a, b)?
                    }
                },
                Ordering::Greater => {
                    if should_also_check_equality {
                        circuit.is_geq(a, b)?
                    } else {
                        circuit.is_gt(a, b)?
                    }
                },
                // Equality test will be handled elsewhere, comparison gate test will not enter here
                Ordering::Equal => circuit.create_boolean_variable_unchecked(expected_result)?,
            }
        };
        assert!(circuit.witness(c.into())?.eq(&expected_result));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
    fn test_enforce_cmp_helper<F: PrimeField>(
        a: &F,
        b: &F,
        ordering: Ordering,
        should_also_check_equality: bool,
        is_b_constant: bool,
    ) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let expected_result =
            a.cmp(b) == ordering || (a.cmp(b) == Ordering::Equal && should_also_check_equality);
        let a = circuit.create_variable(*a)?;
        if is_b_constant {
            match ordering {
                Ordering::Less => {
                    if should_also_check_equality {
                        circuit.enforce_leq_constant(a, *b)?
                    } else {
                        circuit.enforce_lt_constant(a, *b)?
                    }
                },
                Ordering::Greater => {
                    if should_also_check_equality {
                        circuit.enforce_geq_constant(a, *b)?
                    } else {
                        circuit.enforce_gt_constant(a, *b)?
                    }
                },
                // Equality test will be handled elsewhere, comparison gate test will not enter here
                Ordering::Equal => (),
            }
        } else {
            let b = circuit.create_variable(*b)?;
            match ordering {
                Ordering::Less => {
                    if should_also_check_equality {
                        circuit.enforce_leq(a, b)?
                    } else {
                        circuit.enforce_lt(a, b)?
                    }
                },
                Ordering::Greater => {
                    if should_also_check_equality {
                        circuit.enforce_geq(a, b)?
                    } else {
                        circuit.enforce_gt(a, b)?
                    }
                },
                // Equality test will be handled elsewhere, comparison gate test will not enter here
                Ordering::Equal => (),
            }
        };
        if expected_result {
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok())
        } else {
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        }
        Ok(())
    }
}
