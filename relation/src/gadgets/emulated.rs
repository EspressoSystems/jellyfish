// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Emulate arithmetic operations on a large prime field.
//! To emulate arithmetic operations on F_q when the native field is F_p where p
//! < q, we represent the elements in F_q using CRT modulus [p, 2^T] where p *
//! 2^T > q^2 + q. The second componenet, with modulus 2^T, will be divided into
//! limbs each with B bits where 2^{2B} < p.

use crate::{errors::CircuitError, Circuit, PlonkCircuit, Variable};
use ark_ff::PrimeField;
use ark_std::{string::ToString, vec, vec::Vec, Zero};
use core::marker::PhantomData;
use itertools::izip;
use num_bigint::BigUint;

/// Parameters needed for emulating field operations over [`F`].
pub trait EmulationConfig<F: PrimeField>: PrimeField {
    /// Log2 of the other CRT modulus is 2^T.
    const T: usize;
    /// Bit length of each limbs.
    const B: usize;
    /// `B * NUM_LIMBS` should equals to `T`.
    const NUM_LIMBS: usize;
}

fn biguint_to_limbs<F: PrimeField>(mut val: BigUint, b: usize, num_limbs: usize) -> Vec<F> {
    let mut result = vec![];
    let b_pow = BigUint::from(2u32).pow(b as u32);

    // Since q < 2^T, no need to perform mod 2^T
    for _ in 0..num_limbs {
        result.push(F::from(&val % &b_pow));
        val /= &b_pow;
    }
    result
}

/// Convert an element in the emulated field to a list of native field elements.
pub fn from_emulated_field<E, F>(val: E) -> Vec<F>
where
    E: EmulationConfig<F>,
    F: PrimeField,
{
    biguint_to_limbs(val.into(), E::B, E::NUM_LIMBS)
}

/// Inverse conversion of the [`from_emulated_field`]
pub fn to_emulated_field<E, F>(vals: &[F]) -> Result<E, CircuitError>
where
    E: EmulationConfig<F>,
    F: PrimeField,
{
    if vals.len() != E::NUM_LIMBS {
        return Err(CircuitError::FieldAlgebraError(
            "Malformed structure for emulated field element conversion.".to_string(),
        ));
    }
    let b_pow = BigUint::from(2u32).pow(E::B as u32);
    Ok(E::from(
        vals.iter().rfold(BigUint::zero(), |result, &val| {
            result * &b_pow + <F as Into<BigUint>>::into(val)
        }),
    ))
}

/// The variable represents an element in the emulated field.
pub struct EmulatedVariable<E: PrimeField>(pub Vec<Variable>, PhantomData<E>);

impl<F: PrimeField> PlonkCircuit<F> {
    /// Return the witness point for the circuit
    pub fn emulated_witness<E: EmulationConfig<F>>(
        &self,
        var: &EmulatedVariable<E>,
    ) -> Result<E, CircuitError> {
        let values = var
            .0
            .iter()
            .map(|&v| self.witness(v))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        to_emulated_field(&values)
    }

    /// Add an emulated variable
    pub fn create_emulated_variable<E: EmulationConfig<F>>(
        &mut self,
        val: E,
    ) -> Result<EmulatedVariable<E>, CircuitError> {
        Ok(EmulatedVariable::<E>(
            from_emulated_field(val)
                .into_iter()
                .map(|v| self.create_variable(v))
                .collect::<Result<Vec<_>, CircuitError>>()?,
            PhantomData,
        ))
    }

    /// Add a constant emulated variable
    pub fn create_constant_emulated_variable<E: EmulationConfig<F>>(
        &mut self,
        val: E,
    ) -> Result<EmulatedVariable<E>, CircuitError> {
        Ok(EmulatedVariable::<E>(
            from_emulated_field(val)
                .into_iter()
                .map(|v| self.create_constant_variable(v))
                .collect::<Result<Vec<_>, CircuitError>>()?,
            PhantomData,
        ))
    }

    /// Add a public emulated variable
    pub fn create_public_emulated_variable<E: EmulationConfig<F>>(
        &mut self,
        val: E,
    ) -> Result<EmulatedVariable<E>, CircuitError> {
        Ok(EmulatedVariable::<E>(
            from_emulated_field(val)
                .into_iter()
                .map(|v| self.create_public_variable(v))
                .collect::<Result<Vec<_>, CircuitError>>()?,
            PhantomData,
        ))
    }

    /// Constrain that a*b=c in the emulated field.
    pub fn emulated_mul_gate<E: EmulationConfig<F>>(
        &mut self,
        _a: &EmulatedVariable<E>,
        _b: &EmulatedVariable<E>,
        _c: &EmulatedVariable<E>,
    ) -> Result<(), CircuitError> {
        todo!()
    }

    /// Return an [`EmulatedVariable`] which equals to a*b.
    pub fn emulated_mul<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: &EmulatedVariable<E>,
    ) -> Result<EmulatedVariable<E>, CircuitError> {
        let c = self.emulated_witness(a)? * self.emulated_witness(b)?;
        let c = self.create_emulated_variable(c)?;
        self.emulated_add_gate(a, b, &c)?;
        Ok(c)
    }

    /// Constrain that a*b=c in the emulated field.
    pub fn emulated_mul_constant_gate<E: EmulationConfig<F>>(
        &mut self,
        _a: &EmulatedVariable<E>,
        _b: E,
        _c: &EmulatedVariable<E>,
    ) -> Result<(), CircuitError> {
        todo!()
    }

    /// Return an [`EmulatedVariable`] which equals to a*b.
    pub fn emulated_mul_constant<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: E,
    ) -> Result<EmulatedVariable<E>, CircuitError> {
        let c = self.emulated_witness(a)? * b;
        let c = self.create_emulated_variable(c)?;
        self.emulated_mul_constant_gate(a, b, &c)?;
        Ok(c)
    }

    /// Constrain that a+b=c in the emulated field.
    /// Checking whether a + b = k * E::MODULUS + c
    pub fn emulated_add_gate<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: &EmulatedVariable<E>,
        c: &EmulatedVariable<E>,
    ) -> Result<(), CircuitError> {
        let val_a: BigUint = self.emulated_witness(a)?.into();
        let val_b: BigUint = self.emulated_witness(b)?.into();
        let q: BigUint = E::MODULUS.into();
        let b_pow = BigUint::from(2u32).pow(E::B as u32);
        let add_no_mod = &val_a + &val_b;
        let k = if add_no_mod > q { 1u32 } else { 0u32 };
        let var_k = self.create_boolean_variable(add_no_mod > q)?.0;
        let q_limbs = biguint_to_limbs::<F>(q, E::B, E::NUM_LIMBS);

        let add_no_mod_limbs = biguint_to_limbs::<F>(add_no_mod, E::B, E::NUM_LIMBS)
            .into_iter()
            .map(|val| self.create_variable(val))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // Checking whether a + b = add_no_mod_limbs
        let mut carry_out = self.zero();
        for (a, b, c) in izip!(&a.0, &b.0, &add_no_mod_limbs) {
            let next_carry_out =
                F::from(<F as Into<BigUint>>::into(self.witness(*a)? + self.witness(*b)?) / &b_pow);
            let next_carry_out = self.create_variable(next_carry_out)?;

            let wires = [*a, *b, carry_out, next_carry_out, *c];
            let coeffs = [F::one(), F::one(), F::one(), -F::from(b_pow.clone())];
            self.lc_gate(&wires, &coeffs)?;
            carry_out = next_carry_out;

            self.enforce_in_range(*c, E::B)?;
        }

        // Checking whether k * q + c = add_no_mod_limbs
        carry_out = self.zero();
        for (a, b, c) in izip!(q_limbs, &c.0, &add_no_mod_limbs) {
            let next_carry_out =
                F::from(<F as Into<BigUint>>::into(a * F::from(k) + self.witness(*b)?) / &b_pow);
            let next_carry_out = self.create_variable(next_carry_out)?;

            let wires = [var_k, *b, carry_out, next_carry_out, *c];
            let coeffs = [a, F::one(), F::one(), -F::from(b_pow.clone())];
            self.lc_gate(&wires, &coeffs)?;
            carry_out = next_carry_out;

            self.enforce_in_range(*b, E::B)?;
        }
        Ok(())
    }

    /// Return an [`EmulatedVariable`] which equals to a+b.
    pub fn emulated_add<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: &EmulatedVariable<E>,
    ) -> Result<EmulatedVariable<E>, CircuitError> {
        let c = self.emulated_witness(a)? + self.emulated_witness(b)?;
        let c = self.create_emulated_variable(c)?;
        self.emulated_add_gate(a, b, &c)?;
        Ok(c)
    }

    /// Constrain that a+b=c in the emulated field.
    pub fn emulated_add_constant_gate<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: E,
        c: &EmulatedVariable<E>,
    ) -> Result<(), CircuitError> {
        let val_a: BigUint = self.emulated_witness(a)?.into();
        let val_b: BigUint = b.into();
        let q: BigUint = E::MODULUS.into();
        let b_pow = BigUint::from(2u32).pow(E::B as u32);
        let add_no_mod = &val_a + &val_b;
        let k = if add_no_mod > q { 1u32 } else { 0u32 };
        let var_k = self.create_boolean_variable(add_no_mod > q)?.0;
        let q_limbs = biguint_to_limbs::<F>(q, E::B, E::NUM_LIMBS);
        let b_limbs = biguint_to_limbs::<F>(val_b, E::B, E::NUM_LIMBS);

        let add_no_mod_limbs = biguint_to_limbs::<F>(add_no_mod, E::B, E::NUM_LIMBS)
            .into_iter()
            .map(|val| self.create_variable(val))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // Checking whether a + b = add_no_mod_limbs
        let mut carry_out = self.zero();
        for (a, b, c) in izip!(&a.0, b_limbs, &add_no_mod_limbs) {
            let next_carry_out =
                F::from(<F as Into<BigUint>>::into(self.witness(*a)? + b) / &b_pow);
            let next_carry_out = self.create_variable(next_carry_out)?;

            let wires = [*a, self.one(), carry_out, next_carry_out, *c];
            let coeffs = [F::one(), b, F::one(), -F::from(b_pow.clone())];
            self.lc_gate(&wires, &coeffs)?;
            carry_out = next_carry_out;

            self.enforce_in_range(*c, E::B)?;
        }

        // Checking whether k * q + c = add_no_mod_limbs
        carry_out = self.zero();
        for (a, b, c) in izip!(q_limbs, &c.0, &add_no_mod_limbs) {
            let next_carry_out =
                F::from(<F as Into<BigUint>>::into(a * F::from(k) + self.witness(*b)?) / &b_pow);
            let next_carry_out = self.create_variable(next_carry_out)?;

            let wires = [var_k, *b, carry_out, next_carry_out, *c];
            let coeffs = [a, F::one(), F::one(), -F::from(b_pow.clone())];
            self.lc_gate(&wires, &coeffs)?;
            carry_out = next_carry_out;

            self.enforce_in_range(*b, E::B)?;
        }
        Ok(())
    }

    /// Return an [`EmulatedVariable`] which equals to a+b.
    pub fn emulated_add_constant<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: E,
    ) -> Result<EmulatedVariable<E>, CircuitError> {
        let c = self.emulated_witness(a)? + b;
        let c = self.create_emulated_variable(c)?;
        self.emulated_add_constant_gate(a, b, &c)?;
        Ok(c)
    }
}

impl EmulationConfig<ark_bn254::Fr> for ark_bls12_377::Fq {
    const T: usize = 500;

    const B: usize = 125;

    const NUM_LIMBS: usize = 4;
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_basics() {}
}
