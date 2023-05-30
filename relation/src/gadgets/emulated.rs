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
    /// 2^T
    const T_POW: BigUint;
    /// 2^B
    const B_POW: BigUint;
    /// `B * NUM_LIMBS` should equals to `T`.
    const NUM_LIMBS: usize;
    /// CRT coefficient for native element
    const CRT_COEF_NATIVE: Self;
    /// CRT coefficient for power of 2 element
    const CRT_COEF_POWER_OF_2: Self;
}

/// Convert an element in the emulated field to a list of native field elements.
pub fn from_emulated_field<E, F>(val: E) -> Vec<F>
where
    E: EmulationConfig<F>,
    F: PrimeField,
{
    let q: BigUint = F::MODULUS.into();
    let val: BigUint = val.into();
    let mut result = vec![F::from(&val % q)];
    let mut power_of_2_r = &val % E::T_POW;
    for _ in 0..E::NUM_LIMBS {
        result.push(F::from(&power_of_2_r % E::B_POW));
        power_of_2_r /= E::B_POW;
    }
    result
}

/// Inverse conversion of the [`from_emulated_field`]
pub fn to_emulated_field<E, F>(vals: &[F]) -> Result<E, CircuitError>
where
    E: EmulationConfig<F>,
    F: PrimeField,
{
    if vals.len() != E::NUM_LIMBS + 1 {
        return Err(CircuitError::FieldAlgebraError(
            "Malformed structure for emulated field element conversion.".to_string(),
        ));
    }
    let native = E::from(<F as Into<BigUint>>::into(vals[0]));
    let power_of_2_r = E::from(vals.iter().skip(1).rfold(BigUint::zero(), |result, &val| {
        result * E::B_POW + <F as Into<BigUint>>::into(val)
    }));
    Ok(native * E::CRT_COEF_NATIVE + power_of_2_r * E::CRT_COEF_POWER_OF_2)
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
    pub fn emulated_add_gate<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: &EmulatedVariable<E>,
        c: &EmulatedVariable<E>,
    ) -> Result<(), CircuitError> {
        self.add_gate(a.0[0], b.0[0], c.0[0])?;
        let mut carry_out = self.zero();
        for (a, b, c) in izip!(&a.0, &b.0, &c.0).skip(1) {
            let next_carry_out =
                F::from((self.witness(*a)? + self.witness(*b)?).into_bigint().into() % E::B_POW);
            let next_carry_out = self.create_variable(next_carry_out)?;

            let wires = [*a, *b, carry_out, next_carry_out, *c];
            let coeffs = [F::one(), F::one(), F::one(), -F::from(E::B_POW)];
            self.lc_gate(&wires, &coeffs)?;
            carry_out = next_carry_out;

            self.enforce_in_range(*c, E::B)?;
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
        let b = from_emulated_field(b);
        self.add_constant_gate(a.0[0], b[0], c.0[0])?;

        let mut carry_out = self.zero();
        for (a, b, c) in izip!(&a.0, b, &c.0).skip(1) {
            let next_carry_out = F::from((self.witness(*a)? + b).into_bigint().into() % E::B_POW);
            let next_carry_out = self.create_variable(next_carry_out)?;

            let wires = [*a, self.one(), carry_out, next_carry_out, *c];
            let coeffs = [F::one(), b, F::one(), -F::from(E::B_POW)];
            self.lc_gate(&wires, &coeffs)?;
            carry_out = next_carry_out;

            self.enforce_in_range(*c, E::B)?;
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

#[cfg(test)]
mod tests {
    #[test]
    fn test_basics() {}
}
