// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Emulate arithmetic operations on a large prime field.
//! To emulate arithmetic operations on F_q when the native field is F_p where p
//! < q, we represent the elements in F_q using CRT modulus [p, 2^T] where p *
//! 2^T > q^2 + q. This constraint is required to emulate the F_q multiplication
//! by checking a * b - k * q = c (mod 2^T * p) without any overflow. The second
//! componenet, with modulus 2^T, will be divided into limbs each with B bits
//! where 2^{2B} < p.

use crate::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit, Variable};
use ark_ff::PrimeField;
use ark_std::{string::ToString, vec, vec::Vec, One, Zero};
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

fn biguint_to_limbs<F: PrimeField>(val: &BigUint, b: usize, num_limbs: usize) -> Vec<F> {
    let mut result = vec![];
    let b_pow = BigUint::one() << b;
    let mut val = val.clone();

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
    biguint_to_limbs(&val.into(), E::B, E::NUM_LIMBS)
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
    let b_pow = BigUint::one() << E::B;
    Ok(E::from(
        vals.iter().rfold(BigUint::zero(), |result, &val| {
            result * &b_pow + <F as Into<BigUint>>::into(val)
        }),
    ))
}

/// The variable represents an element in the emulated field.
#[derive(Debug, Clone)]
pub struct EmulatedVariable<E: PrimeField>(pub(crate) Vec<Variable>, PhantomData<E>);

impl<E: PrimeField> EmulatedVariable<E> {
    /// Return the list of variables that simulate the field element
    pub fn to_vec(&self) -> Vec<Variable> {
        self.0.clone()
    }
}

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
        let var = self.create_emulated_variable_unchecked(val)?;
        for &v in &var.0 {
            self.enforce_in_range(v, E::B)?;
        }
        Ok(var)
    }

    /// Add an emulated variable without enforcing the validity check
    fn create_emulated_variable_unchecked<E: EmulationConfig<F>>(
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
    /// Checking that a * b - k * E::MODULUS = c.
    pub fn emulated_mul_gate<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: &EmulatedVariable<E>,
        c: &EmulatedVariable<E>,
    ) -> Result<(), CircuitError> {
        self.check_vars_bound(&a.0)?;
        self.check_vars_bound(&b.0)?;
        self.check_vars_bound(&c.0)?;

        let val_a: BigUint = self.emulated_witness(a)?.into();
        let val_b: BigUint = self.emulated_witness(b)?.into();
        let val_k = E::from(&val_a * &val_b / E::MODULUS.into());
        let k = self.create_emulated_variable(val_k)?;
        let a_limbs = biguint_to_limbs::<F>(&val_a, E::B, E::NUM_LIMBS);
        let b_limbs = biguint_to_limbs::<F>(&val_b, E::B, E::NUM_LIMBS);
        let k_limbs = from_emulated_field(val_k);
        let b_pow = F::from(2u32).pow([E::B as u64]);
        let val_expected = E::from(val_a) * E::from(val_b);
        let val_expected_limbs = from_emulated_field(val_expected);

        let neg_modulus = biguint_to_limbs::<F>(
            &(BigUint::from(2u32).pow(E::T as u32) - E::MODULUS.into()),
            E::B,
            E::NUM_LIMBS,
        );

        // enforcing a * b - k * E::MODULUS = c mod 2^t

        // first compare the first limb
        let mut val_carry_out =
            (a_limbs[0] * b_limbs[0] + k_limbs[0] * neg_modulus[0] - val_expected_limbs[0]) / b_pow;
        let mut carry_out = self.create_variable(val_carry_out)?;
        // checking that the carry_out has at most [`E::B`] + 1 bits
        self.enforce_in_range(carry_out, E::B + 1)?;
        // enforcing that a0 * b0 - k0 * modulus[0] - carry_out * 2^E::B = c0
        self.general_arithmetic_gate(
            &[a.0[0], b.0[0], k.0[0], carry_out, c.0[0]],
            &[F::zero(), F::zero(), neg_modulus[0], -b_pow],
            &[F::one(), F::zero()],
            F::zero(),
        )?;

        for i in 1..E::NUM_LIMBS {
            // compare the i-th limb

            // calculate the next carry out
            let val_next_carry_out = ((0..=i)
                .map(|j| k_limbs[j] * neg_modulus[i - j] + a_limbs[j] * b_limbs[i - j])
                .sum::<F>()
                + val_carry_out
                - val_expected_limbs[i])
                / b_pow;
            let next_carry_out = self.create_variable(val_next_carry_out)?;

            // range checking for this carry out.
            // let a = 2^B - 1. The maximum possible value of `next_carry_out` is ((i + 1) *
            // 2 * a^2 + a) / 2^B.
            let num_vals = 2u64 * (i as u64) + 2;
            let log_num_vals = (u64::BITS - num_vals.leading_zeros()) as usize;
            self.enforce_in_range(next_carry_out, E::B + log_num_vals)?;

            // k * E::MODULUS part, waiting for summation
            let mut stack = (0..=i)
                .map(|j| (k.0[j], neg_modulus[i - j]))
                .collect::<Vec<_>>();
            // carry out from last limb
            stack.push((carry_out, F::one()));
            stack.push((next_carry_out, -b_pow));

            // part of the summation \sum_j a_i * b_{i-j}
            for j in (0..i).step_by(2) {
                let t = self.mul_add(
                    &[a.0[j], b.0[i - j], a.0[j + 1], b.0[i - j - 1]],
                    &[F::one(), F::one()],
                )?;
                stack.push((t, F::one()));
            }

            // last item of the summation \sum_j a_i * b_{i-j}
            if i % 2 == 0 {
                let t1 = stack.pop().unwrap();
                let t2 = stack.pop().unwrap();
                let t = self.general_arithmetic(
                    &[a.0[i], b.0[0], t1.0, t2.0],
                    &[F::zero(), F::zero(), t1.1, t2.1],
                    &[F::one(), F::zero()],
                    F::zero(),
                )?;
                stack.push((t, F::one()));
            }

            // linear combination of all items in the stack
            while stack.len() > 4 {
                let t1 = stack.pop().unwrap();
                let t2 = stack.pop().unwrap();
                let t3 = stack.pop().unwrap();
                let t4 = stack.pop().unwrap();
                let t = self.lc(&[t1.0, t2.0, t3.0, t4.0], &[t1.1, t2.1, t3.1, t4.1])?;
                stack.push((t, F::one()));
            }
            let t1 = stack.pop().unwrap_or((self.zero(), F::zero()));
            let t2 = stack.pop().unwrap_or((self.zero(), F::zero()));
            let t3 = stack.pop().unwrap_or((self.zero(), F::zero()));
            let t4 = stack.pop().unwrap_or((self.zero(), F::zero()));

            // checking that the summation equals to i-th limb of c
            self.lc_gate(&[t1.0, t2.0, t3.0, t4.0, c.0[i]], &[t1.1, t2.1, t3.1, t4.1])?;

            val_carry_out = val_next_carry_out;
            carry_out = next_carry_out;
        }

        // enforcing a * b - k * E::MODULUS = c mod F::MODULUS
        let a_mod = self.mod_to_native_field(a)?;
        let b_mod = self.mod_to_native_field(b)?;
        let k_mod = self.mod_to_native_field(&k)?;
        let c_mod = self.mod_to_native_field(c)?;
        let e_mod_f = F::from(E::MODULUS.into());
        self.general_arithmetic_gate(
            &[a_mod, b_mod, k_mod, self.zero(), c_mod],
            &[F::zero(), F::zero(), -e_mod_f, F::zero()],
            &[F::one(), F::zero()],
            F::zero(),
        )?;

        Ok(())
    }

    /// Return an [`EmulatedVariable`] which equals to a*b.
    pub fn emulated_mul<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: &EmulatedVariable<E>,
    ) -> Result<EmulatedVariable<E>, CircuitError> {
        let c = self.emulated_witness(a)? * self.emulated_witness(b)?;
        let c = self.create_emulated_variable(c)?;
        self.emulated_mul_gate(a, b, &c)?;
        Ok(c)
    }

    /// Constrain that a*b=c in the emulated field for a constant b.
    pub fn emulated_mul_constant_gate<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
        b: E,
        c: &EmulatedVariable<E>,
    ) -> Result<(), CircuitError> {
        self.check_vars_bound(&a.0)?;
        self.check_vars_bound(&c.0)?;

        let val_a: BigUint = self.emulated_witness(a)?.into();
        let val_b: BigUint = b.into();
        let val_k = E::from(&val_a * &val_b / E::MODULUS.into());
        let k = self.create_emulated_variable(val_k)?;
        let a_limbs = biguint_to_limbs::<F>(&val_a, E::B, E::NUM_LIMBS);
        let b_limbs = biguint_to_limbs::<F>(&val_b, E::B, E::NUM_LIMBS);
        let k_limbs = from_emulated_field(val_k);
        let b_pow = F::from(2u32).pow([E::B as u64]);
        let val_expected = E::from(val_a) * b;
        let val_expected_limbs = from_emulated_field(val_expected);

        let neg_modulus = biguint_to_limbs::<F>(
            &(BigUint::from(2u32).pow(E::T as u32) - E::MODULUS.into()),
            E::B,
            E::NUM_LIMBS,
        );

        // range checking for output c
        c.0.iter()
            .map(|v| self.enforce_in_range(*v, E::B))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // enforcing a * b - k * E::MODULUS = c mod 2^t

        // first compare the first limb
        let mut val_carry_out =
            (a_limbs[0] * b_limbs[0] + k_limbs[0] * neg_modulus[0] - val_expected_limbs[0]) / b_pow;
        let mut carry_out = self.create_variable(val_carry_out)?;
        // checking that the carry_out has at most [`E::B`] bits
        self.enforce_in_range(carry_out, E::B + 1)?;
        // enforcing that a0 * b0 - k0 * modulus[0] - carry_out * 2^E::B = c0
        self.lc_gate(
            &[a.0[0], k.0[0], carry_out, self.zero(), c.0[0]],
            &[b_limbs[0], neg_modulus[0], -b_pow, F::zero()],
        )?;

        for i in 1..E::NUM_LIMBS {
            // compare the i-th limb

            // calculate the next carry out
            let val_next_carry_out = ((0..=i)
                .map(|j| k_limbs[j] * neg_modulus[i - j] + a_limbs[j] * b_limbs[i - j])
                .sum::<F>()
                + val_carry_out
                - val_expected_limbs[i])
                / b_pow;
            let next_carry_out = self.create_variable(val_next_carry_out)?;

            // range checking for this carry out.
            let num_vals = 2u64 * (i as u64) + 2;
            let log_num_vals = (u64::BITS - num_vals.leading_zeros()) as usize;
            self.enforce_in_range(next_carry_out, E::B + log_num_vals)?;

            // k * E::MODULUS part, waiting for summation
            let mut stack = (0..=i)
                .map(|j| (k.0[j], neg_modulus[i - j]))
                .collect::<Vec<_>>();
            // a * b part
            (0..=i).for_each(|j| stack.push((a.0[j], b_limbs[i - j])));
            // carry out from last limb
            stack.push((carry_out, F::one()));
            stack.push((next_carry_out, -b_pow));

            // linear combination of all items in the stack
            while stack.len() > 4 {
                let t1 = stack.pop().unwrap();
                let t2 = stack.pop().unwrap();
                let t3 = stack.pop().unwrap();
                let t4 = stack.pop().unwrap();
                let t = self.lc(&[t1.0, t2.0, t3.0, t4.0], &[t1.1, t2.1, t3.1, t4.1])?;
                stack.push((t, F::one()));
            }
            let t1 = stack.pop().unwrap_or((self.zero(), F::zero()));
            let t2 = stack.pop().unwrap_or((self.zero(), F::zero()));
            let t3 = stack.pop().unwrap_or((self.zero(), F::zero()));
            let t4 = stack.pop().unwrap_or((self.zero(), F::zero()));

            // checking that the summation equals to i-th limb of c
            self.lc_gate(&[t1.0, t2.0, t3.0, t4.0, c.0[i]], &[t1.1, t2.1, t3.1, t4.1])?;

            val_carry_out = val_next_carry_out;
            carry_out = next_carry_out;
        }

        // enforcing a * b - k * E::MODULUS = c mod F::MODULUS
        let a_mod = self.mod_to_native_field(a)?;
        let b_mod = F::from(val_b);
        let k_mod = self.mod_to_native_field(&k)?;
        let c_mod = self.mod_to_native_field(c)?;
        let e_mod_f = F::from(E::MODULUS.into());
        self.lc_gate(
            &[a_mod, k_mod, self.zero(), self.zero(), c_mod],
            &[b_mod, -e_mod_f, F::zero(), F::zero()],
        )?;

        Ok(())
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
        self.check_vars_bound(&a.0)?;
        self.check_vars_bound(&b.0)?;
        self.check_vars_bound(&c.0)?;

        let val_a: BigUint = self.emulated_witness(a)?.into();
        let val_b: BigUint = self.emulated_witness(b)?.into();
        let modulus: BigUint = E::MODULUS.into();
        let b_pow = BigUint::from(2u32).pow(E::B as u32);
        let add_no_mod = &val_a + &val_b;
        let k = if add_no_mod >= modulus { 1u32 } else { 0u32 };
        let var_k = self.create_boolean_variable(add_no_mod >= modulus)?.0;
        let modulus_limbs = biguint_to_limbs::<F>(&modulus, E::B, E::NUM_LIMBS);

        let add_no_mod_limbs = biguint_to_limbs::<F>(&add_no_mod, E::B, E::NUM_LIMBS)
            .into_iter()
            .map(|val| self.create_variable(val))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // Checking whether a + b = add_no_mod_limbs
        let mut carry_out = self.zero();
        for (a, b, c) in izip!(&a.0, &b.0, &add_no_mod_limbs) {
            let next_carry_out =
                F::from(<F as Into<BigUint>>::into(self.witness(*a)? + self.witness(*b)?) / &b_pow);
            let next_carry_out = self.create_variable(next_carry_out)?;
            self.enforce_bool(next_carry_out)?;

            let wires = [*a, *b, carry_out, next_carry_out, *c];
            let coeffs = [F::one(), F::one(), F::one(), -F::from(b_pow.clone())];
            self.lc_gate(&wires, &coeffs)?;
            carry_out = next_carry_out;

            self.enforce_in_range(*c, E::B)?;
        }

        // Checking whether k * E::MODULUS + c = add_no_mod_limbs
        carry_out = self.zero();
        for (a, b, c) in izip!(modulus_limbs, &c.0, &add_no_mod_limbs) {
            let next_carry_out =
                F::from(<F as Into<BigUint>>::into(a * F::from(k) + self.witness(*b)?) / &b_pow);
            let next_carry_out = self.create_variable(next_carry_out)?;
            self.enforce_bool(next_carry_out)?;

            let wires = [var_k, *b, carry_out, next_carry_out, *c];
            let coeffs = [a, F::one(), F::one(), -F::from(b_pow.clone())];
            self.lc_gate(&wires, &coeffs)?;
            carry_out = next_carry_out;
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
        self.check_vars_bound(&a.0)?;
        self.check_vars_bound(&c.0)?;

        let val_a: BigUint = self.emulated_witness(a)?.into();
        let val_b: BigUint = b.into();
        let q: BigUint = E::MODULUS.into();
        let b_pow = BigUint::from(2u32).pow(E::B as u32);
        let add_no_mod = &val_a + &val_b;
        let k = if add_no_mod >= q { 1u32 } else { 0u32 };
        let var_k = self.create_boolean_variable(add_no_mod >= q)?.0;
        let q_limbs = biguint_to_limbs::<F>(&q, E::B, E::NUM_LIMBS);
        let b_limbs = biguint_to_limbs::<F>(&val_b, E::B, E::NUM_LIMBS);

        let add_no_mod_limbs = biguint_to_limbs::<F>(&add_no_mod, E::B, E::NUM_LIMBS)
            .into_iter()
            .map(|val| self.create_variable(val))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // Checking whether a + b = add_no_mod_limbs
        let mut carry_out = self.zero();
        for (a, b, c) in izip!(&a.0, b_limbs, &add_no_mod_limbs) {
            let next_carry_out =
                F::from(<F as Into<BigUint>>::into(self.witness(*a)? + b) / &b_pow);
            let next_carry_out = self.create_variable(next_carry_out)?;
            self.enforce_bool(next_carry_out)?;

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
            self.enforce_bool(next_carry_out)?;

            let wires = [var_k, *b, carry_out, next_carry_out, *c];
            let coeffs = [a, F::one(), F::one(), -F::from(b_pow.clone())];
            self.lc_gate(&wires, &coeffs)?;
            carry_out = next_carry_out;
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

    /// Obtain an emulated variable of the conditional selection from 2 emulated
    /// variables. `b` is a boolean variable that indicates selection of P_b
    /// from (P0, P1).
    /// Return error if invalid input parameters are provided.
    pub fn conditional_select_emulated<E: EmulationConfig<F>>(
        &mut self,
        b: BoolVar,
        p0: &EmulatedVariable<E>,
        p1: &EmulatedVariable<E>,
    ) -> Result<EmulatedVariable<E>, CircuitError> {
        self.check_var_bound(b.into())?;
        self.check_vars_bound(&p0.0[..])?;
        self.check_vars_bound(&p1.0[..])?;

        let mut vals = vec![];
        for (&x_0, &x_1) in p0.0.iter().zip(p1.0.iter()) {
            let selected = self.conditional_select(b, x_0, x_1)?;
            vals.push(selected);
        }

        Ok(EmulatedVariable::<E>(vals, PhantomData::<E>))
    }

    /// Constrain two emulated variables to be the same.
    /// Return error if the input variables are invalid.
    pub fn enforce_emulated_var_equal<E: EmulationConfig<F>>(
        &mut self,
        p0: &EmulatedVariable<E>,
        p1: &EmulatedVariable<E>,
    ) -> Result<(), CircuitError> {
        self.check_vars_bound(&p0.0[..])?;
        self.check_vars_bound(&p1.0[..])?;
        for (&a, &b) in p0.0.iter().zip(p1.0.iter()) {
            self.enforce_equal(a, b)?;
        }
        Ok(())
    }

    /// Given an emulated field element `a`, return `a mod F::MODULUS` in the
    /// native field.
    fn mod_to_native_field<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedVariable<E>,
    ) -> Result<Variable, CircuitError> {
        let b_pow = F::from(2u32).pow([E::B as u64]);
        let double_b_pow = b_pow * b_pow;
        let triple_b_pow = double_b_pow * b_pow;
        let zero = self.zero();
        let a0 = a.0.first().unwrap_or(&zero);
        let a1 = a.0.get(1).unwrap_or(&zero);
        let a2 = a.0.get(2).unwrap_or(&zero);
        let a3 = a.0.get(3).unwrap_or(&zero);

        let mut result = self.lc(
            &[*a0, *a1, *a2, *a3],
            &[F::one(), b_pow, double_b_pow, triple_b_pow],
        )?;

        if E::NUM_LIMBS > 4 {
            let mut cur_pow = triple_b_pow * b_pow;
            for i in (4..E::NUM_LIMBS).step_by(3) {
                let a0 = a.0.get(i).unwrap_or(&zero);
                let a1 = a.0.get(i + 1).unwrap_or(&zero);
                let a2 = a.0.get(i + 2).unwrap_or(&zero);
                result = self.lc(
                    &[result, *a0, *a1, *a2],
                    &[F::one(), cur_pow, cur_pow * b_pow, cur_pow * double_b_pow],
                )?;
                cur_pow *= triple_b_pow;
            }
        }
        Ok(result)
    }
}

impl EmulationConfig<ark_bn254::Fr> for ark_bls12_377::Fq {
    const T: usize = 500;

    const B: usize = 125;

    const NUM_LIMBS: usize = 4;
}

impl EmulationConfig<ark_bn254::Fr> for ark_bn254::Fq {
    const T: usize = 261;

    const B: usize = 87;

    const NUM_LIMBS: usize = 3;
}

#[cfg(test)]
mod tests {
    use super::EmulationConfig;
    use crate::{gadgets::from_emulated_field, Circuit, PlonkCircuit};
    use ark_bls12_377::Fq as Fq377;
    use ark_bn254::{Fq as Fq254, Fr as Fr254};
    use ark_ff::{MontFp, PrimeField};

    #[test]
    fn test_basics() {
        test_basics_helper::<Fq377, Fr254>();
        test_basics_helper::<Fq254, Fr254>();
    }

    fn test_basics_helper<E, F>()
    where
        E: EmulationConfig<F>,
        F: PrimeField,
    {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let var_x = circuit.create_emulated_variable(E::one()).unwrap();
        let overflow = E::from(F::MODULUS.into() * 2u64 + 1u64);
        let var_y = circuit.create_emulated_variable(overflow).unwrap();
        assert_eq!(circuit.emulated_witness(&var_x).unwrap(), E::one());
        assert_eq!(circuit.emulated_witness(&var_y).unwrap(), overflow);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
    }

    #[test]
    fn test_emulated_add() {
        test_emulated_add_helper::<Fq377, Fr254>();
        test_emulated_add_helper::<Fq254, Fr254>();
    }

    fn test_emulated_add_helper<E, F>()
    where
        E: EmulationConfig<F>,
        F: PrimeField,
    {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let var_x = circuit.create_public_emulated_variable(E::one()).unwrap();
        let overflow = E::from(E::MODULUS.into() - 1u64);
        let var_y = circuit.create_emulated_variable(overflow).unwrap();
        let var_z = circuit.emulated_add(&var_x, &var_y).unwrap();
        assert_eq!(circuit.emulated_witness(&var_x).unwrap(), E::one());
        assert_eq!(circuit.emulated_witness(&var_y).unwrap(), overflow);
        assert_eq!(circuit.emulated_witness(&var_z).unwrap(), E::zero());

        let var_z = circuit.emulated_add_constant(&var_z, overflow).unwrap();
        assert_eq!(circuit.emulated_witness(&var_z).unwrap(), overflow);

        let x = from_emulated_field(E::one());
        assert!(circuit.check_circuit_satisfiability(&x).is_ok());

        let var_z = circuit.create_emulated_variable(E::one()).unwrap();
        circuit.emulated_add_gate(&var_x, &var_y, &var_z).unwrap();
        assert!(circuit.check_circuit_satisfiability(&x).is_err());
    }

    #[test]
    fn test_emulated_mul() {
        test_emulated_mul_helper::<Fq377, Fr254>();
        test_emulated_mul_helper::<Fq254, Fr254>();

        // test for issue (https://github.com/EspressoSystems/jellyfish/issues/306)
        let x : Fq377= MontFp!("218393408942992446968589193493746660101651787560689350338764189588519393175121782177906966561079408675464506489966");
        let y : Fq377 = MontFp!("122268283598675559488486339158635529096981886914877139579534153582033676785385790730042363341236035746924960903179");

        let mut circuit = PlonkCircuit::<Fr254>::new_turbo_plonk();
        let var_x = circuit.create_emulated_variable(x).unwrap();
        let _ = circuit.emulated_mul_constant(&var_x, y).unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
    }

    fn test_emulated_mul_helper<E, F>()
    where
        E: EmulationConfig<F>,
        F: PrimeField,
    {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let x = E::from(6732u64);
        let y = E::from(E::MODULUS.into() - 12387u64);
        let expected = x * y;
        let var_x = circuit.create_public_emulated_variable(x).unwrap();
        let var_y = circuit.create_emulated_variable(y).unwrap();
        let var_z = circuit.emulated_mul(&var_x, &var_y).unwrap();
        assert_eq!(circuit.emulated_witness(&var_x).unwrap(), x);
        assert_eq!(circuit.emulated_witness(&var_y).unwrap(), y);
        assert_eq!(circuit.emulated_witness(&var_z).unwrap(), expected);
        assert!(circuit
            .check_circuit_satisfiability(&from_emulated_field(x))
            .is_ok());

        let var_y_z = circuit.emulated_mul(&var_y, &var_z).unwrap();
        assert_eq!(circuit.emulated_witness(&var_y_z).unwrap(), expected * y);
        assert!(circuit
            .check_circuit_satisfiability(&from_emulated_field(x))
            .is_ok());

        let var_z = circuit.emulated_mul_constant(&var_z, expected).unwrap();
        assert_eq!(
            circuit.emulated_witness(&var_z).unwrap(),
            expected * expected
        );
        assert!(circuit
            .check_circuit_satisfiability(&from_emulated_field(x))
            .is_ok());

        let var_z = circuit.create_emulated_variable(E::one()).unwrap();
        circuit.emulated_mul_gate(&var_x, &var_y, &var_z).unwrap();
        assert!(circuit
            .check_circuit_satisfiability(&from_emulated_field(x))
            .is_err());
    }

    #[test]
    fn test_select() {
        test_select_helper::<Fq377, Fr254>();
        test_select_helper::<Fq254, Fr254>();
    }

    fn test_select_helper<E, F>()
    where
        E: EmulationConfig<F>,
        F: PrimeField,
    {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let var_x = circuit.create_emulated_variable(E::one()).unwrap();
        let overflow = E::from(E::MODULUS.into() - 1u64);
        let var_y = circuit.create_emulated_variable(overflow).unwrap();
        let b = circuit.create_boolean_variable(true).unwrap();
        let var_z = circuit
            .conditional_select_emulated(b, &var_x, &var_y)
            .unwrap();
        assert_eq!(circuit.emulated_witness(&var_z).unwrap(), overflow);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(var_z.0[0]) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_enforce_equal() {
        test_enforce_equal_helper::<Fq377, Fr254>();
        test_enforce_equal_helper::<Fq254, Fr254>();
    }

    fn test_enforce_equal_helper<E, F>()
    where
        E: EmulationConfig<F>,
        F: PrimeField,
    {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let var_x = circuit.create_emulated_variable(E::one()).unwrap();
        let overflow = E::from(E::MODULUS.into() - 1u64);
        let var_y = circuit.create_emulated_variable(overflow).unwrap();
        let var_z = circuit.create_emulated_variable(overflow).unwrap();
        circuit.enforce_emulated_var_equal(&var_y, &var_z).unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        circuit.enforce_emulated_var_equal(&var_x, &var_y).unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
