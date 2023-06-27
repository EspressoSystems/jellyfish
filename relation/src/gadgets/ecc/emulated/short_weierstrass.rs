// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Short Weierstrass curve point addition

use crate::{
    errors::CircuitError,
    gadgets::{EmulatedVariable, EmulationConfig},
    BoolVar, Circuit, PlonkCircuit,
};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec, vec::Vec};

/// An elliptic curve point in short Weierstrass affine form (x, y, infinity).
#[derive(Debug, Eq, PartialEq, Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SWPoint<F: PrimeField>(pub F, pub F, pub bool);

impl<F, P> From<Affine<P>> for SWPoint<F>
where
    F: PrimeField,
    P: SWCurveConfig<BaseField = F>,
{
    fn from(p: Affine<P>) -> Self {
        SWPoint(p.x, p.y, p.infinity)
    }
}

/// The variable represents an SW point in the emulated field.
#[derive(Debug, Clone)]
pub struct EmulatedSWPointVariable<E: PrimeField>(
    pub EmulatedVariable<E>,
    pub EmulatedVariable<E>,
    pub BoolVar,
);

impl<F: PrimeField> PlonkCircuit<F> {
    /// Return the witness point
    pub fn emulated_sw_point_witness<E: EmulationConfig<F>>(
        &self,
        point_var: &EmulatedSWPointVariable<E>,
    ) -> Result<SWPoint<E>, CircuitError> {
        let x = self.emulated_witness(&point_var.0)?;
        let y = self.emulated_witness(&point_var.1)?;
        let infinity = self.witness(point_var.2 .0)? == F::one();
        Ok(SWPoint(x, y, infinity))
    }

    /// Add a new emulated EC point (as witness)
    pub fn create_emulated_sw_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: SWPoint<E>,
    ) -> Result<EmulatedSWPointVariable<E>, CircuitError> {
        let x = self.create_emulated_variable(point.0)?;
        let y = self.create_emulated_variable(point.1)?;
        let infinity = self.create_boolean_variable(point.2)?;
        Ok(EmulatedSWPointVariable(x, y, infinity))
    }

    /// Add a new constant emulated EC point
    pub fn create_constant_emulated_sw_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: SWPoint<E>,
    ) -> Result<EmulatedSWPointVariable<E>, CircuitError> {
        let x = self.create_constant_emulated_variable(point.0)?;
        let y = self.create_constant_emulated_variable(point.1)?;
        let infinity = BoolVar(if point.2 { self.one() } else { self.zero() });
        Ok(EmulatedSWPointVariable(x, y, infinity))
    }

    /// Add a new public emulated EC point
    pub fn create_public_emulated_sw_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: SWPoint<E>,
    ) -> Result<EmulatedSWPointVariable<E>, CircuitError> {
        let x = self.create_public_emulated_variable(point.0)?;
        let y = self.create_public_emulated_variable(point.1)?;
        let infinity = self.create_public_boolean_variable(point.2)?;
        Ok(EmulatedSWPointVariable(x, y, infinity))
    }

    /// Obtain an emulated point variable of the conditional selection from 2
    /// emulated point variables. `b` is a boolean variable that indicates
    /// selection of P_b from (P0, P1).
    /// Return error if invalid input parameters are provided.
    pub fn binary_emulated_sw_point_vars_select<E: EmulationConfig<F>>(
        &mut self,
        b: BoolVar,
        p0: &EmulatedSWPointVariable<E>,
        p1: &EmulatedSWPointVariable<E>,
    ) -> Result<EmulatedSWPointVariable<E>, CircuitError> {
        let select_x = self.conditional_select_emulated(b, &p0.0, &p1.0)?;
        let select_y = self.conditional_select_emulated(b, &p0.1, &p1.1)?;
        let select_infinity = BoolVar(self.conditional_select(b, p0.2 .0, p1.2 .0)?);

        Ok(EmulatedSWPointVariable::<E>(
            select_x,
            select_y,
            select_infinity,
        ))
    }

    /// Constrain two emulated point variables to be the same.
    /// Return error if the input point variables are invalid.
    pub fn enforce_emulated_sw_point_equal<E: EmulationConfig<F>>(
        &mut self,
        p0: &EmulatedSWPointVariable<E>,
        p1: &EmulatedSWPointVariable<E>,
    ) -> Result<(), CircuitError> {
        self.enforce_emulated_var_equal(&p0.0, &p1.0)?;
        self.enforce_emulated_var_equal(&p0.1, &p1.1)?;
        self.enforce_equal(p0.2 .0, p1.2 .0)?;
        Ok(())
    }

    /// Obtain a bool variable representing whether two input emulated point
    /// variables are equal. Return error if variables are invalid.
    pub fn is_emulated_sw_point_equal<E: EmulationConfig<F>>(
        &mut self,
        p0: &EmulatedSWPointVariable<E>,
        p1: &EmulatedSWPointVariable<E>,
    ) -> Result<BoolVar, CircuitError> {
        let mut r0 = self.is_emulated_var_equal(&p0.0, &p1.0)?;
        let r1 = self.is_emulated_var_equal(&p0.1, &p1.1)?;
        let r2 = self.is_equal(p0.2 .0, p1.2 .0)?;
        r0.0 = self.mul(r0.0, r1.0)?;
        r0.0 = self.mul(r0.0, r2.0)?;
        Ok(r0)
    }

    /// Constrain variable `p2` to be the point addition of `p0` and
    /// `p1` over an elliptic curve.
    /// Let p0 = (x0, y0, inf0), p1 = (x1, y1, inf1), p2 = (x2, y2, inf2)
    /// The addition formula for affine points of sw curve is
    ///   If either p0 or p1 is infinity, then p2 equals to another point.
    ///   1. if p0 == p1
    ///     - if y0 == 0 then inf2 = 1
    ///     - Calculate s = (3 * x0^2 + a) / (2 * y0)
    ///     - x2 = s^2 - 2 * x0
    ///     - y2 = s(x0 - x2) - y0
    ///   2. Otherwise
    ///     - if x0 == x1 then inf2 = 1
    ///     - Calculate s = (y0 - y1) / (x0 - x1)
    ///     - x2 = s^2 - x0 - x1
    ///     - y2 = s(x0 - x2) - y0
    /// The first case is equivalent to the following:
    /// - inf0 == 1 || inf1 == 1 || x0 != x1 || y0 != y1 || y0 != 0 || inf2 == 0
    /// - (x2 + 2 * x0) * (y0 + y0)^2 == (3 * x1^2 + a)^2
    /// - (y2 + y0) * (y0 + y0) == (3 * x1^2 + a) (x0 - x2)
    /// The second case is equivalent to the following:
    /// - inf0 == 1 || inf1 == 1 || x0 != x1 || y0 == y1 || inf2 == 0
    /// - (x0 - x1)^2 (x0 + x1 + x2) == (y0 - y1)^2
    /// - (x0 - x2) (y0 - y1) == (y0 + y2) (x0 - x1)
    /// First check in both cases can be combined into the following:
    /// inf0 == 1 || inf1 == 1 || inf2 == 0 || x0 != x1 || (y0 == y1 && y0 != 0)
    /// For the rest equality checks,
    ///   - Both LHS and RHS must be multiplied with an indicator variable
    ///     (!inf0 && !inf1). So that if either p0 or p1 is infinity, those
    ///     checks will trivially pass.
    ///   - For the first case (point doubling), both LHS and RHS must be
    ///     multiplied with an indicator variable (y0 != 0 && x0 == x1 && y1 ==
    ///     y0). So that when y0 == 0 || x0 != x1 || y0 != y1, these checks will
    ///     trivially pass.
    ///   - For the second case, both LHS and RHS must be multiplied with (x0 -
    ///     x1). So that when x0 == x1, these checks will trivially pass.
    pub fn emulated_sw_ecc_add_gate<E: EmulationConfig<F>>(
        &mut self,
        p0: &EmulatedSWPointVariable<E>,
        p1: &EmulatedSWPointVariable<E>,
        p2: &EmulatedSWPointVariable<E>,
        a: E,
    ) -> Result<(), CircuitError> {
        let eq_p1_p2 = self.is_emulated_sw_point_equal(p1, p2)?;
        let eq_p0_p2 = self.is_emulated_sw_point_equal(p0, p2)?;
        // Case 1: either p0 or p1 is infinity
        self.enforce_equal(p0.2 .0, eq_p1_p2.0)?;
        self.enforce_equal(p1.2 .0, eq_p0_p2.0)?;

        // infinity_mark is 1 iff either p0 or p1 is infinity
        let infinity_mark = self.logic_or(p0.2, p1.2)?;
        // is 1 iff both p0 and p1 are not infinity
        let non_infinity_mark = self.logic_neg(infinity_mark)?;

        // Case 2: p2 is infinity, while p0 and p1 are not.
        // inf0 == 1 || inf1 == 1 || inf2 == 0 || x0 != x1 || (y0 == y1 && y0 != 0)
        let non_inf_p2 = self.logic_neg(p2.2)?;
        let eq_x0_x1 = self.is_emulated_var_equal(&p0.0, &p1.0)?;
        let neq_x0_x1 = self.logic_neg(eq_x0_x1)?;
        let eq_y0_y1 = self.is_emulated_var_equal(&p0.1, &p1.1)?;
        let is_y0_zero = self.is_emulated_var_zero(&p0.1)?;
        let not_y0_zero = self.logic_neg(is_y0_zero)?;
        let t = self.logic_and(eq_y0_y1, not_y0_zero)?;
        let t = self.logic_or(neq_x0_x1, t)?;
        let t = self.logic_or(non_inf_p2, t)?;
        self.logic_or_gate(infinity_mark, t)?;

        // Case 3: point doubling
        // doubling mark is 1 iff x0 == x1 and y0 == y1
        let doubling_mark = self.mul(eq_x0_x1.0, eq_y0_y1.0)?;
        let doubling_coef = self.mul(doubling_mark, non_infinity_mark.0)?;
        let doubling_coef = self.mul(doubling_coef, not_y0_zero.0)?;
        // forcefully convert Variable into EmulatedVariable
        // safe because it's boolean
        let mut v = vec![self.zero(); E::NUM_LIMBS];
        v[0] = doubling_coef;
        let doubling_coef = EmulatedVariable::<E>(v, core::marker::PhantomData);

        // first equality (x2 + 2 * x0) * (y0 + y0)^2 == (3 * x1^2 + a)^2
        let y0_times_2 = self.emulated_add(&p0.1, &p0.1)?;
        let x0_plus_x1 = self.emulated_add(&p0.0, &p1.0)?;
        let x0_plus_x1_plus_x2 = self.emulated_add(&p2.0, &x0_plus_x1)?;
        let lhs = self.emulated_mul(&x0_plus_x1_plus_x2, &y0_times_2)?;
        let lhs = self.emulated_mul(&lhs, &y0_times_2)?;
        // s = 3 * x1^2 + a
        let s = self.emulated_mul(&p0.0, &p0.0)?;
        let s = self.emulated_mul_constant(&s, E::from(3u64))?;
        let s = self.emulated_add_constant(&s, a)?;
        let rhs = self.emulated_mul(&s, &s)?;

        let lhs = self.emulated_mul(&lhs, &doubling_coef)?;
        let rhs = self.emulated_mul(&rhs, &doubling_coef)?;
        self.enforce_emulated_var_equal(&lhs, &rhs)?;

        // second equality (y2 + y0) * (y0 + y0) == (3 * x1^2 + a) (x0 - x2)
        let y2_plus_y0 = self.emulated_add(&p2.1, &p0.1)?;
        let lhs = self.emulated_mul(&y2_plus_y0, &y0_times_2)?;
        let x0_minus_x2 = self.emulated_sub(&p0.0, &p2.0)?;
        let rhs = self.emulated_mul(&s, &x0_minus_x2)?;

        let lhs = self.emulated_mul(&lhs, &doubling_coef)?;
        let rhs = self.emulated_mul(&rhs, &doubling_coef)?;
        self.enforce_emulated_var_equal(&lhs, &rhs)?;

        // Case 4: point addition
        let coef = self.mul(non_infinity_mark.0, neq_x0_x1.0)?;
        // forcefully convert Variable into EmulatedVariable
        // safe because it's boolean
        let mut v = vec![self.zero(); E::NUM_LIMBS];
        v[0] = coef;
        let coef = EmulatedVariable::<E>(v, core::marker::PhantomData);

        // first equality (x0 - x1)^2 (x0 + x1 + x2) == (y0 - y1)^2
        let x0_minus_x1 = self.emulated_sub(&p0.0, &p1.0)?;
        let lhs = self.emulated_mul(&x0_minus_x1, &x0_minus_x1)?;
        let lhs = self.emulated_mul(&lhs, &x0_plus_x1_plus_x2)?;
        let y0_minus_y1 = self.emulated_sub(&p0.1, &p1.1)?;
        let rhs = self.emulated_mul(&y0_minus_y1, &y0_minus_y1)?;

        let lhs = self.emulated_mul(&lhs, &coef)?;
        let rhs = self.emulated_mul(&rhs, &coef)?;
        self.enforce_emulated_var_equal(&lhs, &rhs)?;

        // second equality (x0 - x2) (y0 - y1) == (y0 + y2) (x0 - x1)
        let lhs = self.emulated_mul(&x0_minus_x2, &y0_minus_y1)?;
        let y0_plus_y2 = self.emulated_add(&p0.1, &p2.1)?;
        let rhs = self.emulated_mul(&y0_plus_y2, &x0_minus_x1)?;

        let lhs = self.emulated_mul(&lhs, &coef)?;
        let rhs = self.emulated_mul(&rhs, &coef)?;
        self.enforce_emulated_var_equal(&lhs, &rhs)?;

        Ok(())
    }

    /// Obtain a variable to the point addition result of `p0` + `p1`
    pub fn emulated_sw_ecc_add<E: EmulationConfig<F>>(
        &mut self,
        p0: &EmulatedSWPointVariable<E>,
        p1: &EmulatedSWPointVariable<E>,
        a: E,
    ) -> Result<EmulatedSWPointVariable<E>, CircuitError> {
        let x0 = self.emulated_witness(&p0.0)?;
        let y0 = self.emulated_witness(&p0.1)?;
        let infinity0 = self.witness(p0.2 .0)? == F::one();
        let x1 = self.emulated_witness(&p1.0)?;
        let y1 = self.emulated_witness(&p1.1)?;
        let infinity1 = self.witness(p1.2 .0)? == F::one();
        let p2 = if infinity0 {
            SWPoint(x1, y1, infinity1)
        } else if infinity1 {
            SWPoint(x0, y0, infinity0)
        } else if x0 == x1 && y0 == y1 {
            // point doubling
            if y0.is_zero() {
                SWPoint(E::zero(), E::zero(), true)
            } else {
                let s = (x0 * x0 * E::from(3u64) + a) / (y0 + y0);
                let x2 = s * s - x0 - x1;
                let y2 = s * (x0 - x2) - y0;
                SWPoint(x2, y2, false)
            }
        } else {
            // point addition
            if x0 == x1 {
                SWPoint(E::zero(), E::zero(), true)
            } else {
                let s = (y0 - y1) / (x0 - x1);
                let x2 = s * s - x0 - x1;
                let y2 = s * (x0 - x2) - y0;
                SWPoint(x2, y2, false)
            }
        };
        let p2 = self.create_emulated_sw_point_variable(p2)?;
        self.emulated_sw_ecc_add_gate(p0, p1, &p2, a)?;
        Ok(p2)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        gadgets::{ecc::conversion::*, EmulationConfig},
        Circuit, PlonkCircuit,
    };
    use ark_bls12_377::{g1::Config as Param377, Fq as Fq377};
    use ark_bn254::{g1::Config as Param254, Fq as Fq254, Fr as Fr254};
    use ark_ec::{
        short_weierstrass::{Projective, SWCurveConfig},
        CurveGroup, Group,
    };
    use ark_ff::{MontFp, PrimeField};
    use ark_std::{UniformRand, Zero};

    #[test]
    fn test_emulated_sw_point_addition() {
        let a: Fq377 = MontFp!("0");
        test_emulated_sw_point_addition_helper::<Fq377, Fr254, Param377>(a);
        let a: Fq254 = MontFp!("0");
        test_emulated_sw_point_addition_helper::<Fq254, Fr254, Param254>(a);
    }

    fn test_emulated_sw_point_addition_helper<E, F, P>(a: E)
    where
        E: EmulationConfig<F> + SWToTEConParam,
        F: PrimeField,
        P: SWCurveConfig<BaseField = E>,
    {
        let mut rng = jf_utils::test_rng();
        let neutral = Projective::<P>::zero().into_affine();
        let p1 = Projective::<P>::rand(&mut rng).into_affine();
        let p2 = Projective::<P>::rand(&mut rng).into_affine();
        let expected = (p1 + p2).into_affine().into();
        let wrong_result = (p1 + p2 + Projective::<P>::generator())
            .into_affine()
            .into();

        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(20);

        let var_p1 = circuit
            .create_emulated_sw_point_variable(p1.into())
            .unwrap();
        let var_p2 = circuit
            .create_emulated_sw_point_variable(p2.into())
            .unwrap();
        let var_result = circuit.emulated_sw_ecc_add(&var_p1, &var_p2, a).unwrap();
        assert_eq!(
            circuit.emulated_sw_point_witness(&var_result).unwrap(),
            expected
        );
        let var_neutral = circuit
            .create_emulated_sw_point_variable(neutral.into())
            .unwrap();
        let var_neutral_result1 = circuit
            .emulated_sw_ecc_add(&var_p1, &var_neutral, a)
            .unwrap();
        let var_neutral_result2 = circuit
            .emulated_sw_ecc_add(&var_neutral, &var_p1, a)
            .unwrap();
        assert_eq!(
            circuit
                .emulated_sw_point_witness(&var_neutral_result1)
                .unwrap(),
            p1.into()
        );
        assert_eq!(
            circuit
                .emulated_sw_point_witness(&var_neutral_result2)
                .unwrap(),
            p1.into()
        );
        let double_p1 = (p1 + p1).into_affine().into();
        let var_doubling_result = circuit.emulated_sw_ecc_add(&var_p1, &var_p1, a).unwrap();
        assert_eq!(
            circuit
                .emulated_sw_point_witness(&var_doubling_result)
                .unwrap(),
            double_p1
        );
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // fail path
        let var_wrong_result = circuit
            .create_emulated_sw_point_variable(wrong_result)
            .unwrap();
        circuit
            .emulated_sw_ecc_add_gate(&var_p1, &var_p2, &var_wrong_result, a)
            .unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
