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
use ark_std::vec::Vec;

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
        let infinity =
            self.create_boolean_variable_unchecked(if point.2 { F::one() } else { F::zero() })?;
        Ok(EmulatedSWPointVariable(x, y, infinity))
    }

    /// Add a new public emulated EC point
    pub fn create_public_emulated_sw_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: SWPoint<E>,
    ) -> Result<EmulatedSWPointVariable<E>, CircuitError> {
        let x = self.create_public_emulated_variable(point.0)?;
        let y = self.create_public_emulated_variable(point.1)?;
        let infinity =
            self.create_boolean_variable_unchecked(if point.2 { F::one() } else { F::zero() })?;
        Ok(EmulatedSWPointVariable(x, y, infinity))
    }

    /// Obtain an emulated point variable of the conditional selection from 2
    /// emulated point variables. `b` is a boolean variable that indicates
    /// selection of P_b from (P0, P1).
    /// Return error if invalid input parameters are provided.
    pub fn binary_emulated_sw_point_vars_select<E: EmulationConfig<F>>(
        &mut self,
        b: BoolVar,
        point0: &EmulatedSWPointVariable<E>,
        point1: &EmulatedSWPointVariable<E>,
    ) -> Result<EmulatedSWPointVariable<E>, CircuitError> {
        let select_x = self.conditional_select_emulated(b, &point0.0, &point1.0)?;
        let select_y = self.conditional_select_emulated(b, &point0.1, &point1.1)?;
        let select_infinity = BoolVar(self.conditional_select(b, point0.2 .0, point1.2 .0)?);

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
        point0: &EmulatedSWPointVariable<E>,
        point1: &EmulatedSWPointVariable<E>,
    ) -> Result<(), CircuitError> {
        self.enforce_emulated_var_equal(&point0.0, &point1.0)?;
        self.enforce_emulated_var_equal(&point0.1, &point1.1)?;
        self.enforce_equal(point0.2 .0, point1.2 .0)?;
        Ok(())
    }

    /// Obtain a bool variable representing whether two input emulated point
    /// variables are equal. Return error if variables are invalid.
    pub fn is_emulated_sw_point_equal<E: EmulationConfig<F>>(
        &mut self,
        point0: &EmulatedSWPointVariable<E>,
        point1: &EmulatedSWPointVariable<E>,
    ) -> Result<BoolVar, CircuitError> {
        let mut r0 = self.is_emulated_var_equal(&point0.0, &point1.0)?;
        let r1 = self.is_emulated_var_equal(&point0.1, &point1.1)?;
        let r2 = self.is_equal(point0.2 .0, point1.2 .0)?;
        r0.0 = self.mul(r0.0, r1.0)?;
        r0.0 = self.mul(r0.0, r2.0)?;
        Ok(r0)
    }

    /// Constrain variable `c` to be the point addition of `a` and
    /// `b` over an elliptic curve.
    /// Let a = (x0, y0), b = (x1, y1), c = (x2, y2)
    /// The addition formula for affine points of sw curve is
    ///   1. if a == b
    ///     - if y0 == 0 then (x2, y2) = (0, 0)
    ///     - Calculate s = (3 * x0^2 + a) / (2 * y0)
    ///     - x2 = s^2 - 2 * x0
    ///     - y2 = s(x0 - x2) - y0
    ///   2. Otherwise
    ///     - if x0 == x1 then (x2, y2) = (0, 0)
    ///     - Calculate s = (y0 - y1) / (x0 - x1)
    ///     - x2 = s^2 - x0 - x1
    ///     - y2 = s(x0 - x2) - y0
    /// The first case is equivalent to the following:
    ///   - (x2 + 2 * x0) * (y0 + y0) * y0 = (3* x_1^2 + d)^2 * y0
    ///   - (y2 + y0) * 2 * y0 * y0 = (3* x_1^2 + d) (x0 - x2) * y0
    ///   - not_equal(x0, x1) || not_equal(y0, y1) || not_zero(y0) || ((x2 == 0)
    ///     && (y2 == 0))
    /// The second case is equivalent to the following:
    ///   - (x0 - x1)^3 (x0 + x1 + x2) == (x0 - x1) (y0 - y1)^2
    ///   - (x0 - x1) (x0 - x2) (y0 - y1) == (y0 + y2) (x0 - x1)^2
    ///   - not_equal(x0, x1) || is_equal(y0, y1) || ((x2 == 0) && (y2 == 0))
    /// TODO: unfinished
    pub fn emulated_sw_ecc_add_gate<E: EmulationConfig<F>>(
        &mut self,
        p0: &EmulatedSWPointVariable<E>,
        p1: &EmulatedSWPointVariable<E>,
        p2: &EmulatedSWPointVariable<E>,
        _a: E,
    ) -> Result<(), CircuitError> {
        let eq_p1_p2 = self.is_emulated_sw_point_equal(p1, p2)?;
        let eq_p0_p2 = self.is_emulated_sw_point_equal(p0, p2)?;
        // Case 1: either p0 or p1 is infinity
        self.enforce_equal(p0.2 .0, eq_p1_p2.0)?;
        self.enforce_equal(p1.2 .0, eq_p0_p2.0)?;
        todo!()
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

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

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
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // let var_p4 = circuit.emulated_sw_ecc_add(&wrong_result)

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
