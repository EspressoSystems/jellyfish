// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Elliptic curve related gates and gadgets for non-native fields

use crate::{
    errors::CircuitError,
    gadgets::{EmulatedVariable, EmulationConfig},
    BoolVar, Circuit, PlonkCircuit,
};
use ark_ff::PrimeField;

mod short_weierstrass;
mod twisted_edwards;

pub use short_weierstrass::*;
pub use twisted_edwards::*;

use super::Point;

/// The variable represents an EC point in the emulated field.
#[derive(Debug, Clone)]
pub struct EmulatedPointVariable<E: PrimeField>(pub EmulatedVariable<E>, pub EmulatedVariable<E>);

impl<F: PrimeField> PlonkCircuit<F> {
    /// Return the witness point
    pub fn emulated_point_witness<E: EmulationConfig<F>>(
        &self,
        point_var: &EmulatedPointVariable<E>,
    ) -> Result<Point<E>, CircuitError> {
        let x = self.emulated_witness(&point_var.0)?;
        let y = self.emulated_witness(&point_var.1)?;
        Ok(Point(x, y))
    }

    /// Add a new emulated EC point (as witness)
    pub fn create_emulated_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: Point<E>,
    ) -> Result<EmulatedPointVariable<E>, CircuitError> {
        let x = self.create_emulated_variable(point.0)?;
        let y = self.create_emulated_variable(point.1)?;
        Ok(EmulatedPointVariable(x, y))
    }

    /// Add a new constant emulated EC point
    pub fn create_constant_emulated_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: Point<E>,
    ) -> Result<EmulatedPointVariable<E>, CircuitError> {
        let x = self.create_constant_emulated_variable(point.0)?;
        let y = self.create_constant_emulated_variable(point.1)?;
        Ok(EmulatedPointVariable(x, y))
    }

    /// Add a new public emulated EC point
    pub fn create_public_emulated_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: Point<E>,
    ) -> Result<EmulatedPointVariable<E>, CircuitError> {
        let x = self.create_public_emulated_variable(point.0)?;
        let y = self.create_public_emulated_variable(point.1)?;
        Ok(EmulatedPointVariable(x, y))
    }

    /// Obtain an emulated point variable of the conditional selection from 2
    /// emulated point variables. `b` is a boolean variable that indicates
    /// selection of P_b from (P0, P1).
    /// Return error if invalid input parameters are provided.
    pub fn binary_emulated_point_vars_select<E: EmulationConfig<F>>(
        &mut self,
        b: BoolVar,
        point0: &EmulatedPointVariable<E>,
        point1: &EmulatedPointVariable<E>,
    ) -> Result<EmulatedPointVariable<E>, CircuitError> {
        let select_x = self.conditional_select_emulated(b, &point0.0, &point1.0)?;
        let select_y = self.conditional_select_emulated(b, &point0.1, &point1.1)?;

        Ok(EmulatedPointVariable::<E>(select_x, select_y))
    }

    /// Constrain two emulated point variables to be the same.
    /// Return error if the input point variables are invalid.
    pub fn enforce_emulated_point_equal<E: EmulationConfig<F>>(
        &mut self,
        point0: &EmulatedPointVariable<E>,
        point1: &EmulatedPointVariable<E>,
    ) -> Result<(), CircuitError> {
        self.enforce_emulated_var_equal(&point0.0, &point1.0)?;
        self.enforce_emulated_var_equal(&point0.1, &point1.1)?;
        Ok(())
    }

    /// Obtain a bool variable representing whether two input emulated point
    /// variables are equal. Return error if variables are invalid.
    pub fn is_emulated_point_equal<E: EmulationConfig<F>>(
        &mut self,
        point0: &EmulatedPointVariable<E>,
        point1: &EmulatedPointVariable<E>,
    ) -> Result<BoolVar, CircuitError> {
        let mut r0 = self.is_emulated_var_equal(&point0.0, &point1.0)?;
        let r1 = self.is_emulated_var_equal(&point0.1, &point1.1)?;
        r0.0 = self.mul(r0.0, r1.0)?;
        Ok(r0)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        gadgets::{
            ecc::{Point, SWToTEConParam},
            EmulationConfig,
        },
        Circuit, PlonkCircuit,
    };
    use ark_bls12_377::{g1::Config as Param377, Fq as Fq377};
    use ark_bn254::Fr as Fr254;
    use ark_ec::{
        short_weierstrass::{Projective, SWCurveConfig},
        CurveGroup, Group,
    };
    use ark_ff::PrimeField;
    use ark_std::UniformRand;

    #[test]
    fn test_emulated_point_select() {
        test_emulated_point_select_helper::<Fq377, Fr254, Param377>();
    }

    fn test_emulated_point_select_helper<E, F, P>()
    where
        E: EmulationConfig<F> + SWToTEConParam,
        F: PrimeField,
        P: SWCurveConfig<BaseField = E>,
    {
        let mut rng = jf_utils::test_rng();
        let p1 = Projective::<P>::rand(&mut rng).into_affine();
        let p2 = Projective::<P>::rand(&mut rng).into_affine();
        let p1: Point<E> = (&p1).into();
        let p2: Point<E> = (&p2).into();

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let var_p1 = circuit.create_emulated_point_variable(p1).unwrap();
        let var_p2 = circuit.create_emulated_point_variable(p2).unwrap();
        let b = circuit.create_boolean_variable(true).unwrap();
        let var_p3 = circuit
            .binary_emulated_point_vars_select(b, &var_p1, &var_p2)
            .unwrap();
        assert_eq!(circuit.emulated_point_witness(&var_p3).unwrap(), p2);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(var_p3.0 .0[0]) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_enforce_emulated_point_eq() {
        test_enforce_emulated_point_eq_helper::<Fq377, Fr254, Param377>();
    }

    fn test_enforce_emulated_point_eq_helper<E, F, P>()
    where
        E: EmulationConfig<F> + SWToTEConParam,
        F: PrimeField,
        P: SWCurveConfig<BaseField = E>,
    {
        let mut rng = jf_utils::test_rng();
        let p1 = Projective::<P>::rand(&mut rng).into_affine();
        let p2 = (p1 + Projective::<P>::generator()).into_affine();
        let p1: Point<E> = (&p1).into();
        let p2: Point<E> = (&p2).into();

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let var_p1 = circuit.create_emulated_point_variable(p1).unwrap();
        let var_p2 = circuit.create_emulated_point_variable(p2).unwrap();
        let var_p3 = circuit.create_emulated_point_variable(p1).unwrap();
        circuit
            .enforce_emulated_point_equal(&var_p1, &var_p3)
            .unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        circuit
            .enforce_emulated_point_equal(&var_p1, &var_p2)
            .unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
