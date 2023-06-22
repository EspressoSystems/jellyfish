// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Twisted Edwards curve point addition

use crate::{
    errors::CircuitError,
    gadgets::{ecc::TEPoint, EmulatedVariable, EmulationConfig},
    BoolVar, Circuit, PlonkCircuit,
};
use ark_ff::PrimeField;

/// The variable represents an TE point in the emulated field.
#[derive(Debug, Clone)]
pub struct EmulatedTEPointVariable<E: PrimeField>(pub EmulatedVariable<E>, pub EmulatedVariable<E>);

impl<F: PrimeField> PlonkCircuit<F> {
    /// Return the witness point
    pub fn emulated_te_point_witness<E: EmulationConfig<F>>(
        &self,
        point_var: &EmulatedTEPointVariable<E>,
    ) -> Result<TEPoint<E>, CircuitError> {
        let x = self.emulated_witness(&point_var.0)?;
        let y = self.emulated_witness(&point_var.1)?;
        Ok(TEPoint(x, y))
    }

    /// Add a new emulated EC point (as witness)
    pub fn create_emulated_te_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: TEPoint<E>,
    ) -> Result<EmulatedTEPointVariable<E>, CircuitError> {
        let x = self.create_emulated_variable(point.0)?;
        let y = self.create_emulated_variable(point.1)?;
        Ok(EmulatedTEPointVariable(x, y))
    }

    /// Add a new constant emulated EC point
    pub fn create_constant_emulated_te_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: TEPoint<E>,
    ) -> Result<EmulatedTEPointVariable<E>, CircuitError> {
        let x = self.create_constant_emulated_variable(point.0)?;
        let y = self.create_constant_emulated_variable(point.1)?;
        Ok(EmulatedTEPointVariable(x, y))
    }

    /// Add a new public emulated EC point
    pub fn create_public_emulated_te_point_variable<E: EmulationConfig<F>>(
        &mut self,
        point: TEPoint<E>,
    ) -> Result<EmulatedTEPointVariable<E>, CircuitError> {
        let x = self.create_public_emulated_variable(point.0)?;
        let y = self.create_public_emulated_variable(point.1)?;
        Ok(EmulatedTEPointVariable(x, y))
    }

    /// Obtain an emulated point variable of the conditional selection from 2
    /// emulated point variables. `b` is a boolean variable that indicates
    /// selection of P_b from (P0, P1).
    /// Return error if invalid input parameters are provided.
    pub fn binary_emulated_te_point_vars_select<E: EmulationConfig<F>>(
        &mut self,
        b: BoolVar,
        point0: &EmulatedTEPointVariable<E>,
        point1: &EmulatedTEPointVariable<E>,
    ) -> Result<EmulatedTEPointVariable<E>, CircuitError> {
        let select_x = self.conditional_select_emulated(b, &point0.0, &point1.0)?;
        let select_y = self.conditional_select_emulated(b, &point0.1, &point1.1)?;

        Ok(EmulatedTEPointVariable::<E>(select_x, select_y))
    }

    /// Constrain two emulated point variables to be the same.
    /// Return error if the input point variables are invalid.
    pub fn enforce_emulated_te_point_equal<E: EmulationConfig<F>>(
        &mut self,
        point0: &EmulatedTEPointVariable<E>,
        point1: &EmulatedTEPointVariable<E>,
    ) -> Result<(), CircuitError> {
        self.enforce_emulated_var_equal(&point0.0, &point1.0)?;
        self.enforce_emulated_var_equal(&point0.1, &point1.1)?;
        Ok(())
    }

    /// Obtain a bool variable representing whether two input emulated point
    /// variables are equal. Return error if variables are invalid.
    pub fn is_emulated_te_point_equal<E: EmulationConfig<F>>(
        &mut self,
        point0: &EmulatedTEPointVariable<E>,
        point1: &EmulatedTEPointVariable<E>,
    ) -> Result<BoolVar, CircuitError> {
        let mut r0 = self.is_emulated_var_equal(&point0.0, &point1.0)?;
        let r1 = self.is_emulated_var_equal(&point0.1, &point1.1)?;
        r0.0 = self.mul(r0.0, r1.0)?;
        Ok(r0)
    }

    /// Constrain variable `c` to be the point addition of `a` and
    /// `b` over an elliptic curve.
    pub fn emulated_te_ecc_add_gate<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedTEPointVariable<E>,
        b: &EmulatedTEPointVariable<E>,
        c: &EmulatedTEPointVariable<E>,
        d: E,
    ) -> Result<(), CircuitError> {
        let x1y2 = self.emulated_mul(&a.0, &b.1)?;
        let x2y1 = self.emulated_mul(&b.0, &a.1)?;
        let x1x2 = self.emulated_mul(&a.0, &b.0)?;
        let y1y2 = self.emulated_mul(&a.1, &b.1)?;
        let x1x2y1y2 = self.emulated_mul(&x1x2, &y1y2)?;
        let dx1x2y1y2 = self.emulated_mul_constant(&x1x2y1y2, d)?;

        // checking that x3 = x1y2 + x2y1 - dx1y1x2y2x3
        // t1 = x1y2 + x2y1
        let t1 = self.emulated_add(&x1y2, &x2y1)?;
        // t2 = d x1 y1 x2 y2 x3
        let t2 = self.emulated_mul(&dx1x2y1y2, &c.0)?;
        self.emulated_add_gate(&c.0, &t2, &t1)?;

        // checking that y3 = x1x2 + y1y2 + dx1y1x2y2y3
        // t1 = x1x2 + y1y2
        let t1 = self.emulated_add(&x1x2, &y1y2)?;
        let t2 = self.emulated_mul(&dx1x2y1y2, &c.1)?;
        self.emulated_add_gate(&t1, &t2, &c.1)
    }

    /// Obtain a variable to the point addition result of `a` + `b`
    pub fn emulated_te_ecc_add<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedTEPointVariable<E>,
        b: &EmulatedTEPointVariable<E>,
        d: E,
    ) -> Result<EmulatedTEPointVariable<E>, CircuitError> {
        let x1 = self.emulated_witness(&a.0)?;
        let y1 = self.emulated_witness(&a.1)?;
        let x2 = self.emulated_witness(&b.0)?;
        let y2 = self.emulated_witness(&b.1)?;

        let t1 = x1 * y2;
        let t2 = x2 * y1;
        let dx1x2y1y2 = d * t1 * t2;

        let x3 = (t1 + t2) / (E::one() + dx1x2y1y2);
        let y3 = (x1 * x2 + y1 * y2) / (E::one() - dx1x2y1y2);
        let c = self.create_emulated_te_point_variable(TEPoint(x3, y3))?;
        self.emulated_te_ecc_add_gate(a, b, &c, d)?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        gadgets::{
            ecc::{conversion::*, TEPoint},
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
    use ark_ff::{MontFp, PrimeField};
    use ark_std::{UniformRand, Zero};

    #[test]
    fn test_emulated_te_point_addition() {
        let d : Fq377 = MontFp!("122268283598675559488486339158635529096981886914877139579534153582033676785385790730042363341236035746924960903179");
        test_emulated_te_point_addition_helper::<Fq377, Fr254, Param377>(d);
    }

    fn test_emulated_te_point_addition_helper<E, F, P>(d: E)
    where
        E: EmulationConfig<F> + SWToTEConParam,
        F: PrimeField,
        P: SWCurveConfig<BaseField = E>,
    {
        let mut rng = jf_utils::test_rng();
        let neutral = Projective::<P>::zero().into_affine();
        let p1 = Projective::<P>::rand(&mut rng).into_affine();
        let p2 = Projective::<P>::rand(&mut rng).into_affine();
        let expected: TEPoint<E> = (p1 + p2).into_affine().into();
        let wrong_result: TEPoint<E> = (p1 + p2 + Projective::<P>::generator())
            .into_affine()
            .into();
        let p1: TEPoint<E> = p1.into();
        let p2: TEPoint<E> = p2.into();

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let var_p1 = circuit.create_emulated_te_point_variable(p1).unwrap();
        let var_p2 = circuit.create_emulated_te_point_variable(p2).unwrap();
        let var_result = circuit.emulated_te_ecc_add(&var_p1, &var_p2, d).unwrap();
        assert_eq!(
            circuit.emulated_te_point_witness(&var_result).unwrap(),
            expected
        );
        let var_neutral = circuit
            .create_emulated_te_point_variable(neutral.into())
            .unwrap();
        let var_neutral_result = circuit
            .emulated_te_ecc_add(&var_p1, &var_neutral, d)
            .unwrap();
        assert_eq!(
            circuit
                .emulated_te_point_witness(&var_neutral_result)
                .unwrap(),
            p1
        );
        let var_neutral_result = circuit
            .emulated_te_ecc_add(&var_neutral, &var_p1, d)
            .unwrap();
        assert_eq!(
            circuit
                .emulated_te_point_witness(&var_neutral_result)
                .unwrap(),
            p1
        );
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        let var_wrong_result = circuit
            .create_emulated_te_point_variable(wrong_result)
            .unwrap();
        circuit
            .emulated_te_ecc_add_gate(&var_p1, &var_p2, &var_wrong_result, d)
            .unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

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

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let var_p1 = circuit
            .create_emulated_te_point_variable(p1.into())
            .unwrap();
        let var_p2 = circuit
            .create_emulated_te_point_variable(p2.into())
            .unwrap();
        let b = circuit.create_boolean_variable(true).unwrap();
        let var_p3 = circuit
            .binary_emulated_te_point_vars_select(b, &var_p1, &var_p2)
            .unwrap();
        assert_eq!(
            circuit.emulated_te_point_witness(&var_p3).unwrap(),
            p2.into()
        );
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

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let var_p1 = circuit
            .create_emulated_te_point_variable(p1.into())
            .unwrap();
        let var_p2 = circuit
            .create_emulated_te_point_variable(p2.into())
            .unwrap();
        let var_p3 = circuit
            .create_emulated_te_point_variable(p1.into())
            .unwrap();
        circuit
            .enforce_emulated_te_point_equal(&var_p1, &var_p3)
            .unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        circuit
            .enforce_emulated_te_point_equal(&var_p1, &var_p2)
            .unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
