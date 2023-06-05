// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Elliptic curve related gates and gadgets for non-native fields

use super::Point;
use crate::{
    errors::CircuitError,
    gadgets::{EmulatedVariable, EmulationConfig},
    PlonkCircuit,
};
use ark_ff::PrimeField;

/// The variable represents an EC point in the emulated field.
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

    /// Constrain variable `c` to be the point addition of `a` and
    /// `b` over an elliptic curve.
    pub fn emulated_ecc_add_gate<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedPointVariable<E>,
        b: &EmulatedPointVariable<E>,
        c: &EmulatedPointVariable<E>,
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
    pub fn emulated_ecc_add<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedPointVariable<E>,
        b: &EmulatedPointVariable<E>,
        d: E,
    ) -> Result<EmulatedPointVariable<E>, CircuitError> {
        let x1 = self.emulated_witness(&a.0)?;
        let y1 = self.emulated_witness(&a.1)?;
        let x2 = self.emulated_witness(&b.0)?;
        let y2 = self.emulated_witness(&b.1)?;

        let t1 = x1 * y2;
        let t2 = x2 * y1;
        let dx1x2y1y2 = d * t1 * t2;

        let x3 = (t1 + t2) / (E::one() + dx1x2y1y2);
        let y3 = (x1 * x2 + y1 * y2) / (E::one() - dx1x2y1y2);
        let c = self.create_emulated_point_variable(Point(x3, y3))?;
        self.emulated_ecc_add_gate(a, b, &c, d)?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use crate::gadgets::ecc::{conversion::*, Point};
    use crate::gadgets::EmulationConfig;
    use crate::{Circuit, PlonkCircuit};
    use ark_bls12_377::{g1::Config as Param377, Fq as Fq377};
    use ark_bn254::Fr as Fr254;
    use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
    use ark_ec::CurveGroup;
    use ark_ff::{MontFp, PrimeField};
    use ark_std::UniformRand;

    #[test]
    fn test_emulated_point_addition() {
        let d : Fq377 = MontFp!("122268283598675559488486339158635529096981886914877139579534153582033676785385790730042363341236035746924960903179");
        test_emulated_point_addition_helper::<Fq377, Fr254, Param377>(d);
    }

    fn test_emulated_point_addition_helper<E, F, P>(d: E)
    where
        E: EmulationConfig<F> + SWToTEConParam,
        F: PrimeField,
        P: SWCurveConfig<BaseField = E>,
    {
        let mut rng = jf_utils::test_rng();
        let p1 = Projective::<P>::rand(&mut rng).into_affine();
        let p2 = Projective::<P>::rand(&mut rng).into_affine();
        let p3: Point<E> = (&(p1 + p2).into_affine()).into();
        let p1: Point<E> = (&p1).into();
        let p2: Point<E> = (&p2).into();

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let var_p1 = circuit.create_emulated_point_variable(p1).unwrap();
        let var_p2 = circuit.create_emulated_point_variable(p2).unwrap();
        let var_p3 = circuit.emulated_ecc_add(&var_p1, &var_p2, d).unwrap();
        assert_eq!(circuit.emulated_point_witness(&var_p3).unwrap(), p3);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
    }
}
