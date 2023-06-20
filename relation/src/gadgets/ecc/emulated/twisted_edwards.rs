// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Twisted Edwards curve point addition

use super::EmulatedPointVariable;
use crate::{
    errors::CircuitError,
    gadgets::{ecc::Point, EmulationConfig},
    PlonkCircuit,
};
use ark_ff::PrimeField;

impl<F: PrimeField> PlonkCircuit<F> {
    /// Constrain variable `c` to be the point addition of `a` and
    /// `b` over an elliptic curve.
    pub fn emulated_te_ecc_add_gate<E: EmulationConfig<F>>(
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
    pub fn emulated_te_ecc_add<E: EmulationConfig<F>>(
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
        self.emulated_te_ecc_add_gate(a, b, &c, d)?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        gadgets::{
            ecc::{conversion::*, Point},
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
    use ark_std::UniformRand;

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
        let p1 = Projective::<P>::rand(&mut rng).into_affine();
        let p2 = Projective::<P>::rand(&mut rng).into_affine();
        let p3: Point<E> = (&(p1 + p2).into_affine()).into();
        let fail_p3: Point<E> = (&(p1 + p2 + Projective::<P>::generator()).into_affine()).into();
        let p1: Point<E> = (&p1).into();
        let p2: Point<E> = (&p2).into();

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let var_p1 = circuit.create_emulated_point_variable(p1).unwrap();
        let var_p2 = circuit.create_emulated_point_variable(p2).unwrap();
        let var_p3 = circuit.emulated_te_ecc_add(&var_p1, &var_p2, d).unwrap();
        assert_eq!(circuit.emulated_point_witness(&var_p3).unwrap(), p3);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        let var_fail_p3 = circuit.create_emulated_point_variable(fail_p3).unwrap();
        circuit
            .emulated_te_ecc_add_gate(&var_p1, &var_p2, &var_fail_p3, d)
            .unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
