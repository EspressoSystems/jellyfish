// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Short Weierstrass curve point addition

use super::EmulatedTEPointVariable;
use crate::{
    errors::CircuitError,
    gadgets::{ecc::TEPoint, EmulationConfig},
    PlonkCircuit,
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

impl<F: PrimeField> PlonkCircuit<F> {
    /// Constrain variable `c` to be the point addition of `a` and
    /// `b` over an elliptic curve.
    /// Let a = (x1, y1), b = (x2, y2), c = (x3, y3)
    /// The addition formula for affine points of sw curve is
    ///   1. if a == b
    ///     - if y1 == 0 then (x3, y3) = (0, 0)
    ///     - Calculate s = (3 * x1^2 + d) / (2 * y1)
    ///     - x3 = s^2 - 2 * x1
    ///     - y3 = s(x1 - x3) - y1
    ///   2. Otherwise
    ///     - if x1 == x2 then (x3, y3) = (0, 0)
    ///     - Calculate s = (y1 - y2) / (x1 - x2)
    ///     - x3 = s^2 - x1 - x2
    ///     - y3 = s(x1 - x3) - y1
    /// The first case is equivalent to the following:
    ///   - (x3 + 2 * x1) * (y1 + y1) * y1 = (3* x_1^2 + d)^2 * y1
    ///   - (y3 + y1) * 2 * y1 * y1 = (3* x_1^2 + d) (x1 - x3) * y1
    ///   - not_equal(x1, x2) || not_equal(y1, y2) || not_zero(y1) || ((x3 == 0)
    ///     && (y3 == 0))
    /// The second case is equivalent to the following:
    ///   - (x1 - x2)^3 (x1 + x2 + x3) == (x1 - x2) (y1 - y2)^2
    ///   - (x1 - x2) (x1 - x3) (y1 - y2) == (y1 + y3) (x1 - x2)^2
    ///   - not_equal(x1, x2) || is_equal(y1, y2) || ((x3 == 0) && (y3 == 0))
    /// TODO: unfinished
    pub fn emulated_sw_ecc_add_gate<E: EmulationConfig<F>>(
        &mut self,
        _a: &EmulatedTEPointVariable<E>,
        _b: &EmulatedTEPointVariable<E>,
        _c: &EmulatedTEPointVariable<E>,
        _d: E,
    ) -> Result<(), CircuitError> {
        todo!()
    }

    /// Obtain a variable to the point addition result of `a` + `b`
    pub fn emulated_sw_ecc_add<E: EmulationConfig<F>>(
        &mut self,
        a: &EmulatedTEPointVariable<E>,
        b: &EmulatedTEPointVariable<E>,
        d: E,
    ) -> Result<EmulatedTEPointVariable<E>, CircuitError> {
        let x1 = self.emulated_witness(&a.0)?;
        let y1 = self.emulated_witness(&a.1)?;
        let x2 = self.emulated_witness(&b.0)?;
        let y2 = self.emulated_witness(&b.1)?;
        let (x3, y3) = if x1 == x2 && y1 == y2 {
            // point doubling
            if y1.is_zero() {
                (E::zero(), E::zero())
            } else {
                let s = (x1 * x1 * E::from(3u64) + d) / (y1 + y1);
                let x3 = s * s - x1 - x2;
                let y3 = s * (x1 - x3) - y1;
                (x3, y3)
            }
        } else {
            // point addition
            if x1 == x2 {
                (E::zero(), E::zero())
            } else {
                let s = (y1 - y2) / (x1 - x2);
                let x3 = s * s - x1 - x2;
                let y3 = s * (x1 - x3) - y1;
                (x3, y3)
            }
        };
        let c = self.create_emulated_te_point_variable(TEPoint(x3, y3))?;
        // self.emulated_sw_ecc_add_gate(a, b, &c, d)?;
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

    fn test_emulated_sw_point_addition_helper<E, F, P>(d: E)
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

        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let var_p1 = circuit
            .create_emulated_te_point_variable(p1.into())
            .unwrap();
        let var_p2 = circuit
            .create_emulated_te_point_variable(p2.into())
            .unwrap();
        let var_result = circuit.emulated_sw_ecc_add(&var_p1, &var_p2, d).unwrap();
        assert_eq!(
            circuit.emulated_te_point_witness(&var_result).unwrap(),
            expected
        );
        let var_neutral = circuit
            .create_emulated_te_point_variable(neutral.into())
            .unwrap();
        let var_neutral_result1 = circuit
            .emulated_sw_ecc_add(&var_p1, &var_neutral, d)
            .unwrap();
        let var_neutral_result2 = circuit
            .emulated_sw_ecc_add(&var_neutral, &var_p1, d)
            .unwrap();
        assert_eq!(
            circuit
                .emulated_te_point_witness(&var_neutral_result1)
                .unwrap(),
            p1.into()
        );
        assert_eq!(
            circuit
                .emulated_te_point_witness(&var_neutral_result2)
                .unwrap(),
            p2.into()
        );
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // let var_p4 = circuit.emulated_sw_ecc_add(&wrong_result)

        // fail path
        let var_wrong_result = circuit
            .create_emulated_te_point_variable(wrong_result)
            .unwrap();
        circuit
            .emulated_sw_ecc_add_gate(&var_p1, &var_p2, &var_wrong_result, d)
            .unwrap();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
