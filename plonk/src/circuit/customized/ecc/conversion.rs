//! this file implements the conversion logic for elliptic curve point between
//! - short Weierstrass form
//! - twisted Edwards form
//!
//! Note that we should not really need to use this circuit though.
//! An entity should either know both the SW and TE form of a
//! point; or know none of the two. There is no need to generate
//! a circuit for arguing secret knowledge of one form while
//! the other form is public. In practice this means that we
//! will always be working on the TE forms.

use super::Point;
use ark_ec::{short_weierstrass_jacobian::GroupAffine as SWAffine, SWModelParameters as SWParam};
use ark_ff::{BigInteger256, BigInteger384, BigInteger768, PrimeField};

impl<F, P> From<&SWAffine<P>> for Point<F>
where
    F: PrimeField + SWToTEConParam,
    P: SWParam<BaseField = F> + Clone,
{
    fn from(p: &SWAffine<P>) -> Self {
        // this function is only correct for BLS12-377
        // (other curves does not impl an SW form)

        // if p is an infinity point
        // return infinity point
        if p.infinity {
            return Self(F::zero(), F::one());
        }

        // we need to firstly convert this point into
        // TE form, and then build the point
        // more details on the conversion:
        // https://www.notion.so/translucence/BLS12-377-Twisted-Edwards-parameters-47d988917fd540049ebb9e88b3b31d62#90838d24be764728a6dae1edf7d32c20

        // safe unwrap
        let s = F::from_repr(F::S).unwrap();
        let neg_alpha = F::from_repr(F::NEG_ALPHA).unwrap();
        let beta = F::from_repr(F::BETA).unwrap();

        let montgomery_x = s * (p.x + neg_alpha);
        let montgomery_y = s * p.y;
        let edwards_x = beta * montgomery_x / montgomery_y;
        let edwards_y = (montgomery_x - F::one()) / (montgomery_x + F::one());

        Point(edwards_x, edwards_y)
    }
}

/// constants that are used during the conversion from
/// short Weierstrass form to twisted Edwards form
pub trait SWToTEConParam: PrimeField {
    const S: Self::BigInt;
    const NEG_ALPHA: Self::BigInt;
    const BETA: Self::BigInt;
}

// impl<F> PlonkCircuit<F>
// where
//     F: PrimeField + SWToTEConParam,
// {
//     // Input an affine curve point in the short Weierstrass form,
//     // generate the circuit that converts this point into twisted
//     // Edwards form, and return the variables for the tE point.
//     // Cost: 2 constraints.
//     // Note that we should not really need to use this circuit though.
//     // An entity should either know both the SW and TE form of a
//     // point; or know none of the two. There is no need to generate
//     // a circuit for arguing secret knowledge of one form while
//     // the other form is public. In practice this means that we
//     // will always be working on the TE forms.
//     pub fn point_from_sw_form<P>(
//         &mut self,
//         sw_point: &SWAffine<P>,
//     ) -> Result<PointVariable, PlonkError>
//     where
//         P: SWParam<BaseField = F> + Clone,
//     {
//         let te_point: Point<F> = Point::from(sw_point);

//         // Case 1 if the point is the infinity point
//         let is_infinity = self.create_variable(F::from(sw_point.infinity))?;

//         // Case 2 if the point is not the infinity point
//         // We need to show
//         // 1. ex * py - beta * px + beta * alpha = 0
//         // 2. s * px * ey + (1-alpha*s) * ey - s * px + s*alpha + 1 = 0

//         // ================================================
//         // constants
//         // ================================================
//         // TODO(ZZ): pre-compute some of the data
//         // safe unwrap
//         let s = F::from_repr(F::S).unwrap();
//         let neg_alpha = F::from_repr(F::NEG_ALPHA).unwrap();
//         let alpha = -neg_alpha;
//         let beta = F::from_repr(F::BETA).unwrap();
//         let beta_alpha = beta * alpha;
//         let s_alpha_1 = s * alpha + F::one();
//         let one_alpha_s = F::one() + neg_alpha * s;

//         // ================================================
//         // variables
//         // ================================================
//         let ex = self.create_variable(te_point.0)?;
//         let ey = self.create_variable(te_point.1)?;
//         let px = self.create_variable(sw_point.x)?;
//         let py = self.create_variable(sw_point.y)?;

//         // ================================================
//         // Eq.1 ex * py - beta * px + beta_alpha = 0
//         // ================================================
//         let wires = [ex, py, px, self.zero()];
//         let eq_1_output = self.gen_quad_poly(
//             &wires,
//             &[F::zero(), F::zero(), -beta, F::zero()],
//             &[F::one(), F::zero()],
//             beta_alpha,
//         )?;
//         let eq_1_output_is_zero = self.is_zero(eq_1_output)?;

//         // ================================================
//         // Eq.2 s * px * ey + one_alpha_s * ey - s * px + s_alpha_1 = 0
//         // ================================================
//         let wires = [px, ey, self.zero(), self.zero()];
//         let eq_2_output = self.gen_quad_poly(
//             &wires,
//             &[-s, one_alpha_s, F::zero(), F::zero()],
//             &[s, F::zero()],
//             s_alpha_1,
//         )?;
//         let eq_2_output_is_zero = self.is_zero(eq_2_output)?;

//         // Final step, either case 1 or case 2 holds
//         // either
//         //  is_infinity = true
//         // or
//         //  eq_1_output_is_zero = true && eq_2_output_is_zero = true
//         let eq_1_and_eq_2 = self.logic_and(eq_1_output_is_zero,
// eq_2_output_is_zero)?;         self.logic_or_gate(eq_1_and_eq_2,
// is_infinity)?;

//         Ok(PointVariable(ex, ey))
//     }
// }

// ================================================
// BLS12-377::Fq specific implementations
// ================================================
use ark_bls12_377::Fq as Fq377;
impl SWToTEConParam for Fq377 {
    // constants obtained from:
    // https://www.notion.so/translucence/BLS12-377-Twisted-Edwards-parameters-47d988917fd540049ebb9e88b3b31d62#90838d24be764728a6dae1edf7d32c20

    // s = 10189023633222963290707194929886294091415157242906428298294512798502806398782149227503530278436336312243746741931
    const S: Self::BigInt = BigInteger384([
        0x3401d618f0339eab,
        0x0f793b8504b428d4,
        0x0ff643cca95ccc0d,
        0xd7a504665d66cc8c,
        0x1dc07a44b1eeea84,
        0x10f272020f118a,
    ]);

    // alpha = -1
    const NEG_ALPHA: Self::BigInt = BigInteger384([1, 0, 0, 0, 0, 0]);

    // beta = 23560188534917577818843641916571445935985386319233886518929971599490231428764380923487987729215299304184915158756
    const BETA: Self::BigInt = BigInteger384([
        0x450ae9206343e6e4,
        0x7af39509df5027b6,
        0xab82b31405cf8a30,
        0x80d743e1f6c15c7c,
        0x0cec22e650360183,
        0x272fd56ac5c669,
    ]);
}

// ================================================
// Bn254::Fq dummy implementations
// ================================================
use ark_bn254::Fq as Fq254;
/// Dummy implementation for trait bounds
impl SWToTEConParam for Fq254 {
    const S: Self::BigInt = BigInteger256([0, 0, 0, 0]);
    const NEG_ALPHA: Self::BigInt = BigInteger256([0, 0, 0, 0]);
    const BETA: Self::BigInt = BigInteger256([0, 0, 0, 0]);
}

// ================================================
// Bls12-381::Fq dummy implementations
// ================================================
use ark_bls12_381::Fq as Fq381;
/// Dummy implementation for trait bounds
impl SWToTEConParam for Fq381 {
    const S: Self::BigInt = BigInteger384([0, 0, 0, 0, 0, 0]);
    const NEG_ALPHA: Self::BigInt = BigInteger384([0, 0, 0, 0, 0, 0]);
    const BETA: Self::BigInt = BigInteger384([0, 0, 0, 0, 0, 0]);
}

// ================================================
// Bw6-761::Fq dummy implementations
// ================================================
use ark_bw6_761::Fq as Fq761;
/// Dummy implementation for trait bounds
impl SWToTEConParam for Fq761 {
    const S: Self::BigInt = BigInteger768([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const NEG_ALPHA: Self::BigInt = BigInteger768([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const BETA: Self::BigInt = BigInteger768([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::{G1Affine, G1Projective};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{field_new, One};
    use ark_std::{test_rng, UniformRand, Zero};

    // a helper function to check if a point is on the ed curve
    // of bls12-377 G1
    fn is_on_bls12_377_ed_curve(p: &Point<Fq377>) -> bool {
        // Twisted Edwards curve 2: a * x² + y² = 1 + d * x² * y²
        let a = field_new!(Fq377, "-1");
        let d = field_new!(Fq377, "122268283598675559488486339158635529096981886914877139579534153582033676785385790730042363341236035746924960903179");

        let x2 = p.0 * p.0;
        let y2 = p.1 * p.1;

        let left = a * x2 + y2;
        let right = Fq377::one() + d * x2 * y2;

        left == right
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_sw_to_te_conversion() {
        let mut rng = test_rng();

        // test generator
        let g1 = &G1Affine::prime_subgroup_generator();
        let p: Point<Fq377> = g1.into();
        assert!(is_on_bls12_377_ed_curve(&p));

        // test zero point
        let g1 = &G1Affine::zero();
        let p: Point<Fq377> = g1.into();
        assert_eq!(p.0, Fq377::zero());
        assert_eq!(p.1, Fq377::one());
        assert!(is_on_bls12_377_ed_curve(&p));

        // test a random group element
        let g1 = &G1Projective::rand(&mut rng).into_affine();
        let p: Point<Fq377> = g1.into();
        assert!(is_on_bls12_377_ed_curve(&p));
    }

    // #[allow(non_snake_case)]
    // #[test]
    // fn test_SW_to_TE_circuit() {
    //     let mut circuit: PlonkCircuit<Fq> = PlonkCircuit::new(TurboPlonk);
    //     let mut rng = test_rng();

    //     // test generator
    //     let g1 = &G1Affine::prime_subgroup_generator();
    //     let p: Point<Fq> = g1.into();
    //     let p_var = circuit.point_from_sw_form(g1).unwrap();

    //     assert!(is_on_bls12_377_ed_curve(&p));
    //     assert_eq!(circuit.witness(p_var.0).unwrap(), p.0);
    //     assert_eq!(circuit.witness(p_var.1).unwrap(), p.1);
    //     assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

    //     // test zero point
    //     let g1 = &G1Affine::zero();
    //     let p: Point<Fq> = g1.into();
    //     assert_eq!(p.0, Fq::zero());
    //     assert_eq!(p.1, Fq::one());
    //     let p_var = circuit.point_from_sw_form(g1).unwrap();

    //     assert!(is_on_bls12_377_ed_curve(&p));
    //     assert_eq!(circuit.witness(p_var.0).unwrap(), p.0);
    //     assert_eq!(circuit.witness(p_var.1).unwrap(), p.1);
    //     assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

    //     // test a random group element
    //     let g1 = &G1Projective::rand(&mut rng).into_affine();
    //     let p: Point<Fq> = g1.into();
    //     let p_var = circuit.point_from_sw_form(g1).unwrap();

    //     // good path
    //     assert!(is_on_bls12_377_ed_curve(&p));
    //     assert_eq!(circuit.witness(p_var.0).unwrap(), p.0);
    //     assert_eq!(circuit.witness(p_var.1).unwrap(), p.1);
    //     assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

    //     // bad path: wrong witness should fail
    //     let witness = circuit.witness(p_var.0).unwrap();
    //     *circuit.witness_mut(p_var.0) = Fq::rand(&mut rng);
    //     assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    //     *circuit.witness_mut(p_var.0) = witness;
    // }
}
