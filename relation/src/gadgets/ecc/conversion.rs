// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! this file implements the conversion logic for elliptic curve point between
//! - short Weierstrass form
//! - twisted Edwards form
//!
//! Note that the APIs below create no circuits.
//! An entity should either know both the SW and TE form of a
//! point; or know none of the two. There is no need to generate
//! a circuit for arguing secret knowledge of one form while
//! the other form is public. In practice a prover will convert all of the
//! points to the TE form and work on the TE form inside the circuits.

use super::Point;
use ark_ec::short_weierstrass::{Affine as SWAffine, SWCurveConfig as SWParam};
use ark_ff::{BigInteger256, BigInteger384, BigInteger768, PrimeField};

impl<F, P> From<&SWAffine<P>> for Point<F>
where
    F: PrimeField + SWToTEConParam,
    P: SWParam<BaseField = F>,
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

        // safe unwrap
        let s = F::from(F::S);
        let neg_alpha = F::from(F::NEG_ALPHA);
        let beta = F::from(F::BETA);

        // we first transform the Weierstrass point (px, py) to Montgomery point (mx,
        // my) where mx = s * (px - alpha)
        // my = s * py
        let montgomery_x = s * (p.x + neg_alpha);
        let montgomery_y = s * p.y;
        // then we transform the Montgomery point (mx, my) to TE point (ex, ey) where
        // ex = beta * mx / my
        // ey = (mx - 1) / (mx + 1)
        let edwards_x = beta * montgomery_x / montgomery_y;
        let edwards_y = (montgomery_x - F::one()) / (montgomery_x + F::one());

        Point(edwards_x, edwards_y)
    }
}

/// This trait holds constants that are used for curve conversion from
/// short Weierstrass form to twisted Edwards form.
pub trait SWToTEConParam: PrimeField {
    /// Parameter S.
    const S: Self::BigInt;
    /// Parameter 1/alpha.
    const NEG_ALPHA: Self::BigInt;
    /// Parameter beta.
    const BETA: Self::BigInt;
}

// ================================================
// BLS12-377::Fq specific implementations
// ================================================
use ark_bls12_377::Fq as Fq377;
impl SWToTEConParam for Fq377 {
    // s = 10189023633222963290707194929886294091415157242906428298294512798502806398782149227503530278436336312243746741931
    const S: Self::BigInt = BigInteger384::new([
        0x3401d618f0339eab,
        0x0f793b8504b428d4,
        0x0ff643cca95ccc0d,
        0xd7a504665d66cc8c,
        0x1dc07a44b1eeea84,
        0x10f272020f118a,
    ]);

    // alpha = -1
    const NEG_ALPHA: Self::BigInt = BigInteger384::new([1, 0, 0, 0, 0, 0]);

    // beta = 23560188534917577818843641916571445935985386319233886518929971599490231428764380923487987729215299304184915158756
    const BETA: Self::BigInt = BigInteger384::new([
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
    const S: Self::BigInt = BigInteger256::new([0, 0, 0, 0]);
    const NEG_ALPHA: Self::BigInt = BigInteger256::new([0, 0, 0, 0]);
    const BETA: Self::BigInt = BigInteger256::new([0, 0, 0, 0]);
}

// ================================================
// Bls12-381::Fq dummy implementations
// ================================================
use ark_bls12_381::Fq as Fq381;
/// Dummy implementation for trait bounds
impl SWToTEConParam for Fq381 {
    const S: Self::BigInt = BigInteger384::new([0, 0, 0, 0, 0, 0]);
    const NEG_ALPHA: Self::BigInt = BigInteger384::new([0, 0, 0, 0, 0, 0]);
    const BETA: Self::BigInt = BigInteger384::new([0, 0, 0, 0, 0, 0]);
}

// ================================================
// Bw6-761::Fq dummy implementations
// ================================================
use ark_bw6_761::Fq as Fq761;
/// Dummy implementation for trait bounds
impl SWToTEConParam for Fq761 {
    const S: Self::BigInt = BigInteger768::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const NEG_ALPHA: Self::BigInt = BigInteger768::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const BETA: Self::BigInt = BigInteger768::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::{G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{MontFp, One};
    use ark_std::{UniformRand, Zero};
    use jf_utils::test_rng;

    // a helper function to check if a point is on the ed curve
    // of bls12-377 G1
    fn is_on_bls12_377_ed_curve(p: &Point<Fq377>) -> bool {
        // Twisted Edwards curve 2: a * x² + y² = 1 + d * x² * y²
        let a = MontFp!("-1");
        let d = MontFp!("122268283598675559488486339158635529096981886914877139579534153582033676785385790730042363341236035746924960903179");

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
        let g1 = &G1Affine::generator();
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
}
