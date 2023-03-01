// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements a simple wrapper of multi-pairing function

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_std::vec::Vec;

/// A simple wrapper of multi-pairing function.
pub fn multi_pairing<E>(g1_elems: &[E::G1Affine], g2_elems: &[E::G2Affine]) -> PairingOutput<E>
where
    E: Pairing,
{
    let (inputs_g1, inputs_g2): (Vec<E::G1Prepared>, Vec<E::G2Prepared>) = g1_elems
        .iter()
        .zip(g2_elems.iter())
        .map(|(g1, g2)| ((*g1).into(), (*g2).into()))
        .unzip();

    E::multi_pairing(inputs_g1, inputs_g2)
}

#[cfg(test)]
mod test {
    use crate::test_rng;

    use super::*;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_std::{One, UniformRand};

    #[test]
    fn test_multi_pairing() {
        test_multi_pairing_helper::<Bn254>();
        test_multi_pairing_helper::<Bls12_377>();
        test_multi_pairing_helper::<Bls12_381>();
    }

    fn test_multi_pairing_helper<E: Pairing>() {
        let mut rng = test_rng();

        // generators with single pairing
        let g1 = E::G1Affine::generator();
        let g2 = E::G2Affine::generator();
        let gt = E::pairing(g1, g2);

        assert_eq!(multi_pairing::<E>(&[g1], &[g2]), gt);

        // random elements with single pairing
        let r1 = E::ScalarField::rand(&mut rng);
        let r2 = E::ScalarField::rand(&mut rng);
        let f1 = (g1 * r1).into_affine();
        let f2 = (g2 * r2).into_affine();
        let ft = E::pairing(f1, f2);

        assert_eq!(multi_pairing::<E>(&[f1], &[f2]), ft);

        // random multi pairing products
        let ht = PairingOutput(gt.0 * ft.0);
        assert_eq!(multi_pairing::<E>(&[g1, f1], &[g2, f2]), ht);

        // equality test
        assert!(multi_pairing::<E>(
            &[g1, (g1 * -E::ScalarField::one()).into_affine()],
            &[g2, g2]
        )
        .0
        .is_one());
    }
}
