// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements a simple wrapper of multi-pairing function

use ark_ec::PairingEngine;
use ark_std::vec::Vec;

/// A simple wrapper of multi-pairing function.
pub fn multi_pairing<E>(g1_elems: &[E::G1Affine], g2_elems: &[E::G2Affine]) -> E::Fqk
where
    E: PairingEngine,
{
    let inputs: Vec<(E::G1Prepared, E::G2Prepared)> = g1_elems
        .iter()
        .zip(g2_elems.iter())
        .map(|(g1, g2)| ((*g1).into(), (*g2).into()))
        .collect();

    E::product_of_pairings(&inputs)
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
    use ark_std::{test_rng, One, UniformRand};

    #[test]
    fn test_multi_pairing() {
        test_multi_pairing_helper::<Bn254>();
        test_multi_pairing_helper::<Bls12_377>();
        test_multi_pairing_helper::<Bls12_381>();
    }

    fn test_multi_pairing_helper<E: PairingEngine>() {
        let mut rng = test_rng();

        // generators with single pairing
        let g1 = E::G1Affine::prime_subgroup_generator();
        let g2 = E::G2Affine::prime_subgroup_generator();
        let gt = E::pairing(g1, g2);

        assert_eq!(multi_pairing::<E>(&[g1], &[g2]), gt);

        // random elements with single pairing
        let r1 = E::Fr::rand(&mut rng);
        let r2 = E::Fr::rand(&mut rng);
        let f1 = g1.mul(r1).into_affine();
        let f2 = g2.mul(r2).into_affine();
        let ft = E::pairing(f1, f2);

        assert_eq!(multi_pairing::<E>(&[f1], &[f2]), ft);

        // random multi pairing products
        let ht = gt * ft;
        assert_eq!(multi_pairing::<E>(&[g1, f1], &[g2, f2]), ht);

        // equality test
        assert_eq!(multi_pairing::<E>(&[g1, -g1], &[g2, g2]), E::Fqk::one());
    }
}
