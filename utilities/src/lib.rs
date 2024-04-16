// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![cfg_attr(not(feature = "std"), no_std)]
// Temporarily allow warning for nightly compilation with [`displaydoc`].
#![allow(warnings)]
#[cfg(test)]
extern crate std;

#[cfg(any(not(feature = "std"), target_has_atomic = "ptr"))]
#[doc(hidden)]
extern crate alloc;

mod conversion;
pub mod hash_to_group;
mod macros;
mod multi_pairing;
pub mod par_utils;
pub mod reed_solomon_code;
mod serialize;

use ark_ec::twisted_edwards::TECurveConfig as Config;
use ark_ff::{Field, PrimeField};
use ark_std::{
    ops::Mul,
    rand::{self, rngs::StdRng},
    string::{String, ToString},
    vec::Vec,
};

pub use conversion::*;
#[allow(unused_imports)]
pub use macros::*;
pub use multi_pairing::*;
pub use serialize::*;

#[inline]
pub fn curve_cofactor<P: Config>() -> u64 {
    P::COFACTOR[0]
}

#[inline]
pub fn field_byte_len<F: PrimeField>() -> usize {
    ((F::MODULUS_BIT_SIZE + 7) / 8) as usize
}

#[inline]
pub fn field_bit_len<F: PrimeField>() -> usize {
    F::MODULUS_BIT_SIZE as usize
}

#[inline]
pub fn challenge_bit_len<F: PrimeField>() -> usize {
    // Our challenge is of size 248 bits
    // This is enough for a soundness error of 2^-128
    (field_byte_len::<F>() - 1) << 3
}

#[inline]
pub fn compute_len_to_next_multiple(len: usize, multiple: usize) -> usize {
    if len % multiple == 0 {
        len
    } else {
        len + multiple - len % multiple
    }
}

// Pad message with 0 until `msg` is multiple of `multiple`
#[inline]
pub fn pad_with_zeros<F: Field>(vec: &mut Vec<F>, multiple: usize) {
    let len = vec.len();
    let new_len = compute_len_to_next_multiple(len, multiple);
    vec.resize(new_len, F::zero())
}

/// Compute the hadamard product of two vectors (of equal length).
#[inline]
pub fn hadamard_product<T, B>(a: impl AsRef<[T]>, b: impl AsRef<[B]>) -> Result<Vec<B>, String>
where
    B: for<'a> Mul<&'a T, Output = B> + Copy,
{
    let (a, b) = (a.as_ref(), b.as_ref());
    if a.len() != b.len() {
        return Err(
            "Cannot compute hadmard product of two vectors of different length".to_string(),
        );
    }

    let res: Vec<B> = a.iter().zip(b.iter()).map(|(ai, &bi)| bi * ai).collect();
    Ok(res)
}

pub fn test_rng() -> StdRng {
    use rand::SeedableRng;
    // arbitrary seed
    let seed = [
        1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    StdRng::from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;

    fn test_hadamard_template<Fr: PrimeField, G1: CurveGroup<ScalarField = Fr>>() {
        let mut rng = test_rng();
        for _ in 0..10 {
            let a: Vec<Fr> = (0..20).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..20).map(|_| Fr::rand(&mut rng)).collect();

            let product = hadamard_product(&a, &b).unwrap();
            assert!(product.iter().enumerate().all(|(i, &c)| c == a[i] * b[i]));

            let c: Vec<Fr> = (0..21).map(|_| Fr::rand(&mut rng)).collect();
            assert!(hadamard_product(&a, &c).is_err());

            let d: Vec<G1> = (0..20).map(|_| G1::rand(&mut rng)).collect();
            let product = hadamard_product(&a, &d).unwrap();
            assert!(product.iter().enumerate().all(|(i, &c)| c == d[i] * a[i]));
        }
    }

    #[test]
    fn test_hadamard() {
        test_hadamard_template::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>();
        test_hadamard_template::<ark_bls12_377::Fr, ark_bls12_377::G1Projective>();
        test_hadamard_template::<ark_bn254::Fr, ark_bn254::G1Projective>();
    }
}
