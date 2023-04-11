// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![cfg_attr(not(test), no_std)]

mod conversion;
mod macros;
mod multi_pairing;
pub mod par_utils;
mod serialize;

use ark_ff::Field;
use ark_std::{
    convert::AsRef,
    marker::Copy,
    ops::Mul,
    rand::{self, rngs::StdRng},
    string::{String, ToString},
    vec::Vec,
};

pub use conversion::*;
pub use macros::*;
pub use multi_pairing::*;
pub use serialize::*;

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

/// Compute the hadmard product of two vectors (of equal length).
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

#[test]
fn test_hadamard() {
    use ark_bls12_381::{Fr, G1Projective};
    use ark_std::UniformRand;

    let mut rng = test_rng();
    for _ in 0..10 {
        let a: Vec<Fr> = (0..20).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..20).map(|_| Fr::rand(&mut rng)).collect();

        let product = hadamard_product(&a, &b).unwrap();
        assert!(product.iter().enumerate().all(|(i, &c)| c == a[i] * b[i]));

        let c: Vec<Fr> = (0..21).map(|_| Fr::rand(&mut rng)).collect();
        assert!(hadamard_product(&a, &c).is_err());

        let d: Vec<G1Projective> = (0..20).map(|_| G1Projective::rand(&mut rng)).collect();
        let product = hadamard_product(&a, &d).unwrap();
        assert!(product.iter().enumerate().all(|(i, &c)| c == d[i] * a[i]));
    }
}
