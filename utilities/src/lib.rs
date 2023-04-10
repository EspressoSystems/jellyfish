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
pub fn hadamard_product<T>(a: impl AsRef<[T]>, b: impl AsRef<[T]>) -> Result<Vec<T>, String>
where
    T: Mul<T, Output = T> + Copy,
{
    let (a, b) = (a.as_ref(), b.as_ref());
    if a.len() != b.len() {
        return Err(
            "Cannot compute hadmard product of two vectors of different length".to_string(),
        );
    }

    let res: Vec<T> = a.iter().zip(b.iter()).map(|(&ai, &bi)| ai * bi).collect();
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
    use ark_bls12_381::Fq;
    use ark_std::UniformRand;

    let mut rng = test_rng();
    for _ in 0..10 {
        let a: Vec<Fq> = (0..20).map(|_| Fq::rand(&mut rng)).collect();
        let b: Vec<Fq> = (0..20).map(|_| Fq::rand(&mut rng)).collect();

        let product = hadamard_product(&a, &b).unwrap();
        assert!(product.iter().enumerate().all(|(i, &c)| c == a[i] * b[i]));

        let c: Vec<Fq> = (0..21).map(|_| Fq::rand(&mut rng)).collect();
        assert!(hadamard_product(&a, &c).is_err());
    }
}
