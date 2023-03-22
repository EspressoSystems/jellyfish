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
use ark_std::rand::{self, rngs::StdRng};
pub use ark_std::vec::Vec;

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

pub fn test_rng() -> StdRng {
    use rand::SeedableRng;
    // arbitrary seed
    let seed = [
        1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    StdRng::from_seed(seed)
}
