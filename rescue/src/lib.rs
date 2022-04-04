// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![deny(missing_docs)]
//! This module implements Rescue hash function over the following fields
//! - bls12_377 base field
//! - ed_on_bls12_377 base field
//! - ed_on_bls12_381 base field
//! - ed_on_bn254 base field
//!
//! It also has place holders for
//! - bls12_381 base field
//! - bn254 base field
//! - bw6_761 base field
//!
//! Those three place holders should never be used.
#![deny(warnings)]
pub mod errors;
mod param;
mod permutation;
mod rescue_constants;
mod sponge;
mod structs;

pub use param::{RescueParameter, RATE, ROUNDS, STATE_SIZE};
pub use permutation::{Permutation, PRP};
pub use structs::*;

#[derive(Clone, Default)]
/// A rescue hash function consists of a permutation function and
/// an internal state.
pub struct RescueHash<F: RescueParameter> {
    pub(crate) state: RescueVector<F>,
    pub(crate) permutation: Permutation<F>,
}
