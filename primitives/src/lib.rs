// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Crate implements various cryptography primitives, as
//! well as the plonk circuit implementation of those primitives.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(warnings)]
#![deny(missing_docs)]
#[cfg(test)]
extern crate std;

#[macro_use]
extern crate derivative;

#[cfg(any(not(feature = "std"), target_has_atomic = "ptr"))]
#[doc(hidden)]
extern crate alloc;

pub mod aead;
pub mod circuit;
pub mod elgamal;
pub mod errors;
pub mod hash_to_group;
pub mod reed_solomon_code;
pub mod vid;
pub mod vrf;

// Re-exporting rescue
pub use jf_merkle_tree as merkle_tree;
pub use jf_rescue as rescue;

pub(crate) mod utils;
