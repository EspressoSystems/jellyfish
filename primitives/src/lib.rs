// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Crate implements various cryptography primitives, as
//! well as the plonk circuit implementation of those primitives.

#![cfg_attr(not(feature = "std"), no_std)]
// Temporarily allow warning for nightly compilation with [`displaydoc`].
#![allow(warnings)]
#![deny(missing_docs)]
#[cfg(test)]
extern crate std;

#[macro_use]
extern crate derivative;

#[cfg(any(not(feature = "std"), target_has_atomic = "ptr"))]
#[doc(hidden)]
extern crate alloc;

pub mod aead;
pub mod elgamal;
pub mod errors;
#[cfg(feature = "gadgets")]
pub mod gadgets;
pub mod vrf;

// Re-exporting rescue
pub use jf_merkle_tree as merkle_tree;
pub use jf_pcs as pcs;
pub use jf_rescue as rescue;
pub use jf_signature as signatures;
pub use jf_vdf as vdf;
pub use jf_vid as vid;

pub(crate) mod utils;
