//! This is Translucence's implementation of various cryptography primitives, as
//! well as the plonk circuit implementation of those primitives.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(warnings)]
#![deny(missing_docs)]
#[cfg(test)]
extern crate std;

#[macro_use]
extern crate derivative;

pub mod aead;
pub mod circuit;
pub mod commitment;
pub mod constants;
pub mod elgamal;
pub mod errors;
pub mod merkle_tree;
pub mod prf;
pub mod schnorr_dsa;

pub(crate) mod utils;
