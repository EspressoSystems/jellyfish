// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A Rust Implementation of the Plonk ZKP System and Extensions.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#[cfg(test)]
extern crate std;

#[macro_use]
extern crate derivative;

/// Customized circuit
pub mod circuit;
pub mod constants;
pub mod errors;
pub mod proof_system;
pub mod transcript;

pub use jf_relation::PlonkType;

#[cfg(feature = "test_apis")]
pub mod testing_apis;
