// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A Rust Implementation of the Plonk ZKP System and Extensions.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![allow(clippy::derive_hash_xor_eq)]
#[cfg(test)]
extern crate std;

#[macro_use]
extern crate downcast_rs;

#[macro_use]
extern crate derivative;

pub mod circuit;
pub mod constants;
pub mod errors;
pub mod proof_system;
pub mod transcript;

#[cfg(feature = "test_apis")]
pub mod testing_apis;

/// crate prelude consisting important traits and structs
pub mod prelude {
    pub use crate::{
        circuit::{Arithmetization, Circuit, PlonkCircuit},
        errors::{PlonkError, SnarkError},
        proof_system::{structs::*, PlonkKzgSnark, Snark},
        transcript::{PlonkTranscript, StandardTranscript},
    };
}
