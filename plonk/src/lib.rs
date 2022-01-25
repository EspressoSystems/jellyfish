#![cfg_attr(not(feature = "std"), no_std)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Enum for each type of Plonk scheme
pub enum PlonkType {
    /// TurboPlonk
    TurboPlonk,
    /// TurboPlonk that supports Plookup
    UltraPlonk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Enum for each type of mergeable circuit
pub enum MergeableCircuitType {
    TypeA,
    TypeB,
}
