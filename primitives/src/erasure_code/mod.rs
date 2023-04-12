// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Module for erasure code

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, vec::Vec};

use crate::errors::PrimitivesError;

pub mod reed_solomon_erasure;

/// Erasure code trait
/// `T` is the input data type
pub trait ErasureCode<T> {
    /// Type for each data shares (usually depends on `T`)
    /// Why so many trait bounds on `Share`? <https://github.com/rust-lang/rust/issues/20671>
    type Share: Debug
        + Clone
        + Eq
        + PartialEq
        + Sync
        + Send
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Encode `data` into `data.len() + parity_size` shares.
    fn encode(data: &[T], parity_size: usize) -> Result<Vec<Self::Share>, PrimitivesError>;

    /// Decode `shares` into `data_size` data elements.
    /// Return `Result::Err` if `shares.len() < data_size`.
    fn decode(shares: &[Self::Share], data_size: usize) -> Result<Vec<T>, PrimitivesError>;
}
