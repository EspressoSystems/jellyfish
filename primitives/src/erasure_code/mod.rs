// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Module for erasure code

use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, vec::Vec};

pub mod reed_solomon_erasure;

/// Erasure code trait
pub trait ErasureCode: Sized {
    /// Associated field of the erasure code
    type Field: Field;
    /// Type for each data shards
    type Shards: Debug
        + Clone
        + Eq
        + PartialEq
        + Sync
        + Send
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Create a new instance
    ///  * data_len: the message length, and the minimum number of shards
    ///    required for reconstruction
    ///  * num_shards: the block (codeword) length
    fn new(data_len: usize, num_shards: usize) -> Result<Self, PrimitivesError>;

    /// Encoding
    fn encode(&self, data: &[Self::Field]) -> Result<Vec<Self::Shards>, PrimitivesError>;

    /// Decoding
    fn decode(&self, shards: &[Self::Shards]) -> Result<Vec<Self::Field>, PrimitivesError>;
}