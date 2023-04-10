// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Module for erasure code

use crate::errors::PrimitivesError;
use ark_std::vec::Vec;

pub mod reed_solomon_erasure;

/// Erasure code trait
/// `T` is the input data type
pub trait ErasureCode<T>: Sized {
    /// Type for each data shards
    type Shard;

    /// Encoding
    fn encode(&self, data: &[T]) -> Result<Vec<Self::Shard>, PrimitivesError>;

    /// Decoding
    fn decode(&self, shards: &[Self::Shard]) -> Result<Vec<T>, PrimitivesError>;
}
