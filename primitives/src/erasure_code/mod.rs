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
    /// Type for each data shards (usually depends on `T`)
    type Shard: Debug
        + Clone
        + Eq
        + PartialEq
        + Sync
        + Send
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Encoding
    fn encode(data: &[T], parity_size: usize) -> Result<Vec<Self::Shard>, PrimitivesError>;

    /// Decoding
    fn decode(shards: &[Self::Shard]) -> Result<Vec<T>, PrimitivesError>;
}
