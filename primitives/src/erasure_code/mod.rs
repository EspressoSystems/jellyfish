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
pub trait ErasureCode<F: Field>: Sized {
    /// Type for each data shards
    type Shard: Debug
        + Clone
        + Eq
        + PartialEq
        + Sync
        + Send
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Create a new instance
    ///  * `reconstruction_size`: and the minimum number of shards required for
    ///    reconstruction
    ///  * `num_shards`: the block (codeword) length
    /// TODO should we allow constructors at the trait level?
    fn new(reconstruction_size: usize, num_shards: usize) -> Result<Self, PrimitivesError>;

    /// Encoding
    fn encode(&self, data: &[F]) -> Result<Vec<Self::Shard>, PrimitivesError>;

    /// Decoding
    fn decode(&self, shards: &[Self::Shard]) -> Result<Vec<F>, PrimitivesError>;
}
