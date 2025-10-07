// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.
//! Error types

use ark_std::string::String;
use displaydoc::Display;
use jf_poseidon2::Poseidon2Error;
use jf_rescue::RescueError;

/// Error type for Merkle tree
#[derive(Debug, Display, Eq, PartialEq)]
pub enum MerkleTreeError {
    /// Parameters error, {0}
    ParametersError(String),
    /// Queried leaf isn't in this Merkle tree
    NotFound,
    /// Queried leaf is already occupied.
    ExistingLeaf,
    /// Queried leaf is forgotten.
    ForgottenLeaf,
    /// Merkle tree is already full.
    ExceedCapacity,
    /// Digest error, {0}
    DigestError(String),
    /// Inconsistent Structure error, {0}
    InconsistentStructureError(String),
}

impl ark_std::error::Error for MerkleTreeError {}

impl From<RescueError> for MerkleTreeError {
    fn from(err: RescueError) -> Self {
        MerkleTreeError::DigestError(ark_std::format!("{}", err))
    }
}

impl From<Poseidon2Error> for MerkleTreeError {
    fn from(err: Poseidon2Error) -> Self {
        MerkleTreeError::DigestError(ark_std::format!("{}", err))
    }
}
