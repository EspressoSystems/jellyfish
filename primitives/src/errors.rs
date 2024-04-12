// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Error types.

use ark_serialize::SerializationError;
use ark_std::{
    format,
    string::{String, ToString},
};
use displaydoc::Display;
use jf_rescue::RescueError;

/// A glorified [`bool`] that leverages compile lints to encourage the caller to
/// use the result.
///
/// Intended as the return type for verification of proofs, signatures, etc.
/// Recommended for use in the nested [`Result`] pattern: see <https://sled.rs/errors>.
pub type VerificationResult = Result<(), ()>;

/// A `enum` specifying the possible failure modes of the primitives.
#[derive(Debug, Display)]
pub enum PrimitivesError {
    /// Verify fail (proof, sig), {0} [DEPRECATED: use [`VerificationResult`]]
    VerificationError(String),
    /// Bad parameter in function call, {0}
    ParameterError(String),
    #[rustfmt::skip]
    /// ‼ ️Internal error! Please report to Crypto Team immediately!\nMessage: {0}
    InternalError(String),
    /// Deserialization failed: {0}
    DeserializationError(SerializationError),
    /// Decryption failed: {0}
    FailedDecryption(String),
    /// Rescue Error: {0}
    RescueError(RescueError),
    /// Inconsistent Structure error, {0}
    InconsistentStructureError(String),
}

impl From<SerializationError> for PrimitivesError {
    fn from(e: SerializationError) -> Self {
        Self::DeserializationError(e)
    }
}

impl ark_std::error::Error for PrimitivesError {}
