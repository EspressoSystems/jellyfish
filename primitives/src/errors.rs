// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Error types.

use ark_std::string::String;
use displaydoc::Display;
use jf_hashes::HashError;

/// A `enum` specifying the possible failure modes of the primitives.
#[derive(Debug, Display)]
pub enum PrimitivesError {
    /// Unsuccessful verification for proof or signature, {0}
    VerificationError(String),
    /// Bad parameter in function call, {0}
    ParameterError(String),
    #[rustfmt::skip]
    /// ‼ ️Internal error! Please report to Crypto Team immediately!\nMessage: {0}
    InternalError(String),
    /// Deserialization failed: {0}
    DeserializationError(String),
    /// Decryption failed: {0}
    FailedDecryption(String),
    /// Rescue Error: {0}
    HashError(HashError),
    /// Inconsistent Structure error, {0}
    InconsistentStructureError(String),
}

impl From<HashError> for PrimitivesError {
    fn from(e: HashError) -> Self {
        Self::HashError(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrimitivesError {}
