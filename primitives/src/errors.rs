// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Error types.

use crate::rescue::errors::RescueError;
use ark_serialize::SerializationError;
use ark_std::{
    format,
    string::{String, ToString},
};
use blst::BLST_ERROR;
use displaydoc::Display;

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
    DeserializationError(SerializationError),
    /// Decryption failed: {0}
    FailedDecryption(String),
    /// Rescue Error: {0}
    RescueError(RescueError),
    /// Inconsistent Structure error, {0}
    InconsistentStructureError(String),
}

impl From<RescueError> for PrimitivesError {
    fn from(e: RescueError) -> Self {
        Self::RescueError(e)
    }
}

impl From<SerializationError> for PrimitivesError {
    fn from(e: SerializationError) -> Self {
        Self::DeserializationError(e)
    }
}

impl From<BLST_ERROR> for PrimitivesError {
    fn from(e: BLST_ERROR) -> Self {
        match e {
            BLST_ERROR::BLST_SUCCESS => {
                Self::InternalError("Expecting an error, but got a sucess.".to_string())
            },
            BLST_ERROR::BLST_VERIFY_FAIL => Self::VerificationError(format!("{e:?}")),
            _ => Self::ParameterError(format!("{e:?}")),
        }
    }
}

impl ark_std::error::Error for PrimitivesError {}
