// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Error module.

use ark_std::{format, string::String};
use displaydoc::Display;
use jf_primitives::pcs::errors::PCSError;
use jf_relation::errors::CircuitError;

/// A `enum` specifying the possible failure modes of the Plonk.
#[derive(Display, Debug)]
pub enum PlonkError {
    /// The index is too large for the universal public parameters
    IndexTooLarge,
    /// Failed to create domain
    DomainCreationError,
    /// Failed to get array value by index
    IndexError,
    /// Divided by zero field element
    DivisionError,
    /// An error in the Plonk SNARK logic: {0}
    SnarkError(SnarkError),
    /// An error in the underlying polynomial commitment: {0}
    PCSError(PCSError),
    /// An error in the Plonk circuit: {0}
    CircuitError(CircuitError),
    /// An error during IO: {0}
    IoError(ark_std::io::Error),
    /// An error during (de)serialization
    SerializationError(ark_serialize::SerializationError),
    /// Plonk proof verification failed due to wrong proof
    WrongProof,
    /// Rescue Error
    PrimitiveError(jf_primitives::errors::PrimitivesError),
    /// Invalid parameters
    InvalidParameters(String),
    /// Non-native field overflow
    NonNativeFieldOverflow,
    /// Iterator out of range
    IteratorOutOfRange,
    /// Public inputs for partial verification circuit do not match
    PublicInputsDoNotMatch,
}

impl ark_std::error::Error for PlonkError {}

impl From<PCSError> for PlonkError {
    fn from(e: PCSError) -> Self {
        Self::PCSError(e)
    }
}

impl From<ark_std::io::Error> for PlonkError {
    fn from(e: ark_std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<ark_serialize::SerializationError> for PlonkError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}

impl From<jf_primitives::errors::PrimitivesError> for PlonkError {
    fn from(e: jf_primitives::errors::PrimitivesError) -> Self {
        Self::PrimitiveError(e)
    }
}

/// A `enum` specifying the possible failure modes of the underlying SNARK.
#[derive(Display, Debug)]
pub enum SnarkError {
    #[rustfmt::skip]
    /// Suspect: circuit is not satisfied. The quotient polynomial has wrong degree: {0}, expected: {1}. 
    WrongQuotientPolyDegree(usize, usize),
    /// Invalid parameters: {0}
    ParameterError(String),
    /// The SNARK does not support lookup
    SnarkLookupUnsupported,
}

#[cfg(feature = "std")]
impl std::error::Error for SnarkError {}

impl From<SnarkError> for PlonkError {
    fn from(e: SnarkError) -> Self {
        Self::SnarkError(e)
    }
}

impl From<CircuitError> for PlonkError {
    fn from(e: CircuitError) -> Self {
        Self::CircuitError(e)
    }
}

impl From<PlonkError> for CircuitError {
    // this happen during invocation of Plonk proof system API inside Verifier
    // gadget
    fn from(e: PlonkError) -> Self {
        Self::ParameterError(format!("Plonk proof system err: {e:?}"))
    }
}
