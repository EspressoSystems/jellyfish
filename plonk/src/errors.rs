// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Error module.

use ark_std::string::String;
use displaydoc::Display;

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
    PcsError(ark_poly_commit::Error),
    /// An error in the Plonk circuit: {0}
    CircuitError(CircuitError),
    /// An error during IO: {0}
    IoError(ark_std::io::Error),
    /// An error during (de)serialization
    SerializationError(ark_serialize::SerializationError),
    /// Plonk proof verification failed due to wrong proof
    WrongProof,
    /// Rescue Error
    RescueError(jf_rescue::errors::RescueError),
    /// Invalid parameters
    InvalidParameters(String),
    /// Non-native field overflow
    NonNativeFieldOverflow,
    /// Iterator out of range
    IteratorOutOfRange,
    /// Public inputs for partial verification circuit do not match
    PublicInputsDoNotMatch,
}

#[cfg(feature = "std")]
impl std::error::Error for PlonkError {}

impl From<ark_poly_commit::Error> for PlonkError {
    fn from(e: ark_poly_commit::Error) -> Self {
        Self::PcsError(e)
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

impl From<jf_rescue::errors::RescueError> for PlonkError {
    fn from(e: jf_rescue::errors::RescueError) -> Self {
        Self::RescueError(e)
    }
}

/// A `enum` specifying the possible failure modes of the underlying SNARK.
#[derive(Display, Debug)]
pub enum SnarkError {
    #[rustfmt::skip]
    /// The quotient polynomial has wrong degree: {0}, expected: {1}. Suspect: circuit is not satisfied.
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

/// A `enum` specifying the possible failure modes of the circuit.
#[derive(Display, Debug)]
pub enum CircuitError {
    /// Variable index {0} is larger than the bound {1}.
    VarIndexOutOfBound(usize, usize),
    /// Public input length {0} doesn't match num_inputs = {1}.
    PubInputLenMismatch(usize, usize),
    /// The {0}-th gate failed: {1}
    GateCheckFailure(usize, String),
    /// Invalid parameters: {0}
    ParameterError(String),
    /// The circuit is not finalized before doing arithmetization
    UnfinalizedCircuit,
    /// Attempt to modify the finalized circuit
    ModifyFinalizedCircuit,
    /// The circuit has wrong Plonk type
    WrongPlonkType,
    /// The circuit does not support lookup
    LookupUnsupported,
    /// Failed to get array value by index
    IndexError,
    /// Algebra over field failed: {0}
    FieldAlgebraError(String),
    #[rustfmt::skip]
    /// Unexpected field for elliptic curve operation, currently only support Bn254, BLS12-381/377 scalar field
    UnsupportedCurve,
    #[rustfmt::skip]
    /// ‼ ️Internal error! Please report to Crypto Team immediately!\n\Message: {0}
    InternalError(String),
    /// Feature not supported: {0}
    NotSupported(String),
}

#[cfg(feature = "std")]
impl std::error::Error for CircuitError {}

impl From<CircuitError> for PlonkError {
    fn from(e: CircuitError) -> Self {
        Self::CircuitError(e)
    }
}
