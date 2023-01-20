// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Error module.

use ark_std::string::String;
use displaydoc::Display;

/// A `enum` specifying the possible failure modes of the circuit.
#[derive(Display, Debug)]
pub enum CircuitError {
    /// Failed to create domain
    DomainCreationError,
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
