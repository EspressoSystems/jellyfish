// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.
//! Trait definition for cryptographic commitment scheme
#![no_std]

use ark_std::{borrow::Borrow, fmt::Debug, hash::Hash, UniformRand};

/// A glorified [`bool`] that leverages compile lints to encourage the caller to
/// use the result.
///
/// Intended as the return type for verification of proofs, signatures, etc.
/// Recommended for use in the nested [`Result`] pattern: see <https://sled.rs/errors>.
type VerificationResult = Result<(), ()>;

/// Trait defining a cryptographic commitment scheme.
///
/// A commitment scheme allows one to "commit" to a value while keeping it hidden
/// and optionally binding it to a blinding factor. Later, the value can be "opened"
/// to reveal the original input and verify its authenticity.
pub trait CommitmentScheme {
    /// The type of input to the commitment scheme.
    type Input;

    /// The type of output produced by the commitment scheme.
    type Output: Clone + Debug + PartialEq + Eq + Hash;

    /// The type of randomness or blinding factor used in the scheme.
    type Randomness: Clone + Debug + PartialEq + Eq + UniformRand;

    /// The type of error that may occur during commitment or verification.
    type Error: ark_std::error::Error;

    /// Generate a commitment for the given input and optional randomness.
    ///
    /// - If `r` is `None`, the scheme may produce a deterministic commitment or use default randomness.
    fn commit<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
    ) -> Result<Self::Output, Self::Error>;

    /// Verify that the provided commitment corresponds to the input and randomness.
    ///
    /// Returns a `VerificationOutcome` indicating whether the verification succeeded or failed.
    fn verify<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
        comm: &Self::Output,
    ) -> Result<VerificationOutcome, Self::Error>;
}

/// The result of a verification process, indicating success or failure.
type VerificationOutcome = Result<(), VerificationError>;

/// Custom error type for verification failures.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("The commitment does not match the input and randomness.")]
    CommitmentMismatch,
    #[error("Invalid input provided.")]
    InvalidInput,
}
