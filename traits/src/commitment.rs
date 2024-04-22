// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait definition for commitment scheme.

use crate::VerificationResult;
use ark_std::{borrow::Borrow, fmt::Debug, hash::Hash, UniformRand};

/// A trait for cryptographic commitment scheme
pub trait CommitmentScheme {
    /// Input to the commitment
    type Input;
    /// The type of output commitment value
    type Output: Clone + Debug + PartialEq + Eq + Hash;
    /// The type of the hiding/blinding factor
    type Randomness: Clone + Debug + PartialEq + Eq + UniformRand;
    /// Error type
    type Error: ark_std::error::Error;

    /// Commit algorithm that takes `input` and blinding randomness `r`
    /// (optional for hiding commitment schemes), outputs a commitment.
    fn commit<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
    ) -> Result<Self::Output, Self::Error>;

    /// Verify algorithm that output `Ok` if accepted, or `Err` if rejected.
    fn verify<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
        comm: &Self::Output,
    ) -> Result<VerificationResult, Self::Error>;
}
