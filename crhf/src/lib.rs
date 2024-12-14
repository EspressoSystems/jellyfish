// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait definition for Collision-resistant hash function (CRHF).
#![no_std]

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, fmt::Debug, hash::Hash};

/// A trait for CRHF
/// (based on ark-primitives' definition, but self-declared for minimal
/// dependency and easier future upgradability.)
pub trait CRHF {
    /// Input to the CRHF, allowed to be dynamically sized
    type Input: ?Sized;
    /// Output of the CRHF
    type Output: Clone + PartialEq + Eq + Hash + Debug + CanonicalSerialize + CanonicalDeserialize;
    /// Error type
    type Error: ark_std::error::Error;

    /// evaluate inputs and return hash output
    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, Self::Error>;
}
