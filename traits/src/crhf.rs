// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Collision-resistant Hash Functions (CRHF) definitions and implementations.

use ark_std::{borrow::Borrow, fmt::Debug, hash::Hash};

/// A trait for CRHF
/// (based on ark-primitives' definition, but self-declared for minimal
/// dependency and easier future upgradability.)
pub trait CRHF {
    /// Input to the CRHF
    type Input;
    /// Output of the CRHF
    // FIXME: (alex) wait until arkwork 0.4.0 to add the following:
    // + Default + CanonicalSerialize + CanonicalDeserialize;
    // right now, const-generic are not supported yet.
    type Output: Clone + PartialEq + Eq + Hash + Debug;
    /// Error type
    type Error: ark_std::error::Error;

    /// evaluate inputs and return hash output
    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, Self::Error>;
}
