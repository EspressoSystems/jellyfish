// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements a pseudo random function that is derived from
//! the rescue hash function.

use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    rand::{CryptoRng, RngCore},
    UniformRand,
};
/// Trait for Pseudo-random Functions
pub trait PRF {
    // TODO: (alex) add `CanonicalDeserialize` to `Input`, `CanonicalSerialize` to
    // `Output`, both to `Seed`, when we move to arkworks 0.4.0
    /// Input to the PRF
    type Input: Clone;
    /// Output of the PRF
    type Output: Clone + Debug + PartialEq + Eq;
    /// The random seed/key that index a specific function from the PRF
    /// ensembles
    type Seed: Clone + Debug + Default + UniformRand;
    /// Error type
    type Error: ark_std::error::Error;

    /// Compute PRF output with a user-provided randomly generated `seed`
    fn evaluate<S: Borrow<Self::Seed>, I: Borrow<Self::Input>>(
        seed: S,
        input: I,
    ) -> Result<Self::Output, Self::Error>;

    /// same as [`Self::evaluate`] except that we generate a fresh random seed
    /// for the evaluation
    fn evaluate_with_rand_seed<R: RngCore + CryptoRng, T: Borrow<Self::Input>>(
        rng: &mut R,
        input: T,
    ) -> Result<(Self::Seed, Self::Output), Self::Error> {
        let seed = Self::Seed::rand(rng);
        let output = Self::evaluate(&seed, input)?;
        Ok((seed, output))
    }
}
