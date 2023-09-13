// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait and implementation for a Verifiable Delay Function (VDF) <https://eprint.iacr.org/2018/601.pdf>.
use crate::errors::PrimitivesError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    fmt::Debug,
    rand::{CryptoRng, RngCore},
};

pub mod minroot;

/// A trait for VDF proof, evaluation and verification.
pub trait VDF {
    /// Public parameters
    type PublicParameter;

    /// VDF proof.
    type Proof: Debug
        + Clone
        + Send
        + Sync
        + CanonicalSerialize
        + CanonicalDeserialize
        + PartialEq
        + Eq;

    /// VDF input.
    type Input: Debug
        + Clone
        + Send
        + Sync
        + CanonicalSerialize
        + CanonicalDeserialize
        + PartialEq
        + Eq;

    /// VDF output.
    type Output: Debug
        + Clone
        + Send
        + Sync
        + CanonicalSerialize
        + CanonicalDeserialize
        + PartialEq
        + Eq;

    /// Generates a public parameter from RNG with given difficulty.
    /// Concrete instantiations of VDF shall document properly about the
    /// correspondence between the difficulty value and the time required
    /// for evaluation/proof generation.
    fn setup<R: CryptoRng + RngCore>(
        difficulty: u64,
        prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, PrimitivesError>;

    /// Computes the VDF output and proof.
    fn eval(
        pp: &Self::PublicParameter,
        input: &Self::Input,
    ) -> Result<(Self::Output, Self::Proof), PrimitivesError>;

    /// Verifies a VDF output given the proof.
    fn verify(
        pp: &Self::PublicParameter,
        input: &Self::Input,
        output: &Self::Output,
        proof: &Self::Proof,
    ) -> Result<(), PrimitivesError>;
}
