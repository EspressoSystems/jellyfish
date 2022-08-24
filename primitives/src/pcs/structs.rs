// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, Default, PartialEq, Eq)]
/// A commitment is an Affine point.
pub struct Commitment<E: PairingEngine> {
    /// the actual commitment is an affine point.
    pub commitment: E::G1Affine,
}
