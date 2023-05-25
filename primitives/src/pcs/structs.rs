// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
/// A commitment is an Affine point.
pub struct Commitment<E: Pairing>(
    /// the actual commitment is an affine point.
    pub E::G1Affine,
);

/// Allow generic creation from `AffineRepr`
impl<T, E> From<T> for Commitment<E>
where
    T: AffineRepr,
    E: Pairing<G1Affine = T>,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

/// Allow generic access to the underlying `AffineRepr`
impl<T, E> AsRef<T> for Commitment<E>
where
    T: AffineRepr,
    E: Pairing<G1Affine = T>,
{
    fn as_ref(&self) -> &T {
        &self.0
    }
}
