// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
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

/// Allow generic access to the underlying affine point.
/// Convert from `CurveGroup` to `Commitment`.
/// `Commitment` is a newtype wrapper for `AffineRepr`,
/// so why convert from `CurveGroup` instead of `AffineRepr`?
/// Because group arithmetic with `AffineRepr`s produces `CurveGroup`s, not
/// `AffineRepr`s, so we expect callers to want to convert from `CurveGroup`.
impl<T, E> From<T> for Commitment<E>
where
    T: CurveGroup,
    E: Pairing<G1 = T, G1Affine = T::Affine>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl<T, E> AsRef<T> for Commitment<E>
where
    T: AffineRepr,
    E: Pairing<G1Affine = T>,
{
    fn as_ref(&self) -> &T {
        &self.0
    }
}
