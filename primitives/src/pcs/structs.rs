// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use ark_ec::{pairing::Pairing, CurveGroup};
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
impl<T, E> From<T> for Commitment<E>
where
    T: CurveGroup,
    E: Pairing<G1 = T, G1Affine = T::Affine>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

// https://stackoverflow.com/questions/63119000/why-am-i-required-to-cover-t-in-impl-foreigntraitlocaltype-for-t-e0210
// https://users.rust-lang.org/t/generic-conversion-from-newtypes/16247
impl<T, E> From<Commitment<E>> for (T,)
where
    T: CurveGroup,
    E: Pairing<G1 = T, G1Affine = T::Affine>,
{
    fn from(value: Commitment<E>) -> Self {
        (value.0.into(),)
    }
}

impl<T, E> From<&Commitment<E>> for (T,)
where
    T: CurveGroup,
    E: Pairing<G1 = T, G1Affine = T::Affine>,
{
    fn from(value: &Commitment<E>) -> Self {
        (value.0.into(),)
    }
}
