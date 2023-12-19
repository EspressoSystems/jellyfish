// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! "Short Public Key" variant of BLS signature over the BN254 curve.
//! The scheme works as follows:
//! Let `g1` and `g2` be generators of `G1` and `G2`.
//!
//! **KeyGen()**
//!    * sample a random `s` in the scalar field `Fr` and return the key pair
//!      `(sk,pk):=(s,g1^s)`
//!
//! **Sign(sk,m)**
//!    * return `sigma=H(m)^{sk}` (where H maps `m` to a G2 point)
//!
//! **Verify(pk,m,sigma)**
//!    * Check that `e(g_1,sigma)=e(pk,H(m))`

use ark_ec::{CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    hash::{Hash, Hasher},
    rand::Rng,
    vec::Vec,
    UniformRand,
};
use espresso_systems_common::jellyfish::tag;
use serde::{Deserialize, Serialize};
use tagged_base64::tagged;
use zeroize::Zeroize;

/// BLS signature scheme for minimal public key variant.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BLSOverBN254CurveSignatureScheme;

// FIXME: (alex) should we use new tags? separate for two flavors?
#[tagged(tag::BLS_SIGNING_KEY)]
#[derive(
    Clone, Hash, Default, Zeroize, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Debug,
)]
#[zeroize(drop)]
/// Signing key for BLS signature
pub struct SignKey(pub(crate) ark_bn254::Fr);

impl SignKey {
    /// Uniformly random sample a `SignKey`
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        Self(ark_bn254::Fr::rand(rng))
    }
}

/// Verification key for BLS signature
#[tagged(tag::BLS_VER_KEY)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Zeroize, PartialEq, Eq, Clone, Debug, Copy)]
pub struct VerKey(pub(crate) ark_bn254::G1Projective);

impl Hash for VerKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.0.into_affine(), state)
    }
}

impl From<&SignKey> for VerKey {
    fn from(sk: &SignKey) -> Self {
        Self(ark_bn254::G1Projective::generator() * sk.0)
    }
}

impl From<SignKey> for VerKey {
    fn from(sk: SignKey) -> Self {
        Self(ark_bn254::G1Projective::generator() * sk.0)
    }
}

impl VerKey {
    /// Returns the internal projective representation
    pub fn internal(&self) -> ark_bn254::G1Projective {
        self.0
    }

    /// Tranform `VerKey` into its internal affine representation.
    pub fn to_affine(&self) -> ark_bn254::G1Affine {
        self.0.into_affine()
    }
}
