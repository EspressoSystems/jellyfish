// Copyright (c) 2022 TRI (spectrum.xyz)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Hash to Elliptic Curve implementation of <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>

use anyhow::Result;
use ark_ec::ProjectiveCurve;
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;
use digest::Digest;

/// Hash to Curve point, using hash function implementing `H: Digest` and
/// hashing to curve point of `C: ProjectiveCurve`.
/// It accepts any input that can be serialized into bytes: `T:
/// CanonicalSerialize`.
// TODO: (alex) implemented IETF standard
pub fn hash_to_curve<H, C, T>(data: &T) -> Result<C>
where
    H: Digest,
    C: ProjectiveCurve,
    T: CanonicalSerialize + Sized,
{
    let mut bytes = Vec::new();
    data.serialize(&mut bytes).unwrap();

    // unimplemented!();
    Ok(C::prime_subgroup_generator()) // for test only, should remove
}
