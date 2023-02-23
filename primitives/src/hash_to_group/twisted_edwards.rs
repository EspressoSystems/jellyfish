// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Hash to Elliptic Curve implementation of <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>

use crate::errors::PrimitivesError;
use ark_ec::{
    twisted_edwards::{Affine, Projective, TECurveConfig},
    AffineRepr,
};
use ark_std::{
    rand::{Rng, SeedableRng},
    UniformRand,
};
use digest::Digest;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

/// Trait definition and default implementation for hash to group functions for
/// Twisted Edwards Curves.
pub trait TEHashToGroup: TECurveConfig + Sized {
    /// Hash to Group point, using sha2-512 function
    /// hashing to G1 point of `C: ProjectiveCurve`.
    // Default implementation implements a naive solution via rejection sampling.
    // Slow, and non-constant time.
    //
    // For specific curves we may want to overload it with a more efficient
    // algorithm, such as IETF BLS draft.
    fn hash_to_group<B: AsRef<[u8]>>(
        data: B,
        cs_id: B,
    ) -> Result<Projective<Self>, PrimitivesError> {
        let mut hasher = Sha256::new();
        hasher.update([cs_id.as_ref(), data.as_ref()].concat());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(hasher.finalize().as_ref());
        let mut rng = ChaCha20Rng::from_seed(seed);
        loop {
            let y = Self::BaseField::rand(&mut rng);
            // a boolean flag to decide if y is positive or not
            let x_flag = rng.gen();
            if let Some(p) = Affine::<Self>::get_point_from_y_unchecked(y, x_flag) {
                return Ok(p.mul_by_cofactor_to_group());
            }
        }
    }
}

impl TEHashToGroup for ark_ed_on_bls12_377::EdwardsConfig {
    // TODO:
    // overload hash to group with the method in
    // <https://github.com/algorand/pairing-plus/blob/7ec2ae03aae4ba2fc5210810211478171ccededf/src/bls12_381/osswu_map/g1.rs#L47>
}

impl TEHashToGroup for ark_ed_on_bls12_381::EdwardsConfig {
    // TODO:
    // overload hash to group with the method in
    // <https://github.com/algorand/pairing-plus/blob/7ec2ae03aae4ba2fc5210810211478171ccededf/src/bls12_381/osswu_map/g1.rs#L47>
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::vec;

    #[test]
    fn test_hash_to_group() {
        test_hash_to_group_helper::<ark_ed_on_bls12_377::EdwardsConfig>();
        test_hash_to_group_helper::<ark_ed_on_bls12_381::EdwardsConfig>();
    }

    fn test_hash_to_group_helper<P: TEHashToGroup>() {
        let data = vec![1u8, 2, 3, 4, 5];
        let _g1 =
            <P as TEHashToGroup>::hash_to_group::<&[u8]>(data.as_ref(), "Jubjub curves".as_ref())
                .unwrap();
    }
}
