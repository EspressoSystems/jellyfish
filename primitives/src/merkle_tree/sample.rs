// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Provides sample instantiations of merkle tree.
//! E.g. Sparse merkle tree with BigUInt index.

use super::{merkle_tree_impl::MerkleTreeImpl, DigestAlgorithm, ToVec};
use crate::rescue::{Permutation, RescueParameter};
use ark_std::{marker::PhantomData, vec, vec::Vec};
use typenum::U3;

/// A standard merkle tree using RATE-3 rescue hash function
pub type RescueMerkleTree<F> = MerkleTreeImpl<F, RescueHash<F>, u64, U3, F>;

impl<F: RescueParameter> ToVec<F> for u64 {
    fn to_vec(&self) -> Vec<F> {
        vec![F::from(*self)]
    }
}

/// Wrapper for rescue hash function
pub struct RescueHash<F: RescueParameter> {
    phantom_f: PhantomData<F>,
}

impl<F: RescueParameter> DigestAlgorithm<F> for RescueHash<F> {
    fn digest(data: &[F]) -> F {
        let perm = Permutation::default();
        perm.sponge_no_padding(data, 1).unwrap()[0]
    }
}
