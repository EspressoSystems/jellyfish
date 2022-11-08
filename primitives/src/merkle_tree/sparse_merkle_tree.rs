// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical Sparse Merkle Tree.
use super::{
    internal::{build_tree_internal, MerkleNode, MerkleProof},
    DigestAlgorithm, Element, Index, LookupResult, MerkleCommitment, MerkleTreeScheme, NodeValue,
    UniversalMerkleTreeScheme,
};
use crate::{errors::PrimitivesError, generate_merkle_tree_scheme};
use ark_std::{borrow::Borrow, boxed::Box, fmt::Debug, marker::PhantomData, string::ToString};
use num_bigint::BigUint;
use num_traits::pow::pow;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

// A standard Universal Merkle tree implementation
generate_merkle_tree_scheme!(UniversalMerkleTree);

impl<E, H, I, Arity, T> UniversalMerkleTreeScheme for UniversalMerkleTree<E, H, I, Arity, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64>,
    Arity: Unsigned,
    T: NodeValue,
{
    type NonMembershipProof = ();
    type BatchNonMembershipProof = ();

    fn update(&mut self, pos: impl Borrow<I>, elem: impl Borrow<E>) -> LookupResult<E, ()> {
        let pos = pos.borrow();
        let elem = elem.borrow();
        let traversal_path = pos.to_treverse_path(self.height, Self::ARITY);
        let ret = self
            .root
            .update_internal::<H, Arity>(self.height, pos, &traversal_path, elem);
        if let LookupResult::Ok(..) = ret {
            self.num_leaves += 1;
        }
        ret
    }
}
