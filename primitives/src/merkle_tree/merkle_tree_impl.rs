// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical append only merkle tree
use super::{
    utils::{
        build_tree_internal, calculate_capacity, index_to_branches, lookup_internal,
        update_mt_node_internal, MerkleNode, MerkleProof,
    },
    AppendableMerkleTree, DigestAlgorithm, ElementType, IndexType, LookupResult, MerkleTree,
};
use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_std::{borrow::Borrow, boxed::Box, marker::PhantomData, string::ToString};
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    root: Box<MerkleNode<E, F>>,
    height: usize,
    capacity: I,
    num_leaves: I,

    _phantom_h: PhantomData<H>,
    _phantom_la: PhantomData<LeafArity>,
    _phantom_ta: PhantomData<TreeArity>,
}

impl<E, H, I, LeafArity, TreeArity, F> MerkleTree<F>
    for MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    type ElementType = E;
    type Digest = H;
    type IndexType = I;
    type LeafArity = LeafArity;
    type TreeArity = TreeArity;
    type MembershipProof = MerkleProof<E, F, I>;
    type BatchMembershipProof = MerkleNode<E, F>;

    fn new(
        height: usize,
        data: impl Iterator<Item = Self::ElementType>,
    ) -> Result<Self, PrimitivesError> {
        let capacity = calculate_capacity::<I, LeafArity, TreeArity>(height);
        let (root, num_leaves) =
            build_tree_internal::<E, H, I, LeafArity, TreeArity, F>(height, capacity, data)?;
        Ok(MerkleTreeImpl {
            root,
            height,
            capacity,
            num_leaves,
            _phantom_h: PhantomData,
            _phantom_la: PhantomData,
            _phantom_ta: PhantomData,
        })
    }

    fn height(&self) -> usize {
        self.height
    }

    fn capacity(&self) -> Self::IndexType {
        self.capacity
    }

    fn num_leaves(&self) -> Self::IndexType {
        self.num_leaves
    }

    fn root(&self) -> F {
        self.root.value()
    }

    fn lookup(
        &self,
        pos: Self::IndexType,
    ) -> LookupResult<Self::ElementType, Self::MembershipProof> {
        if pos >= self.num_leaves {
            return LookupResult::EmptyLeaf;
        }
        lookup_internal::<E, I, LeafArity, TreeArity, F>(&self.root, self.height, pos)
    }

    fn verify(
        &self,
        _pos: Self::IndexType,
        proof: impl Borrow<Self::MembershipProof>,
    ) -> Result<bool, PrimitivesError> {
        let proof = proof.borrow();
        if self.height != proof.proof.len() {
            return Err(PrimitivesError::ParameterError(
                "Incompatible membership proof for this merkle tree".to_string(),
            ));
        }
        let computed_root_value = proof
            .borrow()
            .verify_membership_proof::<H, LeafArity, TreeArity>()?;
        Ok(computed_root_value == self.root.value())
    }
}

impl<E, H, I, LeafArity, TreeArity, F> AppendableMerkleTree<F>
    for MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    fn push(&mut self, elem: &Self::ElementType) -> Result<(), PrimitivesError> {
        if self.num_leaves == self.capacity {
            return Err(PrimitivesError::InternalError(
                "Merkle tree full".to_string(),
            ));
        }

        let branches = index_to_branches::<I, LeafArity, TreeArity>(self.num_leaves, self.height);
        update_mt_node_internal::<E, H, I, LeafArity, TreeArity, F>(
            &mut self.root,
            self.height,
            &branches,
            elem,
        )?;
        self.num_leaves += 1;
        Ok(())
    }

    fn extend(
        &mut self,
        elems: impl Iterator<Item = Self::ElementType>,
    ) -> Result<(), PrimitivesError> {
        // TODO(Chengyu): efficient batch insert
        for elem in elems {
            self.push(&elem)?;
        }
        Ok(())
    }
}

impl<E, H, I, LeafArity, TreeArity, F> MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    // TODO(Chengyu): extract a merkle frontier/commitment
}

// TODO(Chengyu): unit tests
// #[cfg(test)]
// mod mt_tests {
//     use crate::{merkle_tree::*, rescue::RescueParameter};
//     use ark_ed_on_bls12_377::Fq as Fq377;
//     use ark_ed_on_bls12_381::Fq as Fq381;
//     use ark_ed_on_bn254::Fq as Fq254;

//     #[test]
//     fn test_empty_tree() {
//         test_empty_tree_helper::<Fq254>();
//         test_empty_tree_helper::<Fq377>();
//         test_empty_tree_helper::<Fq381>();
//     }

//     fn test_empty_tree_helper<F: RescueParameter>() {
//         let merkle_tree = MerkleTree::build(10, &[].iter());
//     }
// }
