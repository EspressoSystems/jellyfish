// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical append only merkle tree
use super::{
    utils::{build_tree_internal, calculate_capacity, index_to_branches, MerkleNode, MerkleProof},
    AppendableMerkleTree, DigestAlgorithm, ElementType, ForgetableMerkleTree, IndexType,
    LookupResult, MerkleCommitment, MerkleTree,
};
use crate::{
    errors::PrimitivesError,
    rescue::{Permutation, RescueParameter},
};
use ark_ff::Field;
use ark_std::{borrow::Borrow, boxed::Box, marker::PhantomData, string::ToString};
use serde::{Deserialize, Serialize};
use typenum::{Unsigned, U3};

/// A standard append only Merkle tree implementation
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
    // TODO(Chengyu): implement batch membership proof
    type BatchMembershipProof = ();

    fn new(height: usize) -> Self {
        MerkleTreeImpl {
            root: Box::new(MerkleNode::<E, F>::EmptySubtree),
            height,
            capacity: calculate_capacity::<I, LeafArity, TreeArity>(height),
            num_leaves: I::from(0),
            _phantom_h: PhantomData,
            _phantom_la: PhantomData,
            _phantom_ta: PhantomData,
        }
    }

    fn from_data(
        height: usize,
        data: impl IntoIterator<Item = impl Borrow<Self::ElementType>>,
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
        let branches = index_to_branches::<I, LeafArity, TreeArity>(pos, self.height);
        match self.root.lookup_internal(self.height, &branches) {
            LookupResult::Ok(value, proof) => LookupResult::Ok(value, MerkleProof { pos, proof }),
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
        }
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

    fn commitment(&self) -> super::MerkleCommitment<Self::IndexType, F> {
        MerkleCommitment {
            root_value: self.root.value(),
            height: self.height,
            num_leaves: self.num_leaves,
        }
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
    fn push(&mut self, elem: impl Borrow<Self::ElementType>) -> Result<(), PrimitivesError> {
        if self.num_leaves == self.capacity {
            return Err(PrimitivesError::InternalError(
                "Merkle tree full".to_string(),
            ));
        }

        let branches = index_to_branches::<I, LeafArity, TreeArity>(self.num_leaves, self.height);
        self.root.update_internal::<H, LeafArity, TreeArity>(
            self.height,
            &branches,
            elem.borrow(),
        )?;
        self.num_leaves += 1;
        Ok(())
    }

    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl Borrow<Self::ElementType>>,
    ) -> Result<(), PrimitivesError> {
        let mut iter = elems.into_iter().peekable();
        if iter.peek().is_some() {
            let branch = index_to_branches::<I, LeafArity, TreeArity>(self.num_leaves, self.height);
            self.num_leaves += self.root.extend_internal::<H, LeafArity, TreeArity>(
                self.height,
                &branch,
                &mut iter,
            )?;
        }
        Ok(())
    }
}

impl<E, H, I, LeafArity, TreeArity, F> ForgetableMerkleTree<F>
    for MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    fn forget(
        &mut self,
        pos: Self::IndexType,
    ) -> LookupResult<Self::ElementType, Self::MembershipProof> {
        let branches = index_to_branches::<I, LeafArity, TreeArity>(pos, self.height);
        match self.root.forget_internal(self.height, &branches) {
            LookupResult::Ok(elem, proof) => {
                LookupResult::Ok(elem, MerkleProof::<E, F, I> { pos, proof })
            },
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
        }
    }

    fn remember(
        &mut self,
        _pos: Self::IndexType,
        _element: &Self::ElementType,
        _proof: Self::MembershipProof,
    ) -> LookupResult<(), (u64, F)> {
        todo!()
    }
}

// TODO(Chengyu): extract a merkle frontier

impl IndexType for u64 {}
/// A standard merkle tree using RATE-3 rescue hash function
pub type RescueMerkleTree<F> = MerkleTreeImpl<F, RescueHash<F>, u64, U3, U3, F>;

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

// TODO(Chengyu): unit tests
#[cfg(test)]
mod mt_tests {
    use crate::{merkle_tree::*, rescue::RescueParameter};
    use ark_ed_on_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_381::Fq as Fq381;
    use ark_ed_on_bn254::Fq as Fq254;

    use super::RescueMerkleTree;

    #[test]
    fn test_empty_tree() {
        test_empty_tree_helper::<Fq254>();
        test_empty_tree_helper::<Fq377>();
        test_empty_tree_helper::<Fq381>();
    }

    fn test_empty_tree_helper<F: RescueParameter>() {
        let mut mt = RescueMerkleTree::<F>::new(10);
        assert!(mt.push(&F::from(2u64)).is_ok());
    }
}
