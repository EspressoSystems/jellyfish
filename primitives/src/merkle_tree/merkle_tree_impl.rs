// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical append only merkle tree
use super::{
    utils::{
        build_tree_internal, calculate_capacity, digest_leaf, index_to_branches, MerkleNode,
        MerkleProof,
    },
    AppendableMerkleTree, DigestAlgorithm, ElementType, ForgetableMerkleTree, IndexType,
    LookupResult, MerkleCommitment, MerkleTree,
};
use crate::{
    errors::PrimitivesError,
    rescue::{Permutation, RescueParameter},
};
use ark_ff::Field;
use ark_std::{borrow::Borrow, boxed::Box, marker::PhantomData, string::ToString, vec, vec::Vec};
use serde::{Deserialize, Serialize};
use typenum::{Unsigned, U3};

/// A standard append only Merkle tree implementation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType<F>,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    root: Box<MerkleNode<E, I, F>>,
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
    I: IndexType<F>,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    type ElementType = E;
    type Digest = H;
    type IndexType = I;
    type LeafArity = LeafArity;
    type TreeArity = TreeArity;
    type MembershipProof = MerkleProof<E, I, F>;
    // TODO(Chengyu): implement batch membership proof
    type BatchMembershipProof = ();

    fn new(height: usize) -> Self {
        MerkleTreeImpl {
            root: Box::new(MerkleNode::<E, I, F>::Empty),
            height,
            capacity: calculate_capacity::<I, LeafArity, TreeArity, F>(height),
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
        let capacity = calculate_capacity::<I, LeafArity, TreeArity, F>(height);
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
        let branches = index_to_branches::<I, LeafArity, TreeArity, F>(pos, self.height);
        match self.root.lookup_internal(self.height, &branches) {
            LookupResult::Ok(value, proof) => LookupResult::Ok(value, MerkleProof { pos, proof }),
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
        }
    }

    fn verify(
        &self,
        pos: Self::IndexType,
        proof: impl Borrow<Self::MembershipProof>,
    ) -> Result<bool, PrimitivesError> {
        let proof = proof.borrow();
        if self.height != proof.proof.len() - 1 {
            return Err(PrimitivesError::ParameterError(
                "Incompatible membership proof for this merkle tree".to_string(),
            ));
        }
        if pos != proof.pos {
            return Err(PrimitivesError::ParameterError(
                "Inconsistent proof index".to_string(),
            ));
        }
        let computed_root_value = proof.verify_membership_proof::<H, LeafArity, TreeArity>()?;
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
    I: IndexType<F>,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    fn push(&mut self, elem: impl Borrow<Self::ElementType>) -> Result<(), PrimitivesError> {
        if self.num_leaves >= self.capacity {
            return Err(PrimitivesError::InternalError(
                "Merkle tree full".to_string(),
            ));
        }

        let branches =
            index_to_branches::<I, LeafArity, TreeArity, F>(self.num_leaves, self.height);
        self.root.update_internal::<H, LeafArity, TreeArity>(
            self.height,
            self.num_leaves,
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

        let branch = index_to_branches::<I, LeafArity, TreeArity, F>(self.num_leaves, self.height);
        self.num_leaves += self.root.extend_internal::<H, LeafArity, TreeArity>(
            self.height,
            self.num_leaves,
            &branch,
            true,
            &mut iter,
        )?;
        if iter.peek().is_some() {
            return Err(PrimitivesError::ParameterError(
                "To much data for extension".to_string(),
            ));
        }
        Ok(())
    }
}

impl<E, H, I, LeafArity, TreeArity, F> ForgetableMerkleTree<F>
    for MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType<F>,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    fn forget(
        &mut self,
        pos: Self::IndexType,
    ) -> LookupResult<Self::ElementType, Self::MembershipProof> {
        let branches = index_to_branches::<I, LeafArity, TreeArity, F>(pos, self.height);
        match self.root.forget_internal(self.height, &branches) {
            LookupResult::Ok(elem, proof) => {
                LookupResult::Ok(elem, MerkleProof::<E, I, F> { pos, proof })
            },
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
        }
    }

    fn remember(
        &mut self,
        pos: Self::IndexType,
        _element: impl Borrow<Self::ElementType>,
        proof: impl Borrow<Self::MembershipProof>,
    ) -> Result<(), PrimitivesError> {
        let proof = proof.borrow();
        let branches = index_to_branches::<I, LeafArity, TreeArity, F>(pos, self.height);
        if let MerkleNode::<E, I, F>::Leaf {
            value: _,
            pos,
            elem,
        } = proof.proof[0]
        {
            let proof_leaf_value = digest_leaf::<E, H, I, F>(pos, elem, TreeArity::to_usize());
            let mut path_values = vec![proof_leaf_value];
            branches.iter().zip(proof.proof.iter().skip(1)).fold(
                Ok(proof_leaf_value),
                |result, (branch, node)| -> Result<F, PrimitivesError> {
                    match result {
                        Ok(val) => match node {
                            MerkleNode::Branch { value: _, children } => {
                                let mut data: Vec<_> =
                                    children.iter().map(|node| node.value()).collect();
                                data[*branch] = val;
                                let digest = H::digest(&data);
                                path_values.push(digest);
                                Ok(digest)
                            },
                            _ => Err(PrimitivesError::ParameterError(
                                "Incompatible proof for this merkle tree".to_string(),
                            )),
                        },
                        Err(e) => Err(e),
                    }
                },
            )?;
            self.root.remember_internal::<H, TreeArity>(
                self.height,
                pos,
                &branches,
                &path_values,
                &proof.proof,
            )
        } else {
            Err(PrimitivesError::ParameterError(
                "Invalid proof type".to_string(),
            ))
        }
    }
}

// TODO(Chengyu): extract a merkle frontier

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
    use super::RescueMerkleTree;
    use crate::{
        merkle_tree::{
            utils::{MerkleNode, MerkleProof},
            *,
        },
        rescue::RescueParameter,
    };
    use ark_ed_on_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_381::Fq as Fq381;
    use ark_ed_on_bn254::Fq as Fq254;

    #[test]
    fn test_mt_builder() {
        test_mt_builder_helper::<Fq254>();
        test_mt_builder_helper::<Fq377>();
        test_mt_builder_helper::<Fq381>();
    }

    fn test_mt_builder_helper<F: RescueParameter>() {
        assert!(RescueMerkleTree::<F>::from_data(1, &[F::from(0u64); 3]).is_ok());
        assert!(RescueMerkleTree::<F>::from_data(1, &[F::from(0u64); 4]).is_err());
    }

    #[test]
    fn test_mt_insertion() {
        test_mt_insertion_helper::<Fq254>();
        test_mt_insertion_helper::<Fq377>();
        test_mt_insertion_helper::<Fq381>();
    }

    fn test_mt_insertion_helper<F: RescueParameter>() {
        let mut mt = RescueMerkleTree::<F>::new(2);
        assert_eq!(mt.capacity(), 9u64);
        assert!(mt.push(F::from(2u64)).is_ok());
        assert!(mt.push(F::from(3u64)).is_ok());
        assert!(mt.extend(&[F::from(0u64); 9]).is_err()); // Will err, but first 7 items will be inserted
        assert_eq!(mt.num_leaves(), 9u64); // full merkle tree

        // Now unable to insert more data
        assert!(mt.push(F::from(0u64)).is_err());
        assert!(mt.extend(&[]).is_ok());
        assert!(mt.extend(&[F::from(1u64)]).is_err());
    }

    #[test]
    fn test_mt_lookup() {
        test_mt_lookup_helper::<Fq254>();
        test_mt_lookup_helper::<Fq377>();
        test_mt_lookup_helper::<Fq381>();
    }

    fn test_mt_lookup_helper<F: RescueParameter>() {
        let mt = RescueMerkleTree::<F>::from_data(2, &[F::from(3u64), F::from(1u64)]).unwrap();
        let (elem, proof) = mt.lookup(0).expect_ok().unwrap();
        assert_eq!(elem, F::from(3u64));
        assert_eq!(proof.proof.len(), 3);
        assert!(mt.verify(0u64, &proof).unwrap());

        let mut bad_proof = proof.clone();
        if let MerkleNode::Leaf {
            value: _,
            pos: _,
            elem,
        } = &mut bad_proof.proof[0]
        {
            *elem = F::from(4u64);
        } else {
            unreachable!()
        }

        let result = mt.verify(0u64, &bad_proof);
        assert!(result.is_ok() && !result.unwrap());

        let mut forge_proof = MerkleProof {
            pos: 2,
            proof: proof.proof,
        };
        if let MerkleNode::Leaf {
            value: _,
            pos,
            elem,
        } = &mut forge_proof.proof[0]
        {
            *pos = 2;
            *elem = F::from(0u64);
        } else {
            unreachable!()
        }
        let result = mt.verify(2u64, &forge_proof);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_mt_forget_remember() {
        test_mt_forget_remember_helper::<Fq254>();
        test_mt_forget_remember_helper::<Fq377>();
        test_mt_forget_remember_helper::<Fq381>();
    }

    fn test_mt_forget_remember_helper<F: RescueParameter>() {
        let mut mt = RescueMerkleTree::<F>::from_data(2, &[F::from(3u64), F::from(1u64)]).unwrap();
        let (lookup_elem, lookup_proof) = mt.lookup(0).expect_ok().unwrap();
        let (elem, proof) = mt.forget(0).expect_ok().unwrap();
        assert_eq!(lookup_elem, elem);
        assert_eq!(lookup_proof, proof);
        assert_eq!(elem, F::from(3u64));
        assert_eq!(proof.proof.len(), 3);
        assert!(mt.verify(0, &lookup_proof).unwrap());
        assert!(mt.verify(0, &proof).unwrap());

        assert!(mt.forget(0).expect_ok().is_err());
        assert!(matches!(mt.lookup(0), LookupResult::NotInMemory));

        let mut bad_proof = proof.clone();
        if let MerkleNode::Leaf {
            value: _,
            pos: _,
            elem,
        } = &mut bad_proof.proof[0]
        {
            *elem = F::from(4u64);
        } else {
            unreachable!()
        }

        let result = mt.remember(0u64, elem, &bad_proof);
        assert!(result.is_err());

        let mut forge_proof = MerkleProof {
            pos: 2,
            proof: proof.proof.clone(),
        };
        if let MerkleNode::Leaf {
            value: _,
            pos,
            elem,
        } = &mut forge_proof.proof[0]
        {
            *pos = 2;
            *elem = F::from(0u64);
        } else {
            unreachable!()
        }
        let result = mt.remember(2u64, elem, &forge_proof);
        assert!(result.is_err());

        assert!(mt.remember(0, elem, &proof).is_ok());
        assert!(mt.lookup(0).expect_ok().is_ok());
    }
}
