// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical append only merkle tree

use super::{
    internal::{
        build_tree_internal, calculate_capacity, digest_leaf, index_to_branches, MerkleNode,
        MerkleProof,
    },
    AppendableMerkleTreeScheme, DigestAlgorithm, ForgetableMerkleTreeScheme, IndexOps,
    LookupResult, MerkleCommitment, MerkleTreeScheme, ToUsize, ToVec,
};
use crate::errors::PrimitivesError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow,
    boxed::Box,
    fmt::{Debug, Display},
    marker::PhantomData,
    string::ToString,
    vec,
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

/// A standard append only Merkle tree implementation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleTree<E, H, I, TreeArity, T>
where
    E: ToVec<T> + CanonicalSerialize + CanonicalDeserialize + Copy + Eq + PartialEq + Debug,
    H: DigestAlgorithm<T>,
    I: IndexOps
        + ToVec<T>
        + Ord
        + PartialOrd
        + CanonicalDeserialize
        + CanonicalSerialize
        + ToUsize
        + Eq
        + PartialEq
        + Clone
        + Copy
        + Debug
        + From<u64>,
{
    root: Box<MerkleNode<E, I, T>>,
    height: usize,
    capacity: I,
    num_leaves: I,

    _phantom_h: PhantomData<H>,
    _phantom_ta: PhantomData<TreeArity>,
}

impl<E, H, I, TreeArity, T> MerkleTreeScheme for MerkleTree<E, H, I, TreeArity, T>
where
    E: ToVec<T> + CanonicalSerialize + CanonicalDeserialize + Copy + Clone + Eq + PartialEq + Debug,
    H: DigestAlgorithm<T>,
    I: IndexOps
        + Default
        + ToVec<T>
        + Ord
        + PartialOrd
        + CanonicalDeserialize
        + CanonicalSerialize
        + ToUsize
        + Eq
        + PartialEq
        + Clone
        + Copy
        + Debug
        + From<u64>,
    TreeArity: Unsigned,
    T: Default
        + Eq
        + PartialEq
        + CanonicalDeserialize
        + CanonicalSerialize
        + Clone
        + Display
        + Copy,
{
    type Element = E;
    type Digest = H;
    type Index = I;
    type NodeValue = T;
    type MembershipProof = MerkleProof<E, I, T>;
    // TODO(Chengyu): implement batch membership proof
    type BatchMembershipProof = ();

    const ARITY: usize = TreeArity::USIZE;

    fn from_elems(
        height: usize,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<Self, PrimitivesError> {
        let capacity = calculate_capacity::<I, TreeArity>(height);
        let (root, num_leaves) =
            build_tree_internal::<E, H, I, TreeArity, T>(height, capacity, elems)?;
        Ok(MerkleTree {
            root,
            height,
            capacity,
            num_leaves,
            _phantom_h: PhantomData,
            _phantom_ta: PhantomData,
        })
    }

    fn height(&self) -> usize {
        self.height
    }

    fn capacity(&self) -> Self::Index {
        self.capacity
    }

    fn num_leaves(&self) -> Self::Index {
        self.num_leaves
    }

    fn root(&self) -> T {
        self.root.value()
    }

    fn commitment(&self) -> MerkleCommitment<Self::Index, T> {
        MerkleCommitment {
            root_value: self.root.value(),
            height: self.height,
            num_leaves: self.num_leaves,
        }
    }

    fn lookup(&self, pos: Self::Index) -> LookupResult<Self::Element, Self::MembershipProof> {
        if pos >= self.num_leaves {
            return LookupResult::EmptyLeaf;
        }
        let branches = index_to_branches::<I, TreeArity>(pos, self.height);
        match self.root.lookup_internal(self.height, &branches) {
            LookupResult::Ok(value, proof) => LookupResult::Ok(value, MerkleProof { pos, proof }),
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
        }
    }

    fn verify(
        &self,
        pos: Self::Index,
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
        let computed_root_value = proof.verify_membership_proof::<H, TreeArity>()?;
        Ok(computed_root_value == self.root.value())
    }
}

impl<E, H, I, TreeArity, T> AppendableMerkleTreeScheme for MerkleTree<E, H, I, TreeArity, T>
where
    E: ToVec<T> + CanonicalSerialize + CanonicalDeserialize + Copy + Eq + PartialEq + Debug,
    H: DigestAlgorithm<T>,
    I: IndexOps
        + ToVec<T>
        + Ord
        + Default
        + PartialOrd
        + CanonicalSerialize
        + CanonicalDeserialize
        + ToUsize
        + Eq
        + PartialEq
        + Clone
        + Copy
        + Debug
        + From<u64>,
    TreeArity: Unsigned,
    T: Default
        + Eq
        + PartialEq
        + CanonicalSerialize
        + CanonicalDeserialize
        + Clone
        + Display
        + Copy,
{
    fn push(&mut self, elem: impl Borrow<Self::Element>) -> Result<(), PrimitivesError> {
        if self.num_leaves >= self.capacity {
            return Err(PrimitivesError::InternalError(
                "Merkle tree full".to_string(),
            ));
        }

        let branches = index_to_branches::<I, TreeArity>(self.num_leaves, self.height);
        self.root.update_internal::<H, TreeArity>(
            self.height,
            self.num_leaves,
            &branches,
            elem.borrow(),
        )?;
        self.num_leaves += I::from(1);
        Ok(())
    }

    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<(), PrimitivesError> {
        let mut iter = elems.into_iter().peekable();

        let branch = index_to_branches::<I, TreeArity>(self.num_leaves, self.height);
        self.num_leaves += I::from(self.root.extend_internal::<H, TreeArity>(
            self.height,
            self.num_leaves,
            &branch,
            true,
            &mut iter,
        )?);
        if iter.peek().is_some() {
            return Err(PrimitivesError::ParameterError(
                "To much data for extension".to_string(),
            ));
        }
        Ok(())
    }
}

impl<E, H, I, TreeArity, T> ForgetableMerkleTreeScheme for MerkleTree<E, H, I, TreeArity, T>
where
    E: ToVec<T> + CanonicalSerialize + CanonicalDeserialize + Copy + Eq + PartialEq + Debug,
    H: DigestAlgorithm<T>,
    I: IndexOps
        + ToVec<T>
        + Ord
        + Default
        + PartialOrd
        + CanonicalDeserialize
        + CanonicalSerialize
        + ToUsize
        + Eq
        + PartialEq
        + Clone
        + Copy
        + Debug
        + From<u64>,
    TreeArity: Unsigned,
    T: Default
        + Eq
        + PartialEq
        + CanonicalDeserialize
        + CanonicalSerialize
        + Clone
        + Display
        + Copy,
{
    fn forget(&mut self, pos: Self::Index) -> LookupResult<Self::Element, Self::MembershipProof> {
        let branches = index_to_branches::<I, TreeArity>(pos, self.height);
        match self.root.forget_internal(self.height, &branches) {
            LookupResult::Ok(elem, proof) => {
                LookupResult::Ok(elem, MerkleProof::<E, I, T> { pos, proof })
            },
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
        }
    }

    fn remember(
        &mut self,
        pos: Self::Index,
        _element: impl Borrow<Self::Element>,
        proof: impl Borrow<Self::MembershipProof>,
    ) -> Result<(), PrimitivesError> {
        let proof = proof.borrow();
        let branches = index_to_branches::<I, TreeArity>(pos, self.height);
        if let MerkleNode::<E, I, T>::Leaf {
            value: _,
            pos,
            elem,
        } = proof.proof[0]
        {
            let proof_leaf_value = digest_leaf::<E, H, I, T>(pos, elem, Self::ARITY);
            let mut path_values = vec![proof_leaf_value];
            branches.iter().zip(proof.proof.iter().skip(1)).fold(
                Ok(proof_leaf_value),
                |result, (branch, node)| -> Result<T, PrimitivesError> {
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

// TODO(Chengyu): unit tests
#[cfg(test)]
mod mt_tests {
    use crate::{
        merkle_tree::{
            examples::RescueMerkleTree,
            internal::{MerkleNode, MerkleProof},
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
        assert!(RescueMerkleTree::<F>::from_elems(1, &[F::from(0u64); 3]).is_ok());
        assert!(RescueMerkleTree::<F>::from_elems(1, &[F::from(0u64); 4]).is_err());
    }

    #[test]
    fn test_mt_insertion() {
        test_mt_insertion_helper::<Fq254>();
        test_mt_insertion_helper::<Fq377>();
        test_mt_insertion_helper::<Fq381>();
    }

    fn test_mt_insertion_helper<F: RescueParameter>() {
        let mut mt = RescueMerkleTree::<F>::from_elems(2, &[]).unwrap();
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
        let mt = RescueMerkleTree::<F>::from_elems(2, &[F::from(3u64), F::from(1u64)]).unwrap();
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
        let mut mt = RescueMerkleTree::<F>::from_elems(2, &[F::from(3u64), F::from(1u64)]).unwrap();
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
