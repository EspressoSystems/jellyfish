// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical append only merkle tree

use super::{
    internal::{build_tree_internal, MerkleNode, MerkleProof},
    AppendableMerkleTreeScheme, DigestAlgorithm, Element, ForgetableMerkleTreeScheme, Index,
    LookupResult, MerkleCommitment, MerkleTreeScheme, NodeValue, ToTreversalPath,
};
use crate::errors::PrimitivesError;
use ark_std::{
    borrow::Borrow, boxed::Box, fmt::Debug, marker::PhantomData, string::ToString, vec, vec::Vec,
};
use num_bigint::BigUint;
use num_traits::pow::pow;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

/// A standard append only Merkle tree implementation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleTree<E, H, I, Arity, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64>,
    Arity: Unsigned,
    T: NodeValue,
{
    root: Box<MerkleNode<E, I, T>>,
    height: usize,
    num_leaves: u64,

    _phantom_h: PhantomData<H>,
    _phantom_ta: PhantomData<Arity>,
}

impl<E, H, I, Arity, T> MerkleTreeScheme for MerkleTree<E, H, I, Arity, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64>,
    Arity: Unsigned,
    T: NodeValue,
{
    type Element = E;
    type Digest = H;
    type Index = I;
    type NodeValue = T;
    type MembershipProof = MerkleProof<E, I, T>;
    // TODO(Chengyu): implement batch membership proof
    type BatchMembershipProof = ();

    const ARITY: usize = Arity::USIZE;

    fn from_elems(
        height: usize,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<Self, PrimitivesError> {
        let (root, num_leaves) = build_tree_internal::<E, H, I, Arity, T>(height, elems)?;
        Ok(MerkleTree {
            root,
            height,
            num_leaves,
            _phantom_h: PhantomData,
            _phantom_ta: PhantomData,
        })
    }

    fn height(&self) -> usize {
        self.height
    }

    fn capacity(&self) -> BigUint {
        pow(BigUint::from(Self::ARITY), self.height)
    }

    fn num_leaves(&self) -> u64 {
        self.num_leaves
    }

    fn root(&self) -> T {
        self.root.value()
    }

    fn commitment(&self) -> MerkleCommitment<T> {
        MerkleCommitment {
            root_value: self.root.value(),
            height: self.height,
            num_leaves: self.num_leaves,
        }
    }

    fn lookup(&self, pos: Self::Index) -> LookupResult<Self::Element, Self::MembershipProof> {
        let traversal_path = pos.to_treverse_path(self.height, Self::ARITY);
        match self.root.lookup_internal(self.height, &traversal_path) {
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
        let computed_root_value = proof.verify_membership_proof::<H, Arity>()?;
        Ok(computed_root_value == self.root.value())
    }
}

impl<E, H, I, Arity, T> AppendableMerkleTreeScheme for MerkleTree<E, H, I, Arity, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64>,
    Arity: Unsigned,
    T: NodeValue,
{
    fn push(&mut self, elem: impl Borrow<Self::Element>) -> Result<(), PrimitivesError> {
        self.extend([elem])
    }

    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<(), PrimitivesError> {
        let mut iter = elems.into_iter().peekable();

        let traversal_path = self.num_leaves.to_treverse_path(self.height, Self::ARITY);
        self.num_leaves += self.root.extend_internal::<H, Arity>(
            self.height,
            I::from(self.num_leaves),
            &traversal_path,
            true,
            &mut iter,
        )?;
        if iter.peek().is_some() {
            return Err(PrimitivesError::ParameterError(
                "Exceed merkle tree capacity".to_string(),
            ));
        }
        Ok(())
    }
}

impl<E, H, I, Arity, T> ForgetableMerkleTreeScheme for MerkleTree<E, H, I, Arity, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64>,
    Arity: Unsigned,
    T: NodeValue,
{
    fn forget(&mut self, pos: Self::Index) -> LookupResult<Self::Element, Self::MembershipProof> {
        let traversal_path = pos.to_treverse_path(self.height, Self::ARITY);
        match self.root.forget_internal(self.height, &traversal_path) {
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
        let traversal_path = pos.to_treverse_path(self.height, Self::ARITY);
        if let MerkleNode::<E, I, T>::Leaf {
            value: _,
            pos,
            elem,
        } = proof.proof[0]
        {
            // let proof_leaf_value = digest_leaf::<E, H, I, T>(pos, elem, Self::ARITY);
            let proof_leaf_value = H::digest_leaf(&pos, &elem);
            let mut path_values = vec![proof_leaf_value];
            traversal_path.iter().zip(proof.proof.iter().skip(1)).fold(
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
            self.root.remember_internal::<H, Arity>(
                self.height,
                &traversal_path,
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
        assert_eq!(mt.capacity(), BigUint::from(9u64));
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
