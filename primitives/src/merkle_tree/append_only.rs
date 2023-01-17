// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical append only merkle tree

use core::ops::AddAssign;

use super::{
    internal::{build_tree_internal, MerkleNode, MerkleProof, MerkleTreeCommitment},
    AppendableMerkleTreeScheme, DigestAlgorithm, Element, ForgetableMerkleTreeScheme, Index,
    LookupResult, MerkleCommitment, MerkleTreeScheme, NodeValue, ToTraversalPath,
};
use crate::{errors::PrimitivesError, impl_forgetable_merkle_tree_scheme, impl_merkle_tree_scheme};
use ark_std::{
    borrow::Borrow, boxed::Box, fmt::Debug, marker::PhantomData, string::ToString, vec, vec::Vec,
};
use num_bigint::BigUint;
use num_traits::pow::pow;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

impl_merkle_tree_scheme!(MerkleTree, build_tree_internal);
impl_forgetable_merkle_tree_scheme!(MerkleTree);

impl<E, H, I, Arity, T> AppendableMerkleTreeScheme for MerkleTree<E, H, I, Arity, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64> + AddAssign + ToTraversalPath<Arity>,
    Arity: Unsigned,
    T: NodeValue,
{
    fn push(&mut self, elem: impl Borrow<Self::Element>) -> Result<(), PrimitivesError> {
        <Self as AppendableMerkleTreeScheme>::extend(self, [elem])
    }

    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<(), PrimitivesError> {
        let mut iter = elems.into_iter().peekable();

        let traversal_path = I::from(self.num_leaves).to_traversal_path(self.height);
        self.num_leaves += self.root.extend_internal::<H, Arity>(
            self.height,
            &I::from(self.num_leaves),
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

// TODO(Chengyu): extract a merkle frontier

// TODO(Chengyu): unit tests
#[cfg(test)]
mod mt_tests {
    use crate::{
        merkle_tree::{
            internal::{MerkleNode, MerkleProof},
            prelude::RescueMerkleTree,
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
        assert_eq!(proof.tree_height(), 3);
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

        let mut forge_proof = MerkleProof::new(2, proof.proof);
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
        assert_eq!(proof.tree_height(), 3);
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

        let mut forge_proof = MerkleProof::new(2, proof.proof.clone());
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

    #[test]
    fn test_mt_serde() {
        test_mt_serde_helper::<Fq254>();
        test_mt_serde_helper::<Fq377>();
        test_mt_serde_helper::<Fq381>();
    }

    fn test_mt_serde_helper<F: RescueParameter>() {
        let mt = RescueMerkleTree::<F>::from_elems(2, &[F::from(3u64), F::from(1u64)]).unwrap();
        let proof = mt.lookup(0).expect_ok().unwrap().1;
        let node = &proof.proof[0];

        assert_eq!(
            mt,
            bincode::deserialize(&bincode::serialize(&mt).unwrap()).unwrap()
        );
        assert_eq!(
            proof,
            bincode::deserialize(&bincode::serialize(&proof).unwrap()).unwrap()
        );
        assert_eq!(
            *node,
            bincode::deserialize(&bincode::serialize(node).unwrap()).unwrap()
        );
    }
}
