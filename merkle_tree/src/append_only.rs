// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of an append-only Merkle tree.

use super::internal::{
    build_tree_internal, MerkleNode, MerkleTreeIntoIter, MerkleTreeIter, MerkleTreeProof,
};
use super::{
    AppendableMerkleTreeScheme, DigestAlgorithm, Element, ForgetableMerkleTreeScheme, Index,
    LookupResult, MerkleProof, MerkleTreeScheme, NodeValue, ToTraversalPath,
};
use crate::{
    errors::MerkleTreeError, impl_forgetable_merkle_tree_scheme, impl_merkle_tree_scheme,
    VerificationResult,
};
use alloc::sync::Arc;
use ark_std::{borrow::Borrow, fmt::Debug, marker::PhantomData, vec, vec::Vec};
use num_bigint::BigUint;
use num_traits::pow::pow;
use serde::{Deserialize, Serialize};

// Apply macros for MerkleTree implementations
impl_merkle_tree_scheme!(MerkleTree);
impl_forgetable_merkle_tree_scheme!(MerkleTree);

/// Merkle Tree implementation with append and forget functionality.
impl<E, H, I, const ARITY: usize, T> MerkleTree<E, H, I, ARITY, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index,
    T: NodeValue,
{
    /// Initialize an empty Merkle tree.
    pub fn new(height: usize) -> Self {
        Self {
            root: Arc::new(MerkleNode::<E, I, T>::Empty),
            height,
            num_leaves: 0,
            _phantom: PhantomData,
        }
    }
}

impl<E, H, const ARITY: usize, T> MerkleTree<E, H, u64, ARITY, T>
where
    E: Element,
    H: DigestAlgorithm<E, u64, T>,
    T: NodeValue,
{
    /// Construct a Merkle tree from elements.
    pub fn from_elems(
        height: Option<usize>,
        elems: impl IntoIterator<Item = impl Borrow<E>>,
    ) -> Result<Self, MerkleTreeError> {
        let (root, height, num_leaves) = build_tree_internal::<E, H, ARITY, T>(height, elems)?;
        Ok(Self {
            root,
            height,
            num_leaves,
            _phantom: PhantomData,
        })
    }
}

impl<E, H, const ARITY: usize, T> AppendableMerkleTreeScheme for MerkleTree<E, H, u64, ARITY, T>
where
    E: Element,
    H: DigestAlgorithm<E, u64, T>,
    T: NodeValue,
{
    /// Add a single element to the Merkle tree.
    fn push(&mut self, elem: impl Borrow<Self::Element>) -> Result<(), MerkleTreeError> {
        self.extend([elem])
    }

    /// Extend the Merkle tree with multiple elements.
    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<(), MerkleTreeError> {
        let mut iter = elems.into_iter().peekable();

        let traversal_path =
            ToTraversalPath::<ARITY>::to_traversal_path(&self.num_leaves, self.height);

        let (root, num_inserted) = self.root.extend_internal::<H, ARITY>(
            self.height,
            &self.num_leaves,
            &traversal_path,
            true,
            &mut iter,
        )?;

        self.root = root;
        self.num_leaves += num_inserted;

        if iter.peek().is_some() {
            return Err(MerkleTreeError::ExceedCapacity);
        }

        Ok(())
    }
}

// ============================= Tests =============================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        internal::{MerkleNode, MerkleTreeProof},
        prelude::{RescueMerkleTree, RescueSparseMerkleTree},
    };
    use ark_bls12_377::Fr as Fr377;
    use ark_bls12_381::Fr as Fr381;
    use ark_bn254::Fr as Fr254;
    use jf_rescue::RescueParameter;

    #[test]
    fn test_merkle_tree_builder() {
        test_builder_helper::<Fr254>();
        test_builder_helper::<Fr377>();
        test_builder_helper::<Fr381>();
    }

    fn test_builder_helper<F: RescueParameter>() {
        assert!(RescueMerkleTree::<F>::from_elems(None, [F::from(0u64); 3]).is_ok());
        assert!(RescueMerkleTree::<F>::from_elems(Some(1), [F::from(0u64); 4]).is_err());
    }

    #[test]
    fn test_merkle_tree_insertion() {
        test_insertion_helper::<Fr254>();
        test_insertion_helper::<Fr377>();
        test_insertion_helper::<Fr381>();
    }

    fn test_insertion_helper<F: RescueParameter>() {
        let mut mt = RescueMerkleTree::<F>::new(2);
        assert_eq!(mt.capacity(), BigUint::from(9u64));
        assert!(mt.push(F::from(2u64)).is_ok());
        assert!(mt.push(F::from(3u64)).is_ok());
        assert!(mt.extend(&[F::from(0u64); 9]).is_err());
        assert_eq!(mt.num_leaves(), 9u64);

        assert!(mt.push(F::from(0u64)).is_err());
        assert!(mt.extend(&[]).is_ok());
        assert!(mt.extend(&[F::from(1u64)]).is_err());
    }

    #[test]
    fn test_merkle_tree_lookup() {
        test_lookup_helper::<Fr254>();
        test_lookup_helper::<Fr377>();
        test_lookup_helper::<Fr381>();
    }

    fn test_lookup_helper<F: RescueParameter>() {
        let mt = RescueMerkleTree::<F>::from_elems(None, [F::from(0u64)]).unwrap();
        let (elem, _) = mt.lookup(0).expect_ok().unwrap();
        assert_eq!(elem, &F::from(0u64));

        let mt =
            RescueMerkleTree::<F>::from_elems(Some(2), [F::from(3u64), F::from(1u64)]).unwrap();
        let commitment = mt.commitment();
        let (elem, proof) = mt.lookup(0).expect_ok().unwrap();
        assert_eq!(elem, &F::from(3u64));
        assert!(
            RescueMerkleTree::<F>::verify(&commitment, 0u64, elem, &proof)
                .unwrap()
                .is_ok()
        );

        let mut bad_proof = proof.clone();
        bad_proof.0[0][0] = F::one();
        assert!(
            RescueMerkleTree::<F>::verify(&commitment, 0, elem, &bad_proof)
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn test_merkle_tree_serde() {
        test_serde_helper::<Fr254>();
        test_serde_helper::<Fr377>();
        test_serde_helper::<Fr381>();
    }

    fn test_serde_helper<F: RescueParameter>() {
        let mt =
            RescueMerkleTree::<F>::from_elems(Some(2), [F::from(3u64), F::from(1u64)]).unwrap();
        let (_, proof) = mt.lookup(0).expect_ok().unwrap();

        assert_eq!(
            mt,
            bincode::deserialize(&bincode::serialize(&mt).unwrap()).unwrap()
        );
        assert_eq!(
            proof,
            bincode::deserialize(&bincode::serialize(&proof).unwrap()).unwrap()
        );
    }
}
