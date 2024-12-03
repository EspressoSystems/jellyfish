// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A light weight merkle tree is an append only merkle tree who only keeps its
//! frontier -- the right-most path.

use super::{
    internal::{
        build_light_weight_tree_internal, MerkleNode, MerkleTreeIntoIter, MerkleTreeIter,
        MerkleTreeProof,
    },
    AppendableMerkleTreeScheme, DigestAlgorithm, Element, ForgetableMerkleTreeScheme, Index,
    LookupResult, MerkleProof, MerkleTreeScheme, NodeValue, ToTraversalPath,
};
use crate::{
    errors::MerkleTreeError, impl_forgetable_merkle_tree_scheme, impl_merkle_tree_scheme,
    VerificationResult,
};
use alloc::sync::Arc;
use ark_std::{borrow::Borrow, fmt::Debug, marker::PhantomData, string::ToString, vec, vec::Vec};
use num_bigint::BigUint;
use num_traits::pow::pow;
use serde::{Deserialize, Serialize};

impl_merkle_tree_scheme!(LightWeightMerkleTree);
impl_forgetable_merkle_tree_scheme!(LightWeightMerkleTree);

impl<E, H, I, const ARITY: usize, T> LightWeightMerkleTree<E, H, I, ARITY, T>
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

impl<E, H, const ARITY: usize, T> LightWeightMerkleTree<E, H, u64, ARITY, T>
where
    E: Element,
    H: DigestAlgorithm<E, u64, T>,
    T: NodeValue,
{
    /// Construct a new Merkle tree with given height from a data slice
    /// * `height` - height of the Merkle tree, if `None`, it will calculate the
    ///   minimum height that could hold all elements.
    /// * `elems` - an iterator to all elements
    /// * `returns` - A constructed Merkle tree, or `Err()` if errors
    pub fn from_elems(
        height: Option<usize>,
        elems: impl IntoIterator<Item = impl Borrow<E>>,
    ) -> Result<Self, MerkleTreeError> {
        let (root, height, num_leaves) =
            build_light_weight_tree_internal::<E, H, ARITY, T>(height, elems)?;
        Ok(Self {
            root,
            height,
            num_leaves,
            _phantom: PhantomData,
        })
    }
}

impl<E, H, const ARITY: usize, T> AppendableMerkleTreeScheme
    for LightWeightMerkleTree<E, H, u64, ARITY, T>
where
    E: Element,
    H: DigestAlgorithm<E, u64, T>,
    T: NodeValue,
{
    fn push(&mut self, elem: impl Borrow<Self::Element>) -> Result<(), MerkleTreeError> {
        <Self as AppendableMerkleTreeScheme>::extend(self, [elem])
    }

    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<(), MerkleTreeError> {
        let mut iter = elems.into_iter().peekable();

        let traversal_path =
            ToTraversalPath::<ARITY>::to_traversal_path(&self.num_leaves, self.height);
        let (root, num_inserted) = self.root.extend_and_forget_internal::<H, ARITY>(
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

#[cfg(test)]
mod mt_tests {
    use crate::{
        internal::MerkleNode,
        prelude::{RescueLightWeightMerkleTree, RescueMerkleTree},
        *,
    };
    use ark_bls12_377::Fr as Fr377;
    use ark_bls12_381::Fr as Fr381;
    use ark_bn254::Fr as Fr254;
    use jf_rescue::RescueParameter;

    #[test]
    fn test_light_mt_builder() {
        test_light_mt_builder_helper::<Fr254>();
        test_light_mt_builder_helper::<Fr377>();
        test_light_mt_builder_helper::<Fr381>();
    }

    fn test_light_mt_builder_helper<F: RescueParameter>() {
        let arity: usize = RescueLightWeightMerkleTree::<F>::ARITY;
        let mut data = vec![F::from(0u64); arity];
        assert!(RescueLightWeightMerkleTree::<F>::from_elems(Some(1), &data).is_ok());
        data.push(F::from(0u64));
        assert!(RescueLightWeightMerkleTree::<F>::from_elems(Some(1), &data).is_err());
    }

    #[test]
    fn test_light_mt_insertion() {
        test_light_mt_insertion_helper::<Fr254>();
        test_light_mt_insertion_helper::<Fr377>();
        test_light_mt_insertion_helper::<Fr381>();
    }

    fn test_light_mt_insertion_helper<F: RescueParameter>() {
        let mut mt = RescueLightWeightMerkleTree::<F>::new(2);
        assert_eq!(mt.capacity(), BigUint::from(9u64));
        assert!(mt.push(F::from(2u64)).is_ok());
        assert!(mt.push(F::from(3u64)).is_ok());
        assert!(mt.extend(&[F::from(0u64); 9]).is_err()); // Will err, but first 7 items will be inserted
        assert_eq!(mt.num_leaves(), 9); // full merkle tree

        // Now unable to insert more data
        assert!(mt.push(F::from(0u64)).is_err());
        assert!(mt.extend(&[]).is_ok());
        assert!(mt.extend(&[F::from(1u64)]).is_err());

        // Checks that the prior elements are all forgotten
        (0..8).for_each(|i| assert!(mt.lookup(i).expect_not_in_memory().is_ok()));
        assert!(mt.lookup(8).expect_ok().is_ok());
    }

    #[test]
    fn test_light_mt_lookup() {
        test_light_mt_lookup_helper::<Fr254>();
        test_light_mt_lookup_helper::<Fr377>();
        test_light_mt_lookup_helper::<Fr381>();
    }

    fn test_light_mt_lookup_helper<F: RescueParameter>() {
        // singleton merkle tree test (#499)
        let mt = RescueLightWeightMerkleTree::<F>::from_elems(None, [F::from(0u64)]).unwrap();
        let (elem, _) = mt.lookup(0).expect_ok().unwrap();
        assert_eq!(elem, &F::from(0u64));

        let mut mt =
            RescueLightWeightMerkleTree::<F>::from_elems(Some(2), [F::from(3u64), F::from(1u64)])
                .unwrap();
        let mut full_mt =
            RescueMerkleTree::<F>::from_elems(Some(2), [F::from(3u64), F::from(1u64)]).unwrap();
        assert!(mt.lookup(0).expect_not_in_memory().is_ok());
        assert!(mt.lookup(1).expect_ok().is_ok());
        assert!(mt.extend(&[F::from(33u64), F::from(41u64)]).is_ok());
        assert!(full_mt.extend(&[F::from(33u64), F::from(41u64)]).is_ok());
        assert!(mt.lookup(0).expect_not_in_memory().is_ok());
        assert!(mt.lookup(1).expect_not_in_memory().is_ok());
        assert!(mt.lookup(2).expect_not_in_memory().is_ok());
        assert!(mt.lookup(3).expect_ok().is_ok());

        // Should have the same commitment
        assert_eq!(mt.commitment(), full_mt.commitment());

        let commitment = mt.commitment();
        let (elem, proof) = full_mt.lookup(0).expect_ok().unwrap();
        assert_eq!(elem, &F::from(3u64));
        assert!(
            RescueLightWeightMerkleTree::<F>::verify(&commitment, 0, elem, &proof)
                .unwrap()
                .is_ok()
        );

        // Wrong element value, should fail.
        assert!(
            RescueLightWeightMerkleTree::<F>::verify(&commitment, 0, F::from(14u64), &proof)
                .unwrap()
                .is_err()
        );

        // Wrong pos, should fail.
        assert!(
            RescueLightWeightMerkleTree::<F>::verify(&commitment, 2, elem, &proof)
                .unwrap()
                .is_err()
        );

        let mut bad_proof = proof.clone();
        bad_proof.0[0][0] = F::one();

        assert!(
            RescueLightWeightMerkleTree::<F>::verify(&commitment, 0, elem, &bad_proof)
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn test_light_mt_serde() {
        test_light_mt_serde_helper::<Fr254>();
        test_light_mt_serde_helper::<Fr377>();
        test_light_mt_serde_helper::<Fr381>();
    }

    fn test_light_mt_serde_helper<F: RescueParameter>() {
        let mt =
            RescueLightWeightMerkleTree::<F>::from_elems(Some(2), [F::from(3u64), F::from(1u64)])
                .unwrap();
        let (_, proof) = mt.lookup(1).expect_ok().unwrap();

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
