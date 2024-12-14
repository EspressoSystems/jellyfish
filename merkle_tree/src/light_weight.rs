// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A lightweight Merkle tree implementation.
//! This append-only tree retains only the frontier (right-most path).

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
use ark_std::{borrow::Borrow, vec, vec::Vec, fmt::Debug, marker::PhantomData};
use num_bigint::BigUint;
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
    /// Creates an empty lightweight Merkle tree with the specified height.
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
    /// Constructs a new Merkle tree from a collection of elements.
    ///
    /// # Arguments
    /// - `height`: Height of the tree. If `None`, it's calculated based on the number of elements.
    /// - `elems`: Iterator over the elements to insert into the tree.
    ///
    /// # Returns
    /// - `Ok(Self)`: If the tree is constructed successfully.
    /// - `Err(MerkleTreeError)`: If an error occurs during construction.
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
    /// Adds a single element to the tree.
    fn push(&mut self, elem: impl Borrow<Self::Element>) -> Result<(), MerkleTreeError> {
        self.extend([elem])
    }

    /// Adds multiple elements to the tree, extending the frontier.
    ///
    /// # Arguments
    /// - `elems`: Iterator over elements to insert.
    ///
    /// # Returns
    /// - `Ok(())`: If all elements are successfully added.
    /// - `Err(MerkleTreeError)`: If the tree exceeds capacity or other errors occur.
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
mod tests {
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
        let arity = RescueLightWeightMerkleTree::<F>::ARITY;
        let mut data = vec![F::from(0u64); arity];
        assert!(RescueLightWeightMerkleTree::<F>::from_elems(Some(1), &data).is_ok());
        data.push(F::from(0u64));
        assert!(RescueLightWeightMerkleTree::<F>::from_elems(Some(1), &data).is_err());
    }

    #[test]
    fn test_light_mt_insertion() {
        let mut mt = RescueLightWeightMerkleTree::<Fr254>::new(2);
        assert_eq!(mt.capacity(), BigUint::from(9u64));
        assert!(mt.push(Fr254::from(2u64)).is_ok());
        assert!(mt.push(Fr254::from(3u64)).is_ok());
        assert!(mt.extend(&[Fr254::from(0u64); 9]).is_err());
        assert_eq!(mt.num_leaves(), 9); // Tree is now full.

        // Insertion beyond capacity.
        assert!(mt.push(Fr254::from(0u64)).is_err());
        assert!(mt.extend(&[Fr254::from(1u64)]).is_err());

        // Ensure old elements are forgotten.
        (0..8).for_each(|i| assert!(mt.lookup(i).expect_not_in_memory().is_ok()));
        assert!(mt.lookup(8).expect_ok().is_ok());
    }

    #[test]
    fn test_light_mt_lookup() {
        let mut mt = RescueLightWeightMerkleTree::<Fr254>::from_elems(
            Some(2),
            [Fr254::from(3u64), Fr254::from(1u64)],
        )
        .unwrap();

        // Perform lookups.
        assert!(mt.lookup(0).expect_not_in_memory().is_ok());
        assert!(mt.lookup(1).expect_ok().is_ok());

        // Extend tree and ensure commitments match.
        mt.extend(&[Fr254::from(33u64), Fr254::from(41u64)]).unwrap();
        assert_eq!(mt.num_leaves(), 4);
    }

    #[test]
    fn test_light_mt_serde() {
        let mt = RescueLightWeightMerkleTree::<Fr254>::from_elems(
            Some(2),
            [Fr254::from(3u64), Fr254::from(1u64)],
        )
        .unwrap();

        let serialized = bincode::serialize(&mt).unwrap();
        let deserialized: RescueLightWeightMerkleTree<Fr254> =
            bincode::deserialize(&serialized).unwrap();
        assert_eq!(mt, deserialized);
    }
}
