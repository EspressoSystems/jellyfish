// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical append only merkle tree

use super::{
    internal::{
        build_tree_internal, MerkleNode, MerkleProof, MerkleTreeCommitment, MerkleTreeIntoIter,
        MerkleTreeIter,
    },
    AppendableMerkleTreeScheme, DigestAlgorithm, Element, ForgetableMerkleTreeScheme, Index,
    LookupResult, MerkleCommitment, MerkleTreeScheme, NodeValue, ToTraversalPath,
};
use crate::{
    errors::{MerkleTreeError, VerificationResult},
    impl_forgetable_merkle_tree_scheme, impl_merkle_tree_scheme,
};
use alloc::sync::Arc;
use ark_std::{borrow::Borrow, fmt::Debug, marker::PhantomData, string::ToString, vec, vec::Vec};
use num_bigint::BigUint;
use num_traits::pow::pow;
use serde::{Deserialize, Serialize};

impl_merkle_tree_scheme!(MerkleTree);
impl_forgetable_merkle_tree_scheme!(MerkleTree);

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
    /// Construct a new Merkle tree with given height from a data slice
    /// * `height` - height of the Merkle tree, if `None`, it will calculate the
    ///   minimum height that could hold all elements.
    /// * `elems` - an iterator to all elements
    /// * `returns` - A constructed Merkle tree, or `Err()` if errors
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

// TODO(Chengyu): extract a merkle frontier

#[cfg(test)]
mod mt_tests {
    use crate::{
        internal::{MerkleNode, MerkleProof},
        prelude::{RescueMerkleTree, RescueSparseMerkleTree},
        *,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_bls12_381::Fq as Fq381;
    use ark_bn254::Fq as Fq254;
    use jf_rescue::RescueParameter;

    #[test]
    fn test_mt_builder() {
        test_mt_builder_helper::<Fq254>();
        test_mt_builder_helper::<Fq377>();
        test_mt_builder_helper::<Fq381>();
    }

    fn test_mt_builder_helper<F: RescueParameter>() {
        assert!(RescueMerkleTree::<F>::from_elems(None, [F::from(0u64); 3]).is_ok());
        assert!(RescueMerkleTree::<F>::from_elems(Some(1), [F::from(0u64); 4]).is_err());
    }

    #[test]
    fn test_mt_insertion() {
        test_mt_insertion_helper::<Fq254>();
        test_mt_insertion_helper::<Fq377>();
        test_mt_insertion_helper::<Fq381>();
    }

    fn test_mt_insertion_helper<F: RescueParameter>() {
        let mut mt = RescueMerkleTree::<F>::new(2);
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
        // singleton merkle tree test (#499)
        let mt = RescueMerkleTree::<F>::from_elems(None, [F::from(0u64)]).unwrap();
        let (elem, _) = mt.lookup(0).expect_ok().unwrap();
        assert_eq!(elem, &F::from(0u64));

        let mt =
            RescueMerkleTree::<F>::from_elems(Some(2), [F::from(3u64), F::from(1u64)]).unwrap();
        let root = mt.commitment().digest();
        let (elem, proof) = mt.lookup(0).expect_ok().unwrap();
        assert_eq!(elem, &F::from(3u64));
        assert_eq!(proof.tree_height(), 3);
        assert!(RescueMerkleTree::<F>::verify(&root, 0u64, &proof)
            .unwrap()
            .is_ok());

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

        let result = RescueMerkleTree::<F>::verify(&root, 0, &bad_proof);
        assert!(result.unwrap().is_err());

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
        let result = RescueMerkleTree::<F>::verify(&root, 0, &forge_proof);
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn test_mt_forget_remember() {
        test_mt_forget_remember_helper::<Fq254>();
        test_mt_forget_remember_helper::<Fq377>();
        test_mt_forget_remember_helper::<Fq381>();
    }

    fn test_mt_forget_remember_helper<F: RescueParameter>() {
        let mut mt =
            RescueMerkleTree::<F>::from_elems(Some(2), [F::from(3u64), F::from(1u64)]).unwrap();
        let root = mt.commitment().digest();
        let (lookup_elem, lookup_proof) = mt.lookup(0).expect_ok().unwrap();
        let lookup_elem = *lookup_elem;
        let (elem, proof) = mt.forget(0).expect_ok().unwrap();
        assert_eq!(lookup_elem, elem);
        assert_eq!(lookup_proof, proof);
        assert_eq!(elem, F::from(3u64));
        assert_eq!(proof.tree_height(), 3);
        assert!(RescueMerkleTree::<F>::verify(&root, 0, &lookup_proof)
            .unwrap()
            .is_ok());
        assert!(RescueMerkleTree::<F>::verify(&root, 0, &proof)
            .unwrap()
            .is_ok());

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

        let result = mt.remember(0, elem, &bad_proof);
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
        let result = mt.remember(2, elem, &forge_proof);
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
        let mt =
            RescueMerkleTree::<F>::from_elems(Some(2), [F::from(3u64), F::from(1u64)]).unwrap();
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

    #[test]
    fn test_mt_iter() {
        test_mt_iter_helper::<Fq254>();
        test_mt_iter_helper::<Fq377>();
        test_mt_iter_helper::<Fq381>();
    }

    fn test_mt_iter_helper<F: RescueParameter>() {
        let mut mt = RescueMerkleTree::<F>::from_elems(
            Some(2),
            [F::from(0u64), F::from(1u64), F::from(2u64)],
        )
        .unwrap();
        assert!(mt.iter().all(|(index, elem)| { elem == &F::from(*index) }));

        // Forget index 1
        assert!(mt.forget(1).expect_ok().is_ok());
        // Number of leaves shall not change
        assert_eq!(mt.num_leaves(), 3);
        // Leaves that are forgotten doesn't appear here
        let leaves = mt.into_iter().collect::<Vec<_>>();
        assert_eq!(leaves, [(0, F::from(0u64)), (2, F::from(2u64))]);

        let kv_set = [
            (BigUint::from(64u64), F::from(32u64)),
            (BigUint::from(123u64), F::from(234u64)),
        ];
        let mut mt = RescueSparseMerkleTree::<BigUint, F>::from_kv_set(10, &kv_set).unwrap();
        let kv_refs = kv_set
            .iter()
            .map(|tuple| (&tuple.0, &tuple.1))
            .collect::<Vec<_>>();
        assert_eq!(mt.iter().collect::<Vec<_>>(), kv_refs);
        // insert a new key-value pair
        mt.update(BigUint::from(32u64), F::from(16u64)).unwrap();
        // forget a leave
        mt.forget(BigUint::from(123u64)).expect_ok().unwrap();
        // Check that new insertion and forgeting are reflected
        assert_eq!(
            mt.into_iter().collect::<Vec<_>>(),
            [
                (BigUint::from(32u64), F::from(16u64)),
                (BigUint::from(64u64), F::from(32u64)),
            ]
        );
    }
}
