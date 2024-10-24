// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical Sparse Merkle Tree.
use super::{
    internal::{MerkleNode, MerkleTreeIntoIter, MerkleTreeIter, MerkleTreeProof},
    DigestAlgorithm, Element, ForgetableMerkleTreeScheme, ForgetableUniversalMerkleTreeScheme,
    Index, LookupResult, MerkleProof, MerkleTreeScheme, NodeValue,
    PersistentUniversalMerkleTreeScheme, ToTraversalPath, UniversalMerkleTreeScheme,
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

// A standard Universal Merkle tree implementation
impl_merkle_tree_scheme!(UniversalMerkleTree);
impl_forgetable_merkle_tree_scheme!(UniversalMerkleTree);

impl<E, H, I, const ARITY: usize, T> UniversalMerkleTree<E, H, I, ARITY, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + ToTraversalPath<ARITY>,
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

    /// Build a universal merkle tree from a key-value set.
    /// * `height` - height of the merkle tree
    /// * `data` - an iterator of key-value pairs. Could be a hashmap or simply
    ///   an array or a slice of (key, value) pairs
    pub fn from_kv_set<BI, BE>(
        height: usize,
        data: impl IntoIterator<Item = impl Borrow<(BI, BE)>>,
    ) -> Result<Self, MerkleTreeError>
    where
        BI: Borrow<I>,
        BE: Borrow<E>,
    {
        let mut mt = Self::new(height);
        for tuple in data.into_iter() {
            let (key, value) = tuple.borrow();
            UniversalMerkleTreeScheme::update(&mut mt, key.borrow(), value.borrow())?;
        }
        Ok(mt)
    }
}
impl<E, H, I, const ARITY: usize, T> UniversalMerkleTreeScheme
    for UniversalMerkleTree<E, H, I, ARITY, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + ToTraversalPath<ARITY>,
    T: NodeValue,
{
    type NonMembershipProof = MerkleTreeProof<T>;
    type BatchNonMembershipProof = ();

    fn update_with<F>(
        &mut self,
        pos: impl Borrow<Self::Index>,
        f: F,
    ) -> Result<LookupResult<E, (), ()>, MerkleTreeError>
    where
        F: FnOnce(Option<&Self::Element>) -> Option<Self::Element>,
    {
        let pos = pos.borrow();
        let traversal_path = pos.to_traversal_path(self.height);
        let (new_root, delta, result) =
            self.root
                .update_with_internal::<H, ARITY, F>(self.height, pos, &traversal_path, f)?;
        self.root = new_root;
        self.num_leaves = (delta + self.num_leaves as i64) as u64;
        Ok(result)
    }

    fn non_membership_verify(
        commitment: impl Borrow<Self::Commitment>,
        pos: impl Borrow<Self::Index>,
        proof: impl Borrow<Self::NonMembershipProof>,
    ) -> Result<VerificationResult, MerkleTreeError> {
        crate::internal::verify_merkle_proof::<E, H, I, ARITY, T>(
            commitment.borrow(),
            pos.borrow(),
            None,
            proof.borrow().path_values(),
        )
    }

    fn universal_lookup(
        &self,
        pos: impl Borrow<Self::Index>,
    ) -> LookupResult<&Self::Element, Self::MembershipProof, Self::NonMembershipProof> {
        let pos = pos.borrow();
        let traversal_path = pos.to_traversal_path(self.height);
        self.root.lookup_internal(self.height, &traversal_path)
    }
}

impl<E, H, I, const ARITY: usize, T> PersistentUniversalMerkleTreeScheme
    for UniversalMerkleTree<E, H, I, ARITY, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + ToTraversalPath<ARITY>,
    T: NodeValue,
{
    fn persistent_update_with<F>(
        &self,
        pos: impl Borrow<Self::Index>,
        f: F,
    ) -> Result<Self, MerkleTreeError>
    where
        F: FnOnce(Option<&Self::Element>) -> Option<Self::Element>,
    {
        let pos = pos.borrow();
        let traversal_path = pos.to_traversal_path(self.height);
        let (root, delta, _) =
            self.root
                .update_with_internal::<H, ARITY, F>(self.height, pos, &traversal_path, f)?;
        let num_leaves = (delta + self.num_leaves as i64) as u64;
        Ok(Self {
            root,
            height: self.height,
            num_leaves,
            _phantom: PhantomData,
        })
    }
}

impl<E, H, I, const ARITY: usize, T> ForgetableUniversalMerkleTreeScheme
    for UniversalMerkleTree<E, H, I, ARITY, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + ToTraversalPath<ARITY>,
    T: NodeValue,
{
    /// WARN(#495): this method breaks non-membership proofs.
    fn universal_forget(
        &mut self,
        pos: Self::Index,
    ) -> LookupResult<Self::Element, Self::MembershipProof, Self::NonMembershipProof> {
        let traversal_path = pos.to_traversal_path(self.height);
        let (root, result) = self.root.forget_internal(self.height, &traversal_path);
        self.root = root;
        result
    }

    fn non_membership_remember(
        &mut self,
        pos: Self::Index,
        proof: impl Borrow<Self::NonMembershipProof>,
    ) -> Result<(), MerkleTreeError> {
        let pos = pos.borrow();
        let proof = proof.borrow();
        if Self::non_membership_verify(&self.commitment(), pos, proof)?.is_err() {
            Err(MerkleTreeError::InconsistentStructureError(
                "Wrong proof".to_string(),
            ))
        } else {
            let traversal_path = pos.to_traversal_path(self.height);
            self.root = self.root.remember_internal::<H, ARITY>(
                self.height,
                &traversal_path,
                pos,
                None,
                proof.path_values(),
            )?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod mt_tests {
    use crate::{
        internal::{MerkleNode, MerkleTreeProof},
        prelude::{RescueHash, RescueSparseMerkleTree},
        DigestAlgorithm, ForgetableMerkleTreeScheme, ForgetableUniversalMerkleTreeScheme, Index,
        LookupResult, MerkleProof, MerkleTreeScheme, PersistentUniversalMerkleTreeScheme,
        ToTraversalPath, UniversalMerkleTreeScheme,
    };
    use ark_bls12_377::Fr as Fr377;
    use ark_bls12_381::Fr as Fr381;
    use ark_bn254::Fr as Fr254;
    use hashbrown::HashMap;
    use jf_rescue::RescueParameter;
    use num_bigint::BigUint;

    #[test]
    fn test_universal_mt_builder() {
        test_universal_mt_builder_helper::<Fr254>();
        test_universal_mt_builder_helper::<Fr377>();
        test_universal_mt_builder_helper::<Fr381>();
    }

    fn test_universal_mt_builder_helper<F: RescueParameter>() {
        let mt = RescueSparseMerkleTree::<BigUint, F>::from_kv_set(
            1,
            [(BigUint::from(1u64), F::from(1u64))],
        )
        .unwrap();
        assert_eq!(mt.num_leaves(), 1);

        let mut hashmap = HashMap::new();
        hashmap.insert(BigUint::from(1u64), F::from(2u64));
        hashmap.insert(BigUint::from(2u64), F::from(2u64));
        hashmap.insert(BigUint::from(1u64), F::from(3u64));
        let mt = RescueSparseMerkleTree::<BigUint, F>::from_kv_set(10, &hashmap).unwrap();
        assert_eq!(mt.num_leaves(), hashmap.len() as u64);
    }

    #[test]
    fn test_non_membership_lookup_and_verify() {
        test_non_membership_lookup_and_verify_helper::<Fr254>();
        test_non_membership_lookup_and_verify_helper::<Fr377>();
        test_non_membership_lookup_and_verify_helper::<Fr381>();
    }

    fn test_non_membership_lookup_and_verify_helper<F: RescueParameter>() {
        let mut hashmap = HashMap::new();
        hashmap.insert(BigUint::from(1u64), F::from(2u64));
        hashmap.insert(BigUint::from(2u64), F::from(2u64));
        hashmap.insert(BigUint::from(1u64), F::from(3u64));
        let mt = RescueSparseMerkleTree::<BigUint, F>::from_kv_set(10, &hashmap).unwrap();
        assert_eq!(mt.num_leaves(), hashmap.len() as u64);

        let commitment = mt.commitment();

        let mut proof = mt
            .universal_lookup(BigUint::from(3u64))
            .expect_not_found()
            .unwrap();

        let verify_result = RescueSparseMerkleTree::<BigUint, F>::non_membership_verify(
            &commitment,
            BigUint::from(3u64),
            &proof,
        )
        .unwrap();
        assert!(verify_result.is_ok());

        let verify_result = RescueSparseMerkleTree::<BigUint, F>::non_membership_verify(
            &commitment,
            BigUint::from(1u64),
            &proof,
        )
        .unwrap();
        assert!(verify_result.is_err());
    }

    #[test]
    fn test_update_and_lookup() {
        test_update_and_lookup_helper::<BigUint, Fr254>();
        test_update_and_lookup_helper::<BigUint, Fr377>();
        test_update_and_lookup_helper::<BigUint, Fr381>();

        test_update_and_lookup_helper::<Fr254, Fr254>();
        test_update_and_lookup_helper::<Fr377, Fr377>();
        test_update_and_lookup_helper::<Fr381, Fr381>();
    }

    fn test_update_and_lookup_helper<I, F>()
    where
        I: Index + ToTraversalPath<3>,
        F: RescueParameter + ToTraversalPath<3>,
        RescueHash<F>: DigestAlgorithm<F, I, F>,
    {
        let mut mt = RescueSparseMerkleTree::<F, F>::new(10);
        for i in 0..2 {
            mt.update(F::from(i as u64), F::from(i as u64)).unwrap();
        }
        let commitment = mt.commitment();
        for i in 0..2 {
            let (val, proof) = mt.universal_lookup(F::from(i as u64)).expect_ok().unwrap();
            assert_eq!(val, &F::from(i as u64));
            assert!(RescueSparseMerkleTree::<F, F>::verify(
                &commitment,
                F::from(i as u64),
                val,
                &proof
            )
            .unwrap()
            .is_ok());
        }
        for i in 0..10 {
            mt.update_with(F::from(i as u64), |elem| match elem {
                Some(elem) => Some(*elem),
                None => Some(F::from(i as u64)),
            })
            .unwrap();
        }
        assert_eq!(mt.num_leaves(), 10);
        let commitment = mt.commitment();
        // test lookup at index 7
        let (val, proof) = mt.universal_lookup(F::from(7u64)).expect_ok().unwrap();
        assert_eq!(val, &F::from(7u64));
        assert!(
            RescueSparseMerkleTree::<F, F>::verify(&commitment, F::from(7u64), val, &proof)
                .unwrap()
                .is_ok()
        );

        // Remove index 8
        mt.update_with(F::from(8u64), |_| None).unwrap();
        assert!(mt
            .universal_lookup(F::from(8u64))
            .expect_not_found()
            .is_ok());
        assert_eq!(mt.num_leaves(), 9);
    }

    #[test]
    fn test_universal_mt_forget_remember() {
        test_universal_mt_forget_remember_helper::<Fr254>();
        test_universal_mt_forget_remember_helper::<Fr377>();
        test_universal_mt_forget_remember_helper::<Fr381>();
    }

    fn test_universal_mt_forget_remember_helper<F: RescueParameter>() {
        let mut mt = RescueSparseMerkleTree::<BigUint, F>::from_kv_set(
            10,
            [
                (BigUint::from(0u64), F::from(1u64)),
                (BigUint::from(2u64), F::from(3u64)),
            ],
        )
        .unwrap();
        let commitment = mt.commitment();

        // Look up and forget an element that is in the tree.
        let (lookup_elem, lookup_mem_proof) = mt
            .universal_lookup(BigUint::from(0u64))
            .expect_ok()
            .unwrap();
        let lookup_elem = *lookup_elem;
        let (elem, mem_proof) = mt.universal_forget(0u64.into()).expect_ok().unwrap();
        assert_eq!(lookup_elem, elem);
        assert_eq!(lookup_mem_proof, mem_proof);
        assert_eq!(elem, 1u64.into());
        assert_eq!(mem_proof.height(), 10);
        assert!(RescueSparseMerkleTree::<BigUint, F>::verify(
            &commitment,
            BigUint::from(0u64),
            &elem,
            &lookup_mem_proof
        )
        .unwrap()
        .is_ok());
        assert!(RescueSparseMerkleTree::<BigUint, F>::verify(
            &commitment,
            BigUint::from(0u64),
            &elem,
            &mem_proof
        )
        .unwrap()
        .is_ok());

        // Forgetting or looking up an element that is already forgotten should fail.
        assert!(matches!(
            mt.universal_forget(0u64.into()),
            LookupResult::NotInMemory
        ));
        assert!(matches!(
            mt.universal_lookup(BigUint::from(0u64)),
            LookupResult::NotInMemory
        ));

        // We should still be able to look up an element that is not forgotten.
        let (elem, proof) = mt
            .universal_lookup(BigUint::from(2u64))
            .expect_ok()
            .unwrap();
        assert_eq!(elem, &3u64.into());
        assert!(RescueSparseMerkleTree::<BigUint, F>::verify(
            &commitment,
            BigUint::from(2u64),
            elem,
            &proof
        )
        .unwrap()
        .is_ok());

        // Look up and forget an empty sub-tree.
        let lookup_non_mem_proof = match mt.universal_lookup(BigUint::from(1u64)) {
            LookupResult::NotFound(proof) => proof,
            res => panic!("expected NotFound, got {:?}", res),
        };
        let non_mem_proof = match mt.universal_forget(BigUint::from(1u64)) {
            LookupResult::NotFound(proof) => proof,
            res => panic!("expected NotFound, got {:?}", res),
        };
        assert_eq!(lookup_non_mem_proof, non_mem_proof);
        assert_eq!(non_mem_proof.height(), 10);
        assert!(RescueSparseMerkleTree::<BigUint, F>::non_membership_verify(
            &commitment,
            BigUint::from(1u64),
            &lookup_non_mem_proof
        )
        .unwrap()
        .is_ok());
        assert!(RescueSparseMerkleTree::<BigUint, F>::non_membership_verify(
            &commitment,
            BigUint::from(1u64),
            &non_mem_proof
        )
        .unwrap()
        .is_ok());

        // Forgetting an empty sub-tree will never actually cause any new entries to be
        // forgotten, since empty sub-trees are _already_ treated as if they
        // were forgotten when deciding whether to forget their parent. So even
        // though we "forgot" it, the empty sub-tree is still in memory.
        match mt.universal_lookup(BigUint::from(1u64)) {
            LookupResult::NotFound(proof) => {
                assert!(RescueSparseMerkleTree::<BigUint, F>::non_membership_verify(
                    &commitment,
                    BigUint::from(1u64),
                    &proof
                )
                .unwrap()
                .is_ok());
            },
            res => {
                panic!("expected NotFound, got {:?}", res);
            },
        }

        // We should still be able to look up an element that is not forgotten.
        let (elem, proof) = mt
            .universal_lookup(BigUint::from(2u64))
            .expect_ok()
            .unwrap();
        assert_eq!(elem, &3u64.into());
        assert!(RescueSparseMerkleTree::<BigUint, F>::verify(
            &commitment,
            BigUint::from(2u64),
            elem,
            &proof
        )
        .unwrap()
        .is_ok());

        // Now if we forget the last entry, which is the only thing keeping the root
        // branch in memory, every entry will be forgotten.
        mt.universal_forget(BigUint::from(2u64))
            .expect_ok()
            .unwrap();
        assert!(matches!(
            mt.universal_lookup(BigUint::from(0u64)),
            LookupResult::NotInMemory
        ));
        assert!(matches!(
            mt.universal_lookup(BigUint::from(1u64)),
            LookupResult::NotInMemory
        ));
        assert!(matches!(
            mt.universal_lookup(BigUint::from(2u64)),
            LookupResult::NotInMemory
        ));

        // Remember should fail if the proof is invalid.
        mt.remember(BigUint::from(0u64), F::from(2u64), &mem_proof)
            .unwrap_err();
        mt.remember(BigUint::from(1u64), F::from(1u64), &mem_proof)
            .unwrap_err();
        let mut bad_mem_proof = mem_proof.clone();
        bad_mem_proof.0[0][0] = F::one();
        mt.remember(BigUint::from(0u64), F::from(1u64), &bad_mem_proof)
            .unwrap_err();

        mt.non_membership_remember(0u64.into(), &non_mem_proof)
            .unwrap_err();
        let mut bad_non_mem_proof = non_mem_proof.clone();
        bad_non_mem_proof.0[0][0] = F::one();
        mt.non_membership_remember(1u64.into(), &bad_non_mem_proof)
            .unwrap_err();

        // Remember an occupied and an empty  sub-tree.
        mt.remember(BigUint::from(0u64), F::from(1u64), &mem_proof)
            .unwrap();
        mt.non_membership_remember(1u64.into(), &non_mem_proof)
            .unwrap();

        // We should be able to look up everything we remembered.
        let (elem, proof) = mt
            .universal_lookup(BigUint::from(0u64))
            .expect_ok()
            .unwrap();
        assert_eq!(elem, &1u64.into());
        assert!(RescueSparseMerkleTree::<BigUint, F>::verify(
            &commitment,
            BigUint::from(0u64),
            elem,
            &proof
        )
        .unwrap()
        .is_ok());

        match mt.universal_lookup(BigUint::from(1u64)) {
            LookupResult::NotFound(proof) => {
                assert!(RescueSparseMerkleTree::<BigUint, F>::non_membership_verify(
                    &commitment,
                    BigUint::from(1u64),
                    &proof
                )
                .unwrap()
                .is_ok());
            },
            res => {
                panic!("expected NotFound, got {:?}", res);
            },
        }
    }

    #[test]
    fn test_persistent_update() {
        test_persistent_update_helper::<BigUint, Fr254>();
        test_persistent_update_helper::<BigUint, Fr377>();
        test_persistent_update_helper::<BigUint, Fr381>();

        test_persistent_update_helper::<Fr254, Fr254>();
        test_persistent_update_helper::<Fr377, Fr377>();
        test_persistent_update_helper::<Fr381, Fr381>();
    }

    fn test_persistent_update_helper<I, F>()
    where
        I: Index + ToTraversalPath<3>,
        F: RescueParameter + ToTraversalPath<3>,
        RescueHash<F>: DigestAlgorithm<F, I, F>,
    {
        let mt = RescueSparseMerkleTree::<F, F>::new(10);
        let mut mts = ark_std::vec![mt];
        for i in 1..10u64 {
            mts.push(
                mts.last()
                    .unwrap()
                    .persistent_update(F::from(i), F::from(i))
                    .unwrap(),
            );
            assert_eq!(mts.last().unwrap().num_leaves(), i);
        }
        for i in 1..10u64 {
            mts.iter().enumerate().for_each(|(j, mt)| {
                if j as u64 >= i {
                    assert!(mt.lookup(F::from(i)).expect_ok().is_ok());
                } else {
                    assert!(mt.lookup(F::from(i)).expect_not_found().is_ok());
                }
            });
        }

        assert_eq!(mts[5].num_leaves(), 5);
        let mt = mts[5].persistent_remove(F::from(1u64)).unwrap();
        assert_eq!(mt.num_leaves(), 4);
    }

    #[test]
    fn test_universal_mt_serde() {
        test_universal_mt_serde_helper::<Fr254>();
        test_universal_mt_serde_helper::<Fr377>();
        test_universal_mt_serde_helper::<Fr381>();
    }

    fn test_universal_mt_serde_helper<F: RescueParameter + ToTraversalPath<3>>() {
        let mut hashmap = HashMap::new();
        hashmap.insert(F::from(1u64), F::from(2u64));
        hashmap.insert(F::from(10u64), F::from(3u64));
        let mt = RescueSparseMerkleTree::<F, F>::from_kv_set(3, &hashmap).unwrap();
        let (_, mem_proof) = mt.lookup(F::from(10u64)).expect_ok().unwrap();
        // let node = (F::from(10u64), elem.clone());
        let non_mem_proof = match mt.universal_lookup(F::from(9u64)) {
            LookupResult::NotFound(proof) => proof,
            res => panic!("expected NotFound, got {:?}", res),
        };

        assert_eq!(
            mt,
            bincode::deserialize(&bincode::serialize(&mt).unwrap()).unwrap()
        );
        assert_eq!(
            mem_proof,
            bincode::deserialize(&bincode::serialize(&mem_proof).unwrap()).unwrap()
        );
        assert_eq!(
            non_mem_proof,
            bincode::deserialize(&bincode::serialize(&non_mem_proof).unwrap()).unwrap()
        );
    }
}
