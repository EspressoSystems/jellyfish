// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical Sparse Merkle Tree.
use super::{
    internal::{build_tree_internal, MerkleNode, MerkleProof, MerkleTreeCommitment},
    DigestAlgorithm, Element, ForgetableMerkleTreeScheme, ForgetableUniversalMerkleTreeScheme,
    Index, LookupResult, MerkleCommitment, MerkleTreeScheme, NodeValue, ToTraversalPath,
    UniversalMerkleTreeScheme,
};
use crate::{errors::PrimitivesError, impl_forgetable_merkle_tree_scheme, impl_merkle_tree_scheme};
use ark_std::{
    borrow::Borrow, boxed::Box, fmt::Debug, marker::PhantomData, string::ToString, vec, vec::Vec,
};
use num_bigint::BigUint;
use num_traits::pow::pow;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

// A standard Universal Merkle tree implementation
impl_merkle_tree_scheme!(UniversalMerkleTree, build_tree_internal);
impl_forgetable_merkle_tree_scheme!(UniversalMerkleTree);

impl<E, H, I, Arity, T> UniversalMerkleTreeScheme for UniversalMerkleTree<E, H, I, Arity, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64> + ToTraversalPath<Arity>,
    Arity: Unsigned,
    T: NodeValue,
{
    type NonMembershipProof = MerkleProof<E, I, T, Arity>;
    type BatchNonMembershipProof = ();

    fn update(&mut self, pos: impl Borrow<I>, elem: impl Borrow<E>) -> LookupResult<E, (), ()> {
        let pos = pos.borrow();
        let elem = elem.borrow();
        let traversal_path = pos.to_traversal_path(self.height);
        let ret = self
            .root
            .update_internal::<H, Arity>(self.height, pos, &traversal_path, elem);
        if let LookupResult::NotFound(_) = ret {
            self.num_leaves += 1;
        }
        ret
    }

    fn from_kv_set<BI, BE>(
        height: usize,
        data: impl IntoIterator<Item = impl Borrow<(BI, BE)>>,
    ) -> Result<Self, PrimitivesError>
    where
        BI: Borrow<Self::Index>,
        BE: Borrow<Self::Element>,
    {
        let mut mt = Self::from_elems(height, [] as [&Self::Element; 0])?;
        for tuple in data.into_iter() {
            let (key, value) = tuple.borrow();
            UniversalMerkleTreeScheme::update(&mut mt, key.borrow(), value.borrow());
        }
        Ok(mt)
    }

    fn non_membership_verify(
        &self,
        pos: impl Borrow<Self::Index>,
        proof: impl Borrow<Self::NonMembershipProof>,
    ) -> Result<bool, PrimitivesError> {
        let pos = pos.borrow();
        let proof = proof.borrow();
        if self.height != proof.tree_height() - 1 {
            return Err(PrimitivesError::ParameterError(
                "Incompatible membership proof for this merkle tree".to_string(),
            ));
        }
        if *pos != proof.pos {
            return Err(PrimitivesError::ParameterError(
                "Inconsistent proof index".to_string(),
            ));
        }
        proof.verify_non_membership_proof::<H>(&self.root.value())
    }

    fn universal_lookup(
        &self,
        pos: impl Borrow<Self::Index>,
    ) -> LookupResult<Self::Element, Self::MembershipProof, Self::NonMembershipProof> {
        let pos = pos.borrow();
        let traversal_path = pos.to_traversal_path(self.height);
        match self.root.lookup_internal(self.height, &traversal_path) {
            LookupResult::Ok(value, proof) => {
                LookupResult::Ok(value, MerkleProof::new(pos.clone(), proof))
            },
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::NotFound(non_membership_proof) => {
                LookupResult::NotFound(MerkleProof::new(pos.clone(), non_membership_proof))
            },
        }
    }
}

impl<E, H, I, Arity, T> ForgetableUniversalMerkleTreeScheme
    for UniversalMerkleTree<E, H, I, Arity, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64> + ToTraversalPath<Arity>,
    Arity: Unsigned,
    T: NodeValue,
{
    fn universal_forget(
        &mut self,
        pos: Self::Index,
    ) -> LookupResult<Self::Element, Self::MembershipProof, Self::NonMembershipProof> {
        let traversal_path = pos.to_traversal_path(self.height);
        match self.root.forget_internal(self.height, &traversal_path) {
            LookupResult::Ok(elem, proof) => LookupResult::Ok(elem, MerkleProof::new(pos, proof)),
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::NotFound(proof) => LookupResult::NotFound(MerkleProof::new(pos, proof)),
        }
    }

    fn non_membership_remember(
        &mut self,
        pos: Self::Index,
        proof: impl Borrow<Self::NonMembershipProof>,
    ) -> Result<(), PrimitivesError> {
        let proof = proof.borrow();
        let traversal_path = pos.to_traversal_path(self.height);
        if matches!(&proof.proof[0], MerkleNode::Empty) {
            let empty_value = T::default();
            let mut path_values = vec![empty_value];
            traversal_path.iter().zip(proof.proof.iter().skip(1)).fold(
                Ok(empty_value),
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
                            MerkleNode::Empty => {
                                path_values.push(empty_value);
                                Ok(empty_value)
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

#[cfg(test)]
mod mt_tests {
    use crate::{
        merkle_tree::{
            internal::{MerkleNode, MerkleProof},
            prelude::{RescueHash, RescueSparseMerkleTree},
            DigestAlgorithm, ForgetableMerkleTreeScheme, ForgetableUniversalMerkleTreeScheme,
            Index, LookupResult, MerkleTreeScheme, ToTraversalPath, UniversalMerkleTreeScheme,
        },
        rescue::RescueParameter,
    };
    use ark_ed_on_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_381::Fq as Fq381;
    use ark_ed_on_bn254::Fq as Fq254;
    use hashbrown::HashMap;
    use num_bigint::BigUint;
    use typenum::U3;

    #[test]
    fn test_universal_mt_builder() {
        test_universal_mt_builder_helper::<Fq254>();
        test_universal_mt_builder_helper::<Fq377>();
        test_universal_mt_builder_helper::<Fq381>();
    }

    fn test_universal_mt_builder_helper<F: RescueParameter>() {
        let mt = RescueSparseMerkleTree::<BigUint, F>::from_kv_set(
            1,
            &[(BigUint::from(1u64), F::from(1u64))],
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
        test_non_membership_lookup_and_verify_helper::<Fq254>();
        test_non_membership_lookup_and_verify_helper::<Fq377>();
        test_non_membership_lookup_and_verify_helper::<Fq381>();
    }

    fn test_non_membership_lookup_and_verify_helper<F: RescueParameter>() {
        let mut hashmap = HashMap::new();
        hashmap.insert(BigUint::from(1u64), F::from(2u64));
        hashmap.insert(BigUint::from(2u64), F::from(2u64));
        hashmap.insert(BigUint::from(1u64), F::from(3u64));
        let mt = RescueSparseMerkleTree::<BigUint, F>::from_kv_set(10, &hashmap).unwrap();
        assert_eq!(mt.num_leaves(), hashmap.len() as u64);

        let mut proof = mt
            .universal_lookup(BigUint::from(3u64))
            .expect_not_found()
            .unwrap();
        let verify_result = mt.non_membership_verify(BigUint::from(3u64), &proof);
        assert!(verify_result.is_ok() && verify_result.unwrap());

        proof.pos = BigUint::from(1u64);
        let verify_result = mt.non_membership_verify(BigUint::from(1u64), &proof);
        assert!(verify_result.is_ok() && !verify_result.unwrap());

        let verify_result = mt.non_membership_verify(BigUint::from(4u64), proof);
        assert!(verify_result.is_err());
    }

    #[test]
    fn test_update_and_lookup() {
        test_update_and_lookup_helper::<BigUint, Fq254>();
        test_update_and_lookup_helper::<BigUint, Fq377>();
        test_update_and_lookup_helper::<BigUint, Fq381>();

        test_update_and_lookup_helper::<Fq254, Fq254>();
        test_update_and_lookup_helper::<Fq377, Fq377>();
        test_update_and_lookup_helper::<Fq381, Fq381>();
    }

    fn test_update_and_lookup_helper<I, F>()
    where
        I: Index + ToTraversalPath<U3> + From<u64>,
        F: RescueParameter + ToTraversalPath<U3>,
        RescueHash<F>: DigestAlgorithm<F, I, F>,
    {
        let mut mt =
            RescueSparseMerkleTree::<F, F>::from_kv_set(10, HashMap::<F, F>::new()).unwrap();
        for i in 0..2 {
            mt.update(F::from(i as u64), F::from(i as u64));
        }
        for i in 0..2 {
            let (val, proof) = mt.universal_lookup(F::from(i as u64)).expect_ok().unwrap();
            assert_eq!(val, F::from(i as u64));
            assert_eq!(*proof.elem().unwrap(), val);
            assert!(mt.verify(F::from(i as u64), &proof).unwrap());
        }
    }

    #[test]
    fn test_universal_mt_forget_remember() {
        test_universal_mt_forget_remember_helper::<Fq254>();
        test_universal_mt_forget_remember_helper::<Fq377>();
        test_universal_mt_forget_remember_helper::<Fq381>();
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

        // Look up and forget an element that is in the tree.
        let (lookup_elem, lookup_mem_proof) = mt
            .universal_lookup(BigUint::from(0u64))
            .expect_ok()
            .unwrap();
        let (elem, mem_proof) = mt.universal_forget(0u64.into()).expect_ok().unwrap();
        assert_eq!(lookup_elem, elem);
        assert_eq!(lookup_mem_proof, mem_proof);
        assert_eq!(elem, 1u64.into());
        assert_eq!(mem_proof.tree_height(), 11);
        assert!(mt.verify(BigUint::from(0u64), &lookup_mem_proof).unwrap());
        assert!(mt.verify(BigUint::from(0u64), &mem_proof).unwrap());

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
        assert_eq!(elem, 3u64.into());
        assert!(mt.verify(BigUint::from(2u64), &proof).unwrap());

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
        assert_eq!(non_mem_proof.tree_height(), 11);
        assert!(mt
            .non_membership_verify(BigUint::from(1u64), &lookup_non_mem_proof)
            .unwrap());
        assert!(mt
            .non_membership_verify(BigUint::from(1u64), &non_mem_proof)
            .unwrap());

        // Forgetting an empty sub-tree will never actually cause any new entries to be
        // forgotten, since empty sub-trees are _already_ treated as if they
        // were forgotten when deciding whether to forget their parent. So even
        // though we "forgot" it, the empty sub-tree is still in memory.
        match mt.universal_lookup(BigUint::from(1u64)) {
            LookupResult::NotFound(proof) => {
                assert!(mt
                    .non_membership_verify(BigUint::from(1u64), &proof)
                    .unwrap());
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
        assert_eq!(elem, 3u64.into());
        assert!(mt.verify(BigUint::from(2u64), &proof).unwrap());

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
        let mut bad_mem_proof = mem_proof.clone();
        if let MerkleNode::Leaf { elem, .. } = &mut bad_mem_proof.proof[0] {
            *elem = F::from(4u64);
        } else {
            panic!("expected membership proof to end in a Leaf");
        }
        mt.remember(0u64.into(), F::from(1u64), &bad_mem_proof)
            .unwrap_err();

        let mut bad_non_mem_proof = non_mem_proof.clone();
        bad_non_mem_proof.proof[0] = MerkleNode::Leaf {
            pos: 1u64.into(),
            elem: Default::default(),
            value: Default::default(),
        };
        mt.non_membership_remember(1u64.into(), &bad_non_mem_proof)
            .unwrap_err();

        let mut forge_mem_proof = MerkleProof::new(1u64.into(), mem_proof.proof.clone());
        if let MerkleNode::Leaf { pos, elem, .. } = &mut forge_mem_proof.proof[0] {
            *pos = 1u64.into();
            *elem = F::from(0u64);
        } else {
            panic!("expected membership proof to end in a Leaf");
        }
        mt.remember(BigUint::from(1u64), F::from(0u64), &forge_mem_proof)
            .unwrap_err();

        let forge_non_mem_proof = non_mem_proof.clone();
        assert!(matches!(forge_non_mem_proof.proof[0], MerkleNode::Empty));
        mt.non_membership_remember(0u64.into(), &forge_non_mem_proof)
            .unwrap_err();

        // Remember an occupied and an empty  sub-tree.
        mt.remember(0u64.into(), F::from(1u64), &mem_proof).unwrap();
        mt.non_membership_remember(1u64.into(), &non_mem_proof)
            .unwrap();

        // We should be able to look up everything we remembered.
        let (elem, proof) = mt
            .universal_lookup(BigUint::from(0u64))
            .expect_ok()
            .unwrap();
        assert_eq!(elem, 1u64.into());
        assert!(mt.verify(BigUint::from(0u64), &proof).unwrap());

        match mt.universal_lookup(BigUint::from(1u64)) {
            LookupResult::NotFound(proof) => {
                assert!(mt
                    .non_membership_verify(BigUint::from(1u64), &proof)
                    .unwrap());
            },
            res => {
                panic!("expected NotFound, got {:?}", res);
            },
        }
    }

    #[test]
    fn test_universal_mt_serde() {
        test_universal_mt_serde_helper::<Fq254>();
        test_universal_mt_serde_helper::<Fq377>();
        test_universal_mt_serde_helper::<Fq381>();
    }

    fn test_universal_mt_serde_helper<F: RescueParameter + ToTraversalPath<U3>>() {
        let mut hashmap = HashMap::new();
        hashmap.insert(F::from(1u64), F::from(2u64));
        hashmap.insert(F::from(10u64), F::from(3u64));
        let mt = RescueSparseMerkleTree::<F, F>::from_kv_set(3, &hashmap).unwrap();
        let mem_proof = mt.lookup(F::from(10u64)).expect_ok().unwrap().1;
        let node = &mem_proof.proof[0];
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
        assert_eq!(
            *node,
            bincode::deserialize(&bincode::serialize(node).unwrap()).unwrap()
        );
    }
}
