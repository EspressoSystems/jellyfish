// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical Sparse Merkle Tree.
use super::{
    internal::{build_tree_internal, MerkleNode, MerkleProof, MerkleTreeCommitment},
    DigestAlgorithm, Element, ForgetableMerkleTreeScheme, Index, LookupResult, MerkleCommitment,
    MerkleTreeScheme, NodeValue, ToTraversalPath, UniversalMerkleTreeScheme,
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
impl_merkle_tree_scheme!(UniversalMerkleTree);
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

#[cfg(test)]
mod mt_tests {
    use crate::{
        merkle_tree::{
            prelude::{RescueHash, RescueSparseMerkleTree},
            DigestAlgorithm, Index, LookupResult, MerkleTreeScheme, ToTraversalPath,
            UniversalMerkleTreeScheme,
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
        let mt = RescueSparseMerkleTree::<BigUint, F, F>::from_kv_set(
            1,
            &[(BigUint::from(1u64), F::from(1u64))],
        )
        .unwrap();
        assert_eq!(mt.num_leaves(), 1);

        let mut hashmap = HashMap::new();
        hashmap.insert(BigUint::from(1u64), F::from(2u64));
        hashmap.insert(BigUint::from(2u64), F::from(2u64));
        hashmap.insert(BigUint::from(1u64), F::from(3u64));
        let mt = RescueSparseMerkleTree::<BigUint, F, F>::from_kv_set(10, &hashmap).unwrap();
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
        let mt = RescueSparseMerkleTree::<BigUint, F, F>::from_kv_set(10, &hashmap).unwrap();
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
        F: RescueParameter,
        RescueHash<F>: DigestAlgorithm<F, I, F>,
    {
        let mut mt =
            RescueSparseMerkleTree::<I, F, F>::from_kv_set(10, HashMap::<I, F>::new()).unwrap();
        for i in 0..2 {
            mt.update(I::from(i as u64), F::from(i as u64));
        }
        for i in 0..2 {
            let (val, proof) = mt.universal_lookup(I::from(i as u64)).expect_ok().unwrap();
            assert_eq!(val, F::from(i as u64));
            assert_eq!(*proof.elem().unwrap(), val);
            assert!(mt.verify(I::from(i as u64), &proof).unwrap());
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
        let mt = RescueSparseMerkleTree::<F, F, F>::from_kv_set(3, &hashmap).unwrap();
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
