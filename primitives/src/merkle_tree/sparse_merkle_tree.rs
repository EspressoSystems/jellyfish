// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a typical Sparse Merkle Tree.
use super::{
    internal::{build_tree_internal, MerkleNode, MerkleProof},
    DigestAlgorithm, Element, Index, LookupResult, MerkleCommitment, MerkleTreeScheme, NodeValue,
    UniversalMerkleTreeScheme,
};
use crate::{errors::PrimitivesError, impl_merkle_tree_scheme};
use ark_std::{borrow::Borrow, boxed::Box, fmt::Debug, marker::PhantomData, string::ToString};
use num_bigint::BigUint;
use num_traits::pow::pow;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

// A standard Universal Merkle tree implementation
impl_merkle_tree_scheme!(UniversalMerkleTree);

impl<E, H, I, Arity, T> UniversalMerkleTreeScheme for UniversalMerkleTree<E, H, I, Arity, T>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64>,
    Arity: Unsigned,
    T: NodeValue,
{
    type NonMembershipProof = MerkleProof<E, I, T>;
    type BatchNonMembershipProof = ();

    fn update(&mut self, pos: impl Borrow<I>, elem: impl Borrow<E>) -> LookupResult<E, (), ()> {
        let pos = pos.borrow();
        let elem = elem.borrow();
        let traversal_path = pos.to_traverse_path(self.height, Self::ARITY);
        let ret = self
            .root
            .update_internal::<H, Arity>(self.height, pos, &traversal_path, elem);
        if let LookupResult::EmptyLeaf(_) = ret {
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
        proof.verify_non_membership_proof::<H, Arity>(&self.root())
    }

    fn universal_lookup(
        &self,
        pos: impl Borrow<Self::Index>,
    ) -> LookupResult<Self::Element, Self::MembershipProof, Self::NonMembershipProof> {
        let pos = pos.borrow();
        let traversal_path = pos.to_traverse_path(self.height, Self::ARITY);
        match self.root.lookup_internal(self.height, &traversal_path) {
            LookupResult::Ok(value, proof) => LookupResult::Ok(
                value,
                MerkleProof {
                    pos: pos.clone(),
                    proof,
                },
            ),
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::EmptyLeaf(non_membership_proof) => LookupResult::EmptyLeaf(MerkleProof {
                pos: pos.clone(),
                proof: non_membership_proof,
            }),
        }
    }
}

#[cfg(test)]
mod mt_tests {
    use crate::{
        merkle_tree::{examples::SparseMerkleTree, MerkleTreeScheme, UniversalMerkleTreeScheme},
        rescue::RescueParameter,
    };
    use ark_ed_on_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_381::Fq as Fq381;
    use ark_ed_on_bn254::Fq as Fq254;
    use hashbrown::HashMap;
    use num_bigint::BigUint;

    #[test]
    fn test_universal_mt_builder() {
        test_universal_mt_builder_helper::<Fq254>();
        test_universal_mt_builder_helper::<Fq377>();
        test_universal_mt_builder_helper::<Fq381>();
    }

    fn test_universal_mt_builder_helper<F: RescueParameter>() {
        let mt = SparseMerkleTree::<F, F>::from_kv_set(1, &[(BigUint::from(1u64), F::from(1u64))])
            .unwrap();
        assert_eq!(mt.num_leaves(), 1);

        let mut hashmap = HashMap::new();
        hashmap.insert(BigUint::from(1u64), F::from(2u64));
        hashmap.insert(BigUint::from(2u64), F::from(2u64));
        hashmap.insert(BigUint::from(1u64), F::from(3u64));
        let mt = SparseMerkleTree::<F, F>::from_kv_set(10, &hashmap).unwrap();
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
        let mt = SparseMerkleTree::<F, F>::from_kv_set(10, &hashmap).unwrap();
        assert_eq!(mt.num_leaves(), hashmap.len() as u64);

        let mut proof = mt
            .universal_lookup(BigUint::from(3u64))
            .expect_empty()
            .unwrap();
        let verify_result = mt.non_membership_verify(BigUint::from(3u64), &proof);
        assert!(verify_result.is_ok() && verify_result.unwrap());

        proof.pos = BigUint::from(1u64);
        let verify_result = mt.non_membership_verify(BigUint::from(1u64), &proof);
        assert!(verify_result.is_ok() && !verify_result.unwrap());

        let verify_result = mt.non_membership_verify(BigUint::from(4u64), proof);
        assert!(verify_result.is_err());
    }
}
