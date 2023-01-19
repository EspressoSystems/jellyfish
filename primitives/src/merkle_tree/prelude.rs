// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Prelude

pub use crate::{
    impl_to_traversal_path_biguint, impl_to_traversal_path_primitives,
    merkle_tree::{
        append_only::MerkleTree, universal_merkle_tree::UniversalMerkleTree,
        AppendableMerkleTreeScheme, DigestAlgorithm, Element, ForgetableMerkleTreeScheme,
        ForgetableUniversalMerkleTreeScheme, Index, LookupResult, MerkleCommitment,
        MerkleTreeScheme, NodeValue, ToTraversalPath, UniversalMerkleTreeScheme,
    },
};

use crate::rescue::{sponge::RescueCRHF, RescueParameter};
use ark_std::marker::PhantomData;
use num_bigint::BigUint;
use typenum::U3;

use super::light_weight::LightWeightMerkleTree;

/// Wrapper for rescue hash function
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RescueHash<F: RescueParameter> {
    phantom_f: PhantomData<F>,
}

impl<F: RescueParameter> DigestAlgorithm<F, u64, F> for RescueHash<F> {
    fn digest(data: &[F]) -> F {
        RescueCRHF::<F>::sponge_no_padding(data, 1).unwrap()[0]
    }

    fn digest_leaf(pos: &u64, elem: &F) -> F {
        let data = [F::zero(), F::from(*pos), *elem];
        RescueCRHF::<F>::sponge_no_padding(&data, 1).unwrap()[0]
    }
}

/// A standard merkle tree using RATE-3 rescue hash function
pub type RescueMerkleTree<F> = MerkleTree<F, RescueHash<F>, u64, U3, F>;

/// A standard light merkle tree using RATE-3 rescue hash function
pub type RescueLightWeightMerkleTree<F> = LightWeightMerkleTree<F, RescueHash<F>, u64, U3, F>;

impl<F: RescueParameter> DigestAlgorithm<F, BigUint, F> for RescueHash<F> {
    fn digest(data: &[F]) -> F {
        RescueCRHF::<F>::sponge_no_padding(data, 1).unwrap()[0]
    }

    fn digest_leaf(pos: &BigUint, elem: &F) -> F {
        let data = [F::zero(), F::from(pos.clone()), *elem];
        RescueCRHF::<F>::sponge_no_padding(&data, 1).unwrap()[0]
    }
}

impl<F: RescueParameter> DigestAlgorithm<F, F, F> for RescueHash<F> {
    fn digest(data: &[F]) -> F {
        RescueCRHF::<F>::sponge_no_padding(data, 1).unwrap()[0]
    }

    fn digest_leaf(pos: &F, elem: &F) -> F {
        let data = [F::zero(), *pos, *elem];
        RescueCRHF::<F>::sponge_no_padding(&data, 1).unwrap()[0]
    }
}

/// Example instantiation of a SparseMerkleTree indexed by I
pub type RescueSparseMerkleTree<I, F> = UniversalMerkleTree<F, RescueHash<F>, I, U3, F>;
