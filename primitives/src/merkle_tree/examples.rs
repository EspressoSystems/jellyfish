// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Provides sample instantiations of merkle tree.
//! E.g. Sparse merkle tree with BigUInt index.

use super::{append_only::MerkleTree, DigestAlgorithm, ToBranches, ToVec};
use crate::rescue::{Permutation, RescueParameter};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{convert::TryInto, marker::PhantomData, vec, vec::Vec};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use sha3::{Digest, Sha3_512};
use typenum::U3;

impl<F: RescueParameter> ToVec<F> for F {
    fn to_vec(&self) -> Vec<F> {
        vec![*self]
    }
}

impl<F: RescueParameter> ToVec<F> for u64 {
    fn to_vec(&self) -> Vec<F> {
        vec![F::from(*self)]
    }
}
/// A standard merkle tree using RATE-3 rescue hash function
pub type RescueMerkleTree<F> = MerkleTree<F, RescueHash<F>, u64, U3, F>;

impl ToBranches for BigUint {
    fn to_branches(&self, height: usize, arity: usize) -> Vec<usize> {
        let mut pos = self.clone();
        let mut ret = vec![];
        for _i in 0..height {
            ret.push((&pos % (arity as u64)).to_usize().unwrap());
            pos /= arity as u64;
        }
        ret
    }
}

/// Example instantiation of a SparseMerkleTree indexed by BigUInt
pub type SparseMerkleTree<V, F> = MerkleTree<V, RescueHash<F>, BigUint, U3, F>;

/// Wrapper for rescue hash function
pub struct RescueHash<F: RescueParameter> {
    phantom_f: PhantomData<F>,
}

impl<F: RescueParameter> DigestAlgorithm<F> for RescueHash<F> {
    fn digest(data: &[F]) -> F {
        let perm = Permutation::default();
        perm.sponge_no_padding(data, 1).unwrap()[0]
    }
}

/// Element type for interval merkle tree
pub struct Interval<F>(pub F, pub F);

impl<F: Copy> ToVec<F> for Interval<F> {
    fn to_vec(&self) -> Vec<F> {
        vec![self.0, self.1]
    }
}

/// Interval merkle tree instantiation for interval merkle tree using Rescue
/// hash function.
pub type IntervalMerkleTree<F> = MerkleTree<Interval<F>, RescueHash<F>, u64, U3, F>;

/// Update the array length here
type NodeValue = [u8; 3];

impl<T> ToVec<NodeValue> for T
where
    T: CanonicalSerialize + CanonicalDeserialize,
{
    fn to_vec(&self) -> Vec<NodeValue> {
        // Serialize the value into slices of [u8; X]
        todo!()
    }
}

/// Wrapper for SHA3_512 hash function
pub struct Sha3Digest();

impl DigestAlgorithm<NodeValue> for Sha3Digest {
    fn digest(data: &[NodeValue]) -> NodeValue {
        let mut hasher = Sha3_512::new();
        for value in data {
            hasher.update(value);
        }
        hasher.finalize()[..]
            .try_into()
            .expect("slice with incorrect length")
    }
}

/// Merkle tree using SHA3 hash
pub type SHA3MerkleTree<E> = MerkleTree<E, Sha3Digest, u64, U3, NodeValue>;
