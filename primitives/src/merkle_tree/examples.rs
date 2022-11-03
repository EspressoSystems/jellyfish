// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Provides sample instantiations of merkle tree.
//! E.g. Sparse merkle tree with BigUInt index.

use super::{append_only::MerkleTree, DigestAlgorithm, ToBranches};
use crate::rescue::{Permutation, RescueParameter};
use ark_std::{convert::TryInto, marker::PhantomData, vec, vec::Vec};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use sha3::{Digest, Sha3_512};
use typenum::U3;

/// Wrapper for rescue hash function
pub struct RescueHash<F: RescueParameter> {
    phantom_f: PhantomData<F>,
}

impl<F: RescueParameter> DigestAlgorithm<F, u64, F> for RescueHash<F> {
    fn digest(data: &[F]) -> F {
        let perm = Permutation::default();
        perm.sponge_no_padding(data, 1).unwrap()[0]
    }

    fn digest_leaf(pos: &u64, elem: &F) -> F {
        let data = [F::from(*pos), *elem, F::zero()];
        let perm = Permutation::default();
        perm.sponge_no_padding(&data, 1).unwrap()[0]
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
pub type SparseMerkleTree<E, F> = MerkleTree<E, RescueHash<F>, BigUint, U3, F>;

/// Element type for interval merkle tree
pub struct Interval<F>(pub F, pub F);

impl<F: RescueParameter> DigestAlgorithm<Interval<F>, u64, F> for RescueHash<F> {
    fn digest(data: &[F]) -> F {
        let perm = Permutation::default();
        perm.sponge_no_padding(data, 1).unwrap()[0]
    }

    fn digest_leaf(pos: &u64, elem: &Interval<F>) -> F {
        let data = [F::from(*pos), elem.0, elem.1];
        let perm = Permutation::default();
        perm.sponge_no_padding(&data, 1).unwrap()[0]
    }
}

/// Interval merkle tree instantiation for interval merkle tree using Rescue
/// hash function.
pub type IntervalMerkleTree<F> = MerkleTree<Interval<F>, RescueHash<F>, u64, U3, F>;

/// Update the array length here
type NodeValue = [u8; 3];

/// Wrapper for SHA3_512 hash function
pub struct Sha3Digest();

impl<E, I> DigestAlgorithm<E, I, NodeValue> for Sha3Digest {
    fn digest(data: &[NodeValue]) -> NodeValue {
        let mut hasher = Sha3_512::new();
        for value in data {
            hasher.update(value);
        }
        hasher.finalize()[..]
            .try_into()
            .expect("slice with incorrect length")
    }

    fn digest_leaf(_pos: &I, _elem: &E) -> NodeValue {
        // Serialize and hash
        todo!()
    }
}

/// Merkle tree using SHA3 hash
pub type SHA3MerkleTree<E> = MerkleTree<E, Sha3Digest, u64, U3, NodeValue>;
