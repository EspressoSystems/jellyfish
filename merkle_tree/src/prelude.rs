// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Prelude. Also provides sample instantiations of merkle trees.

pub use crate::{
    append_only::MerkleTree,
    impl_to_traversal_path_biguint, impl_to_traversal_path_primitives,
    internal::{MerkleNode, MerkleTreeProof},
    universal_merkle_tree::UniversalMerkleTree,
    AppendableMerkleTreeScheme, DigestAlgorithm, Element, ForgetableMerkleTreeScheme,
    ForgetableUniversalMerkleTreeScheme, Index, LookupResult, MerkleTreeScheme, NodeValue,
    ToTraversalPath, UniversalMerkleTreeScheme,
};

use super::light_weight::LightWeightMerkleTree;
use crate::errors::MerkleTreeError;
use ark_ff::PrimeField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use ark_std::{fmt, marker::PhantomData, string::ToString, vec, vec::Vec};
use jf_crhf::CRHF;
use jf_poseidon2::{crhf::FixedLenPoseidon2Hash, Poseidon2, Poseidon2Params};
use jf_rescue::{crhf::RescueCRHF, RescueParameter};
use nimue::hash::sponge::Sponge;
use sha3::{Digest, Keccak256, Sha3_256};

/// Wrapper for rescue hash function
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RescueHash<F: RescueParameter> {
    phantom_f: PhantomData<F>,
}

/// domain separator of algebraic hash, for the leaf node
fn leaf_hash_dom_sep<F: PrimeField>() -> F {
    F::one()
}

/// domain separator of algebraic hash, for the internal node
fn internal_hash_dom_sep<F: PrimeField>() -> F {
    F::zero()
}

/// domain separator of byte-oriented hash, for the leaf node
const LEAF_HASH_DOM_SEP: &'static [u8; 1] = b"1";
/// domain separator of byte-oriented hash, for the internal node
const INTERNAL_HASH_DOM_SEP: &'static [u8; 1] = b"1";

impl<I: Index, F: RescueParameter + From<I>> DigestAlgorithm<F, I, F> for RescueHash<F> {
    fn digest(data: &[F]) -> Result<F, MerkleTreeError> {
        let mut input = vec![internal_hash_dom_sep()];
        input.extend(data.iter());
        Ok(RescueCRHF::<F>::sponge_with_zero_padding(&input, 1)[0])
    }

    fn digest_leaf(pos: &I, elem: &F) -> Result<F, MerkleTreeError> {
        let data = [leaf_hash_dom_sep(), F::from(pos.clone()), *elem];
        Ok(RescueCRHF::<F>::sponge_with_zero_padding(&data, 1)[0])
    }
}

/// A standard merkle tree using RATE-3 rescue hash function
pub type RescueMerkleTree<F> = MerkleTree<F, RescueHash<F>, u64, 3, F>;

/// A standard light merkle tree using RATE-3 rescue hash function
pub type RescueLightWeightMerkleTree<F> = LightWeightMerkleTree<F, RescueHash<F>, u64, 3, F>;

/// Example instantiation of a SparseMerkleTree indexed by I
pub type RescueSparseMerkleTree<I, F> = UniversalMerkleTree<F, RescueHash<F>, I, 3, F>;

// Make `FixedLenPoseidon2Hash<F, S, INPUT_SIZE, 1>` usable as Merkle tree hash
// for arity INPUT_SIZE - 1. The first input element is used for the domain
// separation.
impl<I, F, S, const INPUT_SIZE: usize> DigestAlgorithm<F, I, F>
    for FixedLenPoseidon2Hash<F, S, INPUT_SIZE, 1>
where
    I: Index,
    F: PrimeField + From<I> + nimue::Unit,
    S: Sponge<U = F>,
{
    fn digest(data: &[F]) -> Result<F, MerkleTreeError> {
        let mut input = vec![internal_hash_dom_sep()];
        input.extend(data.iter());
        Ok(FixedLenPoseidon2Hash::<F, S, INPUT_SIZE, 1>::evaluate(input)?[0])
    }

    fn digest_leaf(pos: &I, elem: &F) -> Result<F, MerkleTreeError> {
        let mut input = vec![leaf_hash_dom_sep(), F::from(pos.clone()), *elem];
        Ok(FixedLenPoseidon2Hash::<F, S, INPUT_SIZE, 1>::evaluate(input)?[0])
    }
}

/// Implement Internal node type and implement DigestAlgorithm for a hash
/// function with 32 bytes output size
///
/// # Usage
/// `impl_mt_hash_256!(Sha3_256, Sha3Node, Sha3Digest)` will
/// - introduce `struct Sha3Node` for internal node in a merkle tree that use
///   Sha3_256 as hash
/// - introduce `struct Sha3Digest` which implements `DigestAlgorithm`
macro_rules! impl_mt_hash_256 {
    ($hasher:ident, $node_name:ident, $digest_name:ident) => {
        /// Internal node for merkle tree
        #[derive(Default, Eq, PartialEq, Clone, Copy, Ord, PartialOrd, Hash)]
        pub struct $node_name(pub(crate) [u8; 32]);

        impl fmt::Debug for $node_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(&stringify!($node_name))
                    .field(&hex::encode(self.0))
                    .finish()
            }
        }

        impl AsRef<[u8]> for $node_name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl CanonicalSerialize for $node_name {
            fn serialize_with_mode<W: Write>(
                &self,
                mut writer: W,
                _compress: Compress,
            ) -> Result<(), SerializationError> {
                writer.write_all(&self.0)?;
                Ok(())
            }
            fn serialized_size(&self, _compress: Compress) -> usize {
                32
            }
        }
        impl CanonicalDeserialize for $node_name {
            fn deserialize_with_mode<R: Read>(
                mut reader: R,
                _compress: Compress,
                _validate: Validate,
            ) -> Result<Self, SerializationError> {
                let mut ret = [0u8; 32];
                reader.read_exact(&mut ret)?;
                Ok(Self(ret))
            }
        }
        impl Valid for $node_name {
            fn check(&self) -> Result<(), SerializationError> {
                Ok(())
            }
        }

        /// Wrapper for the actual hash function
        #[derive(Clone, Debug, Hash, Eq, PartialEq)]
        pub struct $digest_name;
        impl<E: Element + CanonicalSerialize, I: Index> DigestAlgorithm<E, I, $node_name>
            for $digest_name
        {
            fn digest(data: &[$node_name]) -> Result<$node_name, MerkleTreeError> {
                let mut h = $hasher::new();
                h.update(LEAF_HASH_DOM_SEP);
                for value in data {
                    h.update(value);
                }
                Ok($node_name(h.finalize().into()))
            }

            fn digest_leaf(_pos: &I, elem: &E) -> Result<$node_name, MerkleTreeError> {
                let mut writer = Vec::new();
                elem.serialize_compressed(&mut writer).unwrap();
                let mut h = $hasher::new();
                h.update(INTERNAL_HASH_DOM_SEP);
                h.update(writer);
                Ok($node_name(h.finalize().into()))
            }
        }
    };
}

impl_mt_hash_256!(Sha3_256, Sha3Node, Sha3Digest);
impl_mt_hash_256!(Keccak256, Keccak256Node, Keccak256Digest);

/// Merkle tree using SHA3 hash
pub type SHA3MerkleTree<E> = MerkleTree<E, Sha3Digest, u64, 3, Sha3Node>;
/// Light weight merkle tree using SHA3 hash
pub type LightWeightSHA3MerkleTree<E> = LightWeightMerkleTree<E, Sha3Digest, u64, 3, Sha3Node>;

/// Merkle tree using keccak256 hash
pub type Keccak256MerkleTree<E> = MerkleTree<E, Keccak256Node, u64, 3, Keccak256Digest>;
/// Light weight merkle tree using Keccak256 hash
pub type LightWeightKeccak256MerkleTree<E> =
    LightWeightMerkleTree<E, Keccak256Digest, u64, 3, Keccak256Node>;
