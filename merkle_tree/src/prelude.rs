// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Prelude module providing essential Merkle tree types and sample implementations.

pub use crate::{
    append_only::MerkleTree,
    impl_to_traversal_path_biguint, impl_to_traversal_path_primitives,
    internal::{MerkleNode, MerkleTreeProof},
    universal_merkle_tree::UniversalMerkleTree,
    AppendableMerkleTreeScheme, DigestAlgorithm, Element, ForgetableMerkleTreeScheme,
    ForgetableUniversalMerkleTreeScheme, Index, LookupResult, MerkleTreeScheme, NodeValue,
    ToTraversalPath, UniversalMerkleTreeScheme,
};

use crate::errors::MerkleTreeError;
use super::light_weight::LightWeightMerkleTree;
use ark_ff::PrimeField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use ark_std::{fmt, marker::PhantomData, vec::Vec};
use jf_poseidon2::{Poseidon2, Poseidon2Params};
use jf_rescue::{crhf::RescueCRHF, RescueParameter};
use sha3::{Digest, Keccak256, Sha3_256};

/// Wrapper for the Rescue hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RescueHash<F: RescueParameter> {
    _phantom: PhantomData<F>,
}

impl<I: Index, F: RescueParameter + From<I>> DigestAlgorithm<F, I, F> for RescueHash<F> {
    fn digest(data: &[F]) -> Result<F, MerkleTreeError> {
        RescueCRHF::<F>::sponge_no_padding(data, 1)
            .map(|result| result[0])
            .map_err(MerkleTreeError::from)
    }

    fn digest_leaf(pos: &I, elem: &F) -> Result<F, MerkleTreeError> {
        let input = [F::zero(), F::from(pos.clone()), *elem];
        Self::digest(&input)
    }
}

/// A standard Merkle tree using RATE-3 Rescue hash function.
pub type RescueMerkleTree<F> = MerkleTree<F, RescueHash<F>, u64, 3, F>;

/// A standard lightweight Merkle tree using RATE-3 Rescue hash function.
pub type RescueLightWeightMerkleTree<F> = LightWeightMerkleTree<F, RescueHash<F>, u64, 3, F>;

/// A Sparse Merkle tree indexed by `I`, using Rescue hash function.
pub type RescueSparseMerkleTree<I, F> = UniversalMerkleTree<F, RescueHash<F>, I, 3, F>;

/// Wrapper for the Poseidon2 compression function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poseidon2Compression<F, P, const N: usize>(PhantomData<(F, P, [(); N])>)
where
    F: PrimeField,
    P: Poseidon2Params<F, N>;

impl<I, F, P, const N: usize> DigestAlgorithm<F, I, F> for Poseidon2Compression<F, P, N>
where
    I: Index,
    F: PrimeField + From<I>,
    P: Poseidon2Params<F, N>,
{
    fn digest(data: &[F]) -> Result<F, MerkleTreeError> {
        let mut input = [F::default(); N];
        input.copy_from_slice(&data[..]);
        Ok(Poseidon2::permute::<P, N>(&input)[0])
    }

    fn digest_leaf(pos: &I, elem: &F) -> Result<F, MerkleTreeError> {
        let mut input = [F::default(); N];
        input[N - 1] = F::from(pos.clone());
        input[N - 2] = *elem;
        Ok(Poseidon2::permute::<P, N>(&input)[0])
    }
}

/// Implements internal node types and `DigestAlgorithm` for 32-byte hash functions.
macro_rules! impl_mt_hash_256 {
    ($hasher:ident, $node_name:ident, $digest_name:ident) => {
        /// Internal node for Merkle tree.
        #[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
        pub struct $node_name(pub(crate) [u8; 32]);

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
                let mut buffer = [0u8; 32];
                reader.read_exact(&mut buffer)?;
                Ok(Self(buffer))
            }
        }

        impl Valid for $node_name {
            fn check(&self) -> Result<(), SerializationError> {
                Ok(())
            }
        }

        /// Digest implementation using the given hash function.
        #[derive(Debug, Clone, Hash, Eq, PartialEq)]
        pub struct $digest_name;

        impl<E: Element + CanonicalSerialize, I: Index> DigestAlgorithm<E, I, $node_name>
            for $digest_name
        {
            fn digest(data: &[$node_name]) -> Result<$node_name, MerkleTreeError> {
                let mut hasher = $hasher::new();
                for node in data {
                    hasher.update(node.as_ref());
                }
                Ok($node_name(hasher.finalize().into()))
            }

            fn digest_leaf(_pos: &I, elem: &E) -> Result<$node_name, MerkleTreeError> {
                let mut buffer = Vec::new();
                elem.serialize_compressed(&mut buffer).unwrap();
                let mut hasher = $hasher::new();
                hasher.update(&buffer);
                Ok($node_name(hasher.finalize().into()))
            }
        }
    };
}

// Implement hash functions using the macro.
impl_mt_hash_256!(Sha3_256, Sha3Node, Sha3Digest);
impl_mt_hash_256!(Keccak256, Keccak256Node, Keccak256Digest);

/// A Merkle tree using SHA3 hash function.
pub type SHA3MerkleTree<E> = MerkleTree<E, Sha3Digest, u64, 3, Sha3Node>;
/// A lightweight Merkle tree using SHA3 hash function.
pub type LightWeightSHA3MerkleTree<E> = LightWeightMerkleTree<E, Sha3Digest, u64, 3, Sha3Node>;

/// A Merkle tree using Keccak256 hash function.
pub type Keccak256MerkleTree<E> = MerkleTree<E, Keccak256Digest, u64, 3, Keccak256Node>;
/// A lightweight Merkle tree using Keccak256 hash function.
pub type LightWeightKeccak256MerkleTree<E> =
    LightWeightMerkleTree<E, Keccak256Digest, u64, 3, Keccak256Node>;
