// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A wrapper for [`MerkleTree`] to work with RustCrypto-compatible hash functions.
//! Example usage:
//!
//! ```rust
//! use jf_merkle_tree::{hasher::HasherMerkleTree, AppendableMerkleTreeScheme, MerkleTreeScheme};
//! use sha2::Sha256;
//!
//! fn main() -> Result<(), jf_merkle_tree::errors::MerkleTreeError> {
//!     let data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
//!     let mt = HasherMerkleTree::<Sha256, usize>::from_elems(Some(2), &data)?;
//!
//!     let commitment = mt.commitment();
//!     let (value, proof) = mt.lookup(2).expect_ok()?;
//!     assert_eq!(value, &3);
//!     assert!(HasherMerkleTree::<Sha256, usize>::verify(commitment, 2, value, proof)?.is_ok());
//!     Ok(())
//! }
//! ```

#![allow(clippy::non_canonical_partial_ord_impl)]

use super::{append_only::MerkleTree, DigestAlgorithm, Element, Index};
use crate::errors::MerkleTreeError;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use ark_std::string::ToString;
use derivative::Derivative;
use digest::{
    crypto_common::{generic_array::ArrayLength, Output},
    Digest, OutputSizeUser,
};
use tagged_base64::tagged;

/// A Merkle tree using a RustCrypto-compatible hasher.
///
/// - `H`: Hash function (e.g., `Sha256`).
/// - `E`: Payload type.
pub type HasherMerkleTree<H, E> = GenericHasherMerkleTree<H, E, u64, 3>;

/// A generic Merkle tree with additional parameters.
///
/// - `I`: Index type (e.g., `u64`, `ark_ff::Field`).
/// - `ARITY`: Tree arity (e.g., 2 for binary, 3 for trinary).
pub type GenericHasherMerkleTree<H, E, I, const ARITY: usize> =
    MerkleTree<E, HasherDigestAlgorithm, I, ARITY, HasherNode<H>>;

// ===================================
// Trait: HasherDigest
// ===================================

/// A trait for hashers compatible with RustCrypto [`Digest`].
pub trait HasherDigest: Digest<OutputSize = Self::OutSize> + Write + Send + Sync {
    /// The output size of the hasher.
    type OutSize: ArrayLength<u8, ArrayType = Self::ArrayType>;
    /// The array type of the hasher output.
    type ArrayType: Copy;
}

impl<T> HasherDigest for T
where
    T: Digest + Write + Send + Sync,
    <T::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    type OutSize = T::OutputSize;
    type ArrayType = <Self::OutSize as ArrayLength<u8>>::ArrayType;
}

// ===================================
// Struct: HasherDigestAlgorithm
// ===================================

/// Implements [`DigestAlgorithm`] for Merkle trees.
pub struct HasherDigestAlgorithm;

impl<E, I, H> DigestAlgorithm<E, I, HasherNode<H>> for HasherDigestAlgorithm
where
    E: Element + CanonicalSerialize,
    I: Index + CanonicalSerialize,
    H: HasherDigest,
{
    fn digest(data: &[HasherNode<H>]) -> Result<HasherNode<H>, MerkleTreeError> {
        let mut hasher = H::new();
        for value in data {
            hasher.update(value.as_ref());
        }
        Ok(HasherNode(hasher.finalize()))
    }

    fn digest_leaf(pos: &I, elem: &E) -> Result<HasherNode<H>, MerkleTreeError> {
        let mut hasher = H::new();
        pos.serialize_uncompressed(&mut hasher)
            .map_err(|_| MerkleTreeError::DigestError("Failed to serialize position".to_string()))?;
        elem.serialize_uncompressed(&mut hasher)
            .map_err(|_| MerkleTreeError::DigestError("Failed to serialize element".to_string()))?;
        Ok(HasherNode(hasher.finalize()))
    }
}

// ===================================
// Struct: HasherNode
// ===================================

/// A wrapper for hash outputs in the Merkle tree.
#[derive(Derivative, tagged("HASH"))]
#[derivative(
    Clone(bound = ""),
    Copy(bound = "<<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy"),
    Debug(bound = ""),
    Default(bound = ""),
    Eq(bound = ""),
    Hash(bound = ""),
    Ord(bound = ""),
    PartialEq(bound = ""),
    PartialOrd(bound = "")
)]
pub struct HasherNode<H>(Output<H>)
where
    H: Digest;

impl<H> From<Output<H>> for HasherNode<H>
where
    H: Digest,
{
    fn from(value: Output<H>) -> Self {
        Self(value)
    }
}

impl<H> AsRef<Output<H>> for HasherNode<H>
where
    H: Digest,
{
    fn as_ref(&self) -> &Output<H> {
        &self.0
    }
}

// ===================================
// Serialization Traits
// ===================================

impl<H> CanonicalSerialize for HasherNode<H>
where
    H: Digest,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        _compress: Compress,
    ) -> Result<(), SerializationError> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    fn serialized_size(&self, _compress: Compress) -> usize {
        H::output_size()
    }
}

impl<H> CanonicalDeserialize for HasherNode<H>
where
    H: Digest,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        _compress: Compress,
        _validate: Validate,
    ) -> Result<Self, SerializationError> {
        let mut buffer = Output::<H>::default();
        reader.read_exact(&mut buffer)?;
        Ok(Self(buffer))
    }
}

impl<H> Valid for HasherNode<H>
where
    H: Digest,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

// ===================================
// Tests
// ===================================

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn test_merkle_tree_creation() -> Result<(), MerkleTreeError> {
        let data = [1, 2, 3, 4];
        let mt = HasherMerkleTree::<Sha256, usize>::from_elems(Some(2), &data)?;

        let commitment = mt.commitment();
        let (value, proof) = mt.lookup(2).expect_ok()?;
        assert_eq!(value, &3);
        assert!(HasherMerkleTree::<Sha256, usize>::verify(commitment, 2, value, proof)?.is_ok());
        Ok(())
    }
}
