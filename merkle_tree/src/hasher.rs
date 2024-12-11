// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A convenience wrapper [`HasherMerkleTree`] to instantiate [`MerkleTree`] for any [RustCrypto-compatible](https://github.com/RustCrypto/hashes) hash function.
//!
//! ```
//! # use jf_merkle_tree::errors::MerkleTreeError;
//! use jf_merkle_tree::{hasher::HasherMerkleTree, AppendableMerkleTreeScheme, MerkleTreeScheme};
//! use sha2::Sha256;
//!
//! # fn main() -> Result<(), MerkleTreeError> {
//! let my_data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
//!
//! // payload type is `usize`, hash function is `Sha256`.
//! let mt = HasherMerkleTree::<Sha256, usize>::from_elems(Some(2), &my_data)?;
//!
//! let commitment = mt.commitment();
//! let (val, proof) = mt.lookup(2).expect_ok()?;
//! assert_eq!(val, &3);
//! assert!(HasherMerkleTree::<Sha256, usize>::verify(commitment, 2, val, proof)?.is_ok());
//! # Ok(())
//! # }
//! ```
//!
//! [`HasherMerkleTree`] requires the `std` feature for your hasher, which is
//! enabled by default. Example:
//! ```toml
//! [dependencies]
//! sha2 = "0.10"
//! ```
//!
//! Use [`GenericHasherMerkleTree`] if you prefer to specify your own `ARITY`
//! and node [`Index`] types.

// clippy is freaking out about `HasherNode` and this is the only thing I
// could do to stop it
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

/// Merkle tree generic over [`Digest`] hasher `H`.
///
/// It's a trinary tree whose nodes are indexed by [`u64`].
/// - `H` is a [RustCrypto-compatible](https://github.com/RustCrypto/hashes)
///   hash function.
/// - `E` is a [`Element`] payload data type for the Merkle tree.
pub type HasherMerkleTree<H, E> = GenericHasherMerkleTree<H, E, u64, 3>;

/// Like [`HasherMerkleTree`] except with additional parameters.
///
/// Additional parameters beyond [`HasherMerkleTree`]:
/// - `I` is a [`Index`] data type that impls [`From<u64>`]. (eg. [`u64`],
///   [`Field`](ark_ff::Field), etc.)
/// - `ARITY` is a const generic. (eg. 2 for a binary tree, 3 for a trinary
///   tree, etc.)
pub type GenericHasherMerkleTree<H, E, I, const ARITY: usize> =
    MerkleTree<E, HasherDigestAlgorithm, I, ARITY, HasherNode<H>>;

/// Convenience trait and blanket impl for downstream trait bounds.
///
/// Useful for downstream code that's generic over [`Digest`] hasher `H`.
///
/// # Example
///
/// Do this:
/// ```
/// # use jf_merkle_tree::{hasher::HasherMerkleTree, AppendableMerkleTreeScheme};
/// # use jf_merkle_tree::hasher::HasherDigest;
/// fn generic_over_hasher<H>()
/// where
///     H: HasherDigest,
/// {
///     let my_data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
///     let mt = HasherMerkleTree::<H, usize>::from_elems(None, &my_data).unwrap();
/// }
/// ```
///
/// Instead of this:
/// ```
/// # use digest::{crypto_common::generic_array::ArrayLength, Digest, OutputSizeUser};
/// # use ark_serialize::Write;
/// # use jf_merkle_tree::{hasher::HasherMerkleTree, AppendableMerkleTreeScheme};
/// # use jf_merkle_tree::hasher::HasherDigest;
/// fn generic_over_hasher<H>()
/// where
///     H: Digest + Write + Send + Sync,
///     <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
/// {
///     let my_data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
///     let mt = HasherMerkleTree::<H, usize>::from_elems(None, &my_data).unwrap();
/// }
/// ```
///
/// Note that the complex trait bound for [`Copy`] is necessary:
/// ```compile_fail
/// # use digest::{crypto_common::generic_array::ArrayLength, Digest, OutputSizeUser};
/// # use ark_serialize::Write;
/// # use jf_merkle_tree::{hasher::HasherMerkleTree, AppendableMerkleTreeScheme};
/// # use jf_merkle_tree::hasher::HasherDigest;
/// fn generic_over_hasher<H>()
/// where
///     H: Digest + Write + Send + Sync,
/// {
///     let my_data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
///     let mt = HasherMerkleTree::<H, usize>::from_elems(None, &my_data).unwrap();
/// }
/// ```
pub trait HasherDigest: Digest<OutputSize = Self::OutSize> + Write + Send + Sync {
    /// Type for the output size
    type OutSize: ArrayLength<u8, ArrayType = Self::ArrayType>;
    /// Type for the array
    type ArrayType: Copy;
}
impl<T> HasherDigest for T
where
    T: Digest + Write + Send + Sync,
    <T::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    type OutSize = T::OutputSize;
    type ArrayType = <<T as HasherDigest>::OutSize as ArrayLength<u8>>::ArrayType;
}

/// A struct that impls [`DigestAlgorithm`] for use with [`MerkleTree`].
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
            .map_err(|_| MerkleTreeError::DigestError("Failed serializing pos".to_string()))?;
        elem.serialize_uncompressed(&mut hasher)
            .map_err(|_| MerkleTreeError::DigestError("Failed serializing elem".to_string()))?;
        Ok(HasherNode(hasher.finalize()))
    }
}

/// Newtype wrapper for hash output that impls [`NodeValue`](super::NodeValue).
#[derive(Derivative)]
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
#[tagged("HASH")]
pub struct HasherNode<H>(Output<H>)
where
    H: Digest;

/// Allow creation from [`Output`]
impl<H> From<Output<H>> for HasherNode<H>
where
    H: Digest,
{
    fn from(value: Output<H>) -> Self {
        Self(value)
    }
}

/// Allow access to the underlying [`Output`]
impl<H> AsRef<Output<H>> for HasherNode<H>
where
    H: Digest,
{
    fn as_ref(&self) -> &Output<H> {
        &self.0
    }
}

// Manual impls of some subtraits of [`NodeValue`](super::NodeValue).
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
        <H as Digest>::output_size()
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
        let mut ret = Output::<H>::default();
        reader.read_exact(&mut ret)?;
        Ok(HasherNode(ret))
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
