// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A convenience wrapper [`HasherMerkleTree`] to instantiate [`MerkleTree`] for any [RustCrypto-compatible](https://github.com/RustCrypto/hashes) hash function.
//!
//! ```
//! # use jf_primitives::errors::PrimitivesError;
//! use jf_primitives::merkle_tree::{hasher::HasherMerkleTree, MerkleCommitment, MerkleTreeScheme};
//! use sha2::Sha256;
//!
//! # fn main() -> Result<(), PrimitivesError> {
//! let my_data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
//!
//! // payload type is `usize`, hash function is `Sha256`.
//! let mt = HasherMerkleTree::<Sha256, usize>::from_elems(2, &my_data)?;
//!
//! let root = mt.commitment().digest();
//! let (val, proof) = mt.lookup(2).expect_ok()?;
//! assert_eq!(val, 3);
//! assert!(HasherMerkleTree::<Sha256, usize>::verify(root, proof)?.is_ok());
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
//! Use [`GenericHasherMerkleTree`] if you prefer to specify your own `Arity`
//! and node [`Index`] types.

use super::{append_only::MerkleTree, DigestAlgorithm, Element, Index};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use digest::{
    crypto_common::{generic_array::ArrayLength, Output},
    Digest, OutputSizeUser,
};
use serde::{Deserialize, Serialize};
use typenum::U3;

/// Merkle tree generic over [`Digest`] hasher `H`.
///
/// It's a trinary ([`U3`]) tree whose nodes are indexed by [`u64`].
/// - `H` is a [RustCrypto-compatible](https://github.com/RustCrypto/hashes)
///   hash function.
/// - `E` is a [`Element`] payload data type for the Merkle tree.
pub type HasherMerkleTree<H, E> = GenericHasherMerkleTree<H, E, u64, U3>;

/// Like [`HasherMerkleTree`] except with additional parameters.
///
/// Additional parameters beyond [`HasherMerkleTree`]:
/// - `I` is a [`Index`] data type that impls [`TryFrom<u64>`]. (eg. [`u64`],
///   [`Field`](ark_ff::Field), etc.)
/// - `Arity` is a [`Unsigned`](typenum::Unsigned). (eg. [`U2`](typenum::U2) for
///   a binary tree, [`U3`] for a trinary tree, etc.)
pub type GenericHasherMerkleTree<H, E, I, Arity> =
    MerkleTree<E, HasherDigestAlgorithm, I, Arity, HasherNode<H>>;

/// A struct that impls [`DigestAlgorithm`] for use with [`MerkleTree`].
pub struct HasherDigestAlgorithm;

impl<E, I, H> DigestAlgorithm<E, I, HasherNode<H>> for HasherDigestAlgorithm
where
    E: Element + CanonicalSerialize,
    I: Index + CanonicalSerialize,
    H: Digest + Write,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn digest(data: &[HasherNode<H>]) -> HasherNode<H> {
        let mut hasher = H::new();
        for value in data {
            hasher.update(value.as_ref());
        }
        HasherNode(hasher.finalize())
    }

    fn digest_leaf(pos: &I, elem: &E) -> HasherNode<H> {
        let mut hasher = H::new();
        pos.serialize_uncompressed(&mut hasher)
            .expect("serialize should succeed");
        elem.serialize_uncompressed(&mut hasher)
            .expect("serialize should succeed");
        HasherNode(hasher.finalize())
    }
}

/// Newtype wrapper for hash output that impls [`NodeValue`](super::NodeValue).
#[derive(Derivative, Deserialize, Serialize)]
#[serde(bound = "Output<H>: Serialize + for<'a> Deserialize<'a>")]
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
