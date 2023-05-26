// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A convenience wrapper to instantiate [`MerkleTree`] for any [RustCrypto-compatible](https://github.com/RustCrypto/hashes) hash function.
use super::{append_only::MerkleTree, DigestAlgorithm, Element, Index};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use ark_std::{fmt::Debug, hash::Hash};
use digest::{
    crypto_common::{generic_array::ArrayLength, Output},
    Digest, OutputSizeUser,
};
use typenum::U3;

/// Merkle tree generic over [`Digest`] hasher.
///
/// * `H: Digest` any [`Digest`] hasher
/// * `E: Element` the payload data type
///
/// TODO: example usage.
pub type HasherMerkleTree<H, E> = MerkleTree<E, HasherDigestAlgorithm, u64, U3, HasherNode<H>>;

/// Newtype wrapper for hash output that impls [`NodeValue`].
// Most subtraits of [`NodeValue`] cannot be automatically derived,
// so we must impl them manually.

pub struct HasherNode<H>(Output<H>)
where
    H: Digest;

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

/// Allow generic creation from [`Output`]
impl<H> From<Output<H>> for HasherNode<H>
where
    H: Digest,
{
    fn from(value: Output<H>) -> Self {
        Self(value)
    }
}

/// Allow generic access to the underlying [`Output`]
impl<H> AsRef<Output<H>> for HasherNode<H>
where
    H: Digest,
    // <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn as_ref(&self) -> &Output<H> {
        &self.0
    }
}

// Manual impls of the subtraits of [`NodeValue`] for [`HasherNode`]
impl<H> CanonicalSerialize for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
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
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
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
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
impl<H> Clone for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}
impl<H> Copy for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
}
impl<H> Debug for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("HasherNode").field(&self.0).finish()
    }
}
impl<H> Default for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn default() -> Self {
        Self(Default::default())
    }
}
impl<H> ark_std::cmp::Eq for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
}
impl<H> Hash for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn hash<K: core::hash::Hasher>(&self, state: &mut K) {
        self.0.hash(state);
    }
}
impl<H> ark_std::cmp::Ord for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}
impl<H> ark_std::cmp::PartialEq for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<H> ark_std::cmp::PartialOrd for HasherNode<H>
where
    H: Digest,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}