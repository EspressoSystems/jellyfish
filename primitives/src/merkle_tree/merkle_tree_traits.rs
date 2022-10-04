// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use crate::errors::PrimitivesError;
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    ops::{Add, AddAssign, DivAssign, MulAssign, Rem},
    slice,
    string::ToString,
    vec,
    vec::Vec,
};
use num::traits::AsPrimitive;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
/// The result of querying at an index in the tree
pub enum LookupResult<F, P> {
    /// The value at the given index, and a proof of validity
    Ok(F, P),
    /// The index is valid but we do not have the leaf in memory
    NotInMemory,
    /// The index is outside the occupied range in the tree
    EmptyLeaf,
}

impl<F, P> LookupResult<F, P> {
    /// Assert the lookup result is Ok.
    pub fn expect_ok(self) -> Result<(F, P), PrimitivesError> {
        match self {
            LookupResult::Ok(x, proof) => Ok((x, proof)),
            LookupResult::NotInMemory => Err(PrimitivesError::InternalError(
                "Expected Ok, found NotInMemory".to_string(),
            )),
            LookupResult::EmptyLeaf => Err(PrimitivesError::InternalError(
                "Expected Ok, found EmptyLeaf".to_string(),
            )),
        }
    }
}

/// Merkle tree element type
pub trait ElementType<F: Field>:
    Default + Ord + Clone + Copy + Debug + CanonicalSerialize + CanonicalDeserialize + Eq + PartialEq
{
    /// As a slice ref of field elements
    fn as_slice_ref(&self) -> &[F];

    /// Length of the slice ref
    fn slice_len() -> usize;
}

impl<F: Field> ElementType<F> for F {
    fn as_slice_ref<'a>(&self) -> &[F] {
        slice::from_ref(self)
    }

    fn slice_len() -> usize {
        1
    }
}

/// Merkle tree hash function
pub trait DigestAlgorithm<F: Field> {
    /// Digest a list of values
    fn digest(data: &[F]) -> F;
}

/// Generic index type for merkle tree. In most cases, for merkle tree indexed
/// with `u64`, just add `impl IndexType<F> for u64 {}`.
pub trait IndexType<F: Field>:
    Default
    + Debug
    + Zero
    + Ord
    + Eq
    + PartialEq
    + From<u64>
    + AddAssign<u64>
    + Add<u64, Output = Self>
    + DivAssign<u64>
    + MulAssign<u64>
    + Rem<u64, Output = Self>
    + AsPrimitive<usize>
    + CanonicalSerialize
    + CanonicalDeserialize
{
    /// As a slice ref of field elements
    fn as_slice(&self) -> Vec<F>;

    /// Length of the slice ref
    fn slice_len() -> usize;
}

impl<F: Field> IndexType<F> for u64 {
    fn as_slice(&self) -> Vec<F> {
        vec![F::from(*self)]
    }

    fn slice_len() -> usize {
        1
    }
}

/// A merkle commitment consists a root hash value, a tree height and number of
/// leaves
#[derive(
    Eq, PartialEq, Clone, Copy, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MerkleCommitment<I: IndexType<F>, F: Field> {
    /// Root of a tree
    pub root_value: F,
    /// Height of a tree
    pub height: usize,
    /// Number of leaves in the tree
    pub num_leaves: I,
}

/// Basic functionalities for a merkle tree implementation. Abstracted as an
/// accumulator for fixed-length array. Supports generate membership proof at a
/// given position and verify a membership proof.
pub trait MerkleTree<F: Field>: Sized {
    /// Merkle tree element type
    type ElementType: ElementType<F>;
    /// Hash algorithm used in merkle tree
    type Digest: DigestAlgorithm<F>;
    /// Index type for this merkle tree
    type IndexType: IndexType<F>;
    /// Merkle proof
    type MembershipProof;
    /// Batch proof
    type BatchMembershipProof;

    /// Tree arity
    const ARITY: usize;

    /// Construct a new merkle tree with given height from a data slice
    fn from_elems(
        height: usize,
        elems: impl IntoIterator<Item = impl Borrow<Self::ElementType>>,
    ) -> Result<Self, PrimitivesError>;

    /// Return the height of this merkle tree
    fn height(&self) -> usize;
    /// Return the maximum allowed number leaves
    fn capacity(&self) -> Self::IndexType;
    /// Return the current number of leaves
    fn num_leaves(&self) -> Self::IndexType;

    /// Return the current root value
    fn root(&self) -> F;

    /// Return a merkle commitment
    fn commitment(&self) -> MerkleCommitment<Self::IndexType, F>;

    /// Returns the leaf value given a position
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `returns` - Leaf value at the position along with a proof.
    ///   LookupResult::EmptyLeaf if the leaf position is empty or invalid,
    ///   LookupResult::NotInMemory if the leaf position has been forgotten.
    fn lookup(
        &self,
        pos: Self::IndexType,
    ) -> LookupResult<Self::ElementType, Self::MembershipProof>;

    /// Verify an element is a leaf of a Merkle tree given the proof
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `proof` - a merkle tree proof
    /// * `returns` - Ok(true) if the proof is accepted, Ok(false) if not. Err()
    ///   if the proof is not well structured, E.g. not for this merkle tree.
    fn verify(
        &self,
        pos: Self::IndexType,
        proof: impl Borrow<Self::MembershipProof>,
    ) -> Result<bool, PrimitivesError>;

    // fn batch_lookup(&self, pos: impl Iterator<Item = usize>) -> LookupResult<(),
    // Self::BatchProof>; fn batch_verify(
    //     &self,
    //     pos: impl Iterator<Item = usize>,
    //     proof: impl Borrow<Self::BatchProof>,
    // ) -> Result<(), PrimitivesError>;
}

/// Merkle tree that allows insertion at back. Abstracted as a commitment for
/// append-only vector.
pub trait AppendableMerkleTree<F: Field>: MerkleTree<F> {
    /// Insert a new value at the leftmost available slot
    /// * `elem` - element to insert in the tree
    /// * `returns` - Ok(()) if successful
    fn push(&mut self, elem: impl Borrow<Self::ElementType>) -> Result<(), PrimitivesError>;

    /// Insert a list of new values at the leftmost available slots
    /// * `elems` - elements to insert
    /// * `returns` - Ok(()) if successful. If there are too many elements,
    ///   insertions will be performed until the merkle tree is full, and wil
    ///   return an Err().
    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl Borrow<Self::ElementType>>,
    ) -> Result<(), PrimitivesError> {
        for elem in elems {
            self.push(elem)?;
        }
        Ok(())
    }
}

/// A universal merkle tree is abstracted as a random-access array or a
/// key-value map. It allows manipulation at any given position, and has ability
/// to generate/verify a non-membership proof.
pub trait UniversalMerkleTree<F: Field>: MerkleTree<F> {
    /// Non membership proof for a given index
    type NonMembershipProof;
    /// Batch non membership proof
    type BatchNonMembershipProof;

    /// Update the leaf value at a given position
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `elem` - newly updated element
    fn update(
        &mut self,
        pos: Self::IndexType,
        elem: &Self::ElementType,
    ) -> Result<(), PrimitivesError>;

    // TODO(Chengyu): non-membership proof interfaces
}

/// Merkle tree that allows forget/remember elements from the memory
pub trait ForgetableMerkleTree<F: Field>: MerkleTree<F> {
    /// Trim the leaf at position `i` from memory, if present.
    /// Should not trim if position `i` is the last inserted leaf position.
    /// Return is identical to result if `get_leaf(pos)` were called before this
    /// call.
    fn forget(
        &mut self,
        pos: Self::IndexType,
    ) -> LookupResult<Self::ElementType, Self::MembershipProof>;

    /// "Re-insert" a leaf into the tree using its proof.
    /// Returns Ok(()) if insertion is successful, or Err(err) if the
    /// proof disagrees with the merkle tree
    fn remember(
        &mut self,
        pos: Self::IndexType,
        element: impl Borrow<Self::ElementType>,
        proof: impl Borrow<Self::MembershipProof>,
    ) -> Result<(), PrimitivesError>;
}
