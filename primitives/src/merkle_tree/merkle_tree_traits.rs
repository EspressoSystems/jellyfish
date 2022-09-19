// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, fmt::Debug, string::ToString};
use typenum::Unsigned;

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
    Default
    + Ord
    + Clone
    + Copy
    + Debug
    + CanonicalSerialize
    + CanonicalDeserialize
    + Eq
    + PartialEq
    + AsRef<[F]>
{
    /// Convert the element into a slice of field elements
    /// TODO: is it the same as `AsRef<[F]>`?
    fn as_slice_ref(&self) -> &[F];
}

/// Merkle tree hash function
pub trait Hasher<F: Field> {
    /// Digest a list of values
    fn digest(data: &[F]) -> F;
}

/// Basic functionalities for a merkle tree implementation
pub trait MerkleTree<F: Field>: Sized {
    /// Merkle tree element type
    type ElementType: ElementType<F>;
    /// Hash algorithm used in merkle tree
    type Hasher: Hasher<F>;
    /// Leaf arity
    type LeafArity: Unsigned;
    /// Non-leaf arity
    type TreeArity: Unsigned;
    /// Exsistential proof
    type Proof;
    /// Batch proof
    type BatchProof;

    /// Construct a new merkle tree with given height from a data slice
    fn build(
        height: usize,
        data: impl Iterator<Item = Self::ElementType>,
    ) -> Result<Self, PrimitivesError>;

    /// Return the height of this merkle tree
    fn height(&self) -> usize;
    /// Return the maximum allowed number leaves
    fn capacity(&self) -> u64;
    /// Return the current number of leaves
    fn num_leaves(&self) -> u64;

    /// Return the current root value
    fn value(&self) -> F;

    /// Returns the leaf value given a position
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `returns` - Leaf value at the position. LookupResult::EmptyLeaf if the
    ///   leaf position is empty or invalid, LookupResult::NotInMemory if the
    ///   leaf position has been forgotten.
    fn lookup(&self, pos: u64) -> LookupResult<(), Self::Proof>;

    /// Verify an element is a leaf of a Merkle tree given the proof
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `proof` - a merkle tree proof
    /// * `returns` - Err() if something is wrong with this proof, Ok(result)
    ///   otherwise
    fn verify(&self, pos: u64, proof: impl Borrow<Self::Proof>) -> Result<bool, PrimitivesError>;

    // fn batch_lookup(&self, pos: impl Iterator<Item = usize>) -> LookupResult<(),
    // Self::BatchProof>; fn batch_verify(
    //     &self,
    //     pos: impl Iterator<Item = usize>,
    //     proof: impl Borrow<Self::BatchProof>,
    // ) -> Result<(), PrimitivesError>;
}

/// Merkle tree that allows insertion at back
pub trait AppendableMerkleTree<F: Field>: MerkleTree<F> {
    /// Insert a new value at the leftmost available slot
    /// * `elem` - element to insert in the tree
    /// * `returns` - Ok(()) if successful
    fn push(&mut self, elem: &Self::ElementType) -> Result<(), PrimitivesError>;

    /// Insert a list of new values at the leftmost available slots
    /// * `elems` - elements to insert
    /// * `returns` - Ok(()) if successful
    fn emplace(
        &mut self,
        elems: impl Iterator<Item = Self::ElementType>,
    ) -> Result<(), PrimitivesError>;
}

/// Merkle tree that allows modification
pub trait UpdatableMerkleTree<F: Field>: MerkleTree<F> {
    /// Update the leaf value at a given position
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `elem` - newly updated element
    fn update(&mut self, pos: u64, elem: &Self::ElementType) -> Result<(), PrimitivesError>;
}

/// Merkle tree that allows forget/remember elements from the memory
pub trait ForgetableMerkleTree<F: Field>: MerkleTree<F> {
    /// Trim the leaf at position `i` from memory, if present.
    /// Should not trim if position `i` is the last inserted leaf position.
    /// Return is identical to result if `get_leaf(pos)` were called before this
    /// call.
    fn forget(&mut self, pos: u64) -> LookupResult<(), Self::Proof>;

    /// "Re-insert" a leaf into the tree using its proof.
    /// Returns Ok(()) if insertion is successful, or Err((ix,val)) if the
    /// proof disagrees with the correct node value `val` at position `ix`
    /// in the proof.
    fn remember(
        &mut self,
        pos: u64,
        element: &Self::ElementType,
        proof: Self::Proof,
    ) -> LookupResult<(), (u64, F)>;
}
