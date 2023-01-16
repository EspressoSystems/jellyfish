// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Merkle Tree traits and implementations
pub mod append_only;
pub mod examples;
pub mod light_weight;
pub mod macros;
pub mod universal_merkle_tree;

pub(crate) mod internal;

pub mod prelude;

use crate::{
    errors::PrimitivesError, impl_to_traversal_path_biguint, impl_to_traversal_path_primitives,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, fmt::Debug, hash::Hash, string::ToString, vec, vec::Vec};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
/// The result of querying at an index in the tree
/// Typically, F for element type, P for membership proof type and N for
/// non-membership proof type
pub enum LookupResult<F, P, N> {
    /// The value at the given index, and a proof of validity
    Ok(F, P),
    /// The index is valid but we do not have the leaf in memory
    NotInMemory,
    /// The index is outside the occupied range in the tree, and a
    /// non-membership proof
    NotFound(N),
}

impl<F, P, N> LookupResult<F, P, N> {
    /// Assert the lookup result is Ok. Return a tuple of element and membership
    /// proof.
    pub fn expect_ok(self) -> Result<(F, P), PrimitivesError> {
        match self {
            LookupResult::Ok(x, proof) => Ok((x, proof)),
            LookupResult::NotInMemory => Err(PrimitivesError::InternalError(
                "Expected Ok, found NotInMemory".to_string(),
            )),
            LookupResult::NotFound(_) => Err(PrimitivesError::InternalError(
                "Expected Ok, found NotFound".to_string(),
            )),
        }
    }

    /// Assert the lookup result is NotFound. Return a non-membership proof.
    pub fn expect_not_found(self) -> Result<N, PrimitivesError> {
        match self {
            LookupResult::NotFound(n) => Ok(n),
            LookupResult::Ok(..) => Err(PrimitivesError::InternalError(
                "Expected NotFound, found Ok".to_string(),
            )),
            LookupResult::NotInMemory => Err(PrimitivesError::InternalError(
                "Expected NotFound, found NotInMemory".to_string(),
            )),
        }
    }

    /// Assert the lookup result is NotInMemory.
    pub fn expect_not_in_memory(self) -> Result<(), PrimitivesError> {
        match self {
            LookupResult::NotInMemory => Ok(()),
            LookupResult::Ok(..) => Err(PrimitivesError::InternalError(
                "Expected NotInMemory, found Ok".to_string(),
            )),
            LookupResult::NotFound(..) => Err(PrimitivesError::InternalError(
                "Expected NotInMemory, found NotFound".to_string(),
            )),
        }
    }
}

/// An element of a Merkle tree.
pub trait Element: Clone + Eq + PartialEq {}
impl<T: Clone + Eq + PartialEq> Element for T {}

/// An index type of a leaf in a Merkle tree.
pub trait Index: Debug + Eq + PartialEq + Hash + Ord + PartialOrd + Clone {}
impl<T: Debug + Eq + PartialEq + Hash + Ord + PartialOrd + Clone> Index for T {}

/// An internal node value type in a Merkle tree.
pub trait NodeValue:
    Default
    + Eq
    + PartialEq
    + Hash
    + Ord
    + PartialOrd
    + Copy
    + Clone
    + Debug
    + CanonicalSerialize
    + CanonicalDeserialize
{
}
impl<T> NodeValue for T where
    T: Default
        + Eq
        + PartialEq
        + Hash
        + Ord
        + PartialOrd
        + Copy
        + Clone
        + Debug
        + CanonicalSerialize
        + CanonicalDeserialize
{
}

/// Merkle tree hash function
pub trait DigestAlgorithm<E, I, T>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    /// Digest a list of values
    fn digest(data: &[T]) -> T;

    /// Digest an indexed element
    fn digest_leaf(pos: &I, elem: &E) -> T;
}

/// An trait for Merkle tree index type.
pub trait ToTraversalPath<Arity: Unsigned> {
    /// Convert the given index to a vector of branch indices given tree height
    /// and arity.
    fn to_traversal_path(&self, height: usize) -> Vec<usize>;
}

impl_to_traversal_path_primitives!(usize);
impl_to_traversal_path_primitives!(u8);
impl_to_traversal_path_primitives!(u16);
impl_to_traversal_path_primitives!(u32);
impl_to_traversal_path_primitives!(u64);
impl_to_traversal_path_biguint!(u128);
impl_to_traversal_path_biguint!(BigUint);
impl_to_traversal_path_biguint!(ark_ed_on_bn254::Fq);
impl_to_traversal_path_biguint!(ark_ed_on_bls12_377::Fq);
impl_to_traversal_path_biguint!(ark_ed_on_bls12_381::Fq);

/// Trait for a succint merkle tree commitment
pub trait MerkleCommitment<T: NodeValue>:
    Eq
    + PartialEq
    + Hash
    + Ord
    + PartialOrd
    + Clone
    + Copy
    + Serialize
    + for<'a> Deserialize<'a>
    + CanonicalDeserialize
    + CanonicalSerialize
{
    /// Return a digest of the tree
    fn digest(&self) -> T;
    /// Return the height of the tree
    fn height(&self) -> usize;
    /// Return the number of elements included in the accumulator/tree
    fn size(&self) -> u64;
}

/// Basic functionalities for a merkle tree implementation. Abstracted as an
/// accumulator for fixed-length array. Supports generate membership proof at a
/// given position and verify a membership proof.
pub trait MerkleTreeScheme: Sized {
    /// Merkle tree element type
    type Element: Element;
    /// Index type for this merkle tree
    type Index: Index;
    /// Internal and root node value
    type NodeValue: NodeValue;
    /// Merkle proof
    type MembershipProof: Clone;
    /// Batch proof
    type BatchMembershipProof: Clone;
    /// Merkle tree commitment
    type Commitment: MerkleCommitment<Self::NodeValue>;

    /// Tree arity
    const ARITY: usize;

    /// Construct a new merkle tree with given height from a data slice
    fn from_elems(
        height: usize,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<Self, PrimitivesError>;

    /// Return the height of this merkle tree
    fn height(&self) -> usize;
    /// Return the maximum allowed number leaves
    fn capacity(&self) -> BigUint;
    /// Return the current number of leaves
    fn num_leaves(&self) -> u64;

    /// Return a merkle commitment
    fn commitment(&self) -> Self::Commitment;

    /// Returns the leaf value given a position
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `returns` - Leaf value at the position along with a proof.
    ///   LookupResult::EmptyLeaf if the leaf position is empty or invalid,
    ///   LookupResult::NotInMemory if the leaf position has been forgotten.
    fn lookup(
        &self,
        pos: impl Borrow<Self::Index>,
    ) -> LookupResult<Self::Element, Self::MembershipProof, ()>;

    /// Verify an element is a leaf of a Merkle tree given the proof
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `proof` - a merkle tree proof
    /// * `returns` - Ok(true) if the proof is accepted, Ok(false) if not. Err()
    ///   if the proof is not well structured, E.g. not for this merkle tree.
    fn verify(
        &self,
        pos: impl Borrow<Self::Index>,
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
pub trait AppendableMerkleTreeScheme: MerkleTreeScheme {
    /// Insert a new value at the leftmost available slot
    /// * `elem` - element to insert in the tree
    /// * `returns` - Ok(()) if successful
    fn push(&mut self, elem: impl Borrow<Self::Element>) -> Result<(), PrimitivesError>;

    /// Insert a list of new values at the leftmost available slots
    /// * `elems` - elements to insert
    /// * `returns` - Ok(()) if successful. If there are too many elements,
    ///   insertions will be performed until the merkle tree is full, and wil
    ///   return an Err().
    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
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
pub trait UniversalMerkleTreeScheme: MerkleTreeScheme {
    /// Non membership proof for a given index
    type NonMembershipProof;
    /// Batch non membership proof
    type BatchNonMembershipProof;

    /// Build a universal merkle tree from a key-value set.
    /// * `height` - height of the merkle tree
    /// * `data` - an iterator of key-value pairs. Could be a hashmap or simply
    ///   an array or a slice of (key, value) pairs
    fn from_kv_set<BI, BE>(
        height: usize,
        data: impl IntoIterator<Item = impl Borrow<(BI, BE)>>,
    ) -> Result<Self, PrimitivesError>
    where
        BI: Borrow<Self::Index>,
        BE: Borrow<Self::Element>;

    /// Update the leaf value at a given position
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `elem` - newly updated element
    fn update(
        &mut self,
        pos: impl Borrow<Self::Index>,
        elem: impl Borrow<Self::Element>,
    ) -> LookupResult<Self::Element, (), ()>;

    /// Returns the leaf value given a position
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `returns` - Leaf value at the position along with a proof.
    ///   LookupResult::EmptyLeaf(p) if the leaf position is empty along with a
    ///   proof p. LookupResult::NotInMemory if the leaf position has been
    ///   forgotten.
    fn universal_lookup(
        &self,
        pos: impl Borrow<Self::Index>,
    ) -> LookupResult<Self::Element, Self::MembershipProof, Self::NonMembershipProof>;

    /// Verify an index is not in this merkle tree
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `proof` - a merkle tree proof
    /// * `returns` - Ok(true) if the proof is accepted, Ok(false) if not. Err()
    ///   if the proof is not well structured, E.g. not for this merkle tree.
    fn non_membership_verify(
        &self,
        pos: impl Borrow<Self::Index>,
        proof: impl Borrow<Self::NonMembershipProof>,
    ) -> Result<bool, PrimitivesError>;
    // TODO(Chengyu): non-membership proof interfaces
}

/// Merkle tree that allows forget/remember elements from the memory
pub trait ForgetableMerkleTreeScheme: MerkleTreeScheme {
    /// Trim the leaf at position `i` from memory, if present.
    /// Should not trim if position `i` is the last inserted leaf position.
    /// Return is identical to result if `get_leaf(pos)` were called before this
    /// call.
    fn forget(
        &mut self,
        pos: Self::Index,
    ) -> LookupResult<Self::Element, Self::MembershipProof, ()>;

    /// "Re-insert" a leaf into the tree using its proof.
    /// Returns Ok(()) if insertion is successful, or Err(err) if the
    /// proof disagrees with the merkle tree
    fn remember(
        &mut self,
        pos: Self::Index,
        element: impl Borrow<Self::Element>,
        proof: impl Borrow<Self::MembershipProof>,
    ) -> Result<(), PrimitivesError>;

    /// Rebuild a merkle tree from a commitment.
    /// Return a tree which is entirely forgotten.
    fn from_commitment(commitment: impl Borrow<Self::Commitment>) -> Self;
}

/// Universal Merkle tree that allows forget/remember elements from the memory
pub trait ForgetableUniversalMerkleTreeScheme:
    ForgetableMerkleTreeScheme + UniversalMerkleTreeScheme
{
    /// Trim the leaf at position `pos` from memory.
    ///
    /// This is similar to [forget](ForgetableMerkleTreeScheme::forget), but it
    /// may prune even an empty sub-tree at `pos` and will return a
    /// non-membership proof for the pruned position if it does so. Note
    /// that an implementation may choose _not_ to prune an empty sub-tree, as
    /// it may be more efficient to represent an empty sub-tree than a
    /// forgotten one. In this case,
    /// [universal_lookup](UniversalMerkleTreeScheme::universal_lookup) may
    /// return _either_ [LookupResult::NotInMemory] or
    /// [LookupResult::NotFound] after a successful call to
    /// [universal_forget](Self::universal_forget). In any case, if this
    /// function is called for a `pos` which is in memory but not in the
    /// tree, it will return a non-membership proof.
    ///
    /// The return value is the same as if
    /// [universal_lookup](UniversalMerkleTreeScheme::universal_lookup) were
    /// called before this call.
    fn universal_forget(
        &mut self,
        pos: Self::Index,
    ) -> LookupResult<Self::Element, Self::MembershipProof, Self::NonMembershipProof>;

    /// "Re-insert" an empty leaf into the tree using its proof.
    ///
    /// Returns `Ok(())` if insertion is successful, or `Err(err)` if the proof
    /// disagrees with the merkle tree
    fn non_membership_remember(
        &mut self,
        pos: Self::Index,
        proof: impl Borrow<Self::NonMembershipProof>,
    ) -> Result<(), PrimitivesError>;
}
