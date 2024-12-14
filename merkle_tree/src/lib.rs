// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Merkle Tree traits and implementations.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(warnings)] // Temporarily allow warnings for nightly compilation.
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

#[cfg(any(not(feature = "std"), target_has_atomic = "ptr"))]
extern crate alloc;

pub mod append_only;
pub mod errors;
pub mod examples;
pub mod gadgets;
pub mod hasher;
pub mod light_weight;
pub mod macros;
pub mod universal_merkle_tree;
pub(crate) mod internal;
pub mod prelude;

pub use crate::errors::MerkleTreeError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, fmt::Debug, hash::Hash, vec, vec::Vec};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// Type aliases for verification results.
pub(crate) type VerificationResult = Result<(), ()>;
pub const SUCCESS: VerificationResult = Ok(()); // Verification succeeded.
pub const FAIL: VerificationResult = Err(());   // Verification failed.

/// Lookup results for a Merkle tree query.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum LookupResult<F, P, N> {
    /// The queried element exists, with a proof of membership.
    Ok(F, P),
    /// The index is valid, but the leaf is not in memory.
    NotInMemory,
    /// The index is unoccupied, with a non-membership proof.
    NotFound(N),
}

impl<F, P, N> LookupResult<F, P, N> {
    /// Assert that the result is `Ok` and return the element and proof.
    pub fn expect_ok(self) -> Result<(F, P), MerkleTreeError> {
        match self {
            Self::Ok(element, proof) => Ok((element, proof)),
            Self::NotInMemory => Err(MerkleTreeError::ForgottenLeaf),
            Self::NotFound(_) => Err(MerkleTreeError::NotFound),
        }
    }

    /// Assert that the result is `NotFound` and return the non-membership proof.
    pub fn expect_not_found(self) -> Result<N, MerkleTreeError> {
        match self {
            Self::NotFound(proof) => Ok(proof),
            Self::Ok(..) => Err(MerkleTreeError::ExistingLeaf),
            Self::NotInMemory => Err(MerkleTreeError::ForgottenLeaf),
        }
    }

    /// Assert that the result is `NotInMemory`.
    pub fn expect_not_in_memory(self) -> Result<(), MerkleTreeError> {
        match self {
            Self::NotInMemory => Ok(()),
            Self::Ok(..) => Err(MerkleTreeError::ExistingLeaf),
            Self::NotFound(..) => Err(MerkleTreeError::NotFound),
        }
    }
}

/// Trait for Merkle tree elements.
pub trait Element: Clone + Eq + PartialEq + Hash {}
impl<T: Clone + Eq + PartialEq + Hash> Element for T {}

/// Trait for Merkle tree indices.
pub trait Index: Debug + Eq + PartialEq + Hash + Ord + PartialOrd + Clone {}
impl<T: Debug + Eq + PartialEq + Hash + Ord + PartialOrd + Clone> Index for T {}

/// Trait for node values in a Merkle tree.
pub trait NodeValue:
    Default + Eq + PartialEq + Hash + Copy + Clone + Debug + CanonicalSerialize + CanonicalDeserialize
{
}
impl<T> NodeValue for T where
    T: Default
        + Eq
        + PartialEq
        + Hash
        + Copy
        + Clone
        + Debug
        + CanonicalSerialize
        + CanonicalDeserialize
{
}

/// Hashing operations for a Merkle tree.
pub trait DigestAlgorithm<E, I, T>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    /// Hashes a list of node values.
    fn digest(data: &[T]) -> Result<T, MerkleTreeError>;

    /// Hashes a leaf node using its index and value.
    fn digest_leaf(pos: &I, elem: &E) -> Result<T, MerkleTreeError>;
}

/// Conversion of indices into Merkle tree traversal paths.
pub trait ToTraversalPath<const ARITY: usize> {
    /// Converts an index to a traversal path for a tree with the given `ARITY` and height.
    fn to_traversal_path(&self, height: usize) -> Vec<usize>;
}

/// Trait for Merkle tree proofs.
pub trait MerkleProof<T: NodeValue>:
    Eq
    + PartialEq
    + Hash
    + Clone
    + CanonicalSerialize
    + CanonicalDeserialize
    + Serialize
    + for<'a> Deserialize<'a>
{
    /// Returns the height of the proof.
    fn height(&self) -> usize;

    /// Returns the sibling values along the proof path.
    fn path_values(&self) -> &[Vec<T>];
}

/// A trait defining basic Merkle tree functionality.
pub trait MerkleTreeScheme: Sized {
    type Element: Element;
    type Index: Index;
    type NodeValue: NodeValue;
    type MembershipProof: MerkleProof<Self::NodeValue>;
    type BatchMembershipProof: Clone;
    type Commitment: NodeValue;

    const ARITY: usize;

    fn height(&self) -> usize;
    fn capacity(&self) -> BigUint;
    fn num_leaves(&self) -> u64;
    fn commitment(&self) -> Self::Commitment;

    fn lookup(
        &self,
        pos: impl Borrow<Self::Index>,
    ) -> LookupResult<&Self::Element, Self::MembershipProof, ()>;

    fn verify(
        commitment: impl Borrow<Self::Commitment>,
        pos: impl Borrow<Self::Index>,
        element: impl Borrow<Self::Element>,
        proof: impl Borrow<Self::MembershipProof>,
    ) -> Result<VerificationResult, MerkleTreeError>;

    fn iter(&self) -> MerkleTreeIter<Self::Element, Self::Index, Self::NodeValue>;
}

/// Append-only Merkle tree trait.
pub trait AppendableMerkleTreeScheme: MerkleTreeScheme<Index = u64> {
    fn push(&mut self, elem: impl Borrow<Self::Element>) -> Result<(), MerkleTreeError>;

    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<(), MerkleTreeError> {
        for elem in elems {
            self.push(elem)?;
        }
        Ok(())
    }
}

/// Universal Merkle tree trait supporting random access and non-membership proofs.
pub trait UniversalMerkleTreeScheme: MerkleTreeScheme {
    type NonMembershipProof;
    type BatchNonMembershipProof;

    fn update(
        &mut self,
        pos: impl Borrow<Self::Index>,
        elem: impl Borrow<Self::Element>,
    ) -> Result<LookupResult<Self::Element, (), ()>, MerkleTreeError> {
        self.update_with(pos, |_| Some(elem.borrow().clone()))
    }

    fn remove(
        &mut self,
        pos: impl Borrow<Self::Index>,
    ) -> Result<LookupResult<Self::Element, (), ()>, MerkleTreeError> {
        self.update_with(pos, |_| None)
    }

    fn update_with<F>(
        &mut self,
        pos: impl Borrow<Self::Index>,
        f: F,
    ) -> Result<LookupResult<Self::Element, (), ()>, MerkleTreeError>
    where
        F: FnOnce(Option<&Self::Element>) -> Option<Self::Element>;

    fn universal_lookup(
        &self,
        pos: impl Borrow<Self::Index>,
    ) -> LookupResult<&Self::Element, Self::MembershipProof, Self::NonMembershipProof>;

    fn non_membership_verify(
        commitment: impl Borrow<Self::Commitment>,
        pos: impl Borrow<Self::Index>,
        proof: impl Borrow<Self::NonMembershipProof>,
    ) -> Result<VerificationResult, MerkleTreeError>;
}
