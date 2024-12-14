// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::{DigestAlgorithm, Element, Index, LookupResult, NodeValue, ToTraversalPath};
use crate::{errors::MerkleTreeError, prelude::MerkleTree, VerificationResult, FAIL, SUCCESS};
use alloc::sync::Arc;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, format, iter::Peekable, string::ToString, vec, vec::Vec};
use derivative::Derivative;
use itertools::Itertools;
use jf_utils::canonical;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tagged_base64::tagged;

/// Represents a Merkle node in the tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "E: CanonicalSerialize + CanonicalDeserialize,
                 I: CanonicalSerialize + CanonicalDeserialize,")]
pub enum MerkleNode<E: Element, I: Index, T: NodeValue> {
    /// An empty subtree.
    Empty,
    /// A branch node with children.
    Branch {
        /// Merkle hash value of the subtree.
        #[serde(with = "canonical")]
        value: T,
        /// Children of this branch.
        children: Vec<Arc<MerkleNode<E, I, T>>>,
    },
    /// A leaf node with data.
    Leaf {
        /// Merkle hash value of the leaf.
        #[serde(with = "canonical")]
        value: T,
        /// Index of this leaf.
        #[serde(with = "canonical")]
        pos: I,
        /// The data element stored in this leaf.
        #[serde(with = "canonical")]
        elem: E,
    },
    /// A forgotten subtree with only its value retained.
    ForgottenSubtree {
        /// Merkle hash value of the forgotten subtree.
        #[serde(with = "canonical")]
        value: T,
    },
}

impl<E, I, T> MerkleNode<E, I, T>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    /// Returns the value of the node.
    #[inline]
    pub(crate) fn value(&self) -> T {
        match self {
            Self::Empty => T::default(),
            Self::Leaf { value, .. } | Self::Branch { value, .. } | Self::ForgottenSubtree { value } => *value,
        }
    }

    /// Checks if the node is a forgotten subtree.
    #[inline]
    pub(crate) fn is_forgotten(&self) -> bool {
        matches!(self, Self::ForgottenSubtree { .. })
    }
}

/// A Merkle tree proof containing sibling hashes along the path.
#[derive(
    Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, CanonicalSerialize, CanonicalDeserialize,
)]
#[tagged("MERKLE_PROOF")]
pub struct MerkleTreeProof<T: NodeValue>(pub Vec<Vec<T>>);

impl<T: NodeValue> super::MerkleProof<T> for MerkleTreeProof<T> {
    /// Returns the height of the Merkle tree.
    fn height(&self) -> usize {
        self.0.len()
    }

    /// Returns the sibling values of the Merkle path.
    fn path_values(&self) -> &[Vec<T>] {
        &self.0
    }
}

/// Verifies a Merkle proof.
///
/// # Parameters
/// - `commitment`: The root hash of the Merkle tree.
/// - `pos`: Index of the leaf to verify.
/// - `element`: The leaf element to verify (or `None` for non-membership proofs).
/// - `proof`: The proof to verify.
///
/// # Returns
/// - `Ok(SUCCESS)` if the proof is valid.
/// - `Ok(FAIL)` if the proof is invalid.
/// - `Err(MerkleTreeError)` if there is a structural error.
pub(crate) fn verify_merkle_proof<E, H, I, const ARITY: usize, T>(
    commitment: &T,
    pos: &I,
    element: Option<&E>,
    proof: &[Vec<T>],
) -> Result<VerificationResult, MerkleTreeError>
where
    E: Element,
    I: Index + ToTraversalPath<ARITY>,
    T: NodeValue,
    H: DigestAlgorithm<E, I, T>,
{
    let initial_value = if let Some(elem) = element {
        H::digest_leaf(pos, elem)?
    } else {
        T::default()
    };

    let mut data = [T::default(); ARITY];
    let computed_root = pos
        .to_traversal_path(proof.len())
        .iter()
        .zip(proof.iter())
        .try_fold(initial_value, |val, (branch, siblings)| -> Result<T, MerkleTreeError> {
            if siblings.is_empty() {
                Ok(T::default())
            } else {
                data[..*branch].copy_from_slice(&siblings[..*branch]);
                data[*branch] = val;
                data[*branch + 1..].copy_from_slice(&siblings[*branch..]);
                H::digest(&data)
            }
        })?;

    Ok(if computed_root == *commitment {
        SUCCESS
    } else {
        FAIL
    })
}

/// Efficiently computes the hash for a branch node based on its children.
pub(crate) fn digest_branch<E, H, I, T>(
    children: &[Arc<MerkleNode<E, I, T>>],
) -> Result<T, MerkleTreeError>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index,
    T: NodeValue,
{
    let child_values = children.iter().map(|child| child.value()).collect::<Vec<_>>();
    H::digest(&child_values)
}
