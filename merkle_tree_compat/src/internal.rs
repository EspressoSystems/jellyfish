// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Internal data structures and algorithms for Merkle tree implementations.
//!
//! This module provides the core building blocks for various Merkle tree
//! schemes, including node representations, proof structures, and tree
//! construction algorithms.
//!
//! # Key Components
//!
//! - [`MerkleNode`]: The fundamental node type representing leaves, branches,
//!   and forgotten subtrees in a Merkle tree
//! - [`MerkleTreeCommitment`]: A succinct commitment to a Merkle tree
//!   consisting of a root hash, height, and leaf count
//! - [`MerkleProof`]: Proof structures for membership and non-membership
//!   verification
//! - [`MerkleTreeIter`]: Iterator types for traversing tree elements
//!
//! # Tree Construction
//!
//! This module provides internal functions for building Merkle trees:
//! - [`build_tree_internal`]: Constructs a full Merkle tree from elements
//! - [`build_light_weight_tree_internal`]: Constructs a lightweight tree with
//!   most nodes forgotten except the frontier
//!
//! # Internal Operations
//!
//! The module implements core tree operations including lookup, insertion,
//! update, and forget/remember functionality through methods on [`MerkleNode`].

use super::{
    DigestAlgorithm, Element, Index, LookupResult, MerkleCommitment, NodeValue, ToTraversalPath,
};
use crate::{errors::MerkleTreeError, VerificationResult};
use alloc::sync::Arc;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, format, iter::Peekable, string::ToString, vec, vec::Vec};
use derivative::Derivative;
use itertools::Itertools;
use jf_utils::canonical;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tagged_base64::tagged;

/// A node in a Merkle tree.
///
/// This enum represents the different types of nodes that can appear in a
/// Merkle tree:
/// - Empty nodes represent unoccupied positions
/// - Branch nodes are internal nodes with children
/// - Leaf nodes contain actual data elements
/// - Forgotten subtrees are nodes that have been pruned from memory but whose
///   hash values are retained
///
/// The generic parameters are:
/// - `E`: The element type stored in leaf nodes
/// - `I`: The index type for leaf positions
/// - `T`: The node value type (typically a hash digest)
///
/// # Examples
///
/// ```ignore
/// use merkle_tree::internal::MerkleNode;
///
/// // An empty node
/// let empty = MerkleNode::<String, u64, [u8; 32]>::Empty;
///
/// // A leaf node
/// let leaf = MerkleNode::Leaf {
///     value: [0u8; 32],
///     pos: 0,
///     elem: "data".to_string(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "E: CanonicalSerialize + CanonicalDeserialize,
                 I: CanonicalSerialize + CanonicalDeserialize,")]
pub enum MerkleNode<E: Element, I: Index, T: NodeValue> {
    /// An empty subtree with no elements.
    Empty,
    /// An internal branching node with children.
    Branch {
        /// Merkle hash value of this subtree
        #[serde(with = "canonical")]
        value: T,
        /// All its children nodes
        children: Vec<Arc<MerkleNode<E, I, T>>>,
    },
    /// A leaf node containing an element.
    Leaf {
        /// Merkle hash value of this leaf
        #[serde(with = "canonical")]
        value: T,
        /// Index of this leaf in the tree
        #[serde(with = "canonical")]
        pos: I,
        /// Associated element stored in this leaf
        #[serde(with = "canonical")]
        elem: E,
    },
    /// A subtree that has been forgotten from memory.
    ///
    /// This variant retains only the hash value of the subtree, allowing the
    /// tree commitment to remain valid while reducing memory usage.
    /// Forgotten subtrees can be restored using the `remember_internal`
    /// method if a valid proof is provided.
    ForgettenSubtree {
        /// Merkle hash value of this forgotten subtree
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
    /// Returns the hash value of this node.
    ///
    /// For empty nodes, returns the default value (typically a zero hash).
    /// For other node types, returns the stored hash value.
    #[inline]
    pub fn value(&self) -> T {
        match self {
            Self::Empty => T::default(),
            Self::Leaf {
                value,
                pos: _,
                elem: _,
            } => *value,
            Self::Branch { value, children: _ } => *value,
            Self::ForgettenSubtree { value } => *value,
        }
    }

    /// Checks whether this node is a forgotten subtree.
    ///
    /// Returns `true` if the node is a `ForgettenSubtree` variant, `false`
    /// otherwise.
    #[inline]
    pub fn is_forgotten(&self) -> bool {
        matches!(self, Self::ForgettenSubtree { .. })
    }
}

/// A Merkle path representing nodes from a leaf to the root.
///
/// This is a bottom-up list of nodes that proves the inclusion or exclusion of
/// an element in the tree. The first element is the leaf (or empty) node, and
/// each subsequent element is a parent node, with the last element being at the
/// root level.
///
/// Used in [`MerkleProof`] to verify membership and non-membership claims.
pub type MerklePath<E, I, T> = Vec<MerkleNode<E, I, T>>;

/// A succinct commitment to a Merkle tree.
///
/// This structure represents a compact commitment to the entire Merkle tree
/// state, consisting of:
/// - The root hash digest
/// - The tree height
/// - The number of leaves in the tree
///
/// This commitment can be used to verify proofs without access to the full
/// tree.
///
/// # Examples
///
/// ```ignore
/// use merkle_tree::internal::MerkleTreeCommitment;
///
/// let commitment = MerkleTreeCommitment::new([0u8; 32], 10, 100);
/// assert_eq!(commitment.digest(), [0u8; 32]);
/// assert_eq!(commitment.height(), 10);
/// assert_eq!(commitment.size(), 100);
/// ```
#[derive(
    Eq,
    PartialEq,
    Clone,
    Copy,
    Debug,
    Ord,
    PartialOrd,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
#[tagged("MERKLE_COMM")]
pub struct MerkleTreeCommitment<T: NodeValue> {
    /// Root of a tree
    digest: T,
    /// Height of a tree
    height: usize,
    /// Number of leaves in the tree
    num_leaves: u64,
}

impl<T: NodeValue> MerkleTreeCommitment<T> {
    /// Creates a new Merkle tree commitment.
    ///
    /// # Arguments
    ///
    /// * `digest` - The root hash of the Merkle tree
    /// * `height` - The height of the tree (0 for a single leaf)
    /// * `num_leaves` - The number of leaves currently in the tree
    ///
    /// # Returns
    ///
    /// A new `MerkleTreeCommitment` instance with the specified parameters.
    pub fn new(digest: T, height: usize, num_leaves: u64) -> Self {
        MerkleTreeCommitment {
            digest,
            height,
            num_leaves,
        }
    }
}

impl<T: NodeValue> MerkleCommitment<T> for MerkleTreeCommitment<T> {
    fn digest(&self) -> T {
        self.digest
    }

    fn height(&self) -> usize {
        self.height
    }

    fn size(&self) -> u64 {
        self.num_leaves
    }
}

/// A proof of membership or non-membership in a Merkle tree.
///
/// This structure contains all information needed to verify that an element is
/// (or is not) present at a specific position in the tree. The proof consists
/// of:
/// - The position/index being proved
/// - A Merkle path from the leaf to the root
///
/// The proof can be verified against a [`MerkleTreeCommitment`] without access
/// to the full tree.
///
/// # Type Parameters
///
/// - `E`: The element type
/// - `I`: The index type
/// - `T`: The node value type (hash digest)
/// - `ARITY`: The branching factor of the tree (e.g., 2 for binary trees)
///
/// # Examples
///
/// ```ignore
/// use merkle_tree::internal::MerkleProof;
///
/// let proof = MerkleProof::<String, u64, [u8; 32], 2>::new(5, path);
/// assert_eq!(proof.index(), &5);
/// ```
#[derive(Derivative, Debug, Clone, Serialize, Deserialize)]
#[derivative(Eq, Hash, PartialEq)]
#[serde(bound = "E: CanonicalSerialize + CanonicalDeserialize,
             I: CanonicalSerialize + CanonicalDeserialize,")]
pub struct MerkleProof<E, I, T, const ARITY: usize>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    /// Proof of inclusion for element at index `pos`
    #[serde(with = "canonical")]
    pub pos: I,
    /// Nodes of proof path, from root to leaf
    pub proof: MerklePath<E, I, T>,
}

impl<E, I, T, const ARITY: usize> MerkleProof<E, I, T, ARITY>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    /// Returns the height of the tree this proof is for.
    ///
    /// The height is derived from the length of the proof path.
    pub fn tree_height(&self) -> usize {
        self.proof.len()
    }

    /// Creates a new `MerkleProof` from an index and Merkle path.
    ///
    /// # Arguments
    ///
    /// * `pos` - The index in the tree this proof is for
    /// * `proof` - The Merkle path from leaf to root
    pub fn new(pos: I, proof: MerklePath<E, I, T>) -> Self {
        MerkleProof { pos, proof }
    }

    /// Returns a reference to the index this proof is for.
    pub fn index(&self) -> &I {
        &self.pos
    }

    /// Returns the element associated with this proof, if any.
    ///
    /// Returns `Some(&element)` for membership proofs, or `None` for
    /// non-membership proofs (where the first node in the path is not a
    /// leaf).
    pub fn elem(&self) -> Option<&E> {
        match self.proof.first() {
            Some(MerkleNode::Leaf { elem, .. }) => Some(elem),
            _ => None,
        }
    }
}

/// Builds a complete Merkle tree from a collection of elements.
///
/// This function constructs a full Merkle tree with all leaves and internal
/// nodes present in memory. The tree is built bottom-up, with leaves at the
/// lowest level and branches connecting them up to a single root.
///
/// # Type Parameters
///
/// - `E`: The element type stored in leaves
/// - `H`: The digest algorithm used for hashing
/// - `ARITY`: The branching factor (number of children per internal node)
/// - `T`: The node value type (hash digest)
///
/// # Arguments
///
/// * `height` - Optional tree height. If `None`, the minimum height to fit all
///   elements is calculated automatically
/// * `elems` - An iterator of elements to insert as leaves
///
/// # Returns
///
/// Returns a tuple of:
/// - The root node (as an `Arc`)
/// - The tree height
/// - The number of leaves
///
/// # Errors
///
/// Returns [`MerkleTreeError::ExceedCapacity`] if the number of elements
/// exceeds the tree's capacity for the given height.
///
/// # Examples
///
/// ```ignore
/// use merkle_tree::internal::build_tree_internal;
///
/// let elements = vec![1, 2, 3, 4];
/// let (root, height, num_leaves) =
///     build_tree_internal::<_, MyHasher, 2, _>(None, elements)?;
/// ```
#[allow(clippy::type_complexity)]
pub fn build_tree_internal<E, H, const ARITY: usize, T>(
    height: Option<usize>,
    elems: impl IntoIterator<Item = impl Borrow<E>>,
) -> Result<(Arc<MerkleNode<E, u64, T>>, usize, u64), MerkleTreeError>
where
    E: Element,
    H: DigestAlgorithm<E, u64, T>,
    T: NodeValue,
{
    let leaves: Vec<_> = elems.into_iter().collect();
    let num_leaves = leaves.len() as u64;
    let height = height.unwrap_or_else(|| {
        let mut height = 0usize;
        let mut capacity = 1;
        while capacity < num_leaves {
            height += 1;
            capacity *= ARITY as u64;
        }
        height
    });
    let capacity = BigUint::from(ARITY as u64).pow(height as u32);

    if BigUint::from(num_leaves) > capacity {
        Err(MerkleTreeError::ExceedCapacity)
    } else if num_leaves == 0 {
        Ok((Arc::new(MerkleNode::<E, u64, T>::Empty), height, 0))
    } else if height == 0usize {
        Ok((
            Arc::new(MerkleNode::Leaf {
                value: H::digest_leaf(&0, leaves[0].borrow())?,
                pos: 0,
                elem: leaves[0].borrow().clone(),
            }),
            height,
            1,
        ))
    } else {
        let mut cur_nodes = leaves
            .into_iter()
            .enumerate()
            .chunks(ARITY)
            .into_iter()
            .map(|chunk| {
                let children = chunk
                    .map(|(pos, elem)| {
                        let pos = pos as u64;
                        Ok(Arc::new(MerkleNode::Leaf {
                            value: H::digest_leaf(&pos, elem.borrow())?,
                            pos,
                            elem: elem.borrow().clone(),
                        }))
                    })
                    .pad_using(ARITY, |_| Ok(Arc::new(MerkleNode::Empty)))
                    .collect::<Result<Vec<_>, MerkleTreeError>>()?;
                Ok(Arc::new(MerkleNode::<E, u64, T>::Branch {
                    value: digest_branch::<E, H, u64, T>(&children)?,
                    children,
                }))
            })
            .collect::<Result<Vec<_>, MerkleTreeError>>()?;
        for _ in 1..height {
            cur_nodes = cur_nodes
                .into_iter()
                .chunks(ARITY)
                .into_iter()
                .map(|chunk| {
                    let children = chunk
                        .pad_using(ARITY, |_| Arc::new(MerkleNode::<E, u64, T>::Empty))
                        .collect::<Vec<_>>();
                    Ok(Arc::new(MerkleNode::<E, u64, T>::Branch {
                        value: digest_branch::<E, H, u64, T>(&children)?,
                        children,
                    }))
                })
                .collect::<Result<Vec<_>, MerkleTreeError>>()?;
        }
        Ok((cur_nodes[0].clone(), height, num_leaves))
    }
}

/// Builds a lightweight Merkle tree with most nodes forgotten.
///
/// This function constructs a memory-efficient Merkle tree where all leaves
/// except the last one (the frontier) are immediately forgotten. This is useful
/// for append-only trees where only the most recent state needs to be in
/// memory.
///
/// The resulting tree maintains the correct root hash but keeps only the
/// frontier leaf and path in memory, with all other nodes replaced by
/// `ForgettenSubtree` variants containing just their hash values.
///
/// # Type Parameters
///
/// - `E`: The element type stored in leaves
/// - `H`: The digest algorithm used for hashing
/// - `ARITY`: The branching factor (number of children per internal node)
/// - `T`: The node value type (hash digest)
///
/// # Arguments
///
/// * `height` - Optional tree height. If `None`, the minimum height to fit all
///   elements is calculated automatically
/// * `elems` - An iterator of elements to insert as leaves
///
/// # Returns
///
/// Returns a tuple of:
/// - The root node (as an `Arc`) with most nodes forgotten
/// - The tree height
/// - The number of leaves
///
/// # Errors
///
/// Returns [`MerkleTreeError::ExceedCapacity`] if the number of elements
/// exceeds the tree's capacity for the given height, or
/// [`MerkleTreeError::ParametersError`] if the tree size would be too large.
///
/// # Examples
///
/// ```ignore
/// use merkle_tree::internal::build_light_weight_tree_internal;
///
/// let elements = vec![1, 2, 3, 4];
/// let (root, height, num_leaves) =
///     build_light_weight_tree_internal::<_, MyHasher, 2, _>(None, elements)?;
/// // Only the last element and its path are fully in memory
/// ```
#[allow(clippy::type_complexity)]
pub fn build_light_weight_tree_internal<E, H, const ARITY: usize, T>(
    height: Option<usize>,
    elems: impl IntoIterator<Item = impl Borrow<E>>,
) -> Result<(Arc<MerkleNode<E, u64, T>>, usize, u64), MerkleTreeError>
where
    E: Element,
    H: DigestAlgorithm<E, u64, T>,
    T: NodeValue,
{
    let leaves: Vec<_> = elems.into_iter().collect();
    let num_leaves = leaves.len() as u64;
    let height = height.unwrap_or_else(|| {
        let mut height = 0usize;
        let mut capacity = 1;
        while capacity < num_leaves {
            height += 1;
            capacity *= ARITY as u64;
        }
        height
    });
    let capacity = num_traits::checked_pow(ARITY as u64, height).ok_or_else(|| {
        MerkleTreeError::ParametersError("Merkle tree size too large.".to_string())
    })?;

    if num_leaves > capacity {
        Err(MerkleTreeError::ExceedCapacity)
    } else if num_leaves == 0 {
        Ok((Arc::new(MerkleNode::<E, u64, T>::Empty), height, 0))
    } else if height == 0usize {
        Ok((
            Arc::new(MerkleNode::Leaf {
                value: H::digest_leaf(&0, leaves[0].borrow())?,
                pos: 0,
                elem: leaves[0].borrow().clone(),
            }),
            height,
            1,
        ))
    } else {
        let mut cur_nodes = leaves
            .into_iter()
            .enumerate()
            .chunks(ARITY)
            .into_iter()
            .map(|chunk| {
                let children = chunk
                    .map(|(pos, elem)| {
                        let pos = pos as u64;
                        Ok(if pos < num_leaves - 1 {
                            Arc::new(MerkleNode::ForgettenSubtree {
                                value: H::digest_leaf(&pos, elem.borrow())?,
                            })
                        } else {
                            Arc::new(MerkleNode::Leaf {
                                value: H::digest_leaf(&pos, elem.borrow())?,
                                pos,
                                elem: elem.borrow().clone(),
                            })
                        })
                    })
                    .pad_using(ARITY, |_| Ok(Arc::new(MerkleNode::Empty)))
                    .collect::<Result<Vec<_>, MerkleTreeError>>()?;
                Ok(Arc::new(MerkleNode::<E, u64, T>::Branch {
                    value: digest_branch::<E, H, u64, T>(&children)?,
                    children,
                }))
            })
            .collect::<Result<Vec<_>, MerkleTreeError>>()?;
        for i in 1..cur_nodes.len() - 1 {
            cur_nodes[i] = Arc::new(MerkleNode::ForgettenSubtree {
                value: cur_nodes[i].value(),
            })
        }
        for _ in 1..height {
            cur_nodes = cur_nodes
                .into_iter()
                .chunks(ARITY)
                .into_iter()
                .map(|chunk| {
                    let children = chunk
                        .pad_using(ARITY, |_| Arc::new(MerkleNode::<E, u64, T>::Empty))
                        .collect::<Vec<_>>();
                    Ok(Arc::new(MerkleNode::<E, u64, T>::Branch {
                        value: digest_branch::<E, H, u64, T>(&children)?,
                        children,
                    }))
                })
                .collect::<Result<Vec<_>, MerkleTreeError>>()?;
            for i in 1..cur_nodes.len() - 1 {
                cur_nodes[i] = Arc::new(MerkleNode::ForgettenSubtree {
                    value: cur_nodes[i].value(),
                })
            }
        }
        Ok((cur_nodes[0].clone(), height, num_leaves))
    }
}

/// Computes the digest (hash) of a branch node from its children.
///
/// This function takes a slice of child nodes and computes the hash value that
/// should be stored in their parent branch node. It extracts the hash value
/// from each child node and then applies the digest algorithm to the resulting
/// array.
///
/// # Type Parameters
///
/// - `E`: The element type
/// - `H`: The digest algorithm to use
/// - `I`: The index type
/// - `T`: The node value type (hash digest)
///
/// # Arguments
///
/// * `data` - A slice of child nodes (as `Arc` pointers)
///
/// # Returns
///
/// The computed hash value for the parent node, or an error if hashing fails.
///
/// # Errors
///
/// Returns an error if the digest algorithm fails.
pub fn digest_branch<E, H, I, T>(data: &[Arc<MerkleNode<E, I, T>>]) -> Result<T, MerkleTreeError>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index,
    T: NodeValue,
{
    // Question(Chengyu): any more efficient implementation?
    let data = data.iter().map(|node| node.value()).collect::<Vec<_>>();
    H::digest(&data)
}

impl<E, I, T> MerkleNode<E, I, T>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    /// Forgets a leaf from the Merkle tree, pruning it from memory.
    ///
    /// This method removes a leaf and returns a new tree with the leaf replaced
    /// by a `ForgettenSubtree` node. If all leaves under a branch node are
    /// forgotten, the entire branch may be collapsed into a single
    /// `ForgettenSubtree` node.
    ///
    /// **Warning**: This method can break non-membership proofs. See issue
    /// #495.
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the current node in the tree
    /// * `traversal_path` - The path of branch indices to reach the target leaf
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - A new tree with the leaf forgotten
    /// - A `LookupResult` containing either the forgotten element with its
    ///   proof, `NotInMemory` if already forgotten, or `NotFound` if the
    ///   position was empty
    #[allow(clippy::type_complexity)]
    pub fn forget_internal(
        &self,
        height: usize,
        traversal_path: &[usize],
    ) -> (
        Arc<Self>,
        LookupResult<E, MerklePath<E, I, T>, MerklePath<E, I, T>>,
    ) {
        match self {
            MerkleNode::Empty => (
                Arc::new(self.clone()),
                LookupResult::NotFound(vec![MerkleNode::Empty; height + 1]),
            ),
            MerkleNode::Branch { value, children } => {
                let mut children = children.clone();
                let (new_child, result) = children[traversal_path[height - 1]]
                    .forget_internal(height - 1, traversal_path);
                match result {
                    LookupResult::Ok(elem, mut proof) => {
                        proof.push(MerkleNode::Branch {
                            value: T::default(),
                            children: children
                                .iter()
                                .map(|child| {
                                    if let MerkleNode::Empty = **child {
                                        Arc::new(MerkleNode::Empty)
                                    } else {
                                        Arc::new(MerkleNode::ForgettenSubtree {
                                            value: child.value(),
                                        })
                                    }
                                })
                                .collect::<Vec<_>>(),
                        });
                        children[traversal_path[height - 1]] = new_child;
                        if children.iter().all(|child| {
                            matches!(
                                **child,
                                MerkleNode::Empty | MerkleNode::ForgettenSubtree { .. }
                            )
                        }) {
                            (
                                Arc::new(MerkleNode::ForgettenSubtree { value: *value }),
                                LookupResult::Ok(elem, proof),
                            )
                        } else {
                            (
                                Arc::new(MerkleNode::Branch {
                                    value: *value,
                                    children,
                                }),
                                LookupResult::Ok(elem, proof),
                            )
                        }
                    },
                    LookupResult::NotInMemory => {
                        (Arc::new(self.clone()), LookupResult::NotInMemory)
                    },
                    LookupResult::NotFound(mut non_membership_proof) => {
                        non_membership_proof.push(MerkleNode::Branch {
                            value: T::default(),
                            children: children
                                .iter()
                                .map(|child| {
                                    if let MerkleNode::Empty = **child {
                                        Arc::new(MerkleNode::Empty)
                                    } else {
                                        Arc::new(MerkleNode::ForgettenSubtree {
                                            value: child.value(),
                                        })
                                    }
                                })
                                .collect::<Vec<_>>(),
                        });
                        (
                            Arc::new(self.clone()),
                            LookupResult::NotFound(non_membership_proof),
                        )
                    },
                }
            },
            MerkleNode::Leaf { value, pos, elem } => {
                let elem = elem.clone();
                let proof = vec![MerkleNode::<E, I, T>::Leaf {
                    value: *value,
                    pos: pos.clone(),
                    elem: elem.clone(),
                }];
                (
                    Arc::new(MerkleNode::ForgettenSubtree { value: *value }),
                    LookupResult::Ok(elem, proof),
                )
            },
            _ => (Arc::new(self.clone()), LookupResult::NotInMemory),
        }
    }

    /// Re-inserts a forgotten leaf into the Merkle tree.
    ///
    /// This method restores a previously forgotten subtree using a valid proof.
    /// The proof must have been previously verified to match the tree's
    /// commitment.
    ///
    /// # Type Parameters
    ///
    /// - `H`: The digest algorithm used for verification
    /// - `ARITY`: The branching factor of the tree
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the current node in the tree
    /// * `traversal_path` - The path of branch indices to reach the target
    ///   position
    /// * `path_values` - Expected hash values along the path for verification
    /// * `proof` - The Merkle proof containing the nodes to restore
    ///
    /// # Returns
    ///
    /// A new tree with the forgotten subtree restored, or an error if the proof
    /// is invalid or inconsistent with the current tree.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleTreeError::InconsistentStructureError`] if the proof
    /// doesn't match the tree structure or if hash values don't align.
    pub fn remember_internal<H, const ARITY: usize>(
        &self,
        height: usize,
        traversal_path: &[usize],
        path_values: &[T],
        proof: &[MerkleNode<E, I, T>],
    ) -> Result<Arc<Self>, MerkleTreeError>
    where
        H: DigestAlgorithm<E, I, T>,
    {
        if self.value() != path_values[height] {
            return Err(MerkleTreeError::InconsistentStructureError(format!(
                "Invalid proof. Hash differs at height {}: (expected: {:?}, received: {:?})",
                height,
                self.value(),
                path_values[height]
            )));
        }

        match (self, &proof[height]) {
            (Self::ForgettenSubtree { value }, Self::Branch { children, .. }) => {
                // Recurse into the appropriate sub-tree to remember the rest of the path.
                let mut children = children.clone();
                children[traversal_path[height - 1]] = children[traversal_path[height - 1]]
                    .remember_internal::<H, ARITY>(
                        height - 1,
                        traversal_path,
                        path_values,
                        proof,
                    )?;
                // Remember `*self`.
                Ok(Arc::new(Self::Branch {
                    value: *value,
                    children,
                }))
            },
            (Self::ForgettenSubtree { .. }, node) => {
                // Replace forgotten sub-tree with a hopefully-less-forgotten sub-tree from the
                // proof. Safe because we already checked our hash value matches the proof.
                Ok(Arc::new(node.clone()))
            },
            (Self::Branch { value, children }, Self::Branch { .. }) => {
                let mut children = children.clone();
                children[traversal_path[height - 1]] = children[traversal_path[height - 1]]
                    .remember_internal::<H, ARITY>(
                        height - 1,
                        traversal_path,
                        path_values,
                        proof,
                    )?;
                Ok(Arc::new(Self::Branch {
                    value: *value,
                    children,
                }))
            },
            (Self::Leaf { .. }, Self::Leaf { .. }) | (Self::Empty, Self::Empty) => {
                // This node is already a complete sub-tree, so there's nothing to remember. The
                // proof matches, so just return success.
                Ok(Arc::new(self.clone()))
            },
            (..) => Err(MerkleTreeError::InconsistentStructureError(
                "Invalid proof".into(),
            )),
        }
    }

    /// Looks up an element at a given index in the tree.
    ///
    /// This method traverses the tree following the provided traversal path to
    /// find the element at the specified position. It returns either:
    /// - The element with a membership proof if present
    /// - A non-membership proof if the position is empty
    /// - `NotInMemory` if the position has been forgotten
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the current node in the tree
    /// * `traversal_path` - The path of branch indices to reach the target
    ///   position
    ///
    /// # Returns
    ///
    /// A `LookupResult` containing either:
    /// - `Ok`: A reference to the element and a membership proof
    /// - `NotInMemory`: The position has been forgotten
    /// - `NotFound`: A non-membership proof showing the position is empty
    #[allow(clippy::type_complexity)]
    pub fn lookup_internal(
        &self,
        height: usize,
        traversal_path: &[usize],
    ) -> LookupResult<E, MerklePath<E, I, T>, MerklePath<E, I, T>> {
        match self {
            MerkleNode::Empty => {
                LookupResult::NotFound(vec![MerkleNode::<E, I, T>::Empty; height + 1])
            },
            MerkleNode::Branch { value: _, children } => {
                match children[traversal_path[height - 1]]
                    .lookup_internal(height - 1, traversal_path)
                {
                    LookupResult::Ok(elem, mut proof) => {
                        proof.push(MerkleNode::Branch {
                            value: T::default(),
                            children: children
                                .iter()
                                .map(|child| {
                                    if let MerkleNode::Empty = **child {
                                        Arc::new(MerkleNode::Empty)
                                    } else {
                                        Arc::new(MerkleNode::ForgettenSubtree {
                                            value: child.value(),
                                        })
                                    }
                                })
                                .collect::<Vec<_>>(),
                        });
                        LookupResult::Ok(elem, proof)
                    },
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::NotFound(mut non_membership_proof) => {
                        non_membership_proof.push(MerkleNode::Branch {
                            value: T::default(),
                            children: children
                                .iter()
                                .map(|child| {
                                    if let MerkleNode::Empty = **child {
                                        Arc::new(MerkleNode::Empty)
                                    } else {
                                        Arc::new(MerkleNode::ForgettenSubtree {
                                            value: child.value(),
                                        })
                                    }
                                })
                                .collect::<Vec<_>>(),
                        });
                        LookupResult::NotFound(non_membership_proof)
                    },
                }
            },
            MerkleNode::Leaf {
                elem,
                value: _,
                pos: _,
            } => LookupResult::Ok(elem.clone(), vec![self.clone()]),
            _ => LookupResult::NotInMemory,
        }
    }

    /// Updates the element at a given index using a transformation function.
    ///
    /// This method applies a function to the element at the specified position,
    /// allowing for insertion, update, or removal operations. The function
    /// receives the current element (or `None` if empty) and returns the
    /// new element (or `None` to remove).
    ///
    /// # Type Parameters
    ///
    /// - `H`: The digest algorithm for recomputing hashes
    /// - `ARITY`: The branching factor of the tree
    /// - `F`: The update function type
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the current node in the tree
    /// * `pos` - The index of the element to update
    /// * `traversal_path` - The path of branch indices to reach the target
    ///   position
    /// * `f` - The update function: `Option<&E> -> Option<E>`
    ///
    /// # Returns
    ///
    /// Returns `Ok((new_tree, delta, result))` where:
    /// - `new_tree`: The updated tree (as an `Arc`)
    /// - `delta`: Change in leaf count (-1, 0, or +1)
    /// - `result`: The original `LookupResult` before the update
    ///
    /// # Errors
    ///
    /// Returns [`MerkleTreeError::ForgottenLeaf`] if the target position has
    /// been forgotten, or other errors if hashing fails.
    #[allow(clippy::type_complexity)]
    pub fn update_with_internal<H, const ARITY: usize, F>(
        &self,
        height: usize,
        pos: impl Borrow<I>,
        traversal_path: &[usize],
        f: F,
    ) -> Result<(Arc<Self>, i64, LookupResult<E, (), ()>), MerkleTreeError>
    where
        H: DigestAlgorithm<E, I, T>,
        F: FnOnce(Option<&E>) -> Option<E>,
    {
        let pos = pos.borrow();
        match self {
            MerkleNode::Leaf {
                elem: node_elem,
                value: _,
                pos,
            } => {
                let result = LookupResult::Ok(node_elem.clone(), ());
                match f(Some(node_elem)) {
                    Some(elem) => Ok((
                        Arc::new(MerkleNode::Leaf {
                            value: H::digest_leaf(pos, &elem)?,
                            pos: pos.clone(),
                            elem,
                        }),
                        0i64,
                        result,
                    )),
                    None => Ok((Arc::new(MerkleNode::Empty), -1i64, result)),
                }
            },
            MerkleNode::Branch { value, children } => {
                let branch = traversal_path[height - 1];
                let result = children[branch].update_with_internal::<H, ARITY, _>(
                    height - 1,
                    pos,
                    traversal_path,
                    f,
                )?;
                let mut children = children.clone();
                children[branch] = result.0;
                if matches!(*children[branch], MerkleNode::ForgettenSubtree { .. }) {
                    // If the branch containing the update was forgotten by
                    // user, the update failed and nothing was changed, so we
                    // can short-circuit without recomputing this node's value.
                    Ok((
                        Arc::new(MerkleNode::Branch {
                            value: *value,
                            children,
                        }),
                        result.1,
                        result.2,
                    ))
                } else if children
                    .iter()
                    .all(|child| matches!(**child, MerkleNode::Empty))
                {
                    Ok((Arc::new(MerkleNode::Empty), result.1, result.2))
                } else {
                    // Otherwise, an entry has been updated and the value of one of our children has
                    // changed, so we must recompute our own value.
                    // *value = digest_branch::<E, H, I, T>(&children)?;
                    Ok((
                        Arc::new(MerkleNode::Branch {
                            value: digest_branch::<E, H, I, T>(&children)?,
                            children,
                        }),
                        result.1,
                        result.2,
                    ))
                }
            },
            MerkleNode::Empty => {
                if height == 0 {
                    if let Some(elem) = f(None) {
                        Ok((
                            Arc::new(MerkleNode::Leaf {
                                value: H::digest_leaf(pos, &elem)?,
                                pos: pos.clone(),
                                elem,
                            }),
                            1i64,
                            LookupResult::NotFound(()),
                        ))
                    } else {
                        Ok((
                            Arc::new(MerkleNode::Empty),
                            0i64,
                            LookupResult::NotFound(()),
                        ))
                    }
                } else {
                    let branch = traversal_path[height - 1];
                    let mut children = (0..ARITY)
                        .map(|_| Arc::new(Self::Empty))
                        .collect::<Vec<_>>();
                    // Inserting new leave here, shortcutting
                    let result = children[branch].update_with_internal::<H, ARITY, _>(
                        height - 1,
                        pos,
                        traversal_path,
                        f,
                    )?;
                    children[branch] = result.0;
                    if matches!(*children[branch], MerkleNode::Empty) {
                        // No update performed.
                        Ok((Arc::new(MerkleNode::Empty), 0i64, result.2))
                    } else {
                        Ok((
                            Arc::new(MerkleNode::Branch {
                                value: digest_branch::<E, H, I, T>(&children)?,
                                children,
                            }),
                            result.1,
                            result.2,
                        ))
                    }
                }
            },
            MerkleNode::ForgettenSubtree { .. } => Err(MerkleTreeError::ForgottenLeaf),
        }
    }
}

impl<E, T> MerkleNode<E, u64, T>
where
    E: Element,
    T: NodeValue,
{
    /// Performs batch insertion of elements into the tree.
    ///
    /// This method efficiently inserts multiple elements at once, starting from
    /// a given position. It's optimized for append-only operations where
    /// elements are added sequentially.
    ///
    /// # Type Parameters
    ///
    /// - `H`: The digest algorithm for computing hashes
    /// - `ARITY`: The branching factor of the tree
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the current node
    /// * `pos` - The starting position for insertion
    /// * `traversal_path` - The path to the insertion frontier
    /// * `at_frontier` - Whether we're currently at the frontier of the tree
    /// * `data` - A peekable iterator of elements to insert
    ///
    /// # Returns
    ///
    /// Returns `Ok((new_tree, count))` where:
    /// - `new_tree`: The tree with elements inserted
    /// - `count`: The number of elements successfully inserted
    ///
    /// # Errors
    ///
    /// Returns [`MerkleTreeError::ExistingLeaf`] if trying to insert into an
    /// occupied position, or [`MerkleTreeError::ForgottenLeaf`] if the
    /// insertion position has been forgotten.
    pub fn extend_internal<H, const ARITY: usize>(
        &self,
        height: usize,
        pos: &u64,
        traversal_path: &[usize],
        at_frontier: bool,
        data: &mut Peekable<impl Iterator<Item = impl Borrow<E>>>,
    ) -> Result<(Arc<Self>, u64), MerkleTreeError>
    where
        H: DigestAlgorithm<E, u64, T>,
    {
        if data.peek().is_none() {
            return Ok((Arc::new(self.clone()), 0));
        }
        let mut cur_pos = *pos;
        match self {
            MerkleNode::Branch { value: _, children } => {
                let mut cnt = 0u64;
                let mut frontier = if at_frontier {
                    traversal_path[height - 1]
                } else {
                    0
                };
                let cap = ARITY;
                let mut children = children.clone();
                while data.peek().is_some() && frontier < cap {
                    let (new_child, increment) = children[frontier].extend_internal::<H, ARITY>(
                        height - 1,
                        &cur_pos,
                        traversal_path,
                        at_frontier && frontier == traversal_path[height - 1],
                        data,
                    )?;
                    children[frontier] = new_child;
                    cnt += increment;
                    cur_pos += increment;
                    frontier += 1;
                }
                let value = digest_branch::<E, H, u64, T>(&children)?;
                Ok((Arc::new(Self::Branch { value, children }), cnt))
            },
            MerkleNode::Empty => {
                if height == 0 {
                    let elem = data.next().unwrap();
                    let elem = elem.borrow();
                    Ok((
                        Arc::new(MerkleNode::Leaf {
                            value: H::digest_leaf(pos, elem)?,
                            pos: *pos,
                            elem: elem.clone(),
                        }),
                        1,
                    ))
                } else {
                    let mut cnt = 0u64;
                    let mut frontier = if at_frontier {
                        traversal_path[height - 1]
                    } else {
                        0
                    };
                    let cap = ARITY;
                    let mut children = (0..cap).map(|_| Arc::new(Self::Empty)).collect::<Vec<_>>();
                    while data.peek().is_some() && frontier < cap {
                        let (new_child, increment) = children[frontier]
                            .extend_internal::<H, ARITY>(
                                height - 1,
                                &cur_pos,
                                traversal_path,
                                at_frontier && frontier == traversal_path[height - 1],
                                data,
                            )?;
                        children[frontier] = new_child;
                        cnt += increment;
                        cur_pos += increment;
                        frontier += 1;
                    }
                    Ok((
                        Arc::new(MerkleNode::Branch {
                            value: digest_branch::<E, H, u64, T>(&children)?,
                            children,
                        }),
                        cnt,
                    ))
                }
            },
            MerkleNode::Leaf { .. } => Err(MerkleTreeError::ExistingLeaf),
            MerkleNode::ForgettenSubtree { .. } => Err(MerkleTreeError::ForgottenLeaf),
        }
    }

    /// Performs batch insertion while automatically forgetting non-frontier
    /// leaves.
    ///
    /// Similar to [`extend_internal`](Self::extend_internal), but this function
    /// automatically forgets leaves that are not part of the current frontier,
    /// keeping memory usage minimal. This is ideal for append-only trees where
    /// only the most recent state needs to be in memory.
    ///
    /// # Type Parameters
    ///
    /// - `H`: The digest algorithm for computing hashes
    /// - `ARITY`: The branching factor of the tree
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the current node
    /// * `pos` - The starting position for insertion
    /// * `traversal_path` - The path to the insertion frontier
    /// * `at_frontier` - Whether we're currently at the frontier of the tree
    /// * `data` - A peekable iterator of elements to insert
    ///
    /// # Returns
    ///
    /// Returns `Ok((new_tree, count))` where:
    /// - `new_tree`: The tree with elements inserted and non-frontier leaves
    ///   forgotten
    /// - `count`: The number of elements successfully inserted
    ///
    /// # Errors
    ///
    /// Returns [`MerkleTreeError::ExistingLeaf`] if trying to insert into an
    /// occupied position, or [`MerkleTreeError::ForgottenLeaf`] if the
    /// insertion position has been forgotten.
    pub fn extend_and_forget_internal<H, const ARITY: usize>(
        &self,
        height: usize,
        pos: &u64,
        traversal_path: &[usize],
        at_frontier: bool,
        data: &mut Peekable<impl Iterator<Item = impl Borrow<E>>>,
    ) -> Result<(Arc<Self>, u64), MerkleTreeError>
    where
        H: DigestAlgorithm<E, u64, T>,
    {
        if data.peek().is_none() {
            return Ok((Arc::new(self.clone()), 0));
        }
        let mut cur_pos = *pos;
        match self {
            MerkleNode::Branch { value: _, children } => {
                let mut cnt = 0u64;
                let mut frontier = if at_frontier {
                    traversal_path[height - 1]
                } else {
                    0
                };
                let cap = ARITY;
                let mut children = children.clone();
                while data.peek().is_some() && frontier < cap {
                    if frontier > 0 && !children[frontier - 1].is_forgotten() {
                        children[frontier - 1] =
                            Arc::new(MerkleNode::<E, u64, T>::ForgettenSubtree {
                                value: children[frontier - 1].value(),
                            });
                    }
                    let (new_child, increment) = children[frontier]
                        .extend_and_forget_internal::<H, ARITY>(
                            height - 1,
                            &cur_pos,
                            traversal_path,
                            at_frontier && frontier == traversal_path[height - 1],
                            data,
                        )?;
                    children[frontier] = new_child;
                    cnt += increment;
                    cur_pos += increment;
                    frontier += 1;
                }
                let value = digest_branch::<E, H, u64, T>(&children)?;
                Ok((Arc::new(Self::Branch { value, children }), cnt))
            },
            MerkleNode::Empty => {
                if height == 0 {
                    let elem = data.next().unwrap();
                    let elem = elem.borrow();
                    Ok((
                        Arc::new(MerkleNode::Leaf {
                            value: H::digest_leaf(pos, elem)?,
                            pos: *pos,
                            elem: elem.clone(),
                        }),
                        1,
                    ))
                } else {
                    let mut cnt = 0u64;
                    let mut frontier = if at_frontier {
                        traversal_path[height - 1]
                    } else {
                        0
                    };
                    let cap = ARITY;
                    let mut children = (0..cap).map(|_| Arc::new(Self::Empty)).collect::<Vec<_>>();
                    while data.peek().is_some() && frontier < cap {
                        if frontier > 0 && !children[frontier - 1].is_forgotten() {
                            children[frontier - 1] =
                                Arc::new(MerkleNode::<E, u64, T>::ForgettenSubtree {
                                    value: children[frontier - 1].value(),
                                });
                        }
                        let (new_child, increment) = children[frontier]
                            .extend_and_forget_internal::<H, ARITY>(
                                height - 1,
                                &cur_pos,
                                traversal_path,
                                at_frontier && frontier == traversal_path[height - 1],
                                data,
                            )?;
                        children[frontier] = new_child;
                        cnt += increment;
                        cur_pos += increment;
                        frontier += 1;
                    }
                    Ok((
                        Arc::new(MerkleNode::Branch {
                            value: digest_branch::<E, H, u64, T>(&children)?,
                            children,
                        }),
                        cnt,
                    ))
                }
            },
            MerkleNode::Leaf { .. } => Err(MerkleTreeError::ExistingLeaf),
            MerkleNode::ForgettenSubtree { .. } => Err(MerkleTreeError::ForgottenLeaf),
        }
    }
}

impl<E, I, T, const ARITY: usize> MerkleProof<E, I, T, ARITY>
where
    E: Element,
    I: Index + ToTraversalPath<ARITY>,
    T: NodeValue,
{
    /// Verifies a membership proof against an expected root hash.
    ///
    /// This method recomputes the root hash from the proof and compares it to
    /// the expected value. A successful verification indicates that the
    /// element is indeed present at the claimed position in a tree with the
    /// given root.
    ///
    /// # Type Parameters
    ///
    /// - `H`: The digest algorithm used for hashing
    ///
    /// # Arguments
    ///
    /// * `expected_root` - The expected root hash to verify against
    ///
    /// # Returns
    ///
    /// Returns `Ok(Ok(()))` if the proof is valid, `Ok(Err(()))` if the proof
    /// is invalid (root mismatch), or `Err(MerkleTreeError)` if the proof
    /// is malformed.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleTreeError::InconsistentStructureError`] if the proof
    /// structure is invalid or incompatible with the tree parameters.
    pub fn verify_membership_proof<H>(
        &self,
        expected_root: &T,
    ) -> Result<VerificationResult, MerkleTreeError>
    where
        H: DigestAlgorithm<E, I, T>,
    {
        if let Some(MerkleNode::<E, I, T>::Leaf {
            value: _,
            pos,
            elem,
        }) = self.proof.first()
        {
            let init = H::digest_leaf(pos, elem)?;
            let computed_root = self
                .pos
                .to_traversal_path(self.tree_height() - 1)
                .iter()
                .zip(self.proof.iter().skip(1))
                .try_fold(init, |val, (branch, node)| -> Result<T, MerkleTreeError> {
                    match node {
                        MerkleNode::Branch { value: _, children } => {
                            let mut data =
                                children.iter().map(|node| node.value()).collect::<Vec<_>>();
                            if *branch >= data.len() {
                                return Err(MerkleTreeError::InconsistentStructureError(
                                    "Branch index out of bounds in corrupted proof".to_string(),
                                ));
                            }
                            data[*branch] = val;
                            H::digest(&data)
                        },
                        _ => Err(MerkleTreeError::InconsistentStructureError(
                            "Incompatible proof for this merkle tree".to_string(),
                        )),
                    }
                })?;
            if computed_root == *expected_root {
                Ok(Ok(()))
            } else {
                Ok(Err(()))
            }
        } else {
            Err(MerkleTreeError::InconsistentStructureError(
                "Invalid proof type".to_string(),
            ))
        }
    }

    /// Verifies a non-membership proof against an expected root hash.
    ///
    /// This method verifies that a specific position is empty in a tree with
    /// the given root. It recomputes the root hash from the non-membership
    /// proof and compares it to the expected value.
    ///
    /// # Type Parameters
    ///
    /// - `H`: The digest algorithm used for hashing
    ///
    /// # Arguments
    ///
    /// * `expected_root` - The expected root hash to verify against
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the non-membership proof is valid (the position is
    /// indeed empty), `Ok(false)` if invalid (root mismatch), or
    /// `Err(MerkleTreeError)` if the proof is malformed.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleTreeError::InconsistentStructureError`] if the proof
    /// structure is invalid or incompatible with the tree parameters.
    pub fn verify_non_membership_proof<H>(&self, expected_root: &T) -> Result<bool, MerkleTreeError>
    where
        H: DigestAlgorithm<E, I, T>,
    {
        if let MerkleNode::<E, I, T>::Empty = &self.proof[0] {
            let init = T::default();
            let computed_root = self
                .pos
                .to_traversal_path(self.tree_height() - 1)
                .iter()
                .zip(self.proof.iter().skip(1))
                .try_fold(init, |val, (branch, node)| -> Result<T, MerkleTreeError> {
                    match node {
                        MerkleNode::Branch { value: _, children } => {
                            let mut data =
                                children.iter().map(|node| node.value()).collect::<Vec<_>>();
                            if *branch >= data.len() {
                                return Err(MerkleTreeError::InconsistentStructureError(
                                    "Branch index out of bounds in corrupted proof".to_string(),
                                ));
                            }
                            data[*branch] = val;
                            H::digest(&data)
                        },
                        MerkleNode::Empty => Ok(init),
                        _ => Err(MerkleTreeError::InconsistentStructureError(
                            "Incompatible proof for this merkle tree".to_string(),
                        )),
                    }
                })?;
            Ok(computed_root == *expected_root)
        } else {
            Err(MerkleTreeError::InconsistentStructureError(
                "Invalid proof type".to_string(),
            ))
        }
    }
}

/// An iterator over the elements in a Merkle tree.
///
/// This iterator traverses the tree in order, yielding references to the index
/// and element of each leaf that is currently in memory. Forgotten leaves are
/// skipped.
///
/// # Examples
///
/// ```ignore
/// use merkle_tree::internal::{MerkleTreeIter, MerkleNode};
///
/// let iter = MerkleTreeIter::new(&root);
/// for (index, element) in iter {
///     println!("Element at {}: {:?}", index, element);
/// }
/// ```
pub struct MerkleTreeIter<'a, E: Element, I: Index, T: NodeValue> {
    stack: Vec<&'a MerkleNode<E, I, T>>,
}

impl<'a, E: Element, I: Index, T: NodeValue> MerkleTreeIter<'a, E, I, T> {
    /// Creates a new iterator starting from the given root node.
    ///
    /// # Arguments
    ///
    /// * `root` - The root node of the tree to iterate over
    pub fn new(root: &'a MerkleNode<E, I, T>) -> Self {
        Self { stack: vec![root] }
    }
}

impl<'a, E, I, T> Iterator for MerkleTreeIter<'a, E, I, T>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    type Item = (&'a I, &'a E);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node {
                MerkleNode::Branch { value: _, children } => {
                    children
                        .iter()
                        .rev()
                        .filter(|child| {
                            matches!(
                                ***child,
                                MerkleNode::Branch { .. } | MerkleNode::Leaf { .. }
                            )
                        })
                        .for_each(|child| self.stack.push(child));
                },
                MerkleNode::Leaf {
                    value: _,
                    pos,
                    elem,
                } => {
                    return Some((pos, elem));
                },
                _ => {},
            }
        }
        None
    }
}

/// An owned iterator over the elements in a Merkle tree.
///
/// Unlike [`MerkleTreeIter`], this iterator takes ownership of the tree nodes
/// and yields owned values rather than references. This is useful when you need
/// to consume the tree or move elements out of it.
///
/// # Examples
///
/// ```ignore
/// use merkle_tree::internal::{MerkleTreeIntoIter, MerkleNode};
///
/// let iter = MerkleTreeIntoIter::new(root);
/// for (index, element) in iter {
///     // index and element are owned values
///     println!("Element at {}: {:?}", index, element);
/// }
/// ```
pub struct MerkleTreeIntoIter<E: Element, I: Index, T: NodeValue> {
    stack: Vec<Arc<MerkleNode<E, I, T>>>,
}

impl<E: Element, I: Index, T: NodeValue> MerkleTreeIntoIter<E, I, T> {
    /// Creates a new owned iterator starting from the given root node.
    ///
    /// # Arguments
    ///
    /// * `root` - The root node of the tree to iterate over (as an `Arc`)
    pub fn new(root: Arc<MerkleNode<E, I, T>>) -> Self {
        Self { stack: vec![root] }
    }
}

impl<E, I, T> Iterator for MerkleTreeIntoIter<E, I, T>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    type Item = (I, E);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node.as_ref() {
                MerkleNode::Branch { value: _, children } => {
                    children
                        .iter()
                        .rev()
                        .filter(|child| {
                            matches!(
                                (**child).as_ref(),
                                MerkleNode::Branch { .. } | MerkleNode::Leaf { .. }
                            )
                        })
                        .for_each(|child| self.stack.push(child.clone()));
                },
                MerkleNode::Leaf {
                    value: _,
                    pos,
                    elem,
                } => {
                    return Some((pos.clone(), elem.clone()));
                },
                _ => {},
            }
        }
        None
    }
}
