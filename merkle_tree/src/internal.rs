// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

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

/// An internal Merkle node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "E: CanonicalSerialize + CanonicalDeserialize,
                 I: CanonicalSerialize + CanonicalDeserialize,")]
pub enum MerkleNode<E: Element, I: Index, T: NodeValue> {
    /// An empty subtree.
    Empty,
    /// An internal branching node
    Branch {
        /// Merkle hash value of this subtree
        #[serde(with = "canonical")]
        value: T,
        /// All it's children
        children: Vec<Arc<MerkleNode<E, I, T>>>,
    },
    /// A leaf node
    Leaf {
        /// Merkle hash value of this leaf
        #[serde(with = "canonical")]
        value: T,
        /// Index of this leaf
        #[serde(with = "canonical")]
        pos: I,
        /// Associated element of this leaf
        #[serde(with = "canonical")]
        elem: E,
    },
    /// The subtree is forgotten from the memory
    ForgottenSubtree {
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
    /// Return the value of this [`MerkleNode`].
    #[inline]
    pub(crate) fn value(&self) -> T {
        match self {
            Self::Empty => T::default(),
            Self::Leaf {
                value,
                pos: _,
                elem: _,
            } => *value,
            Self::Branch { value, children: _ } => *value,
            Self::ForgottenSubtree { value } => *value,
        }
    }

    #[inline]
    pub(crate) fn is_forgotten(&self) -> bool {
        matches!(self, Self::ForgottenSubtree { .. })
    }
}

/// A merkle path is a bottom-up list of nodes from leaf to the root.
pub type MerklePath<E, I, T> = Vec<MerkleNode<E, I, T>>;

/// A merkle commitment consists a root hash value, a tree height and number of
/// leaves
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

/// Merkle proof struct.
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
    /// Return the height of this proof.
    pub fn tree_height(&self) -> usize {
        self.proof.len()
    }

    /// Form a `MerkleProof` from a given index and Merkle path.
    pub fn new(pos: I, proof: MerklePath<E, I, T>) -> Self {
        MerkleProof { pos, proof }
    }

    /// Return the index of this `MerkleProof`.
    pub fn index(&self) -> &I {
        &self.pos
    }

    /// Return the element associated with this `MerkleProof`. None if it's a
    /// non-membership proof.
    pub fn elem(&self) -> Option<&E> {
        match self.proof.first() {
            Some(MerkleNode::Leaf { elem, .. }) => Some(elem),
            _ => None,
        }
    }
}

#[allow(clippy::type_complexity)]
pub(crate) fn build_tree_internal<E, H, const ARITY: usize, T>(
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

#[allow(clippy::type_complexity)]
pub(crate) fn build_light_weight_tree_internal<E, H, const ARITY: usize, T>(
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
                            Arc::new(MerkleNode::ForgottenSubtree {
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
            cur_nodes[i] = Arc::new(MerkleNode::ForgottenSubtree {
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
                cur_nodes[i] = Arc::new(MerkleNode::ForgottenSubtree {
                    value: cur_nodes[i].value(),
                })
            }
        }
        Ok((cur_nodes[0].clone(), height, num_leaves))
    }
}

pub(crate) fn digest_branch<E, H, I, T>(
    data: &[Arc<MerkleNode<E, I, T>>],
) -> Result<T, MerkleTreeError>
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
    /// Forget a leaf from the merkle tree. Internal branch merkle node will
    /// also be forgotten if all its leaves are forgotten.
    /// WARN(#495): this method breaks non-membership proofs.
    #[allow(clippy::type_complexity)]
    pub(crate) fn forget_internal(
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
                                        Arc::new(MerkleNode::ForgottenSubtree {
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
                                MerkleNode::Empty | MerkleNode::ForgottenSubtree { .. }
                            )
                        }) {
                            (
                                Arc::new(MerkleNode::ForgottenSubtree { value: *value }),
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
                                        Arc::new(MerkleNode::ForgottenSubtree {
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
                    Arc::new(MerkleNode::ForgottenSubtree { value: *value }),
                    LookupResult::Ok(elem, proof),
                )
            },
            _ => (Arc::new(self.clone()), LookupResult::NotInMemory),
        }
    }

    /// Re-insert a forgotten leaf to the Merkle tree. We assume that the proof
    /// is valid and already checked.
    pub(crate) fn remember_internal<H, const ARITY: usize>(
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
            (Self::ForgottenSubtree { value }, Self::Branch { children, .. }) => {
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
            (Self::ForgottenSubtree { .. }, node) => {
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

    /// Query the given index at the current Merkle node. Return the element
    /// with a membership proof if presence, otherwise return a non-membership
    /// proof.
    #[allow(clippy::type_complexity)]
    pub(crate) fn lookup_internal(
        &self,
        height: usize,
        traversal_path: &[usize],
    ) -> LookupResult<&E, MerklePath<E, I, T>, MerklePath<E, I, T>> {
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
                                        Arc::new(MerkleNode::ForgottenSubtree {
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
                                        Arc::new(MerkleNode::ForgottenSubtree {
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
            } => LookupResult::Ok(elem, vec![self.clone()]),
            _ => LookupResult::NotInMemory,
        }
    }

    /// Update the element at the given index.
    /// * `returns` - `Err()` if any error happens internally. `Ok(delta,
    ///   result)`, `delta` represents the changes to the overall number of
    ///   leaves of the tree, `result` contains the original lookup information
    ///   at the given location.
    #[allow(clippy::type_complexity)]
    pub(crate) fn update_with_internal<H, const ARITY: usize, F>(
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
                if matches!(*children[branch], MerkleNode::ForgottenSubtree { .. }) {
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
            MerkleNode::ForgottenSubtree { .. } => Err(MerkleTreeError::ForgottenLeaf),
        }
    }
}

impl<E, T> MerkleNode<E, u64, T>
where
    E: Element,
    T: NodeValue,
{
    /// Batch insertion for the given Merkle node.
    pub(crate) fn extend_internal<H, const ARITY: usize>(
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
            MerkleNode::ForgottenSubtree { .. } => Err(MerkleTreeError::ForgottenLeaf),
        }
    }

    /// Similar to [`extend_internal`], but this function will automatically
    /// forget every leaf except for the Merkle tree frontier.
    pub(crate) fn extend_and_forget_internal<H, const ARITY: usize>(
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
                            Arc::new(MerkleNode::<E, u64, T>::ForgottenSubtree {
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
                                Arc::new(MerkleNode::<E, u64, T>::ForgottenSubtree {
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
            MerkleNode::ForgottenSubtree { .. } => Err(MerkleTreeError::ForgottenLeaf),
        }
    }
}

impl<E, I, T, const ARITY: usize> MerkleProof<E, I, T, ARITY>
where
    E: Element,
    I: Index + ToTraversalPath<ARITY>,
    T: NodeValue,
{
    /// Verify a membership proof by comparing the computed root value to the
    /// expected one.
    pub(crate) fn verify_membership_proof<H>(
        &self,
        expected_root: &T,
    ) -> Result<VerificationResult, MerkleTreeError>
    where
        H: DigestAlgorithm<E, I, T>,
    {
        if let MerkleNode::<E, I, T>::Leaf {
            value: _,
            pos,
            elem,
        } = &self.proof[0]
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

    /// Verify a non membership proof by comparing the computed root value
    /// to the expected one.
    pub(crate) fn verify_non_membership_proof<H>(
        &self,
        expected_root: &T,
    ) -> Result<bool, MerkleTreeError>
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

/// Iterator type for a merkle tree
pub struct MerkleTreeIter<'a, E: Element, I: Index, T: NodeValue> {
    stack: Vec<&'a MerkleNode<E, I, T>>,
}

impl<'a, E: Element, I: Index, T: NodeValue> MerkleTreeIter<'a, E, I, T> {
    /// Initialize an iterator
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

/// An owned iterator type for a merkle tree
pub struct MerkleTreeIntoIter<E: Element, I: Index, T: NodeValue> {
    stack: Vec<Arc<MerkleNode<E, I, T>>>,
}

impl<E: Element, I: Index, T: NodeValue> MerkleTreeIntoIter<E, I, T> {
    /// Initialize an iterator
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
