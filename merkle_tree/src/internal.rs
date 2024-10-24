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

/// A (non)membership Merkle proof consists of all values of siblings of a
/// Merkle path.
#[derive(
    Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, CanonicalSerialize, CanonicalDeserialize,
)]
#[tagged("MERKLE_PROOF")]
pub struct MerkleTreeProof<T: NodeValue>(pub Vec<Vec<T>>);

impl<T: NodeValue> super::MerkleProof<T> for MerkleTreeProof<T> {
    /// Expected height of the Merkle tree.
    fn height(&self) -> usize {
        self.0.len()
    }

    /// Return all values of siblings of this Merkle path
    fn path_values(&self) -> &[Vec<T>] {
        &self.0
    }
}

/// Verify a merkle proof
/// * `commitment` - a merkle tree commitment
/// * `pos` - zero-based index of the leaf in the tree
/// * `element` - the leaf value, None if verifying a non-membership proof
/// * `proof` - a membership proof for `element` at given `pos`
/// * `returns` - Ok(true) if the proof is accepted, Ok(false) if not. Err() if
///   the proof is not well structured, E.g. not for this merkle tree.
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
    let init = if let Some(elem) = element {
        H::digest_leaf(pos, elem)?
    } else {
        T::default()
    };
    let mut data = [T::default(); ARITY];
    let computed_root = pos
        .to_traversal_path(proof.len())
        .iter()
        .zip(proof.iter())
        .try_fold(
            init,
            |val, (branch, values)| -> Result<T, MerkleTreeError> {
                if values.len() == 0 {
                    Ok(T::default())
                } else {
                    data[..*branch].copy_from_slice(&values[..*branch]);
                    data[*branch] = val;
                    data[*branch + 1..].copy_from_slice(&values[*branch..]);
                    H::digest(&data)
                }
            },
        )?;
    if computed_root == *commitment {
        Ok(SUCCESS)
    } else {
        Ok(FAIL)
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
                    let children: Vec<_> = chunk
                        .pad_using(ARITY, |_| Arc::new(MerkleNode::<E, u64, T>::Empty))
                        .collect();
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
        LookupResult<E, MerkleTreeProof<T>, MerkleTreeProof<T>>,
    ) {
        match self {
            MerkleNode::Empty => (
                Arc::new(self.clone()),
                LookupResult::NotFound(MerkleTreeProof(vec![])),
            ),
            MerkleNode::Branch { value, children } => {
                let mut children = children.clone();
                let (new_child, result) = children[traversal_path[height - 1]]
                    .forget_internal(height - 1, traversal_path);
                match result {
                    LookupResult::Ok(elem, mut membership_proof) => {
                        membership_proof.0.push(
                            children
                                .iter()
                                .enumerate()
                                .filter(|(id, _)| *id != traversal_path[height - 1])
                                .map(|(_, child)| child.value())
                                .collect::<Vec<_>>(),
                        );
                        children[traversal_path[height - 1]] = new_child;
                        if children.iter().all(|child| {
                            matches!(
                                **child,
                                MerkleNode::Empty | MerkleNode::ForgottenSubtree { .. }
                            )
                        }) {
                            (
                                Arc::new(MerkleNode::ForgottenSubtree { value: *value }),
                                LookupResult::Ok(elem, membership_proof),
                            )
                        } else {
                            (
                                Arc::new(MerkleNode::Branch {
                                    value: *value,
                                    children,
                                }),
                                LookupResult::Ok(elem, membership_proof),
                            )
                        }
                    },
                    LookupResult::NotInMemory => {
                        (Arc::new(self.clone()), LookupResult::NotInMemory)
                    },
                    LookupResult::NotFound(mut non_membership_proof) => {
                        non_membership_proof.0.push(
                            children
                                .iter()
                                .enumerate()
                                .filter(|(id, _)| *id != traversal_path[height - 1])
                                .map(|(_, child)| child.value())
                                .collect::<Vec<_>>(),
                        );
                        (
                            Arc::new(self.clone()),
                            LookupResult::NotFound(non_membership_proof),
                        )
                    },
                }
            },
            MerkleNode::Leaf { value, pos, elem } => (
                Arc::new(MerkleNode::ForgottenSubtree { value: *value }),
                LookupResult::Ok(elem.clone(), MerkleTreeProof(vec![])),
            ),
            _ => (Arc::new(self.clone()), LookupResult::NotInMemory),
        }
    }

    /// Re-insert a forgotten leaf to the Merkle tree.
    /// It also fails if the Merkle proof is invalid.
    pub(crate) fn remember_internal<H, const ARITY: usize>(
        &self,
        height: usize,
        traversal_path: &[usize],
        pos: &I,
        element: Option<&E>,
        proof: &[Vec<T>],
    ) -> Result<Arc<Self>, MerkleTreeError>
    where
        H: DigestAlgorithm<E, I, T>,
    {
        match self {
            MerkleNode::Empty => Ok(Arc::new(self.clone())),
            MerkleNode::Leaf {
                value,
                pos: leaf_pos,
                elem,
            } => {
                if height != 0 {
                    // Reach a leaf before it should
                    Err(MerkleTreeError::InconsistentStructureError(
                        "Malformed Merkle tree or proof".to_string(),
                    ))
                } else {
                    Ok(Arc::new(self.clone()))
                }
            },
            MerkleNode::Branch { value, children } => {
                if height == 0 {
                    // Reach a branch when there should be a leaf
                    Err(MerkleTreeError::InconsistentStructureError(
                        "Malformed merkle tree".to_string(),
                    ))
                } else {
                    let branch = traversal_path[height - 1];
                    let mut children = children.clone();
                    children[branch] = children[branch].remember_internal::<H, ARITY>(
                        height - 1,
                        traversal_path,
                        pos,
                        element,
                        proof,
                    )?;
                    Ok(Arc::new(MerkleNode::Branch {
                        value: *value,
                        children,
                    }))
                }
            },
            MerkleNode::ForgottenSubtree { value } => Ok(Arc::new(if height == 0 {
                if let Some(element) = element {
                    MerkleNode::Leaf {
                        value: H::digest_leaf(pos, element)?,
                        pos: pos.clone(),
                        elem: element.clone(),
                    }
                } else {
                    MerkleNode::Empty
                }
            } else {
                let branch = traversal_path[height - 1];
                let mut values = proof[height - 1].clone();
                values.insert(branch, *value);
                let mut children = values
                    .iter()
                    .map(|&value| Arc::new(MerkleNode::ForgottenSubtree { value }))
                    .collect::<Vec<_>>();
                children[branch] = children[branch].remember_internal::<H, ARITY>(
                    height - 1,
                    traversal_path,
                    pos,
                    element,
                    proof,
                )?;
                values[branch] = children[branch].value();
                MerkleNode::Branch {
                    value: H::digest(&values)?,
                    children,
                }
            })),
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
    ) -> LookupResult<&E, MerkleTreeProof<T>, MerkleTreeProof<T>> {
        match self {
            MerkleNode::Empty => LookupResult::NotFound(MerkleTreeProof(vec![vec![]; height])),
            MerkleNode::Branch { value: _, children } => {
                match children[traversal_path[height - 1]]
                    .lookup_internal(height - 1, traversal_path)
                {
                    LookupResult::Ok(elem, mut membership_proof) => {
                        membership_proof.0.push(
                            children
                                .iter()
                                .enumerate()
                                .filter(|(id, _)| *id != traversal_path[height - 1])
                                .map(|(_, child)| child.value())
                                .collect::<Vec<_>>(),
                        );
                        LookupResult::Ok(elem, membership_proof)
                    },
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::NotFound(mut non_membership_proof) => {
                        non_membership_proof.0.push(
                            children
                                .iter()
                                .enumerate()
                                .filter(|(id, _)| *id != traversal_path[height - 1])
                                .map(|(_, child)| child.value())
                                .collect::<Vec<_>>(),
                        );
                        LookupResult::NotFound(non_membership_proof)
                    },
                }
            },
            MerkleNode::Leaf {
                elem,
                value: _,
                pos: _,
            } => LookupResult::Ok(elem, MerkleTreeProof(vec![])),
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
                    let mut children: Vec<_> = (0..ARITY).map(|_| Arc::new(Self::Empty)).collect();
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
                    let mut children: Vec<_> = (0..cap).map(|_| Arc::new(Self::Empty)).collect();
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
                    let mut children: Vec<_> = (0..cap).map(|_| Arc::new(Self::Empty)).collect();
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
