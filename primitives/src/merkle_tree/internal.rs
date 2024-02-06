// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::{
    DigestAlgorithm, Element, Index, LookupResult, MerkleCommitment, NodeValue, ToTraversalPath,
};
use crate::errors::{PrimitivesError, VerificationResult};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow, boxed::Box, format, iter::Peekable, string::ToString, vec, vec::Vec,
};
use core::marker::PhantomData;
use itertools::Itertools;
use jf_utils::canonical;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tagged_base64::tagged;
use typenum::Unsigned;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "E: CanonicalSerialize + CanonicalDeserialize,
                 I: CanonicalSerialize + CanonicalDeserialize,")]
pub enum MerkleNode<E: Element, I: Index, T: NodeValue> {
    Empty,
    Branch {
        #[serde(with = "canonical")]
        value: T,
        children: Vec<Box<MerkleNode<E, I, T>>>,
    },
    Leaf {
        #[serde(with = "canonical")]
        value: T,
        #[serde(with = "canonical")]
        pos: I,
        #[serde(with = "canonical")]
        elem: E,
    },
    ForgettenSubtree {
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
            Self::ForgettenSubtree { value } => *value,
        }
    }

    #[inline]
    pub(crate) fn is_forgotten(&self) -> bool {
        matches!(self, Self::ForgettenSubtree { .. })
    }
}

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

#[derive(Derivative, Debug, Clone, Serialize, Deserialize)]
#[derivative(Eq, Hash, PartialEq)]
#[serde(bound = "E: CanonicalSerialize + CanonicalDeserialize,
             I: CanonicalSerialize + CanonicalDeserialize,")]
pub struct MerkleProof<E, I, T, Arity>
where
    E: Element,
    I: Index,
    T: NodeValue,
    Arity: Unsigned,
{
    /// Proof of inclusion for element at index `pos`
    #[serde(with = "canonical")]
    pub pos: I,
    /// Nodes of proof path, from root to leaf
    pub proof: MerklePath<E, I, T>,

    /// Place holder for Arity
    _phantom_arity: PhantomData<Arity>,
}

impl<E, I, T, Arity> MerkleProof<E, I, T, Arity>
where
    E: Element,
    I: Index,
    T: NodeValue,
    Arity: Unsigned,
{
    pub fn tree_height(&self) -> usize {
        self.proof.len()
    }

    pub fn new(pos: I, proof: MerklePath<E, I, T>) -> Self {
        MerkleProof {
            pos,
            proof,
            _phantom_arity: PhantomData,
        }
    }

    pub fn index(&self) -> &I {
        &self.pos
    }

    pub fn elem(&self) -> Option<&E> {
        match self.proof.first() {
            Some(MerkleNode::Leaf { elem, .. }) => Some(elem),
            _ => None,
        }
    }
}

#[allow(clippy::type_complexity)]
pub(crate) fn build_tree_internal<E, H, Arity, T>(
    height: Option<usize>,
    elems: impl IntoIterator<Item = impl Borrow<E>>,
) -> Result<(Box<MerkleNode<E, u64, T>>, usize, u64), PrimitivesError>
where
    E: Element,
    H: DigestAlgorithm<E, u64, T>,
    Arity: Unsigned,
    T: NodeValue,
{
    let leaves: Vec<_> = elems.into_iter().collect();
    let num_leaves = leaves.len() as u64;
    let height = height.unwrap_or_else(|| {
        let mut height = 0usize;
        let mut capacity = 1;
        while capacity < num_leaves {
            height += 1;
            capacity *= Arity::to_u64();
        }
        height
    });
    let capacity = BigUint::from(Arity::to_u64()).pow(height as u32);

    if BigUint::from(num_leaves) > capacity {
        Err(PrimitivesError::ParameterError(
            "Too many data for merkle tree".to_string(),
        ))
    } else if num_leaves > 0 {
        let mut cur_nodes = leaves
            .into_iter()
            .enumerate()
            .chunks(Arity::to_usize())
            .into_iter()
            .map(|chunk| {
                let children = chunk
                    .map(|(pos, elem)| {
                        let pos = pos as u64;
                        Ok(Box::new(MerkleNode::Leaf {
                            value: H::digest_leaf(&pos, elem.borrow())?,
                            pos,
                            elem: elem.borrow().clone(),
                        }))
                    })
                    .pad_using(Arity::to_usize(), |_| Ok(Box::new(MerkleNode::Empty)))
                    .collect::<Result<Vec<_>, PrimitivesError>>()?;
                Ok(Box::new(MerkleNode::<E, u64, T>::Branch {
                    value: digest_branch::<E, H, u64, T>(&children)?,
                    children,
                }))
            })
            .collect::<Result<Vec<_>, PrimitivesError>>()?;
        for _ in 1..height {
            cur_nodes = cur_nodes
                .into_iter()
                .chunks(Arity::to_usize())
                .into_iter()
                .map(|chunk| {
                    let children = chunk
                        .pad_using(Arity::to_usize(), |_| {
                            Box::new(MerkleNode::<E, u64, T>::Empty)
                        })
                        .collect::<Vec<_>>();
                    Ok(Box::new(MerkleNode::<E, u64, T>::Branch {
                        value: digest_branch::<E, H, u64, T>(&children)?,
                        children,
                    }))
                })
                .collect::<Result<Vec<_>, PrimitivesError>>()?;
        }
        Ok((cur_nodes[0].clone(), height, num_leaves))
    } else {
        Ok((Box::new(MerkleNode::<E, u64, T>::Empty), height, 0))
    }
}

#[allow(clippy::type_complexity)]
pub(crate) fn build_light_weight_tree_internal<E, H, Arity, T>(
    height: Option<usize>,
    elems: impl IntoIterator<Item = impl Borrow<E>>,
) -> Result<(Box<MerkleNode<E, u64, T>>, usize, u64), PrimitivesError>
where
    E: Element,
    H: DigestAlgorithm<E, u64, T>,
    Arity: Unsigned,
    T: NodeValue,
{
    let leaves: Vec<_> = elems.into_iter().collect();
    let num_leaves = leaves.len() as u64;
    let height = height.unwrap_or_else(|| {
        let mut height = 0usize;
        let mut capacity = 1;
        while capacity < num_leaves {
            height += 1;
            capacity *= Arity::to_u64();
        }
        height
    });
    let capacity = num_traits::checked_pow(Arity::to_u64(), height).ok_or_else(|| {
        PrimitivesError::ParameterError("Merkle tree size too large.".to_string())
    })?;

    if num_leaves > capacity {
        Err(PrimitivesError::ParameterError(
            "Too many data for merkle tree".to_string(),
        ))
    } else if num_leaves > 0 {
        let mut cur_nodes = leaves
            .into_iter()
            .enumerate()
            .chunks(Arity::to_usize())
            .into_iter()
            .map(|chunk| {
                let children = chunk
                    .map(|(pos, elem)| {
                        let pos = pos as u64;
                        Ok(if pos < num_leaves - 1 {
                            Box::new(MerkleNode::ForgettenSubtree {
                                value: H::digest_leaf(&pos, elem.borrow())?,
                            })
                        } else {
                            Box::new(MerkleNode::Leaf {
                                value: H::digest_leaf(&pos, elem.borrow())?,
                                pos,
                                elem: elem.borrow().clone(),
                            })
                        })
                    })
                    .pad_using(Arity::to_usize(), |_| Ok(Box::new(MerkleNode::Empty)))
                    .collect::<Result<Vec<_>, PrimitivesError>>()?;
                Ok(Box::new(MerkleNode::<E, u64, T>::Branch {
                    value: digest_branch::<E, H, u64, T>(&children)?,
                    children,
                }))
            })
            .collect::<Result<Vec<_>, PrimitivesError>>()?;
        for i in 1..cur_nodes.len() - 1 {
            cur_nodes[i] = Box::new(MerkleNode::ForgettenSubtree {
                value: cur_nodes[i].value(),
            })
        }
        for _ in 1..height {
            cur_nodes = cur_nodes
                .into_iter()
                .chunks(Arity::to_usize())
                .into_iter()
                .map(|chunk| {
                    let children = chunk
                        .pad_using(Arity::to_usize(), |_| {
                            Box::new(MerkleNode::<E, u64, T>::Empty)
                        })
                        .collect::<Vec<_>>();
                    Ok(Box::new(MerkleNode::<E, u64, T>::Branch {
                        value: digest_branch::<E, H, u64, T>(&children)?,
                        children,
                    }))
                })
                .collect::<Result<Vec<_>, PrimitivesError>>()?;
            for i in 1..cur_nodes.len() - 1 {
                cur_nodes[i] = Box::new(MerkleNode::ForgettenSubtree {
                    value: cur_nodes[i].value(),
                })
            }
        }
        Ok((cur_nodes[0].clone(), height, num_leaves))
    } else {
        Ok((Box::new(MerkleNode::<E, u64, T>::Empty), height, 0))
    }
}

pub(crate) fn digest_branch<E, H, I, T>(
    data: &[Box<MerkleNode<E, I, T>>],
) -> Result<T, PrimitivesError>
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
    /// also be forgotten if all its leafs are forgotten.
    pub(crate) fn forget_internal(
        &mut self,
        height: usize,
        traversal_path: &[usize],
    ) -> LookupResult<E, MerklePath<E, I, T>, MerklePath<E, I, T>> {
        match self {
            MerkleNode::Empty => LookupResult::NotFound(vec![MerkleNode::Empty; height + 1]),
            MerkleNode::Branch { value, children } => {
                match children[traversal_path[height - 1]]
                    .forget_internal(height - 1, traversal_path)
                {
                    LookupResult::Ok(elem, mut proof) => {
                        proof.push(MerkleNode::Branch {
                            value: T::default(),
                            children: children
                                .iter()
                                .map(|child| {
                                    if let MerkleNode::Empty = **child {
                                        Box::new(MerkleNode::Empty)
                                    } else {
                                        Box::new(MerkleNode::ForgettenSubtree {
                                            value: child.value(),
                                        })
                                    }
                                })
                                .collect::<Vec<_>>(),
                        });
                        if children.iter().all(|child| {
                            matches!(
                                **child,
                                MerkleNode::Empty | MerkleNode::ForgettenSubtree { value: _ }
                            )
                        }) {
                            *self = MerkleNode::ForgettenSubtree { value: *value };
                        }
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
                                        Box::new(MerkleNode::Empty)
                                    } else {
                                        Box::new(MerkleNode::ForgettenSubtree {
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
            MerkleNode::Leaf { value, pos, elem } => {
                let elem = elem.clone();
                let proof = vec![MerkleNode::<E, I, T>::Leaf {
                    value: *value,
                    pos: pos.clone(),
                    elem: elem.clone(),
                }];
                *self = MerkleNode::ForgettenSubtree { value: *value };
                LookupResult::Ok(elem, proof)
            },
            _ => LookupResult::NotInMemory,
        }
    }

    /// Re-insert a forgotten leaf to the Merkle tree if the proof is valid.
    pub(crate) fn remember_internal<H, Arity>(
        &mut self,
        height: usize,
        traversal_path: &[usize],
        path_values: &[T],
        proof: &[MerkleNode<E, I, T>],
    ) -> Result<(), PrimitivesError>
    where
        H: DigestAlgorithm<E, I, T>,
        Arity: Unsigned,
    {
        if self.value() != path_values[height] {
            return Err(PrimitivesError::ParameterError(format!(
                "Invalid proof. Hash differs at height {}: (expected: {:?}, received: {:?})",
                height,
                self.value(),
                path_values[height]
            )));
        }

        match (&mut *self, &proof[height]) {
            (Self::ForgettenSubtree { value }, Self::Branch { children, .. }) => {
                // Recurse into the appropriate sub-tree to remember the rest of the path.
                let mut children = children.clone();
                children[traversal_path[height - 1]].remember_internal::<H, Arity>(
                    height - 1,
                    traversal_path,
                    path_values,
                    proof,
                )?;
                // Remember `*self`.
                *self = Self::Branch {
                    value: *value,
                    children,
                };
                Ok(())
            },
            (Self::ForgettenSubtree { .. }, node) => {
                // Replace forgotten sub-tree with a hopefully-less-forgotten sub-tree from the
                // proof. Safe because we already checked our hash value matches the proof.
                *self = node.clone();
                Ok(())
            },
            (Self::Branch { children, .. }, Self::Branch { .. }) => children
                [traversal_path[height - 1]]
                .remember_internal::<H, Arity>(height - 1, traversal_path, path_values, proof),
            (Self::Leaf { .. }, Self::Leaf { .. }) | (Self::Empty, Self::Empty) => {
                // This node is already a complete sub-tree, so there's nothing to remember. The
                // proof matches, so just return success.
                Ok(())
            },
            (..) => Err(PrimitivesError::ParameterError("Invalid proof".into())),
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
                                        Box::new(MerkleNode::Empty)
                                    } else {
                                        Box::new(MerkleNode::ForgettenSubtree {
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
                                        Box::new(MerkleNode::Empty)
                                    } else {
                                        Box::new(MerkleNode::ForgettenSubtree {
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
    pub(crate) fn update_with_internal<H, Arity, F>(
        &mut self,
        height: usize,
        pos: impl Borrow<I>,
        traversal_path: &[usize],
        f: F,
    ) -> Result<(i64, LookupResult<E, (), ()>), PrimitivesError>
    where
        H: DigestAlgorithm<E, I, T>,
        Arity: Unsigned,
        F: FnOnce(Option<&E>) -> Option<E>,
    {
        let pos = pos.borrow();
        match self {
            MerkleNode::Leaf {
                elem: node_elem,
                value,
                pos,
            } => {
                let result = LookupResult::Ok(node_elem.clone(), ());
                match f(Some(node_elem)) {
                    Some(elem) => {
                        *value = H::digest_leaf(pos, &elem)?;
                        *node_elem = elem;
                        Ok((0i64, result))
                    },
                    None => {
                        *self = MerkleNode::Empty;
                        Ok((-1i64, result))
                    },
                }
            },
            MerkleNode::Branch { value, children } => {
                let branch = traversal_path[height - 1];
                let result = children[branch].update_with_internal::<H, Arity, _>(
                    height - 1,
                    pos,
                    traversal_path,
                    f,
                )?;
                if matches!(*children[branch], MerkleNode::ForgettenSubtree { .. }) {
                    // If the branch containing the update was forgotten by
                    // user, the update failed and nothing was changed, so we
                    // can short-circuit without recomputing this node's value.
                } else if children
                    .iter()
                    .all(|child| matches!(**child, MerkleNode::Empty))
                {
                    // If all children are empty, remove the current node.
                    *self = MerkleNode::Empty;
                } else {
                    // Otherwise, an entry has been updated and the value of one of our children has
                    // changed, so we must recompute our own value.
                    *value = digest_branch::<E, H, I, T>(children)?;
                }
                Ok(result)
            },
            MerkleNode::Empty => {
                if height == 0 {
                    if let Some(elem) = f(None) {
                        *self = MerkleNode::Leaf {
                            value: H::digest_leaf(pos, &elem)?,
                            pos: pos.clone(),
                            elem,
                        };
                        Ok((1, LookupResult::NotFound(())))
                    } else {
                        Ok((0, LookupResult::NotFound(())))
                    }
                } else {
                    let branch = traversal_path[height - 1];
                    let mut children = vec![Box::new(MerkleNode::Empty); Arity::to_usize()];
                    let result = children[branch].update_with_internal::<H, Arity, _>(
                        height - 1,
                        pos,
                        traversal_path,
                        f,
                    )?;
                    if matches!(*children[branch], MerkleNode::Empty) {
                        // No update performed.
                    } else {
                        *self = MerkleNode::Branch {
                            value: digest_branch::<E, H, I, T>(&children)?,
                            children,
                        };
                    }
                    Ok(result)
                }
            },
            MerkleNode::ForgettenSubtree { .. } => Ok((0, LookupResult::NotInMemory)),
        }
    }
}

impl<E, T> MerkleNode<E, u64, T>
where
    E: Element,
    T: NodeValue,
{
    /// Batch insertion for the given Merkle node.
    pub(crate) fn extend_internal<H, Arity>(
        &mut self,
        height: usize,
        pos: &u64,
        traversal_path: &[usize],
        at_frontier: bool,
        data: &mut Peekable<impl Iterator<Item = impl Borrow<E>>>,
    ) -> Result<u64, PrimitivesError>
    where
        H: DigestAlgorithm<E, u64, T>,
        Arity: Unsigned,
    {
        if data.peek().is_none() {
            return Ok(0);
        }
        let mut cur_pos = *pos;
        match self {
            MerkleNode::Branch { value, children } => {
                let mut cnt = 0u64;
                let mut frontier = if at_frontier {
                    traversal_path[height - 1]
                } else {
                    0
                };
                let cap = Arity::to_usize();
                while data.peek().is_some() && frontier < cap {
                    let increment = children[frontier].extend_internal::<H, Arity>(
                        height - 1,
                        &cur_pos,
                        traversal_path,
                        at_frontier && frontier == traversal_path[height - 1],
                        data,
                    )?;
                    cnt += increment;
                    cur_pos += increment;
                    frontier += 1;
                }
                *value = digest_branch::<E, H, u64, T>(children)?;
                Ok(cnt)
            },
            MerkleNode::Empty => {
                if height == 0 {
                    let elem = data.next().unwrap();
                    let elem = elem.borrow();
                    *self = MerkleNode::Leaf {
                        value: H::digest_leaf(pos, elem)?,
                        pos: *pos,
                        elem: elem.clone(),
                    };
                    Ok(1)
                } else {
                    let mut cnt = 0u64;
                    let mut frontier = if at_frontier {
                        traversal_path[height - 1]
                    } else {
                        0
                    };
                    let cap = Arity::to_usize();
                    let mut children = vec![Box::new(MerkleNode::Empty); cap];
                    while data.peek().is_some() && frontier < cap {
                        let increment = children[frontier].extend_internal::<H, Arity>(
                            height - 1,
                            &cur_pos,
                            traversal_path,
                            at_frontier && frontier == traversal_path[height - 1],
                            data,
                        )?;
                        cnt += increment;
                        cur_pos += increment;
                        frontier += 1;
                    }
                    *self = MerkleNode::Branch {
                        value: digest_branch::<E, H, u64, T>(&children)?,
                        children,
                    };
                    Ok(cnt)
                }
            },
            MerkleNode::Leaf { .. } => Err(PrimitivesError::ParameterError(
                "Incompatible merkle tree: index already occupied".to_string(),
            )),
            MerkleNode::ForgettenSubtree { .. } => Err(PrimitivesError::ParameterError(
                "Given part of merkle tree is not in memory".to_string(),
            )),
        }
    }

    /// Similar to [`extend_internal`], but this function will automatically
    /// forget every leaf except for the Merkle tree frontier.
    pub(crate) fn extend_and_forget_internal<H, Arity>(
        &mut self,
        height: usize,
        pos: &u64,
        traversal_path: &[usize],
        at_frontier: bool,
        data: &mut Peekable<impl Iterator<Item = impl Borrow<E>>>,
    ) -> Result<u64, PrimitivesError>
    where
        H: DigestAlgorithm<E, u64, T>,
        Arity: Unsigned,
    {
        if data.peek().is_none() {
            return Ok(0);
        }
        let mut cur_pos = *pos;
        match self {
            MerkleNode::Branch { value, children } => {
                let mut cnt = 0u64;
                let mut frontier = if at_frontier {
                    traversal_path[height - 1]
                } else {
                    0
                };
                let cap = Arity::to_usize();
                while data.peek().is_some() && frontier < cap {
                    if frontier > 0 && !children[frontier - 1].is_forgotten() {
                        children[frontier - 1] =
                            Box::new(MerkleNode::<E, u64, T>::ForgettenSubtree {
                                value: children[frontier - 1].value(),
                            });
                    }
                    let increment = children[frontier].extend_and_forget_internal::<H, Arity>(
                        height - 1,
                        &cur_pos,
                        traversal_path,
                        at_frontier && frontier == traversal_path[height - 1],
                        data,
                    )?;
                    cnt += increment;
                    cur_pos += increment;
                    frontier += 1;
                }
                *value = digest_branch::<E, H, u64, T>(children)?;
                Ok(cnt)
            },
            MerkleNode::Empty => {
                if height == 0 {
                    let elem = data.next().unwrap();
                    let elem = elem.borrow();
                    *self = MerkleNode::Leaf {
                        value: H::digest_leaf(pos, elem)?,
                        pos: *pos,
                        elem: elem.clone(),
                    };
                    Ok(1)
                } else {
                    let mut cnt = 0u64;
                    let mut frontier = if at_frontier {
                        traversal_path[height - 1]
                    } else {
                        0
                    };
                    let cap = Arity::to_usize();
                    let mut children = vec![Box::new(MerkleNode::Empty); cap];
                    while data.peek().is_some() && frontier < cap {
                        if frontier > 0 && !children[frontier - 1].is_forgotten() {
                            children[frontier - 1] =
                                Box::new(MerkleNode::<E, u64, T>::ForgettenSubtree {
                                    value: children[frontier - 1].value(),
                                });
                        }
                        let increment = children[frontier].extend_and_forget_internal::<H, Arity>(
                            height - 1,
                            &cur_pos,
                            traversal_path,
                            at_frontier && frontier == traversal_path[height - 1],
                            data,
                        )?;
                        cnt += increment;
                        cur_pos += increment;
                        frontier += 1;
                    }
                    *self = MerkleNode::Branch {
                        value: digest_branch::<E, H, u64, T>(&children)?,
                        children,
                    };
                    Ok(cnt)
                }
            },
            MerkleNode::Leaf { .. } => Err(PrimitivesError::ParameterError(
                "Incompatible merkle tree: index already occupied".to_string(),
            )),
            MerkleNode::ForgettenSubtree { .. } => Err(PrimitivesError::ParameterError(
                "Given part of merkle tree is not in memory".to_string(),
            )),
        }
    }
}

impl<E, I, T, Arity> MerkleProof<E, I, T, Arity>
where
    E: Element,
    I: Index + ToTraversalPath<Arity>,
    T: NodeValue,
    Arity: Unsigned,
{
    /// Verify a membership proof by comparing the computed root value to the
    /// expected one.
    pub(crate) fn verify_membership_proof<H>(
        &self,
        expected_root: &T,
    ) -> Result<VerificationResult, PrimitivesError>
    where
        H: DigestAlgorithm<E, I, T>,
        Arity: Unsigned,
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
                .try_fold(init, |val, (branch, node)| -> Result<T, PrimitivesError> {
                    match node {
                        MerkleNode::Branch { value: _, children } => {
                            let mut data =
                                children.iter().map(|node| node.value()).collect::<Vec<_>>();
                            data[*branch] = val;
                            H::digest(&data)
                        },
                        _ => Err(PrimitivesError::ParameterError(
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
            Err(PrimitivesError::ParameterError(
                "Invalid proof type".to_string(),
            ))
        }
    }

    /// Verify a non membership proof by comparing the computed root value
    /// to the expected one.
    pub(crate) fn verify_non_membership_proof<H>(
        &self,
        expected_root: &T,
    ) -> Result<bool, PrimitivesError>
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
                .try_fold(init, |val, (branch, node)| -> Result<T, PrimitivesError> {
                    match node {
                        MerkleNode::Branch { value: _, children } => {
                            let mut data =
                                children.iter().map(|node| node.value()).collect::<Vec<_>>();
                            data[*branch] = val;
                            H::digest(&data)
                        },
                        MerkleNode::Empty => Ok(init),
                        _ => Err(PrimitivesError::ParameterError(
                            "Incompatible proof for this merkle tree".to_string(),
                        )),
                    }
                })?;
            Ok(computed_root == *expected_root)
        } else {
            Err(PrimitivesError::ParameterError(
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
    stack: Vec<Box<MerkleNode<E, I, T>>>,
}

impl<E: Element, I: Index, T: NodeValue> MerkleTreeIntoIter<E, I, T> {
    /// Initialize an iterator
    pub fn new(root: Box<MerkleNode<E, I, T>>) -> Self {
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
            match *node {
                MerkleNode::Branch { value: _, children } => {
                    children
                        .into_iter()
                        .rev()
                        .filter(|child| {
                            matches!(**child, MerkleNode::Branch { .. } | MerkleNode::Leaf { .. })
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
