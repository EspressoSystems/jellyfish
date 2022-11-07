// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::{DigestAlgorithm, Element, Index, LookupResult, NodeValue};
use crate::errors::PrimitivesError;
use ark_std::{
    borrow::Borrow, boxed::Box, format, iter::Peekable, string::ToString, vec, vec::Vec,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MerkleNode<E: Element, I: Index, T: NodeValue> {
    Empty,
    Branch {
        value: T,
        children: Vec<Box<MerkleNode<E, I, T>>>,
    },
    Leaf {
        value: T,
        pos: I,
        elem: E,
    },
    ForgettenSubtree {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleProof<E, I, T>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    /// Proof of inclusion for element at index `pos`
    pub pos: I,
    /// Nodes of proof path, from root to leaf
    pub proof: Vec<MerkleNode<E, I, T>>,
}

impl<E, I, T> MerkleProof<E, I, T>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    pub fn tree_height(&self) -> usize {
        self.proof.len()
    }
}

#[allow(clippy::type_complexity)]
pub(crate) fn build_tree_internal<E, H, I, Arity, T>(
    height: usize,
    elems: impl IntoIterator<Item = impl Borrow<E>>,
) -> Result<(Box<MerkleNode<E, I, T>>, u64), PrimitivesError>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64>,
    Arity: Unsigned,
    T: NodeValue,
{
    let mut root = Box::new(MerkleNode::Empty);
    let pos = I::from(0);
    let traversal_path = pos.to_treverse_path(height, Arity::to_usize());
    let mut iter = elems.into_iter().peekable();
    let num_leaves =
        root.extend_internal::<H, Arity>(height, I::from(0), &traversal_path, true, &mut iter)?;
    if iter.peek().is_some() {
        Err(PrimitivesError::ParameterError(
            "Exceed merkle tree capacity".to_string(),
        ))
    } else {
        Ok((root, num_leaves))
    }
}

pub(crate) fn digest_branch<E, H, I, T>(data: &[Box<MerkleNode<E, I, T>>]) -> T
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index,
    T: NodeValue,
{
    // Question(Chengyu): any more efficient implementation?
    let data = data.iter().map(|node| node.value()).collect_vec();
    H::digest(&data)
}

impl<E, I, T> MerkleNode<E, I, T>
where
    E: Element,
    I: Index + From<u64>,
    T: NodeValue,
{
    /// Forget a leaf from the merkle tree. Internal branch merkle node will
    /// also be forgotten if all its leafs are forgotten.
    pub(crate) fn forget_internal(
        &mut self,
        height: usize,
        traversal_path: &[usize],
    ) -> LookupResult<E, Vec<MerkleNode<E, I, T>>> {
        match self {
            MerkleNode::Empty => LookupResult::EmptyLeaf,
            MerkleNode::Branch { value, children } => {
                match children[traversal_path[height - 1]].forget_internal(height, traversal_path) {
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
                                .collect_vec(),
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
                    LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
                }
            },
            MerkleNode::Leaf { value, pos, elem } => {
                let elem = *elem;
                let proof = vec![MerkleNode::<E, I, T>::Leaf {
                    value: *value,
                    pos: *pos,
                    elem,
                }];
                *self = MerkleNode::ForgettenSubtree { value: *value };
                LookupResult::Ok(elem, proof)
            },
            _ => LookupResult::NotInMemory,
        }
    }

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
        if height == 0 && matches!(self, MerkleNode::ForgettenSubtree { value: _ }) {
            *self = proof[height].clone();
            Ok(())
        } else if let MerkleNode::Branch {
            value: _,
            children: proof_children,
        } = &proof[height]
        {
            match &mut *self {
                MerkleNode::Branch { value: _, children } => {
                    let branch = traversal_path[height - 1];
                    if !children.iter().zip(proof_children.iter()).enumerate().all(
                        |(index, (child, proof_child))| {
                            index == branch
                                || (matches!(**child, MerkleNode::Empty)
                                    && matches!(**proof_child, MerkleNode::Empty))
                                || child.value() == proof_child.value()
                        },
                    ) {
                        Err(PrimitivesError::ParameterError(format!(
                            "Invalid proof. Sibling differs at height {}",
                            height
                        )))
                    } else {
                        children[branch].remember_internal::<H, Arity>(
                            height - 1,
                            traversal_path,
                            path_values,
                            proof,
                        )
                    }
                },
                MerkleNode::ForgettenSubtree { value: _ } => {
                    *self = MerkleNode::Branch {
                        value: path_values[height],
                        children: {
                            let mut children = proof_children.clone();
                            children[traversal_path[height - 1]].remember_internal::<H, Arity>(
                                height - 1,
                                traversal_path,
                                path_values,
                                proof,
                            )?;
                            children
                        },
                    };
                    Ok(())
                },
                MerkleNode::Empty => Err(PrimitivesError::ParameterError(
                    "Invalid proof. Given location is supposed to be empty.".to_string(),
                )),
                MerkleNode::Leaf {
                    value: _,
                    pos: _,
                    elem: _,
                } => Err(PrimitivesError::ParameterError(
                    "Given position is already occupied".to_string(),
                )),
            }
        } else {
            Err(PrimitivesError::ParameterError("Invalid proof".to_string()))
        }
    }

    pub(crate) fn lookup_internal(
        &self,
        height: usize,
        traversal_path: &[usize],
    ) -> LookupResult<E, Vec<MerkleNode<E, I, T>>> {
        match self {
            MerkleNode::Empty => LookupResult::EmptyLeaf,
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
                                .collect_vec(),
                        });
                        LookupResult::Ok(elem, proof)
                    },
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
                }
            },
            MerkleNode::Leaf {
                elem,
                value: _,
                pos: _,
            } => LookupResult::Ok(*elem, vec![self.clone()]),
            _ => LookupResult::NotInMemory,
        }
    }

    // For future sparse merkle tree use
    #[allow(dead_code)]
    pub(crate) fn update_internal<H, Arity>(
        &mut self,
        height: usize,
        pos: I,
        traversal_path: &[usize],
        elem: impl Borrow<E>,
    ) -> Result<(), PrimitivesError>
    where
        H: DigestAlgorithm<E, I, T>,
        Arity: Unsigned,
    {
        let elem = elem.borrow();
        match self {
            MerkleNode::Leaf {
                elem: node_elem,
                value,
                pos,
            } => {
                *node_elem = *elem;
                *value = H::digest_leaf(pos, elem);
                Ok(())
            },
            MerkleNode::Branch { value: _, children } => (*children[traversal_path[height - 1]])
                .update_internal::<H, Arity>(
                height - 1,
                pos,
                traversal_path,
                elem,
            ),
            MerkleNode::Empty => {
                if height == 0 {
                    *self = MerkleNode::Leaf {
                        value: H::digest_leaf(&pos, elem),
                        pos,
                        elem: *elem.borrow(),
                    };
                } else {
                    let mut children = vec![Box::new(MerkleNode::Empty); Arity::to_usize()];
                    (*children[traversal_path[height - 1]]).update_internal::<H, Arity>(
                        height - 1,
                        pos,
                        traversal_path,
                        elem,
                    )?;
                    *self = MerkleNode::Branch {
                        value: digest_branch::<E, H, I, T>(&children),
                        children,
                    }
                }
                Ok(())
            },
            _ => Err(PrimitivesError::ParameterError(
                "Given index is not in memory".to_string(),
            )),
        }
    }

    pub(crate) fn extend_internal<H, Arity>(
        &mut self,
        height: usize,
        pos: I,
        traversal_path: &[usize],
        tight_frontier: bool,
        data: &mut Peekable<impl Iterator<Item = impl Borrow<E>>>,
    ) -> Result<u64, PrimitivesError>
    where
        H: DigestAlgorithm<E, I, T>,
        Arity: Unsigned,
    {
        if data.peek().is_none() {
            return Ok(0);
        }
        match self {
            MerkleNode::Branch { value, children } => {
                let mut pos = pos;
                let mut cnt = 0u64;
                let mut frontier = if tight_frontier {
                    traversal_path[height - 1]
                } else {
                    0
                };
                let cap = Arity::to_usize();
                while data.peek().is_some() && frontier < cap {
                    let increment = children[frontier].extend_internal::<H, Arity>(
                        height - 1,
                        pos,
                        traversal_path,
                        tight_frontier && frontier == traversal_path[height - 1],
                        data,
                    )?;
                    cnt += increment;
                    pos += I::from(increment);
                    frontier += 1;
                }
                *value = digest_branch::<E, H, I, T>(children);
                Ok(cnt)
            },
            MerkleNode::Empty => {
                if height == 0 {
                    let elem = data.next().unwrap();
                    let elem = elem.borrow();
                    *self = MerkleNode::Leaf {
                        elem: *elem,
                        value: H::digest_leaf(&pos, elem),
                        pos,
                    };
                    Ok(1)
                } else {
                    let mut pos = pos;
                    let mut cnt = 0u64;
                    let mut frontier = if tight_frontier {
                        traversal_path[height - 1]
                    } else {
                        0
                    };
                    let cap = Arity::to_usize();
                    let mut children = vec![Box::new(MerkleNode::Empty); cap];
                    while data.peek().is_some() && frontier < cap {
                        let increment = children[frontier].extend_internal::<H, Arity>(
                            height - 1,
                            pos,
                            traversal_path,
                            tight_frontier && frontier == traversal_path[height - 1],
                            data,
                        )?;
                        cnt += increment;
                        pos += I::from(increment);
                        frontier += 1;
                    }
                    *self = MerkleNode::Branch {
                        value: digest_branch::<E, H, I, T>(&children),
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

impl<E, I, T> MerkleProof<E, I, T>
where
    E: Element,
    I: Index + From<u64>,
    T: NodeValue,
{
    pub(crate) fn verify_membership_proof<H, Arity>(
        &self,
        expected_root: &T,
    ) -> Result<bool, PrimitivesError>
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
            let init = H::digest_leaf(pos, elem);
            let computed_root = self
                .pos
                .to_treverse_path(self.tree_height() - 1, Arity::to_usize())
                .iter()
                .zip(self.proof.iter().skip(1))
                .fold(
                    Ok(init),
                    |result, (branch, node)| -> Result<T, PrimitivesError> {
                        match result {
                            Ok(val) => match node {
                                MerkleNode::Branch { value: _, children } => {
                                    let mut data =
                                        children.iter().map(|node| node.value()).collect_vec();
                                    data[*branch] = val;
                                    Ok(H::digest(&data))
                                },
                                _ => Err(PrimitivesError::ParameterError(
                                    "Incompatible proof for this merkle tree".to_string(),
                                )),
                            },
                            Err(e) => Err(e),
                        }
                    },
                )?;
            Ok(computed_root == *expected_root)
        } else {
            Err(PrimitivesError::ParameterError(
                "Invalid proof type".to_string(),
            ))
        }
    }
}
