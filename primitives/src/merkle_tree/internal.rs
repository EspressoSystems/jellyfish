// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use core::convert::TryInto;

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

pub(crate) fn calculate_capacity(height: usize, arity: u64) -> u64 {
    arity
        .checked_pow(height.try_into().unwrap())
        .unwrap_or(u64::MAX)
}

type BoxMTNode<E, I, T> = Box<MerkleNode<E, I, T>>;

pub(crate) fn build_tree_internal<E, H, I, Arity, T>(
    height: usize,
    capacity: u64,
    iter: impl IntoIterator<Item = impl Borrow<E>>,
) -> Result<(BoxMTNode<E, I, T>, u64), PrimitivesError>
where
    E: Element,
    H: DigestAlgorithm<E, I, T>,
    I: Index + From<u64>,
    Arity: Unsigned,
    T: NodeValue,
{
    let leaves: Vec<_> = iter.into_iter().collect();
    let num_leaves = leaves.len() as u64;

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
                        let pos = I::from(pos as u64);
                        Box::new(MerkleNode::Leaf {
                            value: H::digest_leaf(&pos, elem.borrow()),
                            pos,
                            elem: *elem.borrow(),
                        })
                    })
                    .pad_using(Arity::to_usize(), |_| Box::new(MerkleNode::Empty))
                    .collect_vec();
                Box::new(MerkleNode::<E, I, T>::Branch {
                    value: digest_branch::<E, H, I, T>(&children),
                    children,
                })
            })
            .collect_vec();
        for _ in 1..height {
            cur_nodes = cur_nodes
                .into_iter()
                .chunks(Arity::to_usize())
                .into_iter()
                .map(|chunk| {
                    let children = chunk
                        .pad_using(Arity::to_usize(), |_| {
                            Box::new(MerkleNode::<E, I, T>::Empty)
                        })
                        .collect_vec();
                    Box::new(MerkleNode::<E, I, T>::Branch {
                        value: digest_branch::<E, H, I, T>(&children),
                        children,
                    })
                })
                .collect_vec();
        }
        Ok((cur_nodes[0].clone(), num_leaves))
    } else {
        Ok((Box::new(MerkleNode::<E, I, T>::Empty), 0))
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
        depth: usize,
        branches: &[usize],
    ) -> LookupResult<E, Vec<MerkleNode<E, I, T>>> {
        match self {
            MerkleNode::Empty => LookupResult::EmptyLeaf,
            MerkleNode::Branch { value, children } => {
                match children[branches[depth - 1]].forget_internal(depth, branches) {
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
        depth: usize,
        branches: &[usize],
        path_values: &[T],
        proof: &[MerkleNode<E, I, T>],
    ) -> Result<(), PrimitivesError>
    where
        H: DigestAlgorithm<E, I, T>,
        Arity: Unsigned,
    {
        if self.value() != path_values[depth] {
            return Err(PrimitivesError::ParameterError(format!(
                "Invalid proof. Hash differs at height {}: (expected: {:?}, received: {:?})",
                depth,
                self.value(),
                path_values[depth]
            )));
        }
        if depth == 0 && matches!(self, MerkleNode::ForgettenSubtree { value: _ }) {
            *self = proof[depth].clone();
            Ok(())
        } else if let MerkleNode::Branch {
            value: _,
            children: proof_children,
        } = &proof[depth]
        {
            match &mut *self {
                MerkleNode::Branch { value: _, children } => {
                    let branch = branches[depth - 1];
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
                            depth
                        )))
                    } else {
                        children[branch].remember_internal::<H, Arity>(
                            depth - 1,
                            branches,
                            path_values,
                            proof,
                        )
                    }
                },
                MerkleNode::ForgettenSubtree { value: _ } => {
                    *self = MerkleNode::Branch {
                        value: path_values[depth],
                        children: {
                            let mut children = proof_children.clone();
                            children[branches[depth - 1]].remember_internal::<H, Arity>(
                                depth - 1,
                                branches,
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
        depth: usize,
        branches: &[usize],
    ) -> LookupResult<E, Vec<MerkleNode<E, I, T>>> {
        match self {
            MerkleNode::Empty => LookupResult::EmptyLeaf,
            MerkleNode::Branch { value: _, children } => {
                match children[branches[depth - 1]].lookup_internal(depth - 1, branches) {
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

    pub(crate) fn update_internal<H, Arity>(
        &mut self,
        depth: usize,
        pos: I,
        branches: &[usize],
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
            MerkleNode::Branch { value: _, children } => (*children[branches[depth - 1]])
                .update_internal::<H, Arity>(depth - 1, pos, branches, elem),
            MerkleNode::Empty => {
                if depth == 0 {
                    *self = MerkleNode::Leaf {
                        value: H::digest_leaf(&pos, elem),
                        pos,
                        elem: *elem.borrow(),
                    };
                } else {
                    let mut children = vec![Box::new(MerkleNode::Empty); Arity::to_usize()];
                    (*children[branches[depth - 1]]).update_internal::<H, Arity>(
                        depth - 1,
                        pos,
                        branches,
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
        depth: usize,
        pos: I,
        branches: &[usize],
        tight_frontier: bool,
        data: &mut Peekable<impl Iterator<Item = impl Borrow<E>>>,
    ) -> Result<u64, PrimitivesError>
    where
        H: DigestAlgorithm<E, I, T>,
        Arity: Unsigned,
    {
        if data.peek().is_none() {
            Ok(0)
        } else {
            match self {
                MerkleNode::Branch { value, children } => {
                    let mut pos = pos;
                    let mut cnt = 0u64;
                    let mut frontier = if tight_frontier {
                        branches[depth - 1]
                    } else {
                        0
                    };
                    let cap = Arity::to_usize();
                    while data.peek().is_some() && frontier < cap {
                        let increment = children[frontier].extend_internal::<H, Arity>(
                            depth - 1,
                            pos,
                            branches,
                            tight_frontier && frontier == branches[depth - 1],
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
                    if depth == 0 {
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
                            branches[depth - 1]
                        } else {
                            0
                        };
                        let cap = Arity::to_usize();
                        let mut children = vec![Box::new(MerkleNode::Empty); cap];
                        while data.peek().is_some() && frontier < cap {
                            let increment = children[frontier].extend_internal::<H, Arity>(
                                depth - 1,
                                pos,
                                branches,
                                tight_frontier && frontier == branches[depth - 1],
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
                MerkleNode::Leaf {
                    elem: _,
                    value: _,
                    pos: _,
                } => Err(PrimitivesError::ParameterError(
                    "Incompatible merkle tree: index already occupied".to_string(),
                )),
                _ => Err(PrimitivesError::ParameterError(
                    "Given part of merkle tree is not in memory".to_string(),
                )),
            }
        }
    }
}

impl<E, I, T> MerkleProof<E, I, T>
where
    E: Element,
    I: Index + From<u64>,
    T: NodeValue,
{
    pub(crate) fn verify_membership_proof<H, Arity>(&self) -> Result<T, PrimitivesError>
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
            self.pos
                .to_branches(self.proof.len() - 1, Arity::to_usize())
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
                )
        } else {
            Err(PrimitivesError::ParameterError(
                "Invalid proof type".to_string(),
            ))
        }
    }
}
