// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::{DigestAlgorithm, ElementType, IndexType, LookupResult};
use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_std::{borrow::Borrow, boxed::Box, iter::Peekable, string::ToString, vec, vec::Vec};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MerkleNode<E, F: Field> {
    EmptySubtree,
    Branch {
        value: F,
        children: Vec<Box<MerkleNode<E, F>>>,
    },
    Leaf {
        value: F,
        children: Vec<Box<E>>,
    },
    ForgettenSubtree {
        value: F,
    },
}

impl<E, F: Field> MerkleNode<E, F> {
    /// Returns the value of this [`MerkleNode`].
    #[inline]
    pub(crate) fn value(&self) -> F {
        match self {
            Self::EmptySubtree => F::zero(),
            Self::Branch { value, children: _ } => *value,
            Self::Leaf { value, children: _ } => *value,
            Self::ForgettenSubtree { value } => *value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleProof<E, F: Field, I: IndexType> {
    /// Proof of inclusion for element at index `pos`
    pub pos: I,
    /// Nodes of proof path, from root to leaf
    pub proof: Vec<MerkleNode<E, F>>,
}

/// Return a vector of branching index from leaf to root for a given index
pub(crate) fn index_to_branches<I, LeafArity, TreeArity>(pos: I, height: usize) -> Vec<usize>
where
    TreeArity: Unsigned,
    LeafArity: Unsigned,
    I: IndexType,
{
    let mut pos = pos;
    let mut ret = vec![(pos % LeafArity::to_u64()).as_()];
    pos /= LeafArity::to_u64();
    for _i in 1..height {
        ret.push((pos % TreeArity::to_u64()).as_());
        pos /= TreeArity::to_u64();
    }
    ret
}

pub(crate) fn calculate_capacity<I, LeafArity, TreeArity>(height: usize) -> I
where
    TreeArity: Unsigned,
    LeafArity: Unsigned,
    I: IndexType,
{
    let mut capacity = I::from(LeafArity::to_u64());
    for _i in 1..height {
        capacity *= TreeArity::to_u64();
    }
    capacity
}

pub(crate) fn build_tree_internal<E, H, I, LeafArity, TreeArity, F>(
    height: usize,
    capacity: I,
    iter: impl IntoIterator<Item = impl Borrow<E>>,
) -> Result<(Box<MerkleNode<E, F>>, I), PrimitivesError>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    let leaves: Vec<_> = iter.into_iter().collect();
    let num_leaves = I::from(leaves.len() as u64);

    if num_leaves > capacity {
        Err(PrimitivesError::ParameterError(
            "Too many data for merkle tree".to_string(),
        ))
    } else if num_leaves > I::zero() {
        let mut cur_nodes = leaves
            .into_iter()
            .chunks(LeafArity::to_usize())
            .into_iter()
            .map(|chunk| {
                let children = chunk
                    .map(|elem| Box::new(*elem.borrow()))
                    .pad_using(LeafArity::to_usize(), |_| Box::new(E::default()))
                    .collect_vec();
                Box::new(MerkleNode::<E, F>::Leaf {
                    value: digest_leaf::<E, H, F>(children.as_slice()),
                    children,
                })
            })
            .collect_vec();
        for _ in 1..height {
            cur_nodes = cur_nodes
                .into_iter()
                .chunks(TreeArity::to_usize())
                .into_iter()
                .map(|chunk| {
                    let children = chunk
                        .pad_using(TreeArity::to_usize(), |_| {
                            Box::new(MerkleNode::<E, F>::EmptySubtree)
                        })
                        .collect_vec();
                    Box::new(MerkleNode::<E, F>::Branch {
                        value: digest_branch::<E, H, F>(&children),
                        children,
                    })
                })
                .collect_vec();
        }
        Ok((cur_nodes[0].clone(), num_leaves))
    } else {
        Ok((Box::new(MerkleNode::<E, F>::EmptySubtree), I::zero()))
    }
}

pub(crate) fn digest_leaf<E, H, F>(data: &[Box<E>]) -> F
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    F: Field,
{
    let data = data
        .iter()
        .map(|elem| -> &[F] { elem.as_slice_ref() })
        .collect_vec()
        .concat();
    H::digest(&data)
}

pub(crate) fn digest_branch<E, H, F>(data: &[Box<MerkleNode<E, F>>]) -> F
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    F: Field,
{
    let data = data.iter().map(|node| node.value()).collect_vec();
    H::digest(&data)
}

/// Extend a list to the given node. Return the number of inserted elements.
pub(crate) fn mt_node_extend_internal<E, H, LeafArity, TreeArity, F>(
    node: &mut Box<MerkleNode<E, F>>,
    height: usize,
    branch: &[usize],
    data: &mut Peekable<impl Iterator<Item = impl Borrow<E>>>,
) -> Result<u64, PrimitivesError>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    if data.peek().is_none() {
        Ok(0)
    } else if height == 1 {
        match &mut **node {
            MerkleNode::EmptySubtree => {
                let mut frontier = branch[height - 1];
                let mut cnt = 0u64;
                if frontier == 0 {
                    let mut children = vec![Box::new(E::default()); LeafArity::to_usize()];
                    while data.peek().is_some() && frontier < LeafArity::to_usize() {
                        cnt += 1;
                        frontier += 1;
                        children[frontier] = Box::new(*data.next().unwrap().borrow());
                    }
                    **node = MerkleNode::Leaf {
                        value: digest_leaf::<E, H, F>(&children),
                        children,
                    };
                    Ok(cnt)
                } else {
                    Err(PrimitivesError::ParameterError(
                        "Incompatible merkle tree".to_string(),
                    ))
                }
            },
            MerkleNode::Leaf { value, children } => {
                let mut frontier = branch[height - 1];
                let mut cnt = 0u64;
                while data.peek().is_some() && frontier < LeafArity::to_usize() {
                    cnt += 1;
                    frontier += 1;
                    *children[frontier] = *data.next().unwrap().borrow();
                }
                *value = digest_leaf::<E, H, F>(children);
                Ok(cnt)
            },
            MerkleNode::Branch {
                value: _,
                children: _,
            } => Err(PrimitivesError::ParameterError(
                "Incompatible merkle tree".to_string(),
            )),
            MerkleNode::ForgettenSubtree { value: _ } => Err(PrimitivesError::ParameterError(
                "Given part of merkle tree is not in memory".to_string(),
            )),
        }
    } else {
        match &mut **node {
            MerkleNode::EmptySubtree => {
                let mut frontier = branch[height - 1];
                let mut cnt = 0u64;
                if frontier == 0 {
                    let mut children =
                        vec![Box::new(MerkleNode::EmptySubtree); TreeArity::to_usize()];
                    while data.peek().is_some() && frontier < TreeArity::to_usize() {
                        cnt += mt_node_extend_internal::<E, H, LeafArity, TreeArity, F>(
                            &mut children[frontier],
                            height - 1,
                            branch,
                            data,
                        )?;
                        frontier += 1;
                    }
                    **node = MerkleNode::Branch {
                        value: digest_branch::<E, H, F>(&children),
                        children,
                    };
                    Ok(cnt)
                } else {
                    Err(PrimitivesError::ParameterError(
                        "Incompatible merkle tree".to_string(),
                    ))
                }
            },
            MerkleNode::Branch { value, children } => {
                if height > 1 {
                    let mut frontier = branch[height - 1];
                    let mut cnt = 0u64;
                    while data.peek().is_some() && frontier < TreeArity::to_usize() {
                        cnt += mt_node_extend_internal::<E, H, LeafArity, TreeArity, F>(
                            &mut children[frontier],
                            height - 1,
                            branch,
                            data,
                        )?;
                        frontier += 1;
                    }
                    *value = digest_branch::<E, H, F>(children);
                    Ok(cnt)
                } else {
                    Err(PrimitivesError::ParameterError(
                        "Incompatible merkle tree".to_string(),
                    ))
                }
            },
            MerkleNode::Leaf {
                value: _,
                children: _,
            } => Err(PrimitivesError::ParameterError(
                "Incompatible merkle tree".to_string(),
            )),
            MerkleNode::ForgettenSubtree { value: _ } => Err(PrimitivesError::ParameterError(
                "Given part of merkle tree is not in memory".to_string(),
            )),
        }
    }
}

pub(crate) fn mt_node_update_internal<E, H, I, LeafArity, TreeArity, F>(
    node: &mut Box<MerkleNode<E, F>>,
    depth: usize,
    branches: &[usize],
    elem: impl Borrow<E>,
) -> Result<(), PrimitivesError>
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    if depth == 1 {
        if let MerkleNode::Leaf {
            ref mut value,
            ref mut children,
        } = **node
        {
            *children[branches[depth - 1]] = *elem.borrow();
            *value = digest_leaf::<E, H, F>(children);
        } else {
            return Err(PrimitivesError::InternalError(
                "Inconsistent merkle tree".to_string(),
            ));
        }
    } else if let MerkleNode::<E, F>::Branch {
        value: _,
        ref mut children,
    } = **node
    {
        let child = &mut children[branches[depth - 1]];
        match **child {
            MerkleNode::<E, F>::Branch {
                value: _,
                children: _,
            } => mt_node_update_internal::<E, H, I, LeafArity, TreeArity, F>(
                child,
                depth - 1,
                branches,
                elem,
            )?,
            MerkleNode::<E, F>::Leaf {
                value: _,
                children: _,
            } => mt_node_update_internal::<E, H, I, LeafArity, TreeArity, F>(
                child,
                depth - 1,
                branches,
                elem,
            )?,

            MerkleNode::<E, F>::ForgettenSubtree { value: _ } => {
                return Err(PrimitivesError::InternalError(
                    "Couldn't update the given position: merkle tree data not in memory"
                        .to_string(),
                ))
            },

            MerkleNode::<E, F>::EmptySubtree => {
                **child = if depth == 2 {
                    let mut children = vec![Box::new(E::default()); LeafArity::to_usize()];
                    *children[branches[depth - 1]] = *elem.borrow();
                    MerkleNode::<E, F>::Leaf {
                        value: digest_leaf::<E, H, F>(&children),
                        children,
                    }
                } else {
                    let mut children =
                        vec![Box::new(MerkleNode::EmptySubtree); TreeArity::to_usize()];
                    mt_node_update_internal::<E, H, I, LeafArity, TreeArity, F>(
                        &mut children[branches[depth - 1]],
                        depth - 1,
                        branches,
                        elem,
                    )?;
                    MerkleNode::<E, F>::Branch {
                        value: digest_branch::<E, H, F>(&children),
                        children,
                    }
                }
            },
        }
    } else {
        return Err(PrimitivesError::InternalError(
            "Inconsistent merkle tree".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn lookup_internal<E, I, LeafArity, TreeArity, F>(
    root: &MerkleNode<E, F>,
    height: usize,
    pos: I,
) -> LookupResult<E, MerkleProof<E, F, I>>
where
    E: ElementType<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    let mut proof: Vec<MerkleNode<E, F>> = vec![];
    let mut cur = root.borrow();
    let mut branches = index_to_branches::<I, LeafArity, TreeArity>(pos, height);
    branches.reverse();
    let mut leaf_value = E::default();
    for depth in 0..height {
        match cur {
            MerkleNode::Leaf { value: _, children } => {
                proof.push(cur.clone());
                leaf_value = *children[branches[depth]];
            },
            MerkleNode::Branch { value: _, children } => {
                proof.push(MerkleNode::Branch {
                    value: F::zero(),
                    children: children
                        .iter()
                        .map(|node| {
                            Box::new(MerkleNode::ForgettenSubtree {
                                value: node.value(),
                            })
                        })
                        .collect_vec(),
                });
                cur = &children[branches[depth]];
            },
            MerkleNode::EmptySubtree => return LookupResult::EmptyLeaf,
            MerkleNode::ForgettenSubtree { value: _ } => return LookupResult::NotInMemory,
        }
    }
    LookupResult::Ok(leaf_value, MerkleProof { pos, proof })
}

impl<E, F, I> MerkleProof<E, F, I>
where
    E: ElementType<F>,
    F: Field,
    I: IndexType,
{
    pub(crate) fn verify_membership_proof<H, LeafArity, TreeArity>(
        &self,
    ) -> Result<F, PrimitivesError>
    where
        H: DigestAlgorithm<F>,
        LeafArity: Unsigned,
        TreeArity: Unsigned,
    {
        index_to_branches::<I, LeafArity, TreeArity>(self.pos, self.proof.len())
            .iter()
            .zip(self.proof.iter().rev())
            .fold(
                Ok(F::zero()),
                |result, (branch, node)| -> Result<F, PrimitivesError> {
                    match result {
                        Ok(val) => match node {
                            MerkleNode::Leaf { value: _, children } => {
                                Ok(digest_leaf::<E, H, F>(children))
                            },
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
    }
}
