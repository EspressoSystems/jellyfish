// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::{DigestAlgorithm, ElementType, IndexType, LookupResult};
use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_std::{
    borrow::Borrow, boxed::Box, format, iter::Peekable, string::ToString, vec, vec::Vec,
};
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
        elem: E,
    },
    ForgettenSubtree {
        value: F,
    },
    ForgettenLeaf {
        elem: E,
    },
}

impl<E: ElementType<F>, F: Field> MerkleNode<E, F> {
    /// Return the value of this [`MerkleNode`].
    #[inline]
    pub(crate) fn value(&self) -> F {
        match self {
            Self::EmptySubtree => F::zero(),
            Self::Leaf { elem: _ } => F::zero(),
            Self::ForgettenLeaf { elem: _ } => F::zero(),
            Self::Branch { value, children: _ } => *value,
            Self::ForgettenSubtree { value } => *value,
        }
    }

    /// Return a reference to the element stored in this [`MerkleNode`].
    /// Call this function only if the given node is a leaf.
    pub(crate) fn elem_ref(&self) -> &E {
        match self {
            Self::EmptySubtree => unreachable!(),
            Self::Leaf { elem } => elem,
            Self::ForgettenLeaf { elem } => elem,
            Self::Branch {
                value: _,
                children: _,
            } => unreachable!(),
            Self::ForgettenSubtree { value: _ } => unreachable!(),
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
                    .map(|elem| {
                        Box::new(MerkleNode::Leaf {
                            elem: *elem.borrow(),
                        })
                    })
                    .pad_using(LeafArity::to_usize(), |_| {
                        Box::new(MerkleNode::EmptySubtree)
                    })
                    .collect_vec();
                Box::new(MerkleNode::<E, F>::Branch {
                    value: digest_branch::<E, H, F>(&children, true),
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
                        value: digest_branch::<E, H, F>(&children, false),
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

pub(crate) fn digest_branch<E, H, F>(data: &[Box<MerkleNode<E, F>>], is_bottom: bool) -> F
where
    E: ElementType<F>,
    H: DigestAlgorithm<F>,
    F: Field,
{
    // Question(Chengyu): any more efficient implementation?
    let data = data
        .iter()
        .map(|node| match **node {
            MerkleNode::EmptySubtree => {
                vec![F::zero(); if is_bottom { E::slice_len() } else { 1 }]
            },
            MerkleNode::Leaf { elem: value } => value.as_slice_ref().to_vec(),
            MerkleNode::Branch { value, children: _ } => vec![value],
            MerkleNode::ForgettenLeaf { elem: value } => value.as_slice_ref().to_vec(),
            MerkleNode::ForgettenSubtree { value } => vec![value],
        })
        .collect_vec()
        .concat();
    H::digest(&data)
}

impl<E, F> MerkleNode<E, F>
where
    E: ElementType<F>,
    F: Field,
{
    /// Forget a leaf from the merkle tree. Internal branch merkle node will also be forgotten if all its leafs are forgotten.
    pub(crate) fn forget_internal(
        &mut self,
        depth: usize,
        branches: &[usize],
    ) -> LookupResult<E, Vec<MerkleNode<E, F>>> {
        match self {
            MerkleNode::EmptySubtree => LookupResult::EmptyLeaf,
            MerkleNode::Branch { value, children } => {
                match children[branches[depth - 1]].forget_internal(depth, branches) {
                    LookupResult::Ok(elem, mut proof) => {
                        proof.push(MerkleNode::Branch {
                            value: F::zero(),
                            children: if depth == 1 {
                                children.iter().cloned().collect_vec()
                            } else {
                                children
                                    .iter()
                                    .map(|child| {
                                        if let MerkleNode::EmptySubtree = **child {
                                            Box::new(MerkleNode::EmptySubtree)
                                        } else {
                                            Box::new(MerkleNode::ForgettenSubtree {
                                                value: child.value(),
                                            })
                                        }
                                    })
                                    .collect_vec()
                            },
                        });
                        if children.iter().all(|child| {
                            matches!(
                                **child,
                                MerkleNode::EmptySubtree
                                    | MerkleNode::ForgettenLeaf { elem: _ }
                                    | MerkleNode::ForgettenSubtree { value: _ }
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
            MerkleNode::Leaf { elem: value } => {
                let value = *value;
                *self = MerkleNode::ForgettenLeaf { elem: value };
                LookupResult::Ok(value, vec![])
            },
            _ => LookupResult::NotInMemory,
        }
    }

    pub(crate) fn remember_internal(
        &mut self,
        depth: usize,
        branches: &[usize],
        path_values: &[F],
        proof: &[MerkleNode<E, F>],
    ) -> Result<(), PrimitivesError> {
        if self.value() != path_values[depth - 1] {
            return Err(PrimitivesError::ParameterError(format!(
                "Invalid proof. Hash differs at height {}: (expected: {}, received: {})",
                depth,
                self.value(),
                path_values[depth - 1]
            )));
        }
        if let MerkleNode::Branch {
            value: _,
            children: proof_children,
        } = &proof[depth - 1]
        {
            match &mut *self {
                MerkleNode::Branch { value: _, children } => {
                    let branch = branches[depth - 1];
                    if depth == 1 {
                        if !children.iter().zip(proof_children.iter()).all(
                            |(child, proof_child)| {
                                (matches!(**child, MerkleNode::EmptySubtree)
                                    && matches!(**proof_child, MerkleNode::EmptySubtree))
                                    || *child.elem_ref() == *proof_child.elem_ref()
                            },
                        ) {
                            Err(PrimitivesError::ParameterError(format!(
                                "Invalid proof. Sibling differs at height {}",
                                depth
                            )))
                        } else {
                            *children[branch] = MerkleNode::Leaf {
                                elem: *proof_children[branch].elem_ref(),
                            };
                            Ok(())
                        }
                    } else if !children.iter().zip(proof_children.iter()).all(
                        |(child, proof_child)| {
                            (matches!(**child, MerkleNode::EmptySubtree)
                                && matches!(**proof_child, MerkleNode::EmptySubtree))
                                || child.value() == proof_child.value()
                        },
                    ) {
                        Err(PrimitivesError::ParameterError(format!(
                            "Invalid proof. Sibling differs at height {}",
                            depth
                        )))
                    } else {
                        children[branches[depth - 1]].remember_internal(
                            depth - 1,
                            branches,
                            path_values,
                            proof,
                        )
                    }
                },
                MerkleNode::ForgettenSubtree { value: _ } => {
                    *self = MerkleNode::Branch {
                        value: path_values[depth - 1],
                        children: {
                            let mut children = proof_children.clone();
                            children[branches[depth - 1]].remember_internal(
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
                MerkleNode::Leaf { elem: _ } => unreachable!(),
                MerkleNode::ForgettenLeaf { elem: _ } => unreachable!(),
                MerkleNode::EmptySubtree => Err(PrimitivesError::ParameterError(
                    "Invalid proof. Given location is supposed to be empty.".to_string(),
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
    ) -> LookupResult<E, Vec<MerkleNode<E, F>>> {
        match self {
            MerkleNode::EmptySubtree => LookupResult::EmptyLeaf,
            MerkleNode::Branch { value: _, children } => {
                match children[branches[depth - 1]].lookup_internal(depth, branches) {
                    LookupResult::Ok(value, mut proof) => {
                        proof.push(MerkleNode::Branch {
                            value: F::zero(),
                            children: if depth == 1 {
                                children.iter().cloned().collect_vec()
                            } else {
                                children
                                    .iter()
                                    .map(|child| {
                                        if let MerkleNode::EmptySubtree = **child {
                                            Box::new(MerkleNode::EmptySubtree)
                                        } else {
                                            Box::new(MerkleNode::ForgettenSubtree {
                                                value: child.value(),
                                            })
                                        }
                                    })
                                    .collect_vec()
                            },
                        });
                        LookupResult::Ok(value, proof)
                    },
                    LookupResult::NotInMemory => LookupResult::NotInMemory,
                    LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
                }
            },
            MerkleNode::Leaf { elem: value } => LookupResult::Ok(*value, vec![]),
            _ => LookupResult::NotInMemory,
        }
    }

    pub(crate) fn update_internal<H, LeafArity, TreeArity>(
        &mut self,
        depth: usize,
        branches: &[usize],
        elem: impl Borrow<E>,
    ) -> Result<(), PrimitivesError>
    where
        H: DigestAlgorithm<F>,
        LeafArity: Unsigned,
        TreeArity: Unsigned,
    {
        match self {
            MerkleNode::Leaf { elem: value } => {
                *value = *elem.borrow();
                Ok(())
            },
            MerkleNode::Branch { value: _, children } => (*children[branches[depth - 1]])
                .update_internal::<H, LeafArity, TreeArity>(depth - 1, branches, elem),
            MerkleNode::EmptySubtree => {
                if depth == 0 {
                    *self = MerkleNode::Leaf {
                        elem: *elem.borrow(),
                    };
                } else {
                    let mut children = vec![
                        Box::new(MerkleNode::EmptySubtree);
                        if depth == 1 {
                            LeafArity::to_usize()
                        } else {
                            TreeArity::to_usize()
                        }
                    ];
                    (*children[branches[depth - 1]]).update_internal::<H, LeafArity, TreeArity>(
                        depth - 1,
                        branches,
                        elem,
                    )?;
                    *self = MerkleNode::Branch {
                        value: digest_branch::<E, H, F>(&children, depth == 1),
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

    pub(crate) fn extend_internal<H, LeafArity, TreeArity>(
        &mut self,
        depth: usize,
        branches: &[usize],
        data: &mut Peekable<impl Iterator<Item = impl Borrow<E>>>,
    ) -> Result<u64, PrimitivesError>
    where
        H: DigestAlgorithm<F>,
        LeafArity: Unsigned,
        TreeArity: Unsigned,
    {
        if data.peek().is_none() {
            Ok(0)
        } else {
            match self {
                MerkleNode::Branch { value, children } => {
                    let mut cnt = 0u64;
                    let mut frontier = branches[depth - 1];
                    let cap = if depth == 1 {
                        LeafArity::to_usize()
                    } else {
                        TreeArity::to_usize()
                    };
                    while data.peek().is_some() && frontier < cap {
                        cnt += children[frontier].extend_internal::<H, LeafArity, TreeArity>(
                            depth - 1,
                            branches,
                            data,
                        )?;
                        frontier += 1;
                    }
                    *value = digest_branch::<E, H, F>(children, depth == 1);
                    Ok(cnt)
                },
                MerkleNode::EmptySubtree => {
                    if depth == 0 {
                        *self = MerkleNode::Leaf {
                            elem: *data.next().unwrap().borrow(),
                        };
                        Ok(1)
                    } else {
                        let mut cnt = 0u64;
                        let mut frontier = branches[depth - 1];
                        let cap = if depth == 1 {
                            LeafArity::to_usize()
                        } else {
                            TreeArity::to_usize()
                        };
                        let mut children = vec![Box::new(MerkleNode::EmptySubtree); cap];
                        while data.peek().is_some() && frontier < cap {
                            cnt += children[frontier].extend_internal::<H, LeafArity, TreeArity>(
                                depth - 1,
                                branches,
                                data,
                            )?;
                            frontier += 1;
                        }
                        *self = MerkleNode::Branch {
                            value: digest_branch::<E, H, F>(&children, depth == 1),
                            children,
                        };
                        Ok(cnt)
                    }
                },
                MerkleNode::Leaf { elem: _ } => Err(PrimitivesError::ParameterError(
                    "Incompatible merkle tree: index already occupied".to_string(),
                )),
                _ => Err(PrimitivesError::ParameterError(
                    "Given part of merkle tree is not in memory".to_string(),
                )),
            }
        }
    }
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
            .enumerate()
            .fold(
                Ok(F::zero()),
                |result, (index, (branch, node))| -> Result<F, PrimitivesError> {
                    match result {
                        Ok(val) => match node {
                            MerkleNode::Branch { value: _, children } => {
                                if index == 0 {
                                    Ok(digest_branch::<E, H, F>(children, true))
                                } else {
                                    let mut data =
                                        children.iter().map(|node| node.value()).collect_vec();
                                    data[*branch] = val;
                                    Ok(H::digest(&data))
                                }
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
